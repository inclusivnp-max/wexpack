//! Systematic Vandermonde Reed–Solomon over GF(2^8), polynomial 0x11d.
//! The archive manifest identifies corrupt shards as erasures. Recovery is
//! bounded per stripe, not by a percentage of arbitrary bytes of the whole file.
//! Header/manifest/sentinel must remain readable; they are not recursively protected.
use crate::format::{FecHeader, FormatError, HeaderFlags, ReedSolomonSentinel, SuperBlock};
use std::fmt;
use std::io::{self, Read, Seek, SeekFrom, Write};

pub type Result<T> = std::result::Result<T, FecError>;
pub const MAX_SHARDS: usize = 255;
pub const MAX_SHARD_SIZE: usize = 1 << 20;
pub const DEFAULT_DATA_SHARDS: u16 = 128;
pub const DEFAULT_SHARD_SIZE: u32 = 64 << 10;

#[derive(Debug)]
pub enum FecError {
    Io(io::Error),
    Format(FormatError),
    InvalidGeometry,
    InvalidShards,
    ResourceLimit(&'static str),
    AllocationFailed,
    SingularMatrix,
    TooManyErasures {
        stripe: u32,
        missing: usize,
        parity: usize,
    },
    ManifestMismatch {
        stripe: u32,
        shard: usize,
    },
    InvalidArchive(&'static str),
}
impl fmt::Display for FecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "FEC I/O: {e}"),
            Self::Format(e) => write!(f, "FEC framing: {e}"),
            Self::InvalidGeometry => f.write_str("invalid GF(256) shard geometry"),
            Self::InvalidShards => f.write_str("invalid shard count, size or presence"),
            Self::ResourceLimit(s) => write!(f, "FEC resource limit: {s}"),
            Self::AllocationFailed => f.write_str("FEC allocation failed"),
            Self::SingularMatrix => f.write_str("singular GF(256) matrix"),
            Self::TooManyErasures {
                stripe,
                missing,
                parity,
            } => write!(
                f,
                "stripe {stripe}: {missing} erasures exceed {parity} parity shards"
            ),
            Self::ManifestMismatch { stripe, shard } => write!(
                f,
                "stripe {stripe}, shard {shard}: reconstructed BLAKE3 differs from manifest"
            ),
            Self::InvalidArchive(s) => write!(f, "invalid FEC archive: {s}"),
        }
    }
}
impl std::error::Error for FecError {}
impl From<io::Error> for FecError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}
impl From<FormatError> for FecError {
    fn from(e: FormatError) -> Self {
        Self::Format(e)
    }
}
fn filled<T: Clone>(count: usize, value: T) -> Result<Vec<T>> {
    let mut v = Vec::new();
    v.try_reserve_exact(count)
        .map_err(|_| FecError::AllocationFailed)?;
    v.resize(count, value);
    Ok(v)
}

/// Public field operations also serve as a portable reference for accelerated backends.
pub mod gf256 {
    const fn tables() -> ([u8; 510], [u8; 256]) {
        let mut exp = [0u8; 510];
        let mut log = [0u8; 256];
        let mut x = 1u16;
        let mut i = 0;
        while i < 255 {
            exp[i] = x as u8;
            log[x as usize] = i as u8;
            x <<= 1;
            if x & 0x100 != 0 {
                x ^= 0x11d;
            }
            i += 1;
        }
        while i < 510 {
            exp[i] = exp[i - 255];
            i += 1;
        }
        (exp, log)
    }
    const TABLES: ([u8; 510], [u8; 256]) = tables();
    #[inline]
    pub fn mul(a: u8, b: u8) -> u8 {
        if a == 0 || b == 0 {
            0
        } else {
            TABLES.0[usize::from(TABLES.1[a as usize]) + usize::from(TABLES.1[b as usize])]
        }
    }
    pub fn inverse(a: u8) -> Option<u8> {
        if a == 0 {
            None
        } else {
            Some(TABLES.0[255 - usize::from(TABLES.1[a as usize])])
        }
    }
    pub fn pow(a: u8, exponent: usize) -> u8 {
        if exponent == 0 {
            1
        } else if a == 0 {
            0
        } else {
            TABLES.0[(usize::from(TABLES.1[a as usize]) * (exponent % 255)) % 255]
        }
    }
}

fn invert(matrix: &[u8], size: usize) -> Result<Vec<u8>> {
    if size == 0 || matrix.len() != size * size {
        return Err(FecError::InvalidGeometry);
    }
    let width = size * 2;
    let mut work = filled(size * width, 0u8)?;
    for row in 0..size {
        work[row * width..row * width + size]
            .copy_from_slice(&matrix[row * size..(row + 1) * size]);
        work[row * width + size + row] = 1;
    }
    for column in 0..size {
        let pivot = (column..size)
            .find(|&row| work[row * width + column] != 0)
            .ok_or(FecError::SingularMatrix)?;
        if pivot != column {
            for j in 0..width {
                work.swap(column * width + j, pivot * width + j);
            }
        }
        let factor =
            gf256::inverse(work[column * width + column]).ok_or(FecError::SingularMatrix)?;
        for j in 0..width {
            work[column * width + j] = gf256::mul(work[column * width + j], factor);
        }
        for row in 0..size {
            if row == column {
                continue;
            }
            let factor = work[row * width + column];
            if factor == 0 {
                continue;
            }
            for j in 0..width {
                work[row * width + j] ^= gf256::mul(factor, work[column * width + j]);
            }
        }
    }
    let mut inverse = filled(size * size, 0)?;
    for row in 0..size {
        inverse[row * size..(row + 1) * size]
            .copy_from_slice(&work[row * width + size..(row + 1) * width]);
    }
    Ok(inverse)
}
fn add_scaled(output: &mut [u8], input: &[u8], coefficient: u8) {
    if coefficient == 0 {
        return;
    }
    if coefficient == 1 {
        for (out, &byte) in output.iter_mut().zip(input) {
            *out ^= byte;
        }
    } else {
        for (out, &byte) in output.iter_mut().zip(input) {
            *out ^= gf256::mul(coefficient, byte);
        }
    }
}

/// Immutable code geometry; share across workers. Missing shards are `None`.
/// This primitive corrects known erasures, not unidentified errors. Use the
/// archive helpers to locate errors using the per-shard BLAKE3 manifest.
#[derive(Debug)]
pub struct ReedSolomon {
    data: usize,
    parity: usize,
    generator: Vec<u8>,
}
impl ReedSolomon {
    pub fn new(data_shards: u16, parity_shards: u16) -> Result<Self> {
        let data = usize::from(data_shards);
        let parity = usize::from(parity_shards);
        if data == 0 || parity == 0 || data + parity > MAX_SHARDS {
            return Err(FecError::InvalidGeometry);
        }
        let mut top = filled(data * data, 0)?;
        for row in 0..data {
            for col in 0..data {
                top[row * data + col] = gf256::pow((row + 1) as u8, col);
            }
        }
        let top_inverse = invert(&top, data)?;
        let mut generator = filled((data + parity) * data, 0)?;
        for row in 0..data {
            generator[row * data + row] = 1;
        }
        for row in data..data + parity {
            for j in 0..data {
                let v = gf256::pow((row + 1) as u8, j);
                for col in 0..data {
                    generator[row * data + col] ^= gf256::mul(v, top_inverse[j * data + col]);
                }
            }
        }
        Ok(Self {
            data,
            parity,
            generator,
        })
    }
    pub fn data_shards(&self) -> usize {
        self.data
    }
    pub fn parity_shards(&self) -> usize {
        self.parity
    }
    pub fn generator_matrix(&self) -> &[u8] {
        &self.generator
    }
    fn total(&self) -> usize {
        self.data + self.parity
    }
    fn valid_size(size: usize) -> bool {
        (1..=MAX_SHARD_SIZE).contains(&size)
    }
    pub fn encode(&self, data: &[Vec<u8>]) -> Result<Vec<Vec<u8>>> {
        if data.len() != self.data
            || !Self::valid_size(data[0].len())
            || data.iter().any(|s| s.len() != data[0].len())
        {
            return Err(FecError::InvalidShards);
        }
        let mut parity = filled(self.parity, Vec::new())?;
        for (row, output) in parity.iter_mut().enumerate() {
            *output = filled(data[0].len(), 0)?;
            for (col, input) in data.iter().enumerate() {
                add_scaled(
                    output,
                    input,
                    self.generator[(self.data + row) * self.data + col],
                );
            }
        }
        Ok(parity)
    }
    /// Reconstructs data AND parity, committing only after every allocation succeeds.
    pub fn reconstruct(&self, shards: &mut [Option<Vec<u8>>]) -> Result<usize> {
        if shards.len() != self.total() {
            return Err(FecError::InvalidShards);
        }
        let size = shards
            .iter()
            .find_map(|s| s.as_ref().map(Vec::len))
            .ok_or(FecError::InvalidShards)?;
        if !Self::valid_size(size) || shards.iter().flatten().any(|s| s.len() != size) {
            return Err(FecError::InvalidShards);
        }
        let missing = shards.iter().filter(|s| s.is_none()).count();
        if missing > self.parity {
            return Err(FecError::TooManyErasures {
                stripe: 0,
                missing,
                parity: self.parity,
            });
        }
        if missing == 0 {
            return Ok(0);
        }
        let mut selected = filled(self.data, 0usize)?;
        for (out, index) in selected.iter_mut().zip(
            shards
                .iter()
                .enumerate()
                .filter(|(_, s)| s.is_some())
                .map(|(i, _)| i),
        ) {
            *out = index;
        }
        let mut matrix = filled(self.data * self.data, 0)?;
        for (row, &index) in selected.iter().enumerate() {
            matrix[row * self.data..(row + 1) * self.data]
                .copy_from_slice(&self.generator[index * self.data..(index + 1) * self.data]);
        }
        let decoding = invert(&matrix, self.data)?;
        let mut pending = filled(self.total(), None)?;
        for row in 0..self.total() {
            if shards[row].is_some() {
                continue;
            }
            let mut output = filled(size, 0)?;
            for (source, &index) in selected.iter().enumerate() {
                let mut coefficient = 0;
                for col in 0..self.data {
                    coefficient ^= gf256::mul(
                        self.generator[row * self.data + col],
                        decoding[col * self.data + source],
                    );
                }
                add_scaled(
                    &mut output,
                    shards[index].as_ref().ok_or(FecError::InvalidShards)?,
                    coefficient,
                );
            }
            pending[row] = Some(output);
        }
        for (shard, replacement) in shards.iter_mut().zip(pending) {
            if shard.is_none() {
                *shard = replacement;
            }
        }
        Ok(missing)
    }
}

#[derive(Debug, Clone, Copy)]
pub struct RecoveryConfig {
    pub shard_size: u32,
    pub data_shards: u16,
    pub parity_shards: u16,
}
impl RecoveryConfig {
    /// Percentage denotes parity/data bytes, excluding header/hash overhead.
    pub fn for_percent(percent: u8) -> Result<Self> {
        if !(1..=30).contains(&percent) {
            return Err(FecError::InvalidGeometry);
        }
        let data_shards = DEFAULT_DATA_SHARDS;
        let parity_shards = (u32::from(data_shards) * u32::from(percent)).div_ceil(100) as u16;
        Ok(Self {
            shard_size: DEFAULT_SHARD_SIZE,
            data_shards,
            parity_shards,
        })
    }
}
#[derive(Debug, Clone, Copy)]
pub struct FecLimits {
    pub max_protected_bytes: u64,
    pub max_fec_bytes: u64,
    pub max_stripes: u32,
    pub max_workspace_bytes: u64,
}
impl Default for FecLimits {
    fn default() -> Self {
        Self {
            max_protected_bytes: 1 << 40,
            max_fec_bytes: 1 << 40,
            max_stripes: 1_000_000,
            max_workspace_bytes: 256 << 20,
        }
    }
}
impl FecLimits {
    fn check(&self, header: &FecHeader) -> Result<()> {
        header.validate()?;
        let total = u64::from(header.data_shards) + u64::from(header.parity_shards);
        // Includes live shards, pending reconstructions, matrices and manifest row.
        let workspace = 2 * total * u64::from(header.shard_size) + 8 * total * total + total * 32;
        if header.protected_size > self.max_protected_bytes
            || header.payload_size()? > self.max_fec_bytes
            || header.stripes > self.max_stripes
            || workspace > self.max_workspace_bytes
        {
            return Err(FecError::ResourceLimit("archive geometry/workspace"));
        }
        Ok(())
    }
}
fn read_at<R: Read + Seek>(io: &mut R, offset: u64, buffer: &mut [u8]) -> Result<()> {
    io.seek(SeekFrom::Start(offset))?;
    io.read_exact(buffer)?;
    Ok(())
}
fn write_at<W: Write + Seek>(io: &mut W, offset: u64, buffer: &[u8]) -> Result<()> {
    io.seek(SeekFrom::Start(offset))?;
    io.write_all(buffer)?;
    Ok(())
}
fn stored_data_size(header: &FecHeader, offset: u64) -> usize {
    header
        .protected_size
        .saturating_sub(offset)
        .min(u64::from(header.shard_size)) as usize
}

/// Appends recovery to a finalized archive whose superblock already has REED_SOLOMON.
/// Only one stripe and one stripe's hashes are resident; no archive-sized allocation.
/// As with any writer, an I/O failure may leave a partial suffix: publish via temp+rename.
pub fn append_recovery<T: Read + Write + Seek>(
    archive: &mut T,
    config: RecoveryConfig,
    limits: FecLimits,
) -> Result<ReedSolomonSentinel> {
    let protected_size = archive.seek(SeekFrom::End(0))?;
    let mut raw = [0; 64];
    read_at(archive, 0, &mut raw)?;
    let superblock = SuperBlock::from_bytes(&raw)?;
    if !superblock.flags.contains(HeaderFlags::REED_SOLOMON)
        || superblock.footer_offset + superblock.footer_comp_size != protected_size
    {
        return Err(FecError::InvalidArchive(
            "expected finalized prefix with FEC flag and no suffix",
        ));
    }
    let header = FecHeader::new(
        protected_size,
        config.shard_size,
        config.data_shards,
        config.parity_shards,
    )?;
    limits.check(&header)?;
    let sentinel = ReedSolomonSentinel::new(
        protected_size,
        header.payload_size()?,
        config.parity_shards,
        config.data_shards,
    )?;
    let code = ReedSolomon::new(config.data_shards, config.parity_shards)?;
    write_at(archive, protected_size, &header.to_bytes())?;
    let total = code.total();
    let size = header.shard_size as usize;
    let parity_start = protected_size + 64 + header.manifest_size;
    for stripe in 0..header.stripes {
        let mut data = filled(code.data, Vec::new())?;
        for (i, shard) in data.iter_mut().enumerate() {
            *shard = filled(size, 0)?;
            let offset =
                (u64::from(stripe) * code.data as u64 + i as u64) * u64::from(header.shard_size);
            let count = stored_data_size(&header, offset);
            if count != 0 {
                read_at(archive, offset, &mut shard[..count])?;
            }
        }
        let parity = code.encode(&data)?;
        let manifest_offset = protected_size + 64 + u64::from(stripe) * total as u64 * 32;
        for (i, shard) in data.iter().chain(parity.iter()).enumerate() {
            write_at(
                archive,
                manifest_offset + i as u64 * 32,
                blake3::hash(shard).as_bytes(),
            )?;
        }
        for (i, shard) in parity.iter().enumerate() {
            let offset = parity_start
                + (u64::from(stripe) * code.parity as u64 + i as u64)
                    * u64::from(header.shard_size);
            write_at(archive, offset, shard)?;
        }
    }
    write_at(
        archive,
        protected_size + sentinel.fec_size,
        &sentinel.to_bytes(),
    )?;
    archive.flush()?;
    Ok(sentinel)
}

struct Metadata {
    header: FecHeader,
    sentinel: ReedSolomonSentinel,
    archive_len: u64,
}
impl Metadata {
    fn read<R: Read + Seek>(archive: &mut R, limits: FecLimits) -> Result<Self> {
        let archive_len = archive.seek(SeekFrom::End(0))?;
        if archive_len < 32 {
            return Err(FecError::InvalidArchive("truncated EOF locator"));
        }
        let mut raw = [0; 32];
        read_at(archive, archive_len - 32, &mut raw)?;
        let sentinel = ReedSolomonSentinel::from_bytes(&raw)?;
        // Sentinel::validate has already checked the additions for overflow.
        if sentinel.fec_offset + sentinel.fec_size + 32 != archive_len || sentinel.fec_size < 64 {
            return Err(FecError::InvalidArchive("EOF locator bounds"));
        }
        let mut raw = [0; 64];
        read_at(archive, sentinel.fec_offset, &mut raw)?;
        let header = FecHeader::from_bytes(&raw)?;
        header.validate_against(&sentinel)?;
        limits.check(&header)?;
        Ok(Self {
            header,
            sentinel,
            archive_len,
        })
    }
}
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct VerificationReport {
    pub stripes: u32,
    pub damaged_data_shards: u64,
    pub damaged_parity_shards: u64,
}
impl VerificationReport {
    pub fn is_clean(&self) -> bool {
        self.damaged_data_shards == 0 && self.damaged_parity_shards == 0
    }
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum ScanMode {
    Verify,
    Preflight,
}

// Write operations are supplied separately so verification accepts read-only streams.
fn scan<R: Read + Seek, F: FnMut(&mut R, u64, &[u8]) -> Result<()>>(
    archive: &mut R,
    metadata: &Metadata,
    code: &ReedSolomon,
    mode: ScanMode,
    mut commit: F,
) -> Result<VerificationReport> {
    let header = &metadata.header;
    let size = header.shard_size as usize;
    let total = code.total();
    let parity_start = header.protected_size + 64 + header.manifest_size;
    let mut report = VerificationReport {
        stripes: header.stripes,
        ..VerificationReport::default()
    };
    for stripe in 0..header.stripes {
        let mut hashes = filled(total * 32, 0)?;
        read_at(
            archive,
            header.protected_size + 64 + u64::from(stripe) * total as u64 * 32,
            &mut hashes,
        )?;
        let mut shards = filled(total, None)?;
        let mut damaged = filled(total, false)?;
        for i in 0..total {
            let mut shard = filled(size, 0)?;
            if i < code.data {
                let offset = (u64::from(stripe) * code.data as u64 + i as u64)
                    * u64::from(header.shard_size);
                let count = stored_data_size(header, offset);
                if count != 0 {
                    read_at(archive, offset, &mut shard[..count])?;
                }
            } else {
                let offset = parity_start
                    + (u64::from(stripe) * code.parity as u64 + (i - code.data) as u64)
                        * u64::from(header.shard_size);
                read_at(archive, offset, &mut shard)?;
            }
            if blake3::hash(&shard).as_bytes() == &hashes[i * 32..(i + 1) * 32] {
                shards[i] = Some(shard);
            } else {
                damaged[i] = true;
                if i < code.data {
                    report.damaged_data_shards += 1;
                } else {
                    report.damaged_parity_shards += 1;
                }
            }
        }
        if mode == ScanMode::Preflight {
            let missing = damaged.iter().filter(|&&b| b).count();
            if missing > code.parity {
                return Err(FecError::TooManyErasures {
                    stripe,
                    missing,
                    parity: code.parity,
                });
            }
            code.reconstruct(&mut shards)?;
            for (i, shard) in shards.iter().enumerate() {
                if blake3::hash(shard.as_ref().ok_or(FecError::InvalidShards)?).as_bytes()
                    != &hashes[i * 32..(i + 1) * 32]
                {
                    return Err(FecError::ManifestMismatch { stripe, shard: i });
                }
            }
        }
        if stripe == 0
            && let Some(shard) = &shards[0]
        {
            let raw: &[u8; 64] = shard[..64]
                .try_into()
                .map_err(|_| FecError::InvalidShards)?;
            let superblock = SuperBlock::from_bytes(raw)?;
            metadata
                .sentinel
                .validate_archive(&superblock, metadata.archive_len)?;
        }
        if mode == ScanMode::Preflight {
            for (i, shard) in shards.iter().enumerate() {
                if !damaged[i] {
                    continue;
                }
                let shard = shard.as_ref().ok_or(FecError::InvalidShards)?;
                if i < code.data {
                    let offset = (u64::from(stripe) * code.data as u64 + i as u64)
                        * u64::from(header.shard_size);
                    commit(archive, offset, &shard[..stored_data_size(header, offset)])?;
                } else {
                    let offset = parity_start
                        + (u64::from(stripe) * code.parity as u64 + (i - code.data) as u64)
                            * u64::from(header.shard_size);
                    commit(archive, offset, shard)?;
                }
            }
        }
    }
    Ok(report)
}
/// Verifies the protected archive and parity without needing the password.
/// Hash errors are reported as damage, while invalid locator/header geometry is an error.
pub fn verify_recovery<R: Read + Seek>(
    archive: &mut R,
    limits: FecLimits,
) -> Result<VerificationReport> {
    let metadata = Metadata::read(archive, limits)?;
    let code = ReedSolomon::new(metadata.header.data_shards, metadata.header.parity_shards)?;
    scan(
        archive,
        &metadata,
        &code,
        ScanMode::Verify,
        |_, _, _| Ok(()),
    )
}
/// Dry-runs ALL stripes before the first write, then repairs data and parity and
/// verifies the result. Uncorrectable damage/manifest mismatch leaves bytes intact.
/// Concurrent external mutation and write-time I/O failures require file-level transaction handling.
pub fn repair_recovery<T: Read + Write + Seek>(
    archive: &mut T,
    limits: FecLimits,
) -> Result<VerificationReport> {
    let metadata = Metadata::read(archive, limits)?;
    let code = ReedSolomon::new(metadata.header.data_shards, metadata.header.parity_shards)?;
    let original = scan(archive, &metadata, &code, ScanMode::Preflight, |_, _, _| {
        Ok(())
    })?;
    if !original.is_clean() {
        scan(archive, &metadata, &code, ScanMode::Preflight, write_at)?;
        archive.flush()?;
        let verified = scan(
            archive,
            &metadata,
            &code,
            ScanMode::Verify,
            |_, _, _| Ok(()),
        )?;
        if !verified.is_clean() {
            return Err(FecError::InvalidArchive("post-repair verification failed"));
        }
    }
    Ok(original)
}
