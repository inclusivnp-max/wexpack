//! Explicit little-endian WXP v2 wire format.
//!
//! Rust layouts are never transmuted into archive bytes. Every decoded length,
//! enum, flag, offset, reference and path is validated before it is used.

use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use std::collections::HashMap;
use std::fmt;
use std::io::{self, Cursor, Read, Write};

pub const SUPERBLOCK_MAGIC: [u8; 4] = *b"WXP\x02";
pub const CHUNK_HEADER_MAGIC: [u8; 4] = *b"WXC\x02";
pub const INDEX_FOOTER_MAGIC: [u8; 4] = *b"WXPI";
pub const INDEX_ENVELOPE_MAGIC: [u8; 4] = *b"WXIE";
pub const FEC_SENTINEL_MAGIC: [u8; 8] = *b"WXP_FEC\0";
pub const CURRENT_VERSION: u16 = 2;
pub const SUPERBLOCK_SIZE: usize = 64;
pub const CHUNK_HEADER_SIZE: usize = 64;
pub const CHUNK_DESCRIPTOR_SIZE: usize = 64;
pub const INDEX_ENVELOPE_SIZE: usize = 32;
pub const FEC_SENTINEL_SIZE: usize = 32;
pub const FILE_ENTRY_BASE_SIZE: u64 = 66;
pub const MAX_SOLID_GROUP_SIZE: usize = 16 << 20;
pub const MAX_CHUNK_SIZE: u32 = 1 << 26;
pub const MAX_STORED_CHUNK_SIZE: u32 = 1 << 27;

pub type Fingerprint = [u8; 32];
pub type Result<T> = std::result::Result<T, FormatError>;

/// Dense chunk-table row number. 0xffff_ffff is reserved, never a valid ID.
#[repr(transparent)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ChunkId(u32);

impl ChunkId {
    pub fn new(value: u32) -> Result<Self> {
        if value == u32::MAX {
            return Err(invalid("reserved ChunkID"));
        }
        Ok(Self(value))
    }
    pub const fn get(self) -> u32 {
        self.0
    }
}

impl fmt::Display for ChunkId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

bitflags::bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    #[repr(transparent)]
    pub struct HeaderFlags: u16 {
        const DEDUP = 1 << 0;
        const SOLID = 1 << 1;
        const ENCRYPTED_INDEX = 1 << 2;
        const REED_SOLOMON = 1 << 3;
        const PRECOMP = 1 << 4;
        const ENCRYPTED_DATA = 1 << 5;
        /// Extended 12-byte file references and independently decoded solid groups.
        const SOLID_GROUPS = 1 << 6;
        const STRUCTURED = 1 << 7;
        const LITERAL_CONTEXT = 1 << 8;
    }
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    #[repr(transparent)]
    pub struct ChunkFlags: u16 {
        const ENCRYPTED = 1 << 0;
    }
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    #[repr(transparent)]
    pub struct FileFlags: u16 {
        const REGULAR = 0;
        const DIRECTORY = 1 << 0;
        const SYMLINK = 1 << 1;
        const EXECUTABLE = 1 << 2;
        const READONLY = 1 << 3;
    }
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CodecType {
    Store = 0,
    WexTurbo = 1,
    WexBalanced = 2,
    WexExtreme = 3,
    WexStructured = 4,
    WexContextual = 5,
}
impl CodecType {
    pub fn from_u8(value: u8) -> Result<Self> {
        match value {
            0 => Ok(Self::Store),
            1 => Ok(Self::WexTurbo),
            2 => Ok(Self::WexBalanced),
            3 => Ok(Self::WexExtreme),
            4 => Ok(Self::WexStructured),
            5 => Ok(Self::WexContextual),
            n => Err(FormatError::UnknownCodec(n)),
        }
    }
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TransformType {
    None = 0,
    ByteShuffle4 = 1,
    ByteShuffle8 = 2,
    BcjX86 = 3,
    BcjArm64 = 4,
    DictWord = 5,
}
impl TransformType {
    pub fn from_u8(value: u8) -> Result<Self> {
        match value {
            0 => Ok(Self::None),
            1 => Ok(Self::ByteShuffle4),
            2 => Ok(Self::ByteShuffle8),
            3 => Ok(Self::BcjX86),
            4 => Ok(Self::BcjArm64),
            5 => Ok(Self::DictWord),
            n => Err(FormatError::UnknownTransform(n)),
        }
    }
}

fn invalid(message: &str) -> FormatError {
    FormatError::CorruptedData(message.into())
}
fn header_flags(bits: u16) -> Result<HeaderFlags> {
    HeaderFlags::from_bits(bits).ok_or_else(|| invalid("unknown archive feature flags"))
}
fn chunk_flags(bits: u16) -> Result<ChunkFlags> {
    ChunkFlags::from_bits(bits).ok_or_else(|| invalid("unknown chunk flags"))
}
fn file_flags(bits: u16) -> Result<FileFlags> {
    FileFlags::from_bits(bits).ok_or_else(|| invalid("unknown file flags"))
}
fn add(a: u64, b: u64) -> Result<u64> {
    a.checked_add(b).ok_or_else(|| invalid("integer overflow"))
}
fn count32(length: usize) -> Result<u32> {
    u32::try_from(length).map_err(|_| invalid("table exceeds u32 count"))
}
fn reserve<T>(v: &mut Vec<T>, count: usize) -> Result<()> {
    v.try_reserve_exact(count)
        .map_err(|_| FormatError::ResourceLimit("allocation failed"))
}
fn checksum64(bytes: &[u8]) -> u64 {
    let mut value = [0; 8];
    value.copy_from_slice(&blake3::hash(bytes).as_bytes()[..8]);
    u64::from_le_bytes(value)
}

/// Decode policy: callers may raise these limits for trusted, very large archives.
#[derive(Debug, Clone, Copy)]
pub struct DecodeLimits {
    pub max_index_bytes: usize,
    pub max_chunks: usize,
    pub max_files: usize,
    pub max_references: usize,
    pub max_path_bytes: usize,
}
impl Default for DecodeLimits {
    fn default() -> Self {
        Self {
            max_index_bytes: 256 << 20,
            max_chunks: 4_000_000,
            max_files: 1_000_000,
            max_references: 16_000_000,
            max_path_bytes: 65_535,
        }
    }
}

#[repr(C, align(64))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SuperBlock {
    pub magic: [u8; 4],
    pub version: u16,
    pub flags: HeaderFlags,
    pub chunk_min_bits: u8,
    pub chunk_avg_bits: u8,
    pub chunk_max_bits: u8,
    pub header_size: u8,
    pub chunk_count: u32,
    pub chunk_store_offset: u64,
    pub chunk_store_size: u64,
    pub footer_offset: u64,
    pub footer_comp_size: u64,
    pub footer_uncomp_size: u64,
    pub checksum: u64,
}
impl SuperBlock {
    /// Constructs an empty, finalized STORE archive header (empty index = 64 bytes).
    pub fn new(flags: HeaderFlags, min_bits: u8, avg_bits: u8, max_bits: u8) -> Result<Self> {
        let mut value = Self {
            magic: SUPERBLOCK_MAGIC,
            version: CURRENT_VERSION,
            flags,
            chunk_min_bits: min_bits,
            chunk_avg_bits: avg_bits,
            chunk_max_bits: max_bits,
            header_size: 64,
            chunk_count: 0,
            chunk_store_offset: if flags.contains(HeaderFlags::ENCRYPTED_DATA) {
                192
            } else {
                64
            },
            chunk_store_size: 0,
            footer_offset: if flags.contains(HeaderFlags::ENCRYPTED_DATA) {
                192
            } else {
                64
            },
            footer_comp_size: if flags.contains(HeaderFlags::ENCRYPTED_INDEX) {
                112
            } else {
                96
            },
            footer_uncomp_size: 64,
            checksum: 0,
        };
        value.validate()?;
        value.refresh_checksum();
        Ok(value)
    }
    fn prefix(&self) -> [u8; 56] {
        let mut b = [0; 56];
        b[..4].copy_from_slice(&self.magic);
        b[4..6].copy_from_slice(&self.version.to_le_bytes());
        b[6..8].copy_from_slice(&self.flags.bits().to_le_bytes());
        b[8] = self.chunk_min_bits;
        b[9] = self.chunk_avg_bits;
        b[10] = self.chunk_max_bits;
        b[11] = self.header_size;
        b[12..16].copy_from_slice(&self.chunk_count.to_le_bytes());
        for (i, value) in [
            self.chunk_store_offset,
            self.chunk_store_size,
            self.footer_offset,
            self.footer_comp_size,
            self.footer_uncomp_size,
        ]
        .iter()
        .enumerate()
        {
            b[16 + i * 8..24 + i * 8].copy_from_slice(&value.to_le_bytes());
        }
        b
    }
    pub fn compute_checksum(&self) -> u64 {
        checksum64(&self.prefix())
    }
    pub fn refresh_checksum(&mut self) {
        self.checksum = self.compute_checksum();
    }
    pub fn verify_checksum(&self) -> bool {
        self.checksum == self.compute_checksum()
    }
    pub fn validate(&self) -> Result<()> {
        if self.magic != SUPERBLOCK_MAGIC {
            return Err(FormatError::InvalidMagic(self.magic));
        }
        if self.version != CURRENT_VERSION {
            return Err(FormatError::UnsupportedVersion(self.version));
        }
        header_flags(self.flags.bits())?;
        if self.flags.contains(HeaderFlags::LITERAL_CONTEXT)
            && !self.flags.contains(HeaderFlags::STRUCTURED)
        {
            return Err(invalid("literal context requires structured feature"));
        }
        if self.flags.contains(HeaderFlags::SOLID_GROUPS)
            && !self.flags.contains(HeaderFlags::SOLID)
        {
            return Err(invalid("solid groups require SOLID feature"));
        }
        if self.header_size != 64 {
            return Err(invalid("header size must be 64"));
        }
        if !(1..=26).contains(&self.chunk_min_bits)
            || !(16..=20).contains(&self.chunk_avg_bits)
            || self.chunk_min_bits > self.chunk_avg_bits
            || self.chunk_avg_bits > self.chunk_max_bits
            || self.chunk_max_bits > 26
        {
            return Err(invalid(
                "invalid CDC powers of two; average must be 64 KiB..1 MiB",
            ));
        }
        if self.flags.contains(HeaderFlags::ENCRYPTED_INDEX)
            && !self.flags.contains(HeaderFlags::ENCRYPTED_DATA)
        {
            return Err(invalid("stealth index requires encrypted data"));
        }
        let expected_start = if self.flags.contains(HeaderFlags::ENCRYPTED_DATA) {
            192
        } else {
            64
        };
        if self.chunk_store_offset != expected_start {
            return Err(invalid(
                "chunk store offset differs from public-prefix size",
            ));
        }
        if self.footer_offset != add(self.chunk_store_offset, self.chunk_store_size)? {
            return Err(invalid("index must immediately follow chunk store"));
        }
        if self.chunk_store_size < u64::from(self.chunk_count) * (CHUNK_HEADER_SIZE as u64 + 1) {
            return Err(invalid("chunk store too small for chunk count"));
        }
        if self.chunk_count == 0 && self.chunk_store_size != 0 {
            return Err(invalid("nonempty store with no chunks"));
        }
        if self.footer_comp_size < 32 || self.footer_uncomp_size < 64 {
            return Err(invalid("index is too small"));
        }
        add(self.footer_offset, self.footer_comp_size)?;
        Ok(())
    }
    pub fn validate_archive_len(&self, archive_len: u64, limits: DecodeLimits) -> Result<()> {
        self.validate()?;
        if !self.verify_checksum() {
            return Err(FormatError::ChecksumMismatch);
        }
        if self.footer_comp_size > limits.max_index_bytes as u64
            || self.footer_uncomp_size > limits.max_index_bytes as u64
            || u64::from(self.chunk_count) > limits.max_chunks as u64
        {
            return Err(FormatError::ResourceLimit("index size or chunk count"));
        }
        let end = add(self.footer_offset, self.footer_comp_size)?;
        if self.flags.contains(HeaderFlags::REED_SOLOMON) {
            if add(end, FEC_SENTINEL_SIZE as u64)? >= archive_len {
                return Err(invalid("missing FEC payload or sentinel"));
            }
        } else if end != archive_len {
            return Err(invalid("archive length does not match index end"));
        }
        Ok(())
    }
    pub fn to_bytes(&self) -> [u8; SUPERBLOCK_SIZE] {
        let mut b = [0; SUPERBLOCK_SIZE];
        b[..56].copy_from_slice(&self.prefix());
        b[56..].copy_from_slice(&self.checksum.to_le_bytes());
        b
    }
    pub fn from_bytes(bytes: &[u8; SUPERBLOCK_SIZE]) -> Result<Self> {
        let mut r = Cursor::new(bytes);
        let mut magic = [0; 4];
        r.read_exact(&mut magic)?;
        let version = r.read_u16::<LittleEndian>()?;
        let flags = header_flags(r.read_u16::<LittleEndian>()?)?;
        let value = Self {
            magic,
            version,
            flags,
            chunk_min_bits: r.read_u8()?,
            chunk_avg_bits: r.read_u8()?,
            chunk_max_bits: r.read_u8()?,
            header_size: r.read_u8()?,
            chunk_count: r.read_u32::<LittleEndian>()?,
            chunk_store_offset: r.read_u64::<LittleEndian>()?,
            chunk_store_size: r.read_u64::<LittleEndian>()?,
            footer_offset: r.read_u64::<LittleEndian>()?,
            footer_comp_size: r.read_u64::<LittleEndian>()?,
            footer_uncomp_size: r.read_u64::<LittleEndian>()?,
            checksum: r.read_u64::<LittleEndian>()?,
        };
        if !value.verify_checksum() {
            return Err(FormatError::ChecksumMismatch);
        }
        value.validate()?;
        Ok(value)
    }
    pub fn write_to<W: Write>(&self, w: &mut W) -> Result<()> {
        self.validate()?;
        if !self.verify_checksum() {
            return Err(FormatError::ChecksumMismatch);
        }
        w.write_all(&self.to_bytes())?;
        Ok(())
    }
    pub fn read_from<R: Read>(r: &mut R) -> Result<Self> {
        let mut b = [0; SUPERBLOCK_SIZE];
        r.read_exact(&mut b)?;
        Self::from_bytes(&b)
    }
}

/// Fully independent compression frame. Hash covers ORIGINAL bytes, CRC stored bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChunkHeader {
    pub chunk_id: ChunkId,
    pub uncompressed_size: u32,
    pub transformed_size: u32,
    pub compressed_size: u32,
    pub codec: CodecType,
    pub transform: TransformType,
    pub flags: ChunkFlags,
    pub hash: Fingerprint,
    pub crc32: u32,
}
impl ChunkHeader {
    pub fn validate(&self) -> Result<()> {
        chunk_flags(self.flags.bits())?;
        if self.uncompressed_size == 0
            || self.uncompressed_size > MAX_CHUNK_SIZE
            || self.transformed_size == 0
            || self.transformed_size > MAX_STORED_CHUNK_SIZE
            || self.compressed_size == 0
            || self.compressed_size > MAX_STORED_CHUNK_SIZE
        {
            return Err(invalid("chunk sizes out of range"));
        }
        if self.transform != TransformType::DictWord
            && self.transformed_size != self.uncompressed_size
        {
            return Err(invalid("length-preserving transform changed size"));
        }
        if self.transform == TransformType::DictWord && self.transformed_size <= 8 {
            return Err(invalid(
                "nonempty dictionary chunk requires a header and token stream",
            ));
        }
        let tag_size = if self.flags.contains(ChunkFlags::ENCRYPTED) {
            16
        } else {
            0
        };
        if self.compressed_size <= tag_size {
            return Err(invalid("empty chunk payload"));
        }
        if self.codec == CodecType::Store
            && self.compressed_size
                != add(u64::from(self.transformed_size), tag_size.into())? as u32
        {
            return Err(invalid("STORE length mismatch"));
        }
        Ok(())
    }
    pub fn to_bytes(&self) -> [u8; CHUNK_HEADER_SIZE] {
        let mut b = [0; CHUNK_HEADER_SIZE];
        b[..4].copy_from_slice(&CHUNK_HEADER_MAGIC);
        b[4..8].copy_from_slice(&self.chunk_id.get().to_le_bytes());
        b[8..12].copy_from_slice(&self.uncompressed_size.to_le_bytes());
        b[12..16].copy_from_slice(&self.transformed_size.to_le_bytes());
        b[16..20].copy_from_slice(&self.compressed_size.to_le_bytes());
        b[20] = self.codec as u8;
        b[21] = self.transform as u8;
        b[22..24].copy_from_slice(&self.flags.bits().to_le_bytes());
        b[24..56].copy_from_slice(&self.hash);
        b[56..60].copy_from_slice(&self.crc32.to_le_bytes());
        let crc = crc32fast::hash(&b[..60]);
        b[60..64].copy_from_slice(&crc.to_le_bytes());
        b
    }
    pub fn from_bytes(bytes: &[u8; CHUNK_HEADER_SIZE]) -> Result<Self> {
        if bytes[..4] != CHUNK_HEADER_MAGIC {
            return Err(invalid("bad chunk magic"));
        }
        let mut r = Cursor::new(&bytes[4..]);
        let chunk_id = ChunkId::new(r.read_u32::<LittleEndian>()?)?;
        let uncompressed_size = r.read_u32::<LittleEndian>()?;
        let transformed_size = r.read_u32::<LittleEndian>()?;
        let compressed_size = r.read_u32::<LittleEndian>()?;
        let codec = CodecType::from_u8(r.read_u8()?)?;
        let transform = TransformType::from_u8(r.read_u8()?)?;
        let flags = chunk_flags(r.read_u16::<LittleEndian>()?)?;
        let mut hash = [0; 32];
        r.read_exact(&mut hash)?;
        let crc32 = r.read_u32::<LittleEndian>()?;
        if r.read_u32::<LittleEndian>()? != crc32fast::hash(&bytes[..60]) {
            return Err(FormatError::ChecksumMismatch);
        }
        let value = Self {
            chunk_id,
            uncompressed_size,
            transformed_size,
            compressed_size,
            codec,
            transform,
            flags,
            hash,
            crc32,
        };
        value.validate()?;
        Ok(value)
    }
    pub fn write_to<W: Write>(&self, w: &mut W) -> Result<()> {
        self.validate()?;
        w.write_all(&self.to_bytes())?;
        Ok(())
    }
    pub fn read_from<R: Read>(r: &mut R) -> Result<Self> {
        let mut b = [0; CHUNK_HEADER_SIZE];
        r.read_exact(&mut b)?;
        Self::from_bytes(&b)
    }
    pub fn verify_stored_payload(&self, bytes: &[u8]) -> Result<()> {
        if bytes.len() != self.compressed_size as usize || crc32fast::hash(bytes) != self.crc32 {
            return Err(FormatError::ChecksumMismatch);
        }
        Ok(())
    }
    pub fn verify_original(&self, bytes: &[u8]) -> Result<()> {
        if bytes.len() != self.uncompressed_size as usize
            || *blake3::hash(bytes).as_bytes() != self.hash
        {
            return Err(FormatError::ChecksumMismatch);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChunkDescriptor {
    /// Absolute offset of the 64-byte ChunkHeader.
    pub offset: u64,
    pub header: ChunkHeader,
}
impl ChunkDescriptor {
    fn write_to<W: Write>(&self, w: &mut W) -> Result<()> {
        self.header.validate()?;
        w.write_u64::<LittleEndian>(self.offset)?;
        // Dense table position supplies ChunkID; only metadata bytes are copied.
        w.write_all(&self.header.to_bytes()[8..60])?;
        w.write_u32::<LittleEndian>(0)?;
        Ok(())
    }
    fn read_from<R: Read>(r: &mut R, id: ChunkId) -> Result<Self> {
        let offset = r.read_u64::<LittleEndian>()?;
        let mut b = [0; CHUNK_HEADER_SIZE];
        b[..4].copy_from_slice(&CHUNK_HEADER_MAGIC);
        b[4..8].copy_from_slice(&id.get().to_le_bytes());
        r.read_exact(&mut b[8..60])?;
        if r.read_u32::<LittleEndian>()? != 0 {
            return Err(invalid("nonzero descriptor reserved field"));
        }
        let crc = crc32fast::hash(&b[..60]);
        b[60..].copy_from_slice(&crc.to_le_bytes());
        Ok(Self {
            offset,
            header: ChunkHeader::from_bytes(&b)?,
        })
    }
    pub fn end(&self) -> Result<u64> {
        add(add(self.offset, 64)?, self.header.compressed_size.into())
    }
}

/// Portable archive-root-relative UTF-8 path; never an OS-native absolute path.
pub fn validate_path(path: &str) -> Result<()> {
    if path.is_empty()
        || path.len() > 65_535
        || path
            .chars()
            .any(|c| c.is_control() || "\\:<>\"|?*".contains(c))
    {
        return Err(invalid("invalid portable archive path"));
    }
    for component in path.split('/') {
        if component.is_empty()
            || component == "."
            || component == ".."
            || component.ends_with([' ', '.'])
        {
            return Err(invalid("path traversal or noncanonical path component"));
        }
        let stem = component
            .split('.')
            .next()
            .unwrap_or("")
            .to_ascii_uppercase();
        let numbered = stem
            .strip_prefix("COM")
            .or_else(|| stem.strip_prefix("LPT"));
        if ["CON", "PRN", "AUX", "NUL"].contains(&stem.as_str())
            || numbered.is_some_and(|n| n.len() == 1 && matches!(n.as_bytes()[0], b'1'..=b'9'))
        {
            return Err(invalid("reserved portable path component"));
        }
    }
    Ok(())
}

/// Byte range of a logical dedup chunk inside its physical solid group.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChunkRange {
    pub offset: u32,
    pub size: u32,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileEntry {
    pub path: String,
    pub file_size: u64,
    pub mode: u32,
    /// Signed Unix seconds, permitting timestamps before 1970.
    pub mtime_secs: i64,
    pub mtime_nanos: u32,
    pub file_hash: Fingerprint,
    pub flags: FileFlags,
    /// Archive-root-relative path. Extraction must resolve links after regular files.
    pub symlink_target: Option<String>,
    pub chunk_ids: Vec<ChunkId>,
    /// Empty for legacy whole-chunk references; one range per ID for SOLID_GROUPS.
    pub chunk_ranges: Vec<ChunkRange>,
}
impl FileEntry {
    pub fn is_dir(&self) -> bool {
        self.flags.contains(FileFlags::DIRECTORY)
    }
    pub fn is_symlink(&self) -> bool {
        self.flags.contains(FileFlags::SYMLINK)
    }
    pub fn validate(&self) -> Result<()> {
        validate_path(&self.path)?;
        file_flags(self.flags.bits())?;
        if self.mtime_nanos >= 1_000_000_000 || self.mode & !0o7777 != 0 {
            return Err(invalid("invalid timestamp or permission bits"));
        }
        if self.is_dir() && self.is_symlink() {
            return Err(invalid("conflicting file kinds"));
        }
        if self.is_symlink() != self.symlink_target.is_some() {
            return Err(invalid("symlink target/kind mismatch"));
        }
        if let Some(target) = &self.symlink_target {
            validate_path(target)?;
        }
        if (self.is_dir() || self.is_symlink())
            && (self.file_size != 0 || !self.chunk_ids.is_empty() || self.file_hash != [0; 32])
        {
            return Err(invalid("non-regular entry has content"));
        }
        if !self.is_dir()
            && !self.is_symlink()
            && self.file_size == 0
            && (!self.chunk_ids.is_empty() || self.file_hash != *blake3::hash(&[]).as_bytes())
        {
            return Err(invalid("invalid empty-file content"));
        }
        count32(self.chunk_ids.len())?;
        if !self.chunk_ranges.is_empty()
            && (self.chunk_ranges.len() != self.chunk_ids.len()
                || self.chunk_ranges.iter().any(|r| {
                    r.size == 0
                        || u64::from(r.offset) + u64::from(r.size) > MAX_SOLID_GROUP_SIZE as u64
                }))
        {
            return Err(invalid("solid reference ranges"));
        }
        Ok(())
    }
    pub fn write_to<W: Write>(&self, w: &mut W) -> Result<()> {
        self.write_with_solid(w, false)
    }
    fn write_with_solid<W: Write>(&self, w: &mut W, solid: bool) -> Result<()> {
        self.validate()?;
        if (solid && self.chunk_ranges.len() != self.chunk_ids.len())
            || (!solid && !self.chunk_ranges.is_empty())
        {
            return Err(invalid("reference encoding/feature mismatch"));
        }
        w.write_u16::<LittleEndian>(self.path.len() as u16)?;
        w.write_all(self.path.as_bytes())?;
        w.write_u64::<LittleEndian>(self.file_size)?;
        w.write_u32::<LittleEndian>(self.mode)?;
        w.write_i64::<LittleEndian>(self.mtime_secs)?;
        w.write_u32::<LittleEndian>(self.mtime_nanos)?;
        w.write_all(&self.file_hash)?;
        w.write_u16::<LittleEndian>(self.flags.bits())?;
        let target = self.symlink_target.as_deref().unwrap_or("");
        w.write_u16::<LittleEndian>(target.len() as u16)?;
        w.write_all(target.as_bytes())?;
        w.write_u32::<LittleEndian>(count32(self.chunk_ids.len())?)?;
        for (n, id) in self.chunk_ids.iter().enumerate() {
            w.write_u32::<LittleEndian>(id.get())?;
            if solid {
                w.write_u32::<LittleEndian>(self.chunk_ranges[n].offset)?;
                w.write_u32::<LittleEndian>(self.chunk_ranges[n].size)?;
            }
        }
        Ok(())
    }
    pub fn read_from<R: Read>(r: &mut R, limits: DecodeLimits) -> Result<Self> {
        Self::read_with_solid(r, limits, false)
    }
    fn read_with_solid<R: Read>(r: &mut R, limits: DecodeLimits, solid: bool) -> Result<Self> {
        fn string<R: Read>(r: &mut R, limit: usize) -> Result<String> {
            let n = r.read_u16::<LittleEndian>()? as usize;
            if n > limit {
                return Err(FormatError::ResourceLimit("path length"));
            }
            let mut bytes = vec![0; n];
            r.read_exact(&mut bytes)?;
            String::from_utf8(bytes).map_err(|_| FormatError::InvalidUtf8)
        }
        let path = string(r, limits.max_path_bytes)?;
        let file_size = r.read_u64::<LittleEndian>()?;
        let mode = r.read_u32::<LittleEndian>()?;
        let mtime_secs = r.read_i64::<LittleEndian>()?;
        let mtime_nanos = r.read_u32::<LittleEndian>()?;
        let mut file_hash = [0; 32];
        r.read_exact(&mut file_hash)?;
        let flags = file_flags(r.read_u16::<LittleEndian>()?)?;
        let target = string(r, limits.max_path_bytes)?;
        let count = r.read_u32::<LittleEndian>()? as usize;
        if count > limits.max_references {
            return Err(FormatError::ResourceLimit("chunk reference count"));
        }
        // Grow only as bytes actually arrive: an untrusted count cannot preallocate gigabytes.
        let mut chunk_ids = Vec::new();
        let mut chunk_ranges = Vec::new();
        for _ in 0..count {
            let id = ChunkId::new(r.read_u32::<LittleEndian>()?)?;
            if chunk_ids.len() == chunk_ids.capacity() {
                chunk_ids
                    .try_reserve(1)
                    .map_err(|_| FormatError::ResourceLimit("chunk references"))?;
            }
            chunk_ids.push(id);
            if solid {
                let range = ChunkRange {
                    offset: r.read_u32::<LittleEndian>()?,
                    size: r.read_u32::<LittleEndian>()?,
                };
                if chunk_ranges.len() == chunk_ranges.capacity() {
                    chunk_ranges
                        .try_reserve(1)
                        .map_err(|_| FormatError::ResourceLimit("solid references"))?;
                }
                chunk_ranges.push(range);
            }
        }
        let value = Self {
            path,
            file_size,
            mode,
            mtime_secs,
            mtime_nanos,
            file_hash,
            flags,
            symlink_target: if target.is_empty() {
                None
            } else {
                Some(target)
            },
            chunk_ids,
            chunk_ranges,
        };
        value.validate()?;
        Ok(value)
    }
}

/// Decoded central directory. The final BLAKE3 covers all preceding index bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndexFooter {
    pub flags: HeaderFlags,
    pub chunk_table: Vec<ChunkDescriptor>,
    pub file_table: Vec<FileEntry>,
    pub total_uncompressed_bytes: u64,
}
impl IndexFooter {
    pub fn new(
        flags: HeaderFlags,
        chunk_table: Vec<ChunkDescriptor>,
        file_table: Vec<FileEntry>,
    ) -> Result<Self> {
        let total = file_table
            .iter()
            .try_fold(0, |n, file| add(n, file.file_size))?;
        let value = Self {
            flags,
            chunk_table,
            file_table,
            total_uncompressed_bytes: total,
        };
        value.validate()?;
        Ok(value)
    }
    pub fn validate(&self) -> Result<()> {
        header_flags(self.flags.bits())?;
        if self.flags.contains(HeaderFlags::LITERAL_CONTEXT)
            && !self.flags.contains(HeaderFlags::STRUCTURED)
        {
            return Err(invalid("literal context requires structured feature"));
        }
        if self.flags.contains(HeaderFlags::SOLID_GROUPS)
            && !self.flags.contains(HeaderFlags::SOLID)
        {
            return Err(invalid("solid groups require SOLID feature"));
        }
        if self.flags.contains(HeaderFlags::ENCRYPTED_INDEX)
            && !self.flags.contains(HeaderFlags::ENCRYPTED_DATA)
        {
            return Err(invalid("stealth index requires encrypted data"));
        }
        count32(self.chunk_table.len())?;
        count32(self.file_table.len())?;
        let mut previous_end = None;
        for (index, chunk) in self.chunk_table.iter().enumerate() {
            chunk.header.validate()?;
            if matches!(
                chunk.header.codec,
                CodecType::WexStructured | CodecType::WexContextual
            ) && !self.flags.contains(HeaderFlags::STRUCTURED)
            {
                return Err(invalid("structured codec without feature flag"));
            }
            if chunk.header.codec == CodecType::WexContextual
                && !self.flags.contains(HeaderFlags::LITERAL_CONTEXT)
            {
                return Err(invalid("context codec without feature flag"));
            }
            if self.flags.contains(HeaderFlags::SOLID_GROUPS)
                && (chunk.header.uncompressed_size as usize > MAX_SOLID_GROUP_SIZE
                    || chunk.header.transformed_size as usize > MAX_SOLID_GROUP_SIZE
                    || chunk.header.compressed_size as usize > MAX_SOLID_GROUP_SIZE + 16)
            {
                return Err(invalid("solid group exceeds limit"));
            }
            if chunk.header.chunk_id.get() as usize != index {
                return Err(invalid("non-dense ChunkIDs"));
            }
            if chunk.offset < 64 || previous_end.is_some_and(|end| chunk.offset != end) {
                return Err(invalid("chunk overlap, gap, or invalid offset"));
            }
            if chunk.header.flags.contains(ChunkFlags::ENCRYPTED)
                != self.flags.contains(HeaderFlags::ENCRYPTED_DATA)
            {
                return Err(invalid("chunk encryption flag mismatch"));
            }
            if chunk.header.transform != TransformType::None
                && !self.flags.contains(HeaderFlags::PRECOMP)
            {
                return Err(invalid("transform without PRECOMP feature"));
            }
            previous_end = Some(chunk.end()?);
        }
        let mut paths = HashMap::new();
        paths
            .try_reserve(self.file_table.len())
            .map_err(|_| FormatError::ResourceLimit("path map"))?;
        let mut total = 0;
        for file in &self.file_table {
            file.validate()?;
            if paths.insert(file.path.as_str(), file).is_some() {
                return Err(invalid("duplicate file path"));
            }
            let mut size = 0;
            let solid = self.flags.contains(HeaderFlags::SOLID_GROUPS);
            if (solid && file.chunk_ranges.len() != file.chunk_ids.len())
                || (!solid && !file.chunk_ranges.is_empty())
            {
                return Err(invalid("reference encoding/feature mismatch"));
            }
            for (n, id) in file.chunk_ids.iter().enumerate() {
                let chunk = self
                    .chunk_table
                    .get(id.get() as usize)
                    .ok_or_else(|| invalid("dangling ChunkID"))?;
                let length = if solid {
                    let range = file.chunk_ranges[n];
                    if u64::from(range.offset) + u64::from(range.size)
                        > u64::from(chunk.header.uncompressed_size)
                    {
                        return Err(invalid("solid reference exceeds group"));
                    }
                    range.size
                } else {
                    chunk.header.uncompressed_size
                };
                size = add(size, length.into())?;
            }
            if size != file.file_size {
                return Err(invalid("file size differs from referenced chunks"));
            }
            total = add(total, file.file_size)?;
        }
        for file in &self.file_table {
            for (separator, _) in file.path.match_indices('/') {
                if paths
                    .get(&file.path[..separator])
                    .is_some_and(|parent| !parent.is_dir())
                {
                    return Err(invalid("file or symlink used as parent directory"));
                }
            }
        }
        if total != self.total_uncompressed_bytes {
            return Err(invalid("index total size mismatch"));
        }
        Ok(())
    }
    pub fn validate_against(&self, header: &SuperBlock) -> Result<()> {
        self.validate()?;
        header.validate()?;
        if !header.verify_checksum() {
            return Err(FormatError::ChecksumMismatch);
        }
        if self.flags != header.flags
            || self.chunk_table.len() as u64 != u64::from(header.chunk_count)
        {
            return Err(invalid("header/index flags or count mismatch"));
        }
        if let (Some(first), Some(last)) = (self.chunk_table.first(), self.chunk_table.last())
            && (first.offset != header.chunk_store_offset || last.end()? != header.footer_offset)
        {
            return Err(invalid("header/index chunk-store bounds mismatch"));
        }
        let max_chunk = 1u32 << header.chunk_max_bits;
        if self
            .chunk_table
            .iter()
            .any(|c| c.header.uncompressed_size > max_chunk)
        {
            return Err(invalid("chunk exceeds declared CDC maximum"));
        }
        if self.serialized_size()? != header.footer_uncomp_size {
            return Err(invalid("decoded index length mismatch"));
        }
        Ok(())
    }
    pub fn serialized_size(&self) -> Result<u64> {
        let mut size = add(
            64,
            (self.chunk_table.len() as u64)
                .checked_mul(64)
                .ok_or_else(|| invalid("index size overflow"))?,
        )?;
        size = add(
            size,
            (self.file_table.len() as u64)
                .checked_mul(8)
                .ok_or_else(|| invalid("file table overflow"))?,
        )?;
        for f in &self.file_table {
            let base = add(FILE_ENTRY_BASE_SIZE, f.path.len() as u64)?;
            let base = add(
                base,
                f.symlink_target.as_ref().map_or(0, |s| s.len() as u64),
            )?;
            size = add(
                size,
                add(
                    base,
                    (f.chunk_ids.len() as u64)
                        .checked_mul(if self.flags.contains(HeaderFlags::SOLID_GROUPS) {
                            12
                        } else {
                            4
                        })
                        .ok_or_else(|| invalid("references overflow"))?,
                )?,
            )?;
        }
        Ok(size)
    }
    pub fn serialize(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let length = usize::try_from(self.serialized_size()?)
            .map_err(|_| FormatError::ResourceLimit("index address space"))?;
        let mut b = Vec::new();
        reserve(&mut b, length)?;
        b.write_all(&INDEX_FOOTER_MAGIC)?;
        b.write_u16::<LittleEndian>(2)?;
        b.write_u16::<LittleEndian>(self.flags.bits())?;
        b.write_u64::<LittleEndian>(self.total_uncompressed_bytes)?;
        b.write_u32::<LittleEndian>(count32(self.chunk_table.len())?)?;
        b.write_u32::<LittleEndian>(count32(self.file_table.len())?)?;
        for c in &self.chunk_table {
            c.write_to(&mut b)?;
        }
        let mut offset = 0;
        b.write_u64::<LittleEndian>(offset)?;
        for file in &self.file_table {
            offset = add(
                offset,
                FILE_ENTRY_BASE_SIZE
                    + file.path.len() as u64
                    + file.symlink_target.as_ref().map_or(0, |s| s.len() as u64)
                    + file.chunk_ids.len() as u64
                        * if self.flags.contains(HeaderFlags::SOLID_GROUPS) {
                            12
                        } else {
                            4
                        },
            )?;
            b.write_u64::<LittleEndian>(offset)?;
        }
        for file in &self.file_table {
            file.write_with_solid(&mut b, self.flags.contains(HeaderFlags::SOLID_GROUPS))?;
        }
        let checksum = *blake3::hash(&b).as_bytes();
        b.extend_from_slice(&checksum);
        if b.len() != length {
            return Err(invalid("internal index length inconsistency"));
        }
        Ok(b)
    }
    pub fn deserialize(bytes: &[u8]) -> Result<Self> {
        Self::deserialize_with_limits(bytes, DecodeLimits::default())
    }
    pub fn deserialize_with_limits(bytes: &[u8], limits: DecodeLimits) -> Result<Self> {
        if bytes.len() > limits.max_index_bytes {
            return Err(FormatError::ResourceLimit("decoded index size"));
        }
        if bytes.len() < 64 {
            return Err(FormatError::TruncatedData);
        }
        let payload = &bytes[..bytes.len() - 32];
        if blake3::hash(payload).as_bytes() != &bytes[bytes.len() - 32..] {
            return Err(FormatError::IndexChecksumMismatch);
        }
        let mut r = Cursor::new(payload);
        let mut magic = [0; 4];
        r.read_exact(&mut magic)?;
        if magic != INDEX_FOOTER_MAGIC {
            return Err(FormatError::InvalidMagic(magic));
        }
        let version = r.read_u16::<LittleEndian>()?;
        if version != 2 {
            return Err(FormatError::UnsupportedVersion(version));
        }
        let flags = header_flags(r.read_u16::<LittleEndian>()?)?;
        let total_uncompressed_bytes = r.read_u64::<LittleEndian>()?;
        let chunks = r.read_u32::<LittleEndian>()? as usize;
        let files = r.read_u32::<LittleEndian>()? as usize;
        if chunks > limits.max_chunks || files > limits.max_files {
            return Err(FormatError::ResourceLimit("index table count"));
        }
        let fixed = add(add(24, chunks as u64 * 64)?, (files as u64 + 1) * 8)?;
        // Every file record needs >= 67 bytes, including a nonempty path.
        if add(fixed, files as u64 * 67)? > payload.len() as u64 {
            return Err(FormatError::TruncatedData);
        }
        let mut chunk_table = Vec::new();
        reserve(&mut chunk_table, chunks)?;
        for n in 0..chunks {
            chunk_table.push(ChunkDescriptor::read_from(&mut r, ChunkId::new(n as u32)?)?);
        }
        let mut offsets = Vec::new();
        reserve(&mut offsets, files + 1)?;
        for _ in 0..=files {
            offsets.push(r.read_u64::<LittleEndian>()?);
        }
        let entries = &payload[fixed as usize..];
        if offsets.first() != Some(&0) || offsets.last().copied() != Some(entries.len() as u64) {
            return Err(invalid("file offset table boundaries"));
        }
        let mut file_table = Vec::new();
        reserve(&mut file_table, files)?;
        let mut references_left = limits.max_references;
        for pair in offsets.windows(2) {
            if pair[0] >= pair[1] || pair[1] > entries.len() as u64 {
                return Err(invalid("file offset table ordering"));
            }
            let mut record = Cursor::new(&entries[pair[0] as usize..pair[1] as usize]);
            let local_limits = DecodeLimits {
                max_references: references_left.min(
                    record.get_ref().len()
                        / if flags.contains(HeaderFlags::SOLID_GROUPS) {
                            12
                        } else {
                            4
                        },
                ),
                ..limits
            };
            let file = FileEntry::read_with_solid(
                &mut record,
                local_limits,
                flags.contains(HeaderFlags::SOLID_GROUPS),
            )?;
            if record.position() != pair[1] - pair[0] {
                return Err(invalid("trailing bytes in file record"));
            }
            references_left -= file.chunk_ids.len();
            file_table.push(file);
        }
        let value = Self {
            flags,
            chunk_table,
            file_table,
            total_uncompressed_bytes,
        };
        value.validate()?;
        Ok(value)
    }
    /// Build once after index decoding. Chunk lookup is direct; path lookup expected O(1).
    pub fn lookup(&self) -> Result<IndexLookup<'_>> {
        self.validate()?;
        let mut paths = HashMap::new();
        paths
            .try_reserve(self.file_table.len())
            .map_err(|_| FormatError::ResourceLimit("path map"))?;
        for (n, file) in self.file_table.iter().enumerate() {
            paths.insert(file.path.as_str(), n);
        }
        Ok(IndexLookup {
            footer: self,
            paths,
        })
    }
}

pub struct IndexLookup<'a> {
    footer: &'a IndexFooter,
    paths: HashMap<&'a str, usize>,
}
impl<'a> IndexLookup<'a> {
    pub fn file(&self, path: &str) -> Option<&'a FileEntry> {
        self.paths.get(path).map(|&n| &self.footer.file_table[n])
    }
    pub fn chunk(&self, id: ChunkId) -> Option<&'a ChunkDescriptor> {
        self.footer.chunk_table.get(id.get() as usize)
    }
}

/// Codec envelope for the compressed/encrypted central directory (32 public bytes).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IndexEnvelope {
    pub codec: CodecType,
    pub encrypted: bool,
    pub decoded_size: u64,
    pub payload_size: u64,
}
impl IndexEnvelope {
    pub fn validate(&self, limits: DecodeLimits) -> Result<()> {
        if self.decoded_size < 64 || self.payload_size == 0 {
            return Err(invalid("index envelope size"));
        }
        if self.decoded_size > limits.max_index_bytes as u64
            || add(32, self.payload_size)? > limits.max_index_bytes as u64
        {
            return Err(FormatError::ResourceLimit("index envelope size"));
        }
        if self.codec == CodecType::Store
            && self.payload_size != add(self.decoded_size, if self.encrypted { 16 } else { 0 })?
        {
            return Err(invalid("STORE index size mismatch"));
        }
        Ok(())
    }
    pub fn to_bytes(&self) -> [u8; INDEX_ENVELOPE_SIZE] {
        let mut b = [0; INDEX_ENVELOPE_SIZE];
        b[..4].copy_from_slice(&INDEX_ENVELOPE_MAGIC);
        b[4..6].copy_from_slice(&CURRENT_VERSION.to_le_bytes());
        b[6] = self.codec as u8;
        b[7] = u8::from(self.encrypted);
        b[8..16].copy_from_slice(&self.decoded_size.to_le_bytes());
        b[16..24].copy_from_slice(&self.payload_size.to_le_bytes());
        let crc = crc32fast::hash(&b[..28]);
        b[28..].copy_from_slice(&crc.to_le_bytes());
        b
    }
    pub fn from_bytes(bytes: &[u8; INDEX_ENVELOPE_SIZE], limits: DecodeLimits) -> Result<Self> {
        if bytes[..4] != INDEX_ENVELOPE_MAGIC {
            return Err(invalid("invalid index envelope magic"));
        }
        let mut r = Cursor::new(&bytes[4..]);
        let version = r.read_u16::<LittleEndian>()?;
        if version != 2 {
            return Err(FormatError::UnsupportedVersion(version));
        }
        let codec = CodecType::from_u8(r.read_u8()?)?;
        let flags = r.read_u8()?;
        if flags > 1 {
            return Err(invalid("unknown index envelope flags"));
        }
        let value = Self {
            codec,
            encrypted: flags == 1,
            decoded_size: r.read_u64::<LittleEndian>()?,
            payload_size: r.read_u64::<LittleEndian>()?,
        };
        if r.read_u32::<LittleEndian>()? != 0 {
            return Err(invalid("index envelope reserved field"));
        }
        if r.read_u32::<LittleEndian>()? != crc32fast::hash(&bytes[..28]) {
            return Err(FormatError::ChecksumMismatch);
        }
        value.validate(limits)?;
        Ok(value)
    }
    pub fn validate_against(&self, header: &SuperBlock, limits: DecodeLimits) -> Result<()> {
        self.validate(limits)?;
        if matches!(
            self.codec,
            CodecType::WexStructured | CodecType::WexContextual
        ) && !header.flags.contains(HeaderFlags::STRUCTURED)
        {
            return Err(invalid("structured index without feature flag"));
        }
        if self.codec == CodecType::WexContextual
            && !header.flags.contains(HeaderFlags::LITERAL_CONTEXT)
        {
            return Err(invalid("context index without feature flag"));
        }
        header.validate()?;
        if !header.verify_checksum() {
            return Err(FormatError::ChecksumMismatch);
        }
        if add(32, self.payload_size)? != header.footer_comp_size
            || self.decoded_size != header.footer_uncomp_size
            || self.encrypted != header.flags.contains(HeaderFlags::ENCRYPTED_INDEX)
        {
            return Err(invalid("index envelope/superblock mismatch"));
        }
        Ok(())
    }
    /// Plaintext STORE index encoding, including its codec envelope.
    pub fn store(footer: &IndexFooter) -> Result<Vec<u8>> {
        let bytes = footer.serialize()?;
        if footer.flags.contains(HeaderFlags::ENCRYPTED_INDEX) {
            return Err(invalid("STORE helper requires a plaintext index"));
        }
        let value = Self {
            codec: CodecType::Store,
            encrypted: false,
            decoded_size: bytes.len() as u64,
            payload_size: bytes.len() as u64,
        };
        let mut result = Vec::new();
        reserve(
            &mut result,
            bytes
                .len()
                .checked_add(32)
                .ok_or_else(|| invalid("index size overflow"))?,
        )?;
        result.extend_from_slice(&value.to_bytes());
        result.extend_from_slice(&bytes);
        Ok(result)
    }
    pub fn open_store(bytes: &[u8], limits: DecodeLimits) -> Result<IndexFooter> {
        let raw: &[u8; 32] = bytes
            .get(..32)
            .ok_or(FormatError::TruncatedData)?
            .try_into()
            .map_err(|_| FormatError::TruncatedData)?;
        let value = Self::from_bytes(raw, limits)?;
        if value.codec != CodecType::Store || value.encrypted {
            return Err(invalid("input is not a plaintext STORE index"));
        }
        if value.payload_size != (bytes.len() - 32) as u64 {
            return Err(invalid("stored index payload size"));
        }
        IndexFooter::deserialize_with_limits(&bytes[32..], limits)
    }
}

/// EOF locator for Reed-Solomon parity payload; does not implement error correction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReedSolomonSentinel {
    pub fec_offset: u64,
    pub fec_size: u64,
    pub parity_shards: u16,
    pub data_shards: u16,
}
impl ReedSolomonSentinel {
    pub fn new(
        fec_offset: u64,
        fec_size: u64,
        parity_shards: u16,
        data_shards: u16,
    ) -> Result<Self> {
        let value = Self {
            fec_offset,
            fec_size,
            parity_shards,
            data_shards,
        };
        value.validate()?;
        Ok(value)
    }
    pub fn validate(&self) -> Result<()> {
        if self.fec_offset < 64
            || self.fec_size == 0
            || self.data_shards == 0
            || self.parity_shards == 0
            || u32::from(self.data_shards) + u32::from(self.parity_shards) > 255
        {
            return Err(invalid("invalid GF(256) parity geometry"));
        }
        add(add(self.fec_offset, self.fec_size)?, 32)?;
        Ok(())
    }
    pub fn validate_archive(&self, header: &SuperBlock, archive_len: u64) -> Result<()> {
        self.validate()?;
        header.validate()?;
        if !header.verify_checksum() {
            return Err(FormatError::ChecksumMismatch);
        }
        if !header.flags.contains(HeaderFlags::REED_SOLOMON)
            || self.fec_offset != add(header.footer_offset, header.footer_comp_size)?
            || add(add(self.fec_offset, self.fec_size)?, 32)? != archive_len
        {
            return Err(invalid("FEC sentinel/archive bounds mismatch"));
        }
        Ok(())
    }
    pub fn to_bytes(&self) -> [u8; FEC_SENTINEL_SIZE] {
        let mut b = [0; FEC_SENTINEL_SIZE];
        b[..8].copy_from_slice(&FEC_SENTINEL_MAGIC);
        b[8..16].copy_from_slice(&self.fec_offset.to_le_bytes());
        b[16..24].copy_from_slice(&self.fec_size.to_le_bytes());
        b[24..26].copy_from_slice(&self.parity_shards.to_le_bytes());
        b[26..28].copy_from_slice(&self.data_shards.to_le_bytes());
        let crc = crc32fast::hash(&b[..28]);
        b[28..].copy_from_slice(&crc.to_le_bytes());
        b
    }
    pub fn from_bytes(bytes: &[u8; FEC_SENTINEL_SIZE]) -> Result<Self> {
        if bytes[..8] != FEC_SENTINEL_MAGIC {
            return Err(invalid("bad FEC sentinel magic"));
        }
        let mut r = Cursor::new(&bytes[8..]);
        let value = Self::new(
            r.read_u64::<LittleEndian>()?,
            r.read_u64::<LittleEndian>()?,
            r.read_u16::<LittleEndian>()?,
            r.read_u16::<LittleEndian>()?,
        )?;
        if r.read_u32::<LittleEndian>()? != crc32fast::hash(&bytes[..28]) {
            return Err(FormatError::ChecksumMismatch);
        }
        Ok(value)
    }
}

/// Public 128-byte crypto prefix.
/// KDF 1 = Argon2id v0x13, 32-byte output. AEAD 1 = XChaCha20-Poly1305.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CryptoDescriptor {
    pub memory_kib: u32,
    pub iterations: u32,
    pub lanes: u32,
    pub salt: [u8; 32],
    pub archive_id: [u8; 16],
}
impl CryptoDescriptor {
    pub fn validate(&self) -> Result<()> {
        if !(8192..=1_048_576).contains(&self.memory_kib)
            || !(1..=16).contains(&self.iterations)
            || !(1..=32).contains(&self.lanes)
            || self.memory_kib < 8 * self.lanes
        {
            return Err(invalid("Argon2id parameters outside v2 policy"));
        }
        Ok(())
    }
    pub fn to_bytes(&self) -> [u8; 128] {
        let mut b = [0; 128];
        b[..4].copy_from_slice(b"WXCR");
        b[4..6].copy_from_slice(&CURRENT_VERSION.to_le_bytes());
        b[6] = 1;
        b[7] = 1;
        b[8..12].copy_from_slice(&self.memory_kib.to_le_bytes());
        b[12..16].copy_from_slice(&self.iterations.to_le_bytes());
        b[16..20].copy_from_slice(&self.lanes.to_le_bytes());
        b[24..56].copy_from_slice(&self.salt);
        b[56..72].copy_from_slice(&self.archive_id);
        let digest = *blake3::hash(&b[..96]).as_bytes();
        b[96..].copy_from_slice(&digest);
        b
    }
    pub fn from_bytes(bytes: &[u8; 128]) -> Result<Self> {
        if &bytes[..4] != b"WXCR" || bytes[4..8] != [2, 0, 1, 1] {
            return Err(invalid("unknown crypto prefix format"));
        }
        if bytes[20..24]
            .iter()
            .chain(bytes[72..96].iter())
            .any(|&b| b != 0)
        {
            return Err(invalid("crypto reserved fields"));
        }
        if blake3::hash(&bytes[..96]).as_bytes() != &bytes[96..] {
            return Err(FormatError::ChecksumMismatch);
        }
        let mut r = Cursor::new(&bytes[8..20]);
        let mut value = Self {
            memory_kib: r.read_u32::<LittleEndian>()?,
            iterations: r.read_u32::<LittleEndian>()?,
            lanes: r.read_u32::<LittleEndian>()?,
            salt: [0; 32],
            archive_id: [0; 16],
        };
        value.salt.copy_from_slice(&bytes[24..56]);
        value.archive_id.copy_from_slice(&bytes[56..72]);
        value.validate()?;
        Ok(value)
    }
}

/// FEC payload framing. The manifest hashes every padded data/parity shard.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FecHeader {
    pub protected_size: u64,
    pub shard_size: u32,
    pub stripes: u32,
    pub data_shards: u16,
    pub parity_shards: u16,
    pub manifest_size: u64,
    pub parity_size: u64,
}
impl FecHeader {
    pub fn new(
        protected_size: u64,
        shard_size: u32,
        data_shards: u16,
        parity_shards: u16,
    ) -> Result<Self> {
        if shard_size == 0 || data_shards == 0 {
            return Err(invalid("zero FEC dimension"));
        }
        let stripes = protected_size.div_ceil(u64::from(shard_size) * u64::from(data_shards));
        let value = Self {
            protected_size,
            shard_size,
            stripes: u32::try_from(stripes).map_err(|_| invalid("too many FEC stripes"))?,
            data_shards,
            parity_shards,
            manifest_size: stripes
                .checked_mul((u64::from(data_shards) + u64::from(parity_shards)) * 32)
                .ok_or_else(|| invalid("FEC manifest overflow"))?,
            parity_size: stripes
                .checked_mul(u64::from(parity_shards) * u64::from(shard_size))
                .ok_or_else(|| invalid("FEC parity overflow"))?,
        };
        value.validate()?;
        Ok(value)
    }
    pub fn validate(&self) -> Result<()> {
        if self.protected_size < 64
            || !self.shard_size.is_power_of_two()
            || !(512..=1_048_576).contains(&self.shard_size)
            || self.data_shards == 0
            || self.parity_shards == 0
            || u32::from(self.data_shards) + u32::from(self.parity_shards) > 255
        {
            return Err(invalid("invalid FEC dimensions"));
        }
        let stripes = self
            .protected_size
            .div_ceil(u64::from(self.shard_size) * u64::from(self.data_shards));
        if stripes != u64::from(self.stripes)
            || self.manifest_size
                != stripes * (u64::from(self.data_shards) + u64::from(self.parity_shards)) * 32
            || self.parity_size
                != stripes * u64::from(self.parity_shards) * u64::from(self.shard_size)
        {
            return Err(invalid("FEC derived dimensions mismatch"));
        }
        self.payload_size()?;
        Ok(())
    }
    pub fn payload_size(&self) -> Result<u64> {
        add(add(64, self.manifest_size)?, self.parity_size)
    }
    pub fn validate_against(&self, sentinel: &ReedSolomonSentinel) -> Result<()> {
        self.validate()?;
        sentinel.validate()?;
        if self.protected_size != sentinel.fec_offset
            || self.payload_size()? != sentinel.fec_size
            || self.data_shards != sentinel.data_shards
            || self.parity_shards != sentinel.parity_shards
        {
            return Err(invalid("FEC header/sentinel mismatch"));
        }
        Ok(())
    }
    pub fn to_bytes(&self) -> [u8; 64] {
        let mut b = [0; 64];
        b[..4].copy_from_slice(b"WXRS");
        b[4..6].copy_from_slice(&CURRENT_VERSION.to_le_bytes());
        b[8..16].copy_from_slice(&self.protected_size.to_le_bytes());
        b[16..20].copy_from_slice(&self.shard_size.to_le_bytes());
        b[20..24].copy_from_slice(&self.stripes.to_le_bytes());
        b[24..26].copy_from_slice(&self.data_shards.to_le_bytes());
        b[26..28].copy_from_slice(&self.parity_shards.to_le_bytes());
        b[28] = 1;
        b[32..40].copy_from_slice(&self.manifest_size.to_le_bytes());
        b[40..48].copy_from_slice(&self.parity_size.to_le_bytes());
        let digest = *blake3::hash(&b[..48]).as_bytes();
        b[48..].copy_from_slice(&digest[..16]);
        b
    }
    pub fn from_bytes(bytes: &[u8; 64]) -> Result<Self> {
        if &bytes[..4] != b"WXRS" || bytes[4..8] != [2, 0, 0, 0] || bytes[28..32] != [1, 0, 0, 0] {
            return Err(invalid("unknown FEC header format"));
        }
        if blake3::hash(&bytes[..48]).as_bytes()[..16] != bytes[48..] {
            return Err(FormatError::ChecksumMismatch);
        }
        let mut r = Cursor::new(&bytes[8..48]);
        let protected_size = r.read_u64::<LittleEndian>()?;
        let shard_size = r.read_u32::<LittleEndian>()?;
        let stripes = r.read_u32::<LittleEndian>()?;
        let data_shards = r.read_u16::<LittleEndian>()?;
        let parity_shards = r.read_u16::<LittleEndian>()?;
        r.read_u32::<LittleEndian>()?;
        let value = Self {
            protected_size,
            shard_size,
            stripes,
            data_shards,
            parity_shards,
            manifest_size: r.read_u64::<LittleEndian>()?,
            parity_size: r.read_u64::<LittleEndian>()?,
        };
        value.validate()?;
        Ok(value)
    }
}

#[derive(Debug)]
pub enum FormatError {
    Io(io::Error),
    InvalidMagic([u8; 4]),
    UnsupportedVersion(u16),
    UnknownCodec(u8),
    UnknownTransform(u8),
    ChecksumMismatch,
    IndexChecksumMismatch,
    CorruptedData(String),
    TruncatedData,
    InvalidUtf8,
    ResourceLimit(&'static str),
}
impl fmt::Display for FormatError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "I/O: {e}"),
            Self::InvalidMagic(m) => write!(f, "invalid magic: {m:02x?}"),
            Self::UnsupportedVersion(v) => write!(f, "unsupported version: {v}"),
            Self::UnknownCodec(c) => write!(f, "unknown codec: {c}"),
            Self::UnknownTransform(t) => write!(f, "unknown transform: {t}"),
            Self::ChecksumMismatch => write!(f, "checksum mismatch"),
            Self::IndexChecksumMismatch => write!(f, "index BLAKE3 mismatch"),
            Self::CorruptedData(s) => write!(f, "invalid archive: {s}"),
            Self::TruncatedData => write!(f, "truncated data"),
            Self::InvalidUtf8 => write!(f, "invalid UTF-8"),
            Self::ResourceLimit(s) => write!(f, "resource limit: {s}"),
        }
    }
}
impl std::error::Error for FormatError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        if let Self::Io(e) = self {
            Some(e)
        } else {
            None
        }
    }
}
impl From<io::Error> for FormatError {
    fn from(e: io::Error) -> Self {
        if e.kind() == io::ErrorKind::UnexpectedEof {
            Self::TruncatedData
        } else {
            Self::Io(e)
        }
    }
}
