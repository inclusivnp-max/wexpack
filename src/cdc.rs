//! WXP Gear-based FastCDC with subminimum skipping and dual-mask normalization.
//! This is the specified WXP variant, not a promise of identical boundaries with
//! other FastCDC implementations. All arithmetic in the Gear hash wraps modulo 2^64.

use crate::format::{ChunkId, Fingerprint, MAX_CHUNK_SIZE, SuperBlock};
use parking_lot::Mutex;
use std::collections::HashMap;
use std::fmt;
use std::io::{self, BufRead, BufReader, Read};
use std::iter::FusedIterator;
use std::sync::atomic::{AtomicU64, Ordering};

pub const GEAR_SEED: u64 = 0x5758_5002_4745_4152;
const fn gear_table() -> [u64; 256] {
    let mut table = [0; 256];
    let mut state = GEAR_SEED;
    let mut i = 0;
    while i < 256 {
        state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = state;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        table[i] = z ^ (z >> 31);
        i += 1;
    }
    table
}
pub const GEAR_TABLE: [u64; 256] = gear_table();

/// Spread selected bits across the word. 13 is coprime to 64, so no repeats.
const fn mask(bits: u32) -> u64 {
    let mut value = 0;
    let mut i = 0;
    while i < bits {
        value |= 1u64 << ((7 + 13 * i) % 64);
        i += 1;
    }
    value
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FastCdcConfig {
    min_size: usize,
    avg_size: usize,
    max_size: usize,
    normalization: u32,
    mask_s: u64,
    mask_l: u64,
}
impl FastCdcConfig {
    pub fn custom(
        min_size: usize,
        avg_size: usize,
        max_size: usize,
        normalization: u32,
    ) -> Result<Self, CdcError> {
        if !min_size.is_power_of_two()
            || !avg_size.is_power_of_two()
            || !max_size.is_power_of_two()
            || min_size > avg_size
            || avg_size > max_size
            || max_size > MAX_CHUNK_SIZE as usize
            || normalization > 3
            || avg_size.trailing_zeros() <= normalization
        {
            return Err(CdcError::InvalidConfig);
        }
        let bits = avg_size.trailing_zeros();
        Ok(Self {
            min_size,
            avg_size,
            max_size,
            normalization,
            mask_s: mask(bits + normalization),
            mask_l: mask(bits - normalization),
        })
    }
    pub fn from_header(header: &SuperBlock) -> Result<Self, CdcError> {
        header.validate().map_err(|_| CdcError::InvalidConfig)?;
        Self::custom(
            1usize << header.chunk_min_bits,
            1usize << header.chunk_avg_bits,
            1usize << header.chunk_max_bits,
            2,
        )
    }
    pub fn default_64k() -> Self {
        Self::default()
    }
    pub fn preset_256k() -> Self {
        Self {
            min_size: 1 << 16,
            avg_size: 1 << 18,
            max_size: 1 << 22,
            normalization: 2,
            mask_s: mask(20),
            mask_l: mask(16),
        }
    }
    pub fn preset_1m() -> Self {
        Self {
            min_size: 1 << 18,
            avg_size: 1 << 20,
            max_size: 1 << 23,
            normalization: 2,
            mask_s: mask(22),
            mask_l: mask(18),
        }
    }
    pub const fn min_size(self) -> usize {
        self.min_size
    }
    pub const fn avg_size(self) -> usize {
        self.avg_size
    }
    pub const fn max_size(self) -> usize {
        self.max_size
    }
    pub const fn normalization(self) -> u32 {
        self.normalization
    }
    pub const fn strict_mask(self) -> u64 {
        self.mask_s
    }
    pub const fn loose_mask(self) -> u64 {
        self.mask_l
    }
    /// Current byte has zero-based index `index`, before it is appended.
    #[inline]
    fn boundary(self, index: usize, byte: u8, fingerprint: &mut u64) -> bool {
        if index < self.min_size {
            return index + 1 == self.max_size;
        }
        *fingerprint = fingerprint
            .wrapping_shl(1)
            .wrapping_add(GEAR_TABLE[byte as usize]);
        let selected_mask = if index < self.avg_size {
            self.mask_s
        } else {
            self.mask_l
        };
        (*fingerprint & selected_mask) == 0 || index + 1 == self.max_size
    }
    /// Returns 0 only for empty input; a short slice is treated as final EOF.
    pub fn cut(self, input: &[u8]) -> usize {
        let end = input.len().min(self.max_size);
        if end <= self.min_size {
            return end;
        }
        let mut fp = 0;
        for (i, &byte) in input.iter().enumerate().take(end).skip(self.min_size) {
            if self.boundary(i, byte, &mut fp) {
                return i + 1;
            }
        }
        end
    }
}
impl Default for FastCdcConfig {
    fn default() -> Self {
        Self {
            min_size: 1 << 14,
            avg_size: 1 << 16,
            max_size: 1 << 20,
            normalization: 2,
            mask_s: mask(18),
            mask_l: mask(14),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChunkSlice<'a> {
    pub offset: usize,
    pub length: usize,
    pub data: &'a [u8],
}

/// Borrowed input is suitable for an mmap; this iterator does not copy payloads.
pub struct FastCdcIterator<'a> {
    source: &'a [u8],
    config: FastCdcConfig,
    cursor: usize,
}
impl<'a> FastCdcIterator<'a> {
    pub fn new(source: &'a [u8], config: FastCdcConfig) -> Self {
        Self {
            source,
            config,
            cursor: 0,
        }
    }
}
impl<'a> Iterator for FastCdcIterator<'a> {
    type Item = ChunkSlice<'a>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.cursor == self.source.len() {
            return None;
        }
        let offset = self.cursor;
        let length = self.config.cut(&self.source[offset..]);
        self.cursor += length;
        Some(ChunkSlice {
            offset,
            length,
            data: &self.source[offset..self.cursor],
        })
    }
    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = self.source.len() - self.cursor;
        if remaining == 0 {
            (0, Some(0))
        } else {
            (
                remaining.div_ceil(self.config.max_size),
                Some(remaining.div_ceil(self.config.min_size)),
            )
        }
    }
}
impl FusedIterator for FastCdcIterator<'_> {}

/// Stream sequence numbers are not global ChunkIDs: dedup assigns those later.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnedChunk {
    pub ordinal: u64,
    pub offset: u64,
    pub data: Vec<u8>,
    pub hash: Fingerprint,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StreamChunk<'a> {
    pub ordinal: u64,
    pub offset: u64,
    pub data: &'a [u8],
    pub hash: Fingerprint,
}

/// Bounded memory: at most max_size bytes of chunk capacity plus a 64-KiB reader.
/// `next_chunk_ref` reuses storage; the borrow prevents refilling while in use.
pub struct FastCdcStream<R: Read> {
    reader: BufReader<R>,
    config: FastCdcConfig,
    data: Vec<u8>,
    offset: u64,
    ordinal: u64,
    eof: bool,
    failed: bool,
}
impl<R: Read> FastCdcStream<R> {
    pub fn new(reader: R, config: FastCdcConfig) -> Self {
        Self {
            reader: BufReader::with_capacity(64 << 10, reader),
            config,
            data: Vec::new(),
            offset: 0,
            ordinal: 0,
            eof: false,
            failed: false,
        }
    }
    pub fn next_chunk_ref(&mut self) -> io::Result<Option<StreamChunk<'_>>> {
        if self.failed {
            return Err(io::Error::other("chunk reader is failed"));
        }
        if self.eof {
            return Ok(None);
        }
        self.data.clear();
        if self.data.capacity() < self.config.max_size {
            self.data
                .try_reserve_exact(self.config.max_size)
                .map_err(|_| io::Error::other("chunk allocation failed"))?;
        }
        let mut fp = 0;
        loop {
            let available = match self.reader.fill_buf() {
                Ok(bytes) => bytes,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => {
                    self.failed = true;
                    return Err(e);
                }
            };
            if available.is_empty() {
                self.eof = true;
                break;
            }
            let start = self.data.len();
            let limit = available.len().min(self.config.max_size - start);
            let mut consumed = 0;
            let mut found = false;
            // Skip subminimum bytes in one bulk copy, without Gear calculations.
            if start < self.config.min_size {
                consumed = (self.config.min_size - start).min(limit);
            }
            if start + consumed == self.config.max_size {
                found = true;
            }
            while consumed < limit && !found {
                found = self
                    .config
                    .boundary(start + consumed, available[consumed], &mut fp);
                consumed += 1;
            }
            self.data.extend_from_slice(&available[..consumed]);
            self.reader.consume(consumed);
            if found {
                break;
            }
        }
        if self.data.is_empty() {
            return Ok(None);
        }
        let offset = self.offset;
        let ordinal = self.ordinal;
        let Some(next_offset) = self.offset.checked_add(self.data.len() as u64) else {
            self.failed = true;
            return Err(io::Error::other("stream offset overflow"));
        };
        let Some(next_ordinal) = self.ordinal.checked_add(1) else {
            self.failed = true;
            return Err(io::Error::other("stream ordinal overflow"));
        };
        self.offset = next_offset;
        self.ordinal = next_ordinal;
        Ok(Some(StreamChunk {
            ordinal,
            offset,
            hash: *blake3::hash(&self.data).as_bytes(),
            data: &self.data,
        }))
    }
    pub fn next_chunk(&mut self) -> io::Result<Option<OwnedChunk>> {
        Ok(self.next_chunk_ref()?.map(|chunk| OwnedChunk {
            ordinal: chunk.ordinal,
            offset: chunk.offset,
            data: chunk.data.to_vec(),
            hash: chunk.hash,
        }))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DedupOutcome {
    pub chunk_id: ChunkId,
    pub hash: Fingerprint,
    pub is_duplicate: bool,
    pub uncompressed_size: u32,
}
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct DedupStats {
    pub total_chunks: u64,
    pub unique_chunks: u64,
    pub duplicate_chunks: u64,
    pub total_input_bytes: u64,
    pub unique_bytes: u64,
    pub deduped_bytes: u64,
}
impl DedupStats {
    pub fn savings_ratio(self) -> f64 {
        if self.total_input_bytes == 0 {
            0.0
        } else {
            self.deduped_bytes as f64 / self.total_input_bytes as f64
        }
    }
    pub fn dedup_factor(self) -> f64 {
        if self.unique_bytes == 0 {
            1.0
        } else {
            self.total_input_bytes as f64 / self.unique_bytes as f64
        }
    }
    fn combined(self, other: Self) -> Result<Self, CdcError> {
        fn sum(a: u64, b: u64) -> Result<u64, CdcError> {
            a.checked_add(b).ok_or(CdcError::CounterOverflow)
        }
        Ok(Self {
            total_chunks: sum(self.total_chunks, other.total_chunks)?,
            unique_chunks: sum(self.unique_chunks, other.unique_chunks)?,
            duplicate_chunks: sum(self.duplicate_chunks, other.duplicate_chunks)?,
            total_input_bytes: sum(self.total_input_bytes, other.total_input_bytes)?,
            unique_bytes: sum(self.unique_bytes, other.unique_bytes)?,
            deduped_bytes: sum(self.deduped_bytes, other.deduped_bytes)?,
        })
    }
    fn record(self, bytes: u32, duplicate: bool) -> Result<Self, CdcError> {
        self.combined(Self {
            total_chunks: 1,
            total_input_bytes: bytes.into(),
            duplicate_chunks: u64::from(duplicate),
            unique_chunks: u64::from(!duplicate),
            unique_bytes: if duplicate { 0 } else { bytes.into() },
            deduped_bytes: if duplicate { bytes.into() } else { 0 },
        })
    }
}

#[derive(Clone, Copy)]
struct Entry {
    id: ChunkId,
    size: u32,
}
#[derive(Default)]
struct Shard {
    index: HashMap<Fingerprint, Entry>,
    stats: DedupStats,
}
const SHARDS: usize = 64;

/// Sharded concurrent registry. Hashing is outside locks; equal digests choose
/// the same shard, making check+ID publication atomic. This is not lock-free.
/// The default bounds registry entries; payloads are not retained here.
/// If a unique chunk's compression/write fails, the archive operation must abort.
pub struct DedupEngine {
    shards: [Mutex<Shard>; SHARDS],
    next_id: AtomicU64,
    max_unique: u32,
}
impl DedupEngine {
    pub fn new() -> Self {
        Self::with_capacity_limit(4_000_000)
    }
    pub fn with_capacity_limit(max_unique: u32) -> Self {
        Self {
            shards: std::array::from_fn(|_| Mutex::new(Shard::default())),
            next_id: AtomicU64::new(0),
            max_unique,
        }
    }
    /// IDs can vary with thread scheduling. Feed registration through one ordered
    /// actor when reproducible archives are required; compression may then fan out.
    pub fn process_chunk(&self, data: &[u8]) -> Result<DedupOutcome, CdcError> {
        if data.is_empty() || data.len() > MAX_CHUNK_SIZE as usize {
            return Err(CdcError::InvalidChunkSize);
        }
        let size = data.len() as u32;
        let hash = *blake3::hash(data).as_bytes();
        let mut shard = self.shards[hash[0] as usize & (SHARDS - 1)].lock();
        if let Some(entry) = shard.index.get(&hash).copied() {
            if entry.size != size {
                return Err(CdcError::HashCollision);
            }
            let stats = shard.stats.record(size, true)?;
            shard.stats = stats;
            return Ok(DedupOutcome {
                chunk_id: entry.id,
                hash,
                is_duplicate: true,
                uncompressed_size: size,
            });
        }
        let stats = shard.stats.record(size, false)?;
        shard
            .index
            .try_reserve(1)
            .map_err(|_| CdcError::AllocationFailed)?;
        let mut id = self.next_id.load(Ordering::Relaxed);
        loop {
            if id >= u64::from(self.max_unique) {
                return Err(CdcError::ChunkLimit);
            }
            match self.next_id.compare_exchange_weak(
                id,
                id + 1,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(actual) => id = actual,
            }
        }
        // max_unique <= u32::MAX, so the reserved u32::MAX value is never assigned.
        let chunk_id = ChunkId::new(id as u32).map_err(|_| CdcError::ChunkLimit)?;
        shard.index.insert(hash, Entry { id: chunk_id, size });
        shard.stats = stats;
        Ok(DedupOutcome {
            chunk_id,
            hash,
            is_duplicate: false,
            uncompressed_size: size,
        })
    }
    pub fn lookup(&self, hash: &Fingerprint) -> Option<ChunkId> {
        self.shards[hash[0] as usize & (SHARDS - 1)]
            .lock()
            .index
            .get(hash)
            .map(|entry| entry.id)
    }
    /// Locks shards in a fixed order, giving a consistent snapshot under mutation.
    pub fn stats(&self) -> Result<DedupStats, CdcError> {
        let guards: Vec<_> = self.shards.iter().map(|shard| shard.lock()).collect();
        guards
            .iter()
            .try_fold(DedupStats::default(), |stats, shard| {
                stats.combined(shard.stats)
            })
    }
    /// IDs allocated so far; use stats() for a synchronized committed count.
    pub fn unique_count(&self) -> u32 {
        self.next_id.load(Ordering::Relaxed) as u32
    }
}
impl Default for DedupEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CdcError {
    InvalidConfig,
    InvalidChunkSize,
    ChunkLimit,
    CounterOverflow,
    HashCollision,
    AllocationFailed,
}
impl fmt::Display for CdcError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidConfig => {
                "CDC requires ordered power-of-two bounds <=64 MiB and valid normalization"
            }
            Self::InvalidChunkSize => "chunk must contain 1..64 MiB of data",
            Self::ChunkLimit => "unique chunk limit reached",
            Self::CounterOverflow => "deduplication counter overflow",
            Self::HashCollision => "BLAKE3 digest collision with different lengths",
            Self::AllocationFailed => "deduplication allocation failed",
        })
    }
}
impl std::error::Error for CdcError {}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn chunk_id_does_not_wrap_at_u32_boundary() {
        let registry = DedupEngine::with_capacity_limit(u32::MAX);
        registry
            .next_id
            .store(u64::from(u32::MAX - 1), Ordering::Relaxed);
        assert_eq!(
            registry.process_chunk(b"last").unwrap().chunk_id.get(),
            u32::MAX - 1
        );
        assert_eq!(
            registry.process_chunk(b"overflow"),
            Err(CdcError::ChunkLimit)
        );
        assert!(registry.process_chunk(b"last").unwrap().is_duplicate);
    }
    #[test]
    fn overflow_failure_does_not_publish_an_entry() {
        let registry = DedupEngine::new();
        let bytes = b"overflow counter";
        let hash = *blake3::hash(bytes).as_bytes();
        registry.shards[hash[0] as usize & (SHARDS - 1)]
            .lock()
            .stats
            .total_chunks = u64::MAX;
        assert_eq!(
            registry.process_chunk(bytes),
            Err(CdcError::CounterOverflow)
        );
        assert_eq!(registry.lookup(&hash), None);
        assert_eq!(registry.unique_count(), 0);
    }
}
