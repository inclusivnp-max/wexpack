//! WexEngine: independently framed LZ77, rANS and context-mixed arithmetic coding.
//!
//! ```
//! use wexpack::codec::{WexEngine, CodecError};
//! let source = b"WexPack compression engine\n".repeat(1024);
//! let packed = WexEngine::compress(&source, 5)?;
//! let restored = WexEngine::decompress(&packed.data, packed.codec, source.len())?;
//! assert_eq!(restored, source);
//! # Ok::<(), CodecError>(())
//! ```
pub mod ans;
pub mod cm;
pub mod lz;

use crate::format::{CodecType, MAX_STORED_CHUNK_SIZE};
use std::borrow::Cow;
use std::fmt;

pub const BLOCK_SIZE: usize = 256 << 10;
pub const MAX_LZ_SIZE: usize = BLOCK_SIZE + BLOCK_SIZE.div_ceil(8);
const FRAME_HEADER: usize = 24;
const BLOCK_HEADER: usize = 20;
pub type Result<T> = std::result::Result<T, CodecError>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CodecError {
    InvalidLevel(u8),
    InputLimit,
    OutputLimit,
    AllocationFailed,
    Truncated,
    InvalidData(&'static str),
    LengthMismatch { expected: usize, actual: usize },
    ChecksumMismatch,
}
impl fmt::Display for CodecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLevel(v) => write!(f, "compression level must be 1..9, got {v}"),
            Self::InputLimit => f.write_str("codec input limit exceeded"),
            Self::OutputLimit => f.write_str("codec output limit exceeded"),
            Self::AllocationFailed => f.write_str("codec allocation failed"),
            Self::Truncated => f.write_str("truncated codec stream"),
            Self::InvalidData(s) => write!(f, "invalid codec stream: {s}"),
            Self::ChecksumMismatch => f.write_str("codec checksum mismatch"),
            Self::LengthMismatch { expected, actual } => write!(
                f,
                "codec length mismatch: expected {expected}, got {actual}"
            ),
        }
    }
}
impl std::error::Error for CodecError {}
pub(super) fn invalid(s: &'static str) -> CodecError {
    CodecError::InvalidData(s)
}
pub(super) fn vector<T: Clone>(size: usize, value: T) -> Result<Vec<T>> {
    let mut v = Vec::new();
    v.try_reserve_exact(size)
        .map_err(|_| CodecError::AllocationFailed)?;
    v.resize(size, value);
    Ok(v)
}
pub(super) fn bytes(capacity: usize) -> Result<Vec<u8>> {
    let mut v = Vec::new();
    v.try_reserve_exact(capacity)
        .map_err(|_| CodecError::AllocationFailed)?;
    Ok(v)
}
pub(super) fn exact(actual: usize, expected: usize) -> Result<()> {
    if actual == expected {
        Ok(())
    } else {
        Err(CodecError::LengthMismatch { expected, actual })
    }
}
pub(super) fn crc(data: &[u8], expected: u32) -> Result<()> {
    if crc32fast::hash(data) == expected {
        Ok(())
    } else {
        Err(CodecError::ChecksumMismatch)
    }
}
pub(super) struct Reader<'a> {
    data: &'a [u8],
    position: usize,
}
impl<'a> Reader<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self { data, position: 0 }
    }
    pub fn take(&mut self, count: usize) -> Result<&'a [u8]> {
        let end = self
            .position
            .checked_add(count)
            .ok_or(CodecError::InputLimit)?;
        let slice = self
            .data
            .get(self.position..end)
            .ok_or(CodecError::Truncated)?;
        self.position = end;
        Ok(slice)
    }
    pub fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }
    pub fn u16(&mut self) -> Result<u16> {
        let b = self.take(2)?;
        Ok(u16::from_le_bytes([b[0], b[1]]))
    }
    pub fn u32(&mut self) -> Result<u32> {
        let b = self.take(4)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }
    pub fn remaining(&self) -> usize {
        self.data.len() - self.position
    }
    pub fn rest(&mut self) -> &'a [u8] {
        let b = &self.data[self.position..];
        self.position = self.data.len();
        b
    }
    pub fn finish(&self) -> Result<()> {
        if self.remaining() == 0 {
            Ok(())
        } else {
            Err(invalid("trailing bytes"))
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CompressionLevel(u8);
impl CompressionLevel {
    pub fn new(level: u8) -> Result<Self> {
        if (1..=9).contains(&level) {
            Ok(Self(level))
        } else {
            Err(CodecError::InvalidLevel(level))
        }
    }
    pub const fn get(self) -> u8 {
        self.0
    }
    pub const fn codec(self) -> CodecType {
        match self.0 {
            1..=3 => CodecType::WexTurbo,
            4..=7 => CodecType::WexBalanced,
            _ => CodecType::WexExtreme,
        }
    }
    fn lz(self) -> (lz::ParseMode, lz::LzOptions) {
        let (hash_bits, depth, window, mode) = match self.0 {
            1 => (12, 1, 16 << 10, lz::ParseMode::Greedy),
            2 => (14, 1, 64 << 10, lz::ParseMode::Greedy),
            3 => (16, 1, BLOCK_SIZE, lz::ParseMode::Greedy),
            4 => (15, 8, BLOCK_SIZE, lz::ParseMode::Lazy),
            5 => (16, 16, BLOCK_SIZE, lz::ParseMode::Lazy),
            6 => (16, 32, BLOCK_SIZE, lz::ParseMode::Lazy),
            7 => (16, 64, BLOCK_SIZE, lz::ParseMode::Lazy),
            8 => (16, 128, BLOCK_SIZE, lz::ParseMode::Optimal { horizon: 256 }),
            _ => (
                16,
                256,
                BLOCK_SIZE,
                lz::ParseMode::Optimal { horizon: 1024 },
            ),
        };
        (
            mode,
            lz::LzOptions {
                hash_bits,
                chain_depth: depth,
                window_size: window,
            },
        )
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompressedChunk {
    pub codec: CodecType,
    pub data: Vec<u8>,
}
#[derive(Debug, Clone, Copy)]
pub struct CodecLimits {
    pub max_output_size: usize,
    pub max_input_size: usize,
}
impl Default for CodecLimits {
    fn default() -> Self {
        Self {
            max_output_size: MAX_STORED_CHUNK_SIZE as usize,
            max_input_size: MAX_STORED_CHUNK_SIZE as usize,
        }
    }
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Method {
    Store = 0,
    Lz = 1,
    LzAns = 2,
    LzCm = 3,
    Ans = 4,
    Cm = 5,
}
impl Method {
    fn read(value: u8, codec: CodecType) -> Result<Self> {
        match (value, codec) {
            (0, _) => Ok(Self::Store),
            (1, _) => Ok(Self::Lz),
            (2, CodecType::WexBalanced) => Ok(Self::LzAns),
            (4, CodecType::WexBalanced) => Ok(Self::Ans),
            (3, CodecType::WexExtreme) => Ok(Self::LzCm),
            (5, CodecType::WexExtreme) => Ok(Self::Cm),
            _ => Err(invalid("unsupported block method for codec")),
        }
    }
}
struct Candidate<'a> {
    method: Method,
    intermediate: usize,
    payload: Cow<'a, [u8]>,
}
impl Candidate<'_> {
    fn consider(&mut self, method: Method, intermediate: usize, payload: Vec<u8>) {
        if payload.len() < self.payload.len() {
            *self = Self {
                method,
                intermediate,
                payload: Cow::Owned(payload),
            };
        }
    }
}

// Partial frames only grow. STORE is the only later alternative that can be
// smaller than that prefix, so both bounds must fail before rejecting a pass.
fn finish_candidate(
    data: &[u8],
    output: &mut Vec<u8>,
    budget: Option<usize>,
) -> Option<Option<CodecType>> {
    if output.len() >= data.len() {
        output.clear();
        if budget.is_some_and(|limit| data.len() > limit) {
            return Some(None);
        }
        output.extend_from_slice(data);
        return Some(Some(CodecType::Store));
    }
    if budget.is_some_and(|limit| output.len() > limit && data.len() > limit) {
        output.clear();
        return Some(None);
    }
    None
}

pub struct WexEngine;
impl WexEngine {
    pub fn compress(data: &[u8], level: u8) -> Result<CompressedChunk> {
        let mut output = Vec::new();
        let codec = Self::compress_into(data, level, &mut output)?;
        Ok(CompressedChunk {
            codec,
            data: output,
        })
    }
    /// The output buffer can be retained by a worker between chunks.
    pub fn compress_into(data: &[u8], level: u8, output: &mut Vec<u8>) -> Result<CodecType> {
        Self::compress_frame(data, level, output, false, None)?
            .ok_or_else(|| invalid("unbounded frame aborted"))
    }
    /// WXE revision 2 keeps LZ history across blocks inside a bounded solid frame.
    pub fn compress_solid_into(data: &[u8], level: u8, output: &mut Vec<u8>) -> Result<CodecType> {
        if data.len() > lz::SOLID_WINDOW {
            return Err(CodecError::InputLimit);
        }
        Self::compress_frame(data, level, output, true, None)?
            .ok_or_else(|| invalid("unbounded frame aborted"))
    }
    /// Returns None only when neither the partial frame nor STORE can fit the
    /// inclusive byte budget. No partial output survives an aborted candidate.
    pub fn compress_solid_bounded_into(
        data: &[u8],
        level: u8,
        output: &mut Vec<u8>,
        max_size: usize,
    ) -> Result<Option<CodecType>> {
        if data.len() > lz::SOLID_WINDOW {
            return Err(CodecError::InputLimit);
        }
        Self::compress_frame(data, level, output, true, Some(max_size))
    }
    fn compress_frame(
        data: &[u8],
        level: u8,
        output: &mut Vec<u8>,
        solid: bool,
        budget: Option<usize>,
    ) -> Result<Option<CodecType>> {
        let level = CompressionLevel::new(level)?;
        if data.len() > MAX_STORED_CHUNK_SIZE as usize {
            return Err(CodecError::InputLimit);
        }
        output.clear();
        let blocks = data.len().div_ceil(BLOCK_SIZE);
        let capacity = data.len() + FRAME_HEADER + blocks * BLOCK_HEADER;
        output
            .try_reserve_exact(capacity)
            .map_err(|_| CodecError::AllocationFailed)?;
        if data.is_empty() {
            return Ok(Some(CodecType::Store));
        }
        output.extend_from_slice(if solid { b"WXE\x02" } else { b"WXE\x01" });
        output.extend([level.codec() as u8, level.get(), 0, 0]);
        output.extend_from_slice(&(data.len() as u32).to_le_bytes());
        output.extend_from_slice(&(blocks as u32).to_le_bytes());
        output.extend_from_slice(&crc32fast::hash(data).to_le_bytes());
        let header_crc = crc32fast::hash(output);
        output.extend_from_slice(&header_crc.to_le_bytes());
        if let Some(result) = finish_candidate(data, output, budget) {
            return Ok(result);
        }
        let (mode, options) = level.lz();
        let mut solid_finder = if solid {
            let mut solid_options = options;
            solid_options.window_size = lz::SOLID_WINDOW;
            // Keep about four positions per bucket, rather than forcing long
            // random-data collision chains as the history grows to 16 MiB.
            solid_options.hash_bits = (data
                .len()
                .max(1)
                .next_power_of_two()
                .trailing_zeros()
                .saturating_sub(2))
            .clamp(16, 22) as u8;

            Some(lz::MatchFinder::new(data, solid_options)?)
        } else {
            None
        };
        for (n, block) in data.chunks(BLOCK_SIZE).enumerate() {
            let mut best = Candidate {
                method: Method::Store,
                intermediate: 0,
                payload: Cow::Borrowed(block),
            };
            let lz = if let Some(finder) = &mut solid_finder {
                let start = n * BLOCK_SIZE;
                lz::encode_solid_block(finder, start..start + block.len(), mode)?
            } else {
                lz::encode(block, mode, options)?
            };
            match level.codec() {
                CodecType::WexBalanced => {
                    best.consider(Method::LzAns, lz.len(), ans::encode(&lz)?);
                    best.consider(Method::Ans, block.len(), ans::encode(block)?);
                }
                CodecType::WexExtreme => {
                    best.consider(Method::LzCm, lz.len(), cm::encode(&lz)?);
                    best.consider(Method::Cm, block.len(), cm::encode(block)?);
                }
                _ => {}
            }
            let lz_size = lz.len();
            best.consider(Method::Lz, lz_size, lz);
            output.extend([best.method as u8, 0, 0, 0]);
            output.extend_from_slice(&(block.len() as u32).to_le_bytes());
            output.extend_from_slice(&(best.intermediate as u32).to_le_bytes());
            output.extend_from_slice(&(best.payload.len() as u32).to_le_bytes());
            output.extend_from_slice(&crc32fast::hash(block).to_le_bytes());
            output.extend_from_slice(&best.payload);
            if let Some(result) = finish_candidate(data, output, budget) {
                return Ok(result);
            }
        }
        Ok(Some(level.codec()))
    }
    pub fn decompress(data: &[u8], codec: CodecType, expected_size: usize) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        Self::decompress_into(data, codec, expected_size, CodecLimits::default(), &mut out)?;
        Ok(out)
    }
    pub fn decompress_into(
        data: &[u8],
        codec: CodecType,
        expected_size: usize,
        limits: CodecLimits,
        out: &mut Vec<u8>,
    ) -> Result<()> {
        if data.len() > limits.max_input_size || data.len() > MAX_STORED_CHUNK_SIZE as usize {
            return Err(CodecError::InputLimit);
        }
        if expected_size > limits.max_output_size || expected_size > MAX_STORED_CHUNK_SIZE as usize
        {
            return Err(CodecError::OutputLimit);
        }
        if codec == CodecType::Store {
            exact(data.len(), expected_size)?;
            out.clear();
            out.try_reserve_exact(expected_size)
                .map_err(|_| CodecError::AllocationFailed)?;
            out.extend_from_slice(data);
            return Ok(());
        }
        let mut r = Reader::new(data);
        let magic = r.take(4)?;
        let solid = magic == b"WXE\x02";
        if (magic != b"WXE\x01" && !solid) || r.u8()? != codec as u8 {
            return Err(invalid("frame magic or codec"));
        }
        if solid && expected_size > lz::SOLID_WINDOW {
            return Err(CodecError::OutputLimit);
        }
        let level = CompressionLevel::new(r.u8()?)?;
        if level.codec() != codec || r.u16()? != 0 {
            return Err(invalid("frame level or flags"));
        }
        exact(r.u32()? as usize, expected_size)?;
        let blocks = r.u32()? as usize;
        let checksum = r.u32()?;
        if r.u32()? != crc32fast::hash(&data[..20])
            || expected_size == 0
            || blocks != expected_size.div_ceil(BLOCK_SIZE)
        {
            return Err(invalid("frame block count or reserved field"));
        }
        if blocks > r.remaining() / (BLOCK_HEADER + 1) {
            return Err(CodecError::Truncated);
        }
        out.clear();
        out.try_reserve_exact(expected_size)
            .map_err(|_| CodecError::AllocationFailed)?;
        for n in 0..blocks {
            let method = Method::read(r.u8()?, codec)?;
            if r.take(3)? != [0, 0, 0] {
                return Err(invalid("block reserved fields"));
            }
            let raw_size = r.u32()? as usize;
            let intermediate = r.u32()? as usize;
            let stored = r.u32()? as usize;
            let checksum = r.u32()?;
            let wanted = (expected_size - n * BLOCK_SIZE).min(BLOCK_SIZE);
            exact(raw_size, wanted)?;
            let max_lz = raw_size + raw_size.div_ceil(8);
            match method {
                Method::Store if intermediate != 0 || stored != raw_size => {
                    return Err(invalid("STORE block sizes"));
                }
                Method::Lz | Method::LzAns | Method::LzCm
                    if intermediate == 0 || intermediate > max_lz =>
                {
                    return Err(invalid("LZ intermediate size"));
                }
                Method::Ans | Method::Cm if intermediate != raw_size => {
                    return Err(invalid("direct entropy size"));
                }
                _ => {}
            }
            // Writer only retains payloads strictly smaller than raw, except STORE.
            if stored == 0 || stored > raw_size || (method != Method::Store && stored == raw_size) {
                return Err(invalid("block payload size"));
            }
            let payload = r.take(stored)?;
            let begin = out.len();
            match method {
                Method::Store => out.extend_from_slice(payload),
                Method::Lz | Method::LzAns | Method::LzCm => {
                    let decoded;
                    let lz_payload = match method {
                        Method::Lz => {
                            exact(stored, intermediate)?;
                            payload
                        }
                        Method::LzAns => {
                            decoded = ans::decode(payload, intermediate)?;
                            &decoded
                        }
                        Method::LzCm => {
                            decoded = cm::decode(payload, intermediate)?;
                            &decoded
                        }
                        _ => unreachable!(),
                    };
                    if solid {
                        lz::decode_append(lz_payload, raw_size, out, true)?;
                    } else {
                        out.extend_from_slice(&lz::decode(lz_payload, raw_size)?);
                    }
                }
                Method::Ans => out.extend_from_slice(&ans::decode(payload, raw_size)?),
                Method::Cm => out.extend_from_slice(&cm::decode(payload, raw_size)?),
            }
            crc(&out[begin..], checksum)?;
        }
        r.finish()?;
        exact(out.len(), expected_size)?;
        crc(out, checksum)
    }
}
