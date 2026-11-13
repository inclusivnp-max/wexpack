//! Bounded profiling and reversible WXP v2 precompression filters.
//! Each chunk uses identity or one transform, as specified by the v2 frame.
//! Decoding takes the original size from ChunkHeader and never re-runs profiling.
//!
//! ```
//! use wexpack::filters::{SmartTransform, ProfileHint, invert_transform, FilterError};
//! let source = b"function return sensorSerialNumber;\n".repeat(128);
//! let prepared = SmartTransform::prepare(&source, ProfileHint::Auto)?;
//! let restored = invert_transform(&prepared.data, prepared.transform, 0, source.len())?;
//! assert_eq!(restored, source);
//! # Ok::<(), FilterError>(())
//! ```

use crate::format::{MAX_CHUNK_SIZE, MAX_STORED_CHUNK_SIZE, TransformType};
use std::borrow::Cow;
use std::collections::HashMap;
use std::fmt;
use std::sync::OnceLock;

pub const HIGH_ENTROPY_THRESHOLD: f64 = 7.95;
pub const PROFILE_SAMPLE_SIZE: usize = 4096;
pub const DICT_ESCAPE_BYTE: u8 = 0x02;
pub const DICT_MAGIC: [u8; 4] = *b"WXD\x01";
pub const DICT_REVISION: u16 = 1;
pub const MAX_DYNAMIC_WORDS: usize = 127;
pub const MAX_WORD_LENGTH: usize = 64;
const MAX_CANDIDATES: usize = 4096;

type Result<T> = std::result::Result<T, FilterError>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FilterError {
    InputTooLarge,
    OutputTooLarge,
    AllocationFailed,
    InvalidWordSize,
    UnalignedArmIp,
    InvalidDictionary(&'static str),
    LengthMismatch { expected: usize, actual: usize },
}
impl fmt::Display for FilterError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InputTooLarge => f.write_str("filter input exceeds its chunk limit"),
            Self::OutputTooLarge => f.write_str("filter output exceeds its chunk limit"),
            Self::AllocationFailed => f.write_str("filter allocation failed"),
            Self::InvalidWordSize => f.write_str("byte shuffle requires word size 4 or 8"),
            Self::UnalignedArmIp => f.write_str("ARM64 filter IP must be divisible by 4"),
            Self::InvalidDictionary(s) => write!(f, "invalid dictionary stream: {s}"),
            Self::LengthMismatch { expected, actual } => write!(
                f,
                "filter length mismatch: expected {expected}, got {actual}"
            ),
        }
    }
}
impl std::error::Error for FilterError {}

fn input_limit(data: &[u8], limit: u32) -> Result<()> {
    if data.len() > limit as usize {
        Err(FilterError::InputTooLarge)
    } else {
        Ok(())
    }
}
fn prepare_output(out: &mut Vec<u8>, size: usize) -> Result<()> {
    out.clear();
    out.try_reserve_exact(size)
        .map_err(|_| FilterError::AllocationFailed)?;
    out.resize(size, 0);
    Ok(())
}
fn copy_into(src: &[u8], out: &mut Vec<u8>) -> Result<()> {
    prepare_output(out, src.len())?;
    out.copy_from_slice(src);
    Ok(())
}
fn exact_size(actual: usize, expected: usize) -> Result<()> {
    if actual == expected {
        Ok(())
    } else {
        Err(FilterError::LengthMismatch { expected, actual })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Architecture {
    X86,
    Arm64,
    Other,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DataKind {
    Empty,
    Text,
    Numeric,
    Executable(Architecture),
    Container,
    Binary,
    HighEntropy,
}
/// Hints must come from the caller's file metadata, never the decoder.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum ProfileHint {
    #[default]
    Auto,
    Numeric4,
    Numeric8,
    X86,
    Arm64,
}
#[derive(Debug, Clone, PartialEq)]
pub struct ProfileResult {
    pub entropy: f64,
    pub sample_size: usize,
    pub kind: DataKind,
    pub recommended_transform: TransformType,
    pub bypass_compression: bool,
}

pub struct DataProfiler;
impl DataProfiler {
    pub fn calculate_entropy(data: &[u8]) -> f64 {
        let mut counts = [0usize; 256];
        for &byte in data {
            counts[byte as usize] += 1;
        }
        histogram_entropy(&counts, data.len())
    }
    pub fn profile(chunk: &[u8]) -> ProfileResult {
        Self::profile_with_hint(chunk, ProfileHint::Auto)
    }
    /// Sampling and classification inspect at most the first 4096 bytes.
    pub fn profile_with_hint(chunk: &[u8], hint: ProfileHint) -> ProfileResult {
        let sample = &chunk[..chunk.len().min(PROFILE_SAMPLE_SIZE)];
        let entropy = Self::calculate_entropy(sample);
        let mut result = ProfileResult {
            entropy,
            sample_size: sample.len(),
            kind: DataKind::Binary,
            recommended_transform: TransformType::None,
            bypass_compression: false,
        };
        if sample.is_empty() {
            result.kind = DataKind::Empty;
            return result;
        }
        match hint {
            ProfileHint::Numeric4 if chunk.len() >= 4 => {
                result.kind = DataKind::Numeric;
                result.recommended_transform = TransformType::ByteShuffle4;
                return result;
            }
            ProfileHint::Numeric8 if chunk.len() >= 8 => {
                result.kind = DataKind::Numeric;
                result.recommended_transform = TransformType::ByteShuffle8;
                return result;
            }
            ProfileHint::X86 => {
                result.kind = DataKind::Executable(Architecture::X86);
                result.recommended_transform = TransformType::BcjX86;
                return result;
            }
            ProfileHint::Arm64 => {
                result.kind = DataKind::Executable(Architecture::Arm64);
                result.recommended_transform = TransformType::BcjArm64;
                return result;
            }
            _ => {}
        }
        if let Some(architecture) = executable_architecture(sample) {
            result.kind = DataKind::Executable(architecture);
            result.recommended_transform = match architecture {
                Architecture::X86 => TransformType::BcjX86,
                Architecture::Arm64 => TransformType::BcjArm64,
                Architecture::Other => TransformType::None,
            };
            return result;
        }
        if known_container(sample) {
            result.kind = DataKind::Container;
            return result;
        }
        if entropy > HIGH_ENTROPY_THRESHOLD {
            result.kind = DataKind::HighEntropy;
            result.bypass_compression = true;
            return result;
        }
        if textual(sample) {
            result.kind = DataKind::Text;
            result.recommended_transform = TransformType::DictWord;
            return result;
        }
        let score4 = shuffle_score(sample, 4);
        let score8 = shuffle_score(sample, 8);
        if score4 >= 0.65 || score8 >= 0.65 {
            result.kind = DataKind::Numeric;
            result.recommended_transform = if score8 > score4 + 0.25 {
                TransformType::ByteShuffle8
            } else {
                TransformType::ByteShuffle4
            };
        }
        result
    }
}
fn histogram_entropy(counts: &[usize; 256], length: usize) -> f64 {
    if length == 0 {
        return 0.0;
    }
    let n = length as f64;
    let sum: f64 = counts
        .iter()
        .filter(|&&c| c != 0)
        .map(|&c| {
            let p = c as f64 / n;
            -p * p.log2()
        })
        .sum();
    sum.clamp(0.0, 8.0)
}
/// Entropy conditional on byte lane, with a finite-sample bias penalty.
fn shuffle_score(sample: &[u8], width: usize) -> f64 {
    let words = sample.len() / width;
    if words < 32 {
        return 0.0;
    }
    let sample = &sample[..words * width];
    let mut lanes = [[0usize; 256]; 8];
    for (i, &byte) in sample.iter().enumerate() {
        lanes[i % width][byte as usize] += 1;
    }
    let conditional = lanes[..width]
        .iter()
        .map(|h| histogram_entropy(h, words))
        .sum::<f64>()
        / width as f64;
    let penalty = (width - 1) as f64 * 255.0 / (2.0 * sample.len() as f64 * std::f64::consts::LN_2);
    (DataProfiler::calculate_entropy(sample) - conditional - penalty).max(0.0)
}
fn textual(sample: &[u8]) -> bool {
    // A sample can end in the middle of a UTF-8 scalar, but not contain bad UTF-8.
    let text = match std::str::from_utf8(sample) {
        Ok(s) => s,
        Err(e) if e.error_len().is_none() => {
            match std::str::from_utf8(&sample[..e.valid_up_to()]) {
                Ok(s) => s,
                Err(_) => return false,
            }
        }
        Err(_) => return false,
    };
    if text.is_empty() {
        return false;
    }
    let total = text.chars().count();
    let printable = text
        .chars()
        .filter(|&c| !c.is_control() || matches!(c, '\t' | '\n' | '\r'))
        .count();
    printable * 100 >= total * 95
}
fn executable_architecture(s: &[u8]) -> Option<Architecture> {
    if s.starts_with(b"\x7fELF") {
        if s.len() < 20 || !matches!(s[4], 1 | 2) || !matches!(s[5], 1 | 2) || s[6] != 1 {
            return Some(Architecture::Other);
        }
        let machine = if s[5] == 1 {
            u16::from_le_bytes([s[18], s[19]])
        } else {
            u16::from_be_bytes([s[18], s[19]])
        };
        return Some(match (s[5], machine) {
            (1, 3 | 62) => Architecture::X86,
            (1, 183) => Architecture::Arm64,
            _ => Architecture::Other,
        });
    }
    if s.starts_with(b"MZ") {
        let machine = (|| {
            let raw: [u8; 4] = s.get(0x3c..0x40)?.try_into().ok()?;
            let offset = u32::from_le_bytes(raw) as usize;
            if offset < 64 {
                return None;
            }
            let pe = s.get(offset..offset.checked_add(24)?)?;
            if &pe[..4] != b"PE\0\0" {
                return None;
            }
            Some(u16::from_le_bytes([pe[4], pe[5]]))
        })();
        return Some(match machine {
            Some(0x014c | 0x8664) => Architecture::X86,
            Some(0xaa64) => Architecture::Arm64,
            _ => Architecture::Other,
        });
    }
    if s.len() >= 4 {
        let magic = u32::from_le_bytes([s[0], s[1], s[2], s[3]]);
        if matches!(magic, 0xfeed_face | 0xfeed_facf) {
            let cpu = s
                .get(4..8)
                .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]));
            return Some(match cpu {
                Some(7 | 0x0100_0007) => Architecture::X86,
                Some(0x0100_000c) => Architecture::Arm64,
                _ => Architecture::Other,
            });
        }
        if matches!(
            magic,
            0xcefa_edfe | 0xcffa_edfe | 0xbeba_feca | 0xbfbafeca | 0xcafe_babe | 0xcafe_babf
        ) {
            return Some(Architecture::Other);
        }
    }
    None
}
fn known_container(s: &[u8]) -> bool {
    const SIGNATURES: &[&[u8]] = &[
        b"\x1f\x8b",
        b"PK\x03\x04",
        b"PK\x05\x06",
        b"7z\xbc\xaf\x27\x1c",
        b"Rar!\x1a\x07",
        b"\x28\xb5\x2f\xfd",
        b"\xfd7zXZ\0",
        b"BZh",
        b"WXP\x02",
        b"\x89PNG\r\n\x1a\n",
        b"\xff\xd8\xff",
        b"GIF87a",
        b"GIF89a",
        b"%PDF-",
        b"fLaC",
        b"OggS",
        b"\x93NUMPY",
        b"\x89HDF\r\n\x1a\n",
    ];
    SIGNATURES.iter().any(|magic| s.starts_with(magic))
        || s.get(257..262) == Some(b"ustar")
        || (s.starts_with(b"RIFF")
            && s.get(8..12)
                .is_some_and(|v| matches!(v, b"WAVE" | b"AVI " | b"WEBP")))
        || s.get(4..8) == Some(b"ftyp")
}

pub struct ByteShuffle;
impl ByteShuffle {
    /// All complete words are transposed; a partial trailing word stays in place.
    pub fn shuffle_into(src: &[u8], width: usize, out: &mut Vec<u8>) -> Result<()> {
        input_limit(src, MAX_CHUNK_SIZE)?;
        if !matches!(width, 4 | 8) {
            return Err(FilterError::InvalidWordSize);
        }
        prepare_output(out, src.len())?;
        let words = src.len() / width;
        // Small tiles keep all 4/8 output lanes hot without unsafe SIMD accesses.
        for block in (0..words).step_by(256) {
            let end = (block + 256).min(words);
            for lane in 0..width {
                for word in block..end {
                    out[lane * words + word] = src[word * width + lane];
                }
            }
        }
        out[words * width..].copy_from_slice(&src[words * width..]);
        Ok(())
    }
    pub fn unshuffle_into(src: &[u8], width: usize, out: &mut Vec<u8>) -> Result<()> {
        input_limit(src, MAX_CHUNK_SIZE)?;
        if !matches!(width, 4 | 8) {
            return Err(FilterError::InvalidWordSize);
        }
        prepare_output(out, src.len())?;
        let words = src.len() / width;
        for block in (0..words).step_by(256) {
            let end = (block + 256).min(words);
            for lane in 0..width {
                for word in block..end {
                    out[word * width + lane] = src[lane * words + word];
                }
            }
        }
        out[words * width..].copy_from_slice(&src[words * width..]);
        Ok(())
    }
    pub fn shuffle_4(src: &[u8]) -> Result<Vec<u8>> {
        let mut v = Vec::new();
        Self::shuffle_into(src, 4, &mut v)?;
        Ok(v)
    }
    pub fn shuffle_8(src: &[u8]) -> Result<Vec<u8>> {
        let mut v = Vec::new();
        Self::shuffle_into(src, 8, &mut v)?;
        Ok(v)
    }
    pub fn unshuffle_4(src: &[u8]) -> Result<Vec<u8>> {
        let mut v = Vec::new();
        Self::unshuffle_into(src, 4, &mut v)?;
        Ok(v)
    }
    pub fn unshuffle_8(src: &[u8]) -> Result<Vec<u8>> {
        let mut v = Vec::new();
        Self::unshuffle_into(src, 8, &mut v)?;
        Ok(v)
    }
}

pub struct BcjFilter;
impl BcjFilter {
    pub fn x86_in_place(data: &mut [u8], ip: u32, inverse: bool) -> Result<()> {
        input_limit(data, MAX_CHUNK_SIZE)?;
        let mut i = 0;
        while data.len() - i >= 5 {
            if matches!(data[i], 0xe8 | 0xe9) {
                let value =
                    u32::from_le_bytes([data[i + 1], data[i + 2], data[i + 3], data[i + 4]]);
                let next_ip = ip.wrapping_add(i as u32).wrapping_add(5);
                let converted = if inverse {
                    value.wrapping_sub(next_ip)
                } else {
                    value.wrapping_add(next_ip)
                };
                data[i + 1..i + 5].copy_from_slice(&converted.to_le_bytes());
                // Skip operands on both paths, so embedded E8/E9 bytes stay operands.
                i += 5;
            } else {
                i += 1;
            }
        }
        Ok(())
    }
    pub fn arm64_in_place(data: &mut [u8], ip: u32, inverse: bool) -> Result<()> {
        input_limit(data, MAX_CHUNK_SIZE)?;
        if !ip.is_multiple_of(4) {
            return Err(FilterError::UnalignedArmIp);
        }
        for (i, word) in data.as_chunks_mut::<4>().0.iter_mut().enumerate() {
            let instruction = u32::from_le_bytes([word[0], word[1], word[2], word[3]]);
            if instruction & 0x7c00_0000 == 0x1400_0000 {
                let immediate = instruction & 0x03ff_ffff;
                let pc_words = ip.wrapping_add((i as u32) * 4) >> 2;
                let target = if inverse {
                    immediate.wrapping_sub(pc_words)
                } else {
                    immediate.wrapping_add(pc_words)
                };
                word.copy_from_slice(
                    &((instruction & 0xfc00_0000) | (target & 0x03ff_ffff)).to_le_bytes(),
                );
            }
        }
        Ok(())
    }
    pub fn encode_x86(src: &[u8], ip: u32) -> Result<Vec<u8>> {
        apply_transform(src, TransformType::BcjX86, ip)
    }
    pub fn decode_x86(src: &[u8], ip: u32) -> Result<Vec<u8>> {
        invert_transform(src, TransformType::BcjX86, ip, src.len())
    }
    pub fn encode_arm64(src: &[u8], ip: u32) -> Result<Vec<u8>> {
        apply_transform(src, TransformType::BcjArm64, ip)
    }
    pub fn decode_arm64(src: &[u8], ip: u32) -> Result<Vec<u8>> {
        invert_transform(src, TransformType::BcjArm64, ip, src.len())
    }
}

// Vocabulary revision 1 is immutable: changing IDs requires a new wire revision.
pub const STATIC_DICT: [&[u8]; 128] = [
    b"function",
    b"return",
    b"import",
    b"export",
    b"const",
    b"struct",
    b"class",
    b"public",
    b"private",
    b"protected",
    b"virtual",
    b"override",
    b"template",
    b"typename",
    b"namespace",
    b"include",
    b"string",
    b"vector",
    b"static",
    b"inline",
    b"constexpr",
    b"default",
    b"switch",
    b"case",
    b"break",
    b"continue",
    b"while",
    b"false",
    b"true",
    b"null",
    b"nullptr",
    b"undefined",
    b"boolean",
    b"number",
    b"object",
    b"package",
    b"interface",
    b"implements",
    b"extends",
    b"throws",
    b"finally",
    b"catch",
    b"try",
    b"throw",
    b"sizeof",
    b"typeof",
    b"instanceof",
    b"async",
    b"await",
    b"yield",
    b"lambda",
    b"match",
    b"mut",
    b"self",
    b"Self",
    b"enum",
    b"trait",
    b"where",
    b"unsafe",
    b"extern",
    b"crate",
    b"pub(crate)",
    b"Result",
    b"Option",
    b"Some",
    b"None",
    b"Ok",
    b"Err",
    b": false",
    b": true",
    b": null",
    b": \"",
    b"\",\n",
    b"{\n",
    b"}\n",
    b"(\"",
    b"\")",
    b"->",
    b"=>",
    b"::",
    b"==",
    b"!=",
    b"<=",
    b">=",
    b"&&",
    b"||",
    b"+=",
    b"-=",
    b"*=",
    b"/=",
    b"//",
    b"/*",
    b"*/",
    b"<!DOCTYPE",
    b"html",
    b"head",
    b"body",
    b"div",
    b"span",
    b"style",
    b"script",
    b"width",
    b"height",
    b"margin",
    b"padding",
    b"border",
    b"color",
    b"background",
    b"display",
    b"flex",
    b"position",
    b"absolute",
    b"relative",
    b"name",
    b"value",
    b"data",
    b"type",
    b"id",
    b"error",
    b"message",
    b"status",
    b"timestamp",
    b"count",
    b"result",
    b"version",
    b"enabled",
    b"description",
    b"metadata",
];
fn word_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}
fn identifier(word: &[u8]) -> bool {
    (3..=MAX_WORD_LENGTH).contains(&word.len())
        && (word[0].is_ascii_alphabetic() || word[0] == b'_')
        && word.iter().all(|&b| word_byte(b))
}
fn static_buckets() -> &'static [Vec<usize>; 128] {
    static BUCKETS: OnceLock<[Vec<usize>; 128]> = OnceLock::new();
    BUCKETS.get_or_init(|| {
        let mut buckets: [Vec<usize>; 128] = std::array::from_fn(|_| Vec::new());
        for (i, word) in STATIC_DICT.iter().enumerate() {
            buckets[word[0] as usize].push(i);
        }
        for bucket in &mut buckets {
            bucket.sort_unstable_by(|&a, &b| {
                STATIC_DICT[b]
                    .len()
                    .cmp(&STATIC_DICT[a].len())
                    .then(a.cmp(&b))
            });
        }
        buckets
    })
}
fn static_exact(word: &[u8]) -> bool {
    word.first().is_some_and(|&first| {
        first < 128
            && static_buckets()[first as usize]
                .iter()
                .any(|&i| STATIC_DICT[i] == word)
    })
}
struct EncodeDictionary<'a> {
    words: Vec<&'a [u8]>,
    codes: HashMap<&'a [u8], u8>,
}
impl<'a> EncodeDictionary<'a> {
    fn train(src: &'a [u8]) -> Result<Self> {
        let mut counts: HashMap<&[u8], u32> = HashMap::new();
        let mut i = 0;
        while i < src.len() {
            if !word_byte(src[i]) {
                i += 1;
                continue;
            }
            let start = i;
            while i < src.len() && word_byte(src[i]) {
                i += 1;
            }
            let word = &src[start..i];
            if !identifier(word) || static_exact(word) {
                continue;
            }
            if let Some(count) = counts.get_mut(word) {
                *count += 1;
            } else if counts.len() < MAX_CANDIDATES {
                counts
                    .try_reserve(1)
                    .map_err(|_| FilterError::AllocationFailed)?;
                counts.insert(word, 1);
            }
        }
        let mut ranked = Vec::new();
        ranked
            .try_reserve_exact(counts.len())
            .map_err(|_| FilterError::AllocationFailed)?;
        for (word, count) in counts {
            let savings = (word.len() as u64 - 2) * u64::from(count);
            let metadata_cost = word.len() as u64 + 1;
            if savings > metadata_cost {
                ranked.push((savings - metadata_cost, word));
            }
        }
        // Deterministic despite HashMap's randomized iteration order.
        ranked.sort_unstable_by(|a, b| b.0.cmp(&a.0).then(a.1.cmp(b.1)));
        ranked.truncate(MAX_DYNAMIC_WORDS);
        let mut words = Vec::new();
        let mut codes = HashMap::new();
        words
            .try_reserve_exact(ranked.len())
            .map_err(|_| FilterError::AllocationFailed)?;
        codes
            .try_reserve(ranked.len())
            .map_err(|_| FilterError::AllocationFailed)?;
        for (_, word) in ranked {
            codes.insert(word, (words.len() + 1) as u8);
            words.push(word);
        }
        Ok(Self { words, codes })
    }
}
enum EncodeUnit<'a> {
    Literal(&'a [u8]),
    Static(u8),
    Dynamic(u8),
}
fn visit_encoded<'a>(
    src: &'a [u8],
    dictionary: &EncodeDictionary<'_>,
    mut emit: impl FnMut(EncodeUnit<'a>) -> Result<()>,
) -> Result<()> {
    let mut i = 0;
    while i < src.len() {
        let byte = src[i];
        let boundary = i == 0 || !word_byte(src[i - 1]);
        let mut word_end = i;
        if word_byte(byte) && boundary {
            word_end += 1;
            while word_end < src.len() && word_byte(src[word_end]) {
                word_end += 1;
            }
        }
        let dynamic = if word_end > i {
            dictionary.codes.get(&src[i..word_end]).copied()
        } else {
            None
        };
        let mut best_static = None;
        if byte < 128 {
            for &index in &static_buckets()[byte as usize] {
                let word = STATIC_DICT[index];
                if word_byte(word[0]) && !boundary {
                    continue;
                }
                if !src[i..].starts_with(word) {
                    continue;
                }
                let end = i + word.len();
                if word_byte(word[word.len() - 1]) && src.get(end).is_some_and(|&b| word_byte(b)) {
                    continue;
                }
                best_static = Some(index);
                break;
            }
        }
        if let Some(code) = dynamic
            && best_static.is_none_or(|index| word_end - i > STATIC_DICT[index].len())
        {
            emit(EncodeUnit::Dynamic(code))?;
            i = word_end;
        } else if let Some(index) = best_static {
            emit(EncodeUnit::Static(0x80 + index as u8))?;
            i += STATIC_DICT[index].len();
        } else {
            let end = if word_end > i { word_end } else { i + 1 };
            emit(EncodeUnit::Literal(&src[i..end]))?;
            i = end;
        }
    }
    Ok(())
}
struct DecodeDictionary<'a> {
    words: Vec<&'a [u8]>,
    body: &'a [u8],
}
impl<'a> DecodeDictionary<'a> {
    fn parse(src: &'a [u8]) -> Result<Self> {
        if src.len() < 8 || src[..4] != DICT_MAGIC {
            return Err(FilterError::InvalidDictionary("bad or truncated header"));
        }
        if u16::from_le_bytes([src[4], src[5]]) != DICT_REVISION || src[7] != 0 {
            return Err(FilterError::InvalidDictionary(
                "unsupported vocabulary revision or flags",
            ));
        }
        let count = src[6] as usize;
        if count > MAX_DYNAMIC_WORDS {
            return Err(FilterError::InvalidDictionary("too many dynamic tokens"));
        }
        let mut words = Vec::new();
        words
            .try_reserve_exact(count)
            .map_err(|_| FilterError::AllocationFailed)?;
        let mut i = 8;
        for _ in 0..count {
            let length = *src
                .get(i)
                .ok_or(FilterError::InvalidDictionary("missing token length"))?
                as usize;
            i += 1;
            let word = src
                .get(i..i + length)
                .ok_or(FilterError::InvalidDictionary("truncated dynamic token"))?;
            if !identifier(word) || static_exact(word) || words.contains(&word) {
                return Err(FilterError::InvalidDictionary(
                    "invalid or duplicate dynamic token",
                ));
            }
            words.push(word);
            i += length;
        }
        Ok(Self {
            words,
            body: &src[i..],
        })
    }
    fn visit(&self, mut emit: impl FnMut(&[u8]) -> Result<()>) -> Result<()> {
        let mut i = 0;
        while i < self.body.len() {
            let byte = self.body[i];
            i += 1;
            if byte == DICT_ESCAPE_BYTE {
                let code = *self
                    .body
                    .get(i)
                    .ok_or(FilterError::InvalidDictionary("truncated escape"))?;
                i += 1;
                match code {
                    0 => emit(&[DICT_ESCAPE_BYTE])?,
                    1..=127 => emit(
                        self.words
                            .get(code as usize - 1)
                            .ok_or(FilterError::InvalidDictionary("unknown dynamic token"))?,
                    )?,
                    128..=255 => emit(&[code])?,
                }
            } else if byte >= 128 {
                emit(STATIC_DICT[(byte - 128) as usize])?;
            } else {
                emit(&[byte])?;
            }
        }
        Ok(())
    }
}

pub struct DictTransform;
impl DictTransform {
    /// One-byte static codes, two-byte dynamic codes, explicit escaping of binary literals.
    pub fn encode_into(src: &[u8], out: &mut Vec<u8>) -> Result<()> {
        input_limit(src, MAX_CHUNK_SIZE)?;
        let dictionary = EncodeDictionary::train(src)?;
        let header_size = 8 + dictionary
            .words
            .iter()
            .map(|word| word.len() + 1)
            .sum::<usize>();
        let mut size = header_size;
        visit_encoded(src, &dictionary, |unit| {
            let length = match unit {
                EncodeUnit::Literal(bytes) => {
                    bytes.len()
                        + bytes
                            .iter()
                            .filter(|&&b| b >= 128 || b == DICT_ESCAPE_BYTE)
                            .count()
                }
                EncodeUnit::Static(_) => 1,
                EncodeUnit::Dynamic(_) => 2,
            };
            size = size
                .checked_add(length)
                .ok_or(FilterError::OutputTooLarge)?;
            if size > MAX_STORED_CHUNK_SIZE as usize {
                return Err(FilterError::OutputTooLarge);
            }
            Ok(())
        })?;
        prepare_output(out, size)?;
        out[..4].copy_from_slice(&DICT_MAGIC);
        out[4..6].copy_from_slice(&DICT_REVISION.to_le_bytes());
        out[6] = dictionary.words.len() as u8;
        out[7] = 0;
        let mut position = 8;
        for word in &dictionary.words {
            out[position] = word.len() as u8;
            position += 1;
            out[position..position + word.len()].copy_from_slice(word);
            position += word.len();
        }
        visit_encoded(src, &dictionary, |unit| {
            match unit {
                EncodeUnit::Literal(bytes) => {
                    for &byte in bytes {
                        if byte >= 128 || byte == DICT_ESCAPE_BYTE {
                            out[position] = DICT_ESCAPE_BYTE;
                            position += 1;
                            out[position] = if byte == DICT_ESCAPE_BYTE { 0 } else { byte };
                            position += 1;
                        } else {
                            out[position] = byte;
                            position += 1;
                        }
                    }
                }
                EncodeUnit::Static(code) => {
                    out[position] = code;
                    position += 1;
                }
                EncodeUnit::Dynamic(code) => {
                    out[position] = DICT_ESCAPE_BYTE;
                    out[position + 1] = code;
                    position += 2;
                }
            }
            Ok(())
        })?;
        exact_size(position, size)
    }
    /// Validate the entire expansion length before allocating the output buffer.
    pub fn decode_into(src: &[u8], expected_size: usize, out: &mut Vec<u8>) -> Result<()> {
        input_limit(src, MAX_STORED_CHUNK_SIZE)?;
        if expected_size > MAX_CHUNK_SIZE as usize {
            return Err(FilterError::OutputTooLarge);
        }
        let dictionary = DecodeDictionary::parse(src)?;
        let mut size = 0usize;
        dictionary.visit(|bytes| {
            size = size
                .checked_add(bytes.len())
                .ok_or(FilterError::OutputTooLarge)?;
            if size > expected_size {
                return Err(FilterError::LengthMismatch {
                    expected: expected_size,
                    actual: size,
                });
            }
            Ok(())
        })?;
        exact_size(size, expected_size)?;
        prepare_output(out, expected_size)?;
        let mut position = 0;
        dictionary.visit(|bytes| {
            out[position..position + bytes.len()].copy_from_slice(bytes);
            position += bytes.len();
            Ok(())
        })?;
        Ok(())
    }
    pub fn encode(src: &[u8]) -> Result<Vec<u8>> {
        let mut v = Vec::new();
        Self::encode_into(src, &mut v)?;
        Ok(v)
    }
    pub fn decode(src: &[u8], expected_size: usize) -> Result<Vec<u8>> {
        let mut v = Vec::new();
        Self::decode_into(src, expected_size, &mut v)?;
        Ok(v)
    }
}

/// `ip=0` is mandatory when writing WXP v2 chunks; nonzero IP supports standalone use.
pub fn apply_transform_into(
    data: &[u8],
    transform: TransformType,
    ip: u32,
    out: &mut Vec<u8>,
) -> Result<()> {
    input_limit(data, MAX_CHUNK_SIZE)?;
    match transform {
        TransformType::None => copy_into(data, out),
        TransformType::ByteShuffle4 => ByteShuffle::shuffle_into(data, 4, out),
        TransformType::ByteShuffle8 => ByteShuffle::shuffle_into(data, 8, out),
        TransformType::BcjX86 => {
            copy_into(data, out)?;
            BcjFilter::x86_in_place(out, ip, false)
        }
        TransformType::BcjArm64 => {
            copy_into(data, out)?;
            BcjFilter::arm64_in_place(out, ip, false)
        }
        TransformType::DictWord => DictTransform::encode_into(data, out),
    }
}
pub fn invert_transform_into(
    data: &[u8],
    transform: TransformType,
    ip: u32,
    expected_size: usize,
    out: &mut Vec<u8>,
) -> Result<()> {
    input_limit(data, MAX_STORED_CHUNK_SIZE)?;
    if expected_size > MAX_CHUNK_SIZE as usize {
        return Err(FilterError::OutputTooLarge);
    }
    if transform != TransformType::DictWord {
        exact_size(data.len(), expected_size)?;
    }
    match transform {
        TransformType::None => copy_into(data, out),
        TransformType::ByteShuffle4 => ByteShuffle::unshuffle_into(data, 4, out),
        TransformType::ByteShuffle8 => ByteShuffle::unshuffle_into(data, 8, out),
        TransformType::BcjX86 => {
            copy_into(data, out)?;
            BcjFilter::x86_in_place(out, ip, true)
        }
        TransformType::BcjArm64 => {
            copy_into(data, out)?;
            BcjFilter::arm64_in_place(out, ip, true)
        }
        TransformType::DictWord => DictTransform::decode_into(data, expected_size, out),
    }
}
pub fn apply_transform(data: &[u8], transform: TransformType, ip: u32) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    apply_transform_into(data, transform, ip, &mut out)?;
    Ok(out)
}
pub fn invert_transform(
    data: &[u8],
    transform: TransformType,
    ip: u32,
    expected_size: usize,
) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    invert_transform_into(data, transform, ip, expected_size, &mut out)?;
    Ok(out)
}

#[derive(Debug, Clone, PartialEq)]
pub struct PreparedChunk<'a> {
    pub profile: ProfileResult,
    pub transform: TransformType,
    pub bypass_compression: bool,
    pub data: Cow<'a, [u8]>,
}
pub struct SmartTransform;
impl SmartTransform {
    /// STORE/identity borrows its input. Dictionary output is kept only if smaller.
    pub fn prepare(data: &[u8], hint: ProfileHint) -> Result<PreparedChunk<'_>> {
        input_limit(data, MAX_CHUNK_SIZE)?;
        let profile = DataProfiler::profile_with_hint(data, hint);
        let transform = profile.recommended_transform;
        let bypass_compression = profile.bypass_compression;
        if bypass_compression || transform == TransformType::None {
            return Ok(PreparedChunk {
                profile,
                transform: TransformType::None,
                bypass_compression,
                data: Cow::Borrowed(data),
            });
        }
        let encoded = match apply_transform(data, transform, 0) {
            Ok(bytes) => bytes,
            Err(FilterError::OutputTooLarge) if transform == TransformType::DictWord => {
                return Ok(PreparedChunk {
                    profile,
                    transform: TransformType::None,
                    bypass_compression: false,
                    data: Cow::Borrowed(data),
                });
            }
            Err(error) => return Err(error),
        };
        if transform == TransformType::DictWord && encoded.len() >= data.len() {
            return Ok(PreparedChunk {
                profile,
                transform: TransformType::None,
                bypass_compression: false,
                data: Cow::Borrowed(data),
            });
        }
        Ok(PreparedChunk {
            profile,
            transform,
            bypass_compression: false,
            data: Cow::Owned(encoded),
        })
    }
}
