//! Integer-only context mixing and a 32-bit binary arithmetic/range coder.
//! E1/E2/E3 renormalization avoids carry and underflow ambiguities. The coding
//! interval is inclusive; the decoder never fabricates missing padding bytes.
use super::{CodecError, MAX_LZ_SIZE, Reader, Result, bytes, crc, exact, invalid, vector};
const SCALE: u32 = 4096;
const HALF: u32 = 0x8000_0000;
const QUARTER: u32 = 0x4000_0000;
const THREE_QUARTERS: u32 = 0xc000_0000;
const MAX_FRAME: usize = 12 * MAX_LZ_SIZE + 128;
const HISTORY: usize = 1 << 16;
const MATCH_TABLE: usize = 1 << 14;

struct BitWriter {
    data: Vec<u8>,
    length: usize,
}
impl BitWriter {
    fn new() -> Result<Self> {
        Ok(Self {
            data: bytes(256)?,
            length: 0,
        })
    }
    fn bit(&mut self, value: bool) -> Result<()> {
        if self.length.is_multiple_of(8) {
            if self.data.len() >= MAX_FRAME - 16 {
                return Err(CodecError::OutputLimit);
            }
            self.data
                .try_reserve(1)
                .map_err(|_| CodecError::AllocationFailed)?;
            self.data.push(0);
        }
        if value {
            self.data[self.length / 8] |= 1 << (7 - self.length % 8);
        }
        self.length += 1;
        Ok(())
    }
}
struct BitReader<'a> {
    data: &'a [u8],
    length: usize,
    position: usize,
}
impl<'a> BitReader<'a> {
    fn new(data: &'a [u8], length: usize) -> Result<Self> {
        if data.len() > MAX_FRAME || length < 34 || length.div_ceil(8) != data.len() {
            return Err(invalid("arithmetic bit length"));
        }
        if !length.is_multiple_of(8) && data[data.len() - 1] & ((1 << (8 - length % 8)) - 1) != 0 {
            return Err(invalid("arithmetic byte padding"));
        }
        let reader = Self {
            data,
            length,
            position: 0,
        };
        for position in length - 32..length {
            if reader.at(position) {
                return Err(invalid("arithmetic zero tail"));
            }
        }
        Ok(reader)
    }
    fn at(&self, position: usize) -> bool {
        self.data[position / 8] & (1 << (7 - position % 8)) != 0
    }
    fn bit(&mut self) -> Result<bool> {
        if self.position >= self.length {
            return Err(CodecError::Truncated);
        }
        let bit = self.at(self.position);
        self.position += 1;
        Ok(bit)
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RangeStream {
    pub data: Vec<u8>,
    pub bit_len: u32,
}
pub struct BinaryRangeEncoder {
    low: u32,
    high: u32,
    pending: u32,
    writer: BitWriter,
    symbols: usize,
}
impl BinaryRangeEncoder {
    pub fn new() -> Result<Self> {
        Ok(Self {
            low: 0,
            high: u32::MAX,
            pending: 0,
            writer: BitWriter::new()?,
            symbols: 0,
        })
    }
    fn emit(&mut self, bit: bool) -> Result<()> {
        self.writer.bit(bit)?;
        for _ in 0..self.pending {
            self.writer.bit(!bit)?;
        }
        self.pending = 0;
        Ok(())
    }
    pub fn encode_bit(&mut self, bit: bool, probability_one: u16) -> Result<()> {
        if !(1..4096).contains(&probability_one) {
            return Err(invalid("binary probability must be 1..4095"));
        }
        if self.symbols >= 8 * MAX_LZ_SIZE {
            return Err(CodecError::InputLimit);
        }
        self.symbols += 1;
        let range = u64::from(self.high) - u64::from(self.low) + 1;
        let zeros = (range * u64::from(SCALE - u32::from(probability_one))) >> 12;
        let split = self.low + zeros as u32 - 1;
        if bit {
            self.low = split + 1;
        } else {
            self.high = split;
        }
        loop {
            if self.high < HALF {
                self.emit(false)?;
            } else if self.low >= HALF {
                self.emit(true)?;
                self.low -= HALF;
                self.high -= HALF;
            } else if self.low >= QUARTER && self.high < THREE_QUARTERS {
                self.pending += 1;
                self.low -= QUARTER;
                self.high -= QUARTER;
            } else {
                break;
            }
            self.low <<= 1;
            self.high = (self.high << 1) | 1;
        }
        Ok(())
    }
    pub fn finish(mut self) -> Result<RangeStream> {
        self.pending += 1;
        self.emit(self.low >= QUARTER)?;
        for _ in 0..32 {
            self.writer.bit(false)?;
        }
        Ok(RangeStream {
            data: self.writer.data,
            bit_len: self.writer.length as u32,
        })
    }
}
pub struct BinaryRangeDecoder<'a> {
    low: u32,
    high: u32,
    code: u32,
    reader: BitReader<'a>,
    symbols: usize,
}
impl<'a> BinaryRangeDecoder<'a> {
    pub fn new(data: &'a [u8], bit_len: u32) -> Result<Self> {
        let mut reader = BitReader::new(data, bit_len as usize)?;
        let mut code = 0;
        for _ in 0..32 {
            code = (code << 1) | u32::from(reader.bit()?);
        }
        Ok(Self {
            low: 0,
            high: u32::MAX,
            code,
            reader,
            symbols: 0,
        })
    }
    pub fn decode_bit(&mut self, probability_one: u16) -> Result<bool> {
        if !(1..4096).contains(&probability_one) {
            return Err(invalid("binary probability must be 1..4095"));
        }
        if self.symbols >= 8 * MAX_LZ_SIZE {
            return Err(CodecError::OutputLimit);
        }
        self.symbols += 1;
        let range = u64::from(self.high) - u64::from(self.low) + 1;
        let zeros = (range * u64::from(SCALE - u32::from(probability_one))) >> 12;
        let split = self.low + zeros as u32 - 1;
        let bit = self.code > split;
        if bit {
            self.low = split + 1;
        } else {
            self.high = split;
        }
        loop {
            if self.high < HALF {
            } else if self.low >= HALF {
                self.low -= HALF;
                self.high -= HALF;
                self.code -= HALF;
            } else if self.low >= QUARTER && self.high < THREE_QUARTERS {
                self.low -= QUARTER;
                self.high -= QUARTER;
                self.code -= QUARTER;
            } else {
                break;
            }
            self.low <<= 1;
            self.high = (self.high << 1) | 1;
            self.code = (self.code << 1) | u32::from(self.reader.bit()?);
        }
        if self.code < self.low || self.code > self.high {
            return Err(invalid("arithmetic code outside interval"));
        }
        Ok(bit)
    }
    pub fn finish(self) -> Result<()> {
        // R renormalizations emit R+2 finish bits, followed by 32 zeros. The
        // decoder consumes 32+R bits, leaving exactly the final two zero bits.
        if self.reader.position != self.reader.length - 2 {
            return Err(invalid("arithmetic consumption or termination"));
        }
        Ok(())
    }
}
#[derive(Clone, Copy)]
struct MatchEntry {
    context: u32,
    position: u32,
}

pub struct ContextMixer {
    order0: [u16; 256],
    order1: Vec<u16>,
    match_probabilities: [u16; 16],
    weights: [[u32; 3]; 8],
    history: Vec<u8>,
    matches: Vec<MatchEntry>,
    position: u32,
    context: u32,
    previous_byte: u8,
    prefix: u16,
    bit_position: usize,
    predicted_byte: Option<u8>,
}
fn adapt(probability: &mut u16, bit: bool, rate: u32) {
    if bit {
        *probability += ((4096 - *probability) >> rate).max(1);
    } else {
        *probability -= (*probability >> rate).max(1);
    }
    *probability = (*probability).clamp(1, 4095);
}
impl ContextMixer {
    pub fn new() -> Result<Self> {
        Ok(Self {
            order0: [2048; 256],
            order1: vector(256 * 256, 2048)?,
            match_probabilities: std::array::from_fn(|i| if i % 2 == 0 { 512 } else { 3584 }),
            weights: [[1024; 3]; 8],
            history: vector(HISTORY, 0)?,
            matches: vector(
                MATCH_TABLE,
                MatchEntry {
                    context: 0,
                    position: u32::MAX,
                },
            )?,
            position: 0,
            context: 0,
            previous_byte: 0,
            prefix: 1,
            bit_position: 0,
            predicted_byte: None,
        })
    }
    fn probabilities(&self) -> [u16; 3] {
        let match_probability = match self.predicted_byte {
            Some(byte) => {
                self.match_probabilities
                    [2 * self.bit_position + ((byte >> (7 - self.bit_position)) & 1) as usize]
            }
            None => 2048,
        };
        [
            self.order0[self.prefix as usize],
            self.order1[self.previous_byte as usize * 256 + self.prefix as usize],
            match_probability,
        ]
    }
    fn mix(&self, probabilities: [u16; 3]) -> u16 {
        let weights = self.weights[self.bit_position];
        let sum: u32 = weights.iter().sum();
        let weighted: u32 = weights
            .iter()
            .zip(probabilities)
            .map(|(&w, p)| w * u32::from(p))
            .sum();
        ((weighted + sum / 2) / sum).clamp(1, 4095) as u16
    }
    pub fn prediction(&self) -> u16 {
        self.mix(self.probabilities())
    }
    pub fn weights(&self) -> [[u32; 3]; 8] {
        self.weights
    }
    pub fn update(&mut self, bit: bool) -> Result<()> {
        if self.position as usize >= MAX_LZ_SIZE {
            return Err(CodecError::InputLimit);
        }
        let probabilities = self.probabilities();
        let mixed = self.mix(probabilities);
        let likelihood = if bit {
            u32::from(mixed)
        } else {
            SCALE - u32::from(mixed)
        };
        // Online Bayesian expert weighting with floors/ceilings for adaptation.
        for (weight, probability) in self.weights[self.bit_position]
            .iter_mut()
            .zip(probabilities)
        {
            let expert = if bit {
                u32::from(probability)
            } else {
                SCALE - u32::from(probability)
            };
            *weight = ((*weight * expert + likelihood / 2) / likelihood).clamp(32, 4096);
        }
        adapt(&mut self.order0[self.prefix as usize], bit, 5);
        adapt(
            &mut self.order1[self.previous_byte as usize * 256 + self.prefix as usize],
            bit,
            6,
        );
        if let Some(byte) = self.predicted_byte {
            let predicted = (byte >> (7 - self.bit_position)) & 1;
            adapt(
                &mut self.match_probabilities[2 * self.bit_position + predicted as usize],
                bit,
                5,
            );
            if (predicted != 0) != bit {
                self.predicted_byte = None;
            }
        }
        self.prefix = (self.prefix << 1) | u16::from(bit);
        self.bit_position += 1;
        if self.bit_position == 8 {
            let byte = self.prefix as u8;
            self.history[self.position as usize & (HISTORY - 1)] = byte;
            self.position += 1;
            self.context = (self.context << 8) | u32::from(byte);
            self.previous_byte = byte;
            self.prefix = 1;
            self.bit_position = 0;
            self.predicted_byte = None;
            if self.position >= 4 {
                let hash = (self.context.wrapping_mul(0x9e37_79b1) >> 18) as usize;
                let entry = self.matches[hash];
                if entry.position < self.position
                    && self.position - entry.position <= HISTORY as u32
                    && entry.context == self.context
                {
                    self.predicted_byte =
                        Some(self.history[entry.position as usize & (HISTORY - 1)]);
                }
                self.matches[hash] = MatchEntry {
                    context: self.context,
                    position: self.position,
                };
            }
        }
        Ok(())
    }
}
pub fn encode(input: &[u8]) -> Result<Vec<u8>> {
    if input.len() > MAX_LZ_SIZE {
        return Err(CodecError::InputLimit);
    }
    let mut model = ContextMixer::new()?;
    let mut encoder = BinaryRangeEncoder::new()?;
    for &byte in input {
        for shift in (0..8).rev() {
            let bit = byte & (1 << shift) != 0;
            encoder.encode_bit(bit, model.prediction())?;
            model.update(bit)?;
        }
    }
    let stream = encoder.finish()?;
    let mut out = bytes(16 + stream.data.len())?;
    out.extend_from_slice(b"WCM\x01");
    out.extend_from_slice(&(input.len() as u32).to_le_bytes());
    out.extend_from_slice(&stream.bit_len.to_le_bytes());
    out.extend_from_slice(&crc32fast::hash(input).to_le_bytes());
    out.extend_from_slice(&stream.data);
    Ok(out)
}
pub fn decode(input: &[u8], expected_size: usize) -> Result<Vec<u8>> {
    if input.len() > MAX_FRAME {
        return Err(CodecError::InputLimit);
    }
    if expected_size > MAX_LZ_SIZE {
        return Err(CodecError::OutputLimit);
    }
    let mut r = Reader::new(input);
    if r.take(4)? != b"WCM\x01" {
        return Err(invalid("context mixer magic"));
    }
    exact(r.u32()? as usize, expected_size)?;
    let bits = r.u32()?;
    let checksum = r.u32()?;
    let mut decoder = BinaryRangeDecoder::new(r.rest(), bits)?;
    let mut model = ContextMixer::new()?;
    let mut out = bytes(expected_size)?;
    for _ in 0..expected_size {
        let mut byte = 0;
        for _ in 0..8 {
            let bit = decoder.decode_bit(model.prediction())?;
            byte = (byte << 1) | u8::from(bit);
            model.update(bit)?;
        }
        out.push(byte);
    }
    decoder.finish()?;
    crc(&out, checksum)?;
    Ok(out)
}
