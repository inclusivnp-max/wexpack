//! Hash-chain LZ77 with greedy, lazy and bounded-horizon optimal parsing.
//! Optimal parsing minimizes 9 bits/literal and 1+8*(ULEB sizes) bits/match
//! over every match visible to the bounded match finder, including shorter matches.
use super::{BLOCK_SIZE, CodecError, MAX_LZ_SIZE, Reader, Result, bytes, exact, invalid, vector};
use std::cmp::Reverse;
use std::ops::Range;

/// A solid frame never imports history from another independently decoded frame.
pub const SOLID_WINDOW: usize = 16 << 20;
use std::collections::BinaryHeap;

pub const MIN_MATCH: usize = 4;
const NONE: u32 = u32::MAX;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LzOptions {
    pub hash_bits: u8,
    pub chain_depth: usize,
    pub window_size: usize,
}
impl Default for LzOptions {
    fn default() -> Self {
        Self {
            hash_bits: 16,
            chain_depth: 16,
            window_size: BLOCK_SIZE,
        }
    }
}
impl LzOptions {
    fn validate(self) -> Result<()> {
        if !(8..=22).contains(&self.hash_bits)
            || !(1..=1024).contains(&self.chain_depth)
            || self.window_size == 0
            || self.window_size > SOLID_WINDOW
        {
            return Err(invalid("LZ finder options"));
        }
        Ok(())
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseMode {
    Greedy,
    Lazy,
    Optimal { horizon: usize },
}
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Match {
    pub length: usize,
    pub distance: usize,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Token {
    Literal(u8),
    Match { length: usize, distance: usize },
}

pub struct MatchFinder<'a> {
    input: &'a [u8],
    options: LzOptions,
    heads: Vec<u32>,
    previous: Vec<u32>,
    cursor: usize,
}
impl<'a> MatchFinder<'a> {
    pub fn new(input: &'a [u8], options: LzOptions) -> Result<Self> {
        options.validate()?;
        if input.len() > SOLID_WINDOW {
            return Err(CodecError::InputLimit);
        }
        Ok(Self {
            input,
            options,
            heads: vector(1 << options.hash_bits, NONE)?,
            previous: if options.chain_depth > 1 {
                vector(input.len(), NONE)?
            } else {
                Vec::new()
            },
            cursor: 0,
        })
    }
    fn hash(&self, position: usize) -> usize {
        let b = &self.input[position..position + 4];
        let value = u32::from_le_bytes([b[0], b[1], b[2], b[3]]);
        (value.wrapping_mul(0x9e37_79b1) >> (32 - self.options.hash_bits)) as usize
    }
    /// Best length for each ULEB128 distance-price class. All positions before
    /// `position` must have been inserted; future bytes are never dictionary entries.
    pub fn find(&self, position: usize, max_length: usize) -> Result<[Match; 4]> {
        if position != self.cursor || position > self.input.len() {
            return Err(invalid("nonsequential match lookup"));
        }
        let limit = max_length.min(self.input.len() - position);
        let mut best = [Match::default(); 4];
        if limit < MIN_MATCH {
            return Ok(best);
        }
        let mut candidate = self.heads[self.hash(position)];
        let mut examined = 0;
        while candidate != NONE && examined < self.options.chain_depth {
            let candidate_pos = candidate as usize;
            if candidate_pos >= position {
                return Err(invalid("nondecreasing match chain"));
            }
            let distance = position - candidate_pos;
            if distance > self.options.window_size {
                break;
            }
            let class = varint_size((distance - 1) as u32) - 1;
            // A candidate cannot improve this distance-price class if it already
            // differs at the current best length. Avoid re-scanning long prefixes.
            let known = best[class].length;
            let length = if known < limit
                && self.input[position + known] == self.input[candidate_pos + known]
                && self.input[position..position + MIN_MATCH]
                    == self.input[candidate_pos..candidate_pos + MIN_MATCH]
            {
                common_prefix(
                    &self.input[position..position + limit],
                    &self.input[candidate_pos..candidate_pos + limit],
                )
            } else {
                0
            };
            if length >= MIN_MATCH && length > best[class].length {
                best[class] = Match { length, distance };
            }
            if length == limit || self.previous.is_empty() {
                break;
            }
            candidate = self.previous[candidate_pos];
            examined += 1;
        }
        Ok(best)
    }
    pub fn insert(&mut self, position: usize) -> Result<()> {
        if position != self.cursor || position >= self.input.len() {
            return Err(invalid("nonsequential match insertion"));
        }
        if self.input.len() - position >= MIN_MATCH {
            let hash = self.hash(position);
            if !self.previous.is_empty() {
                self.previous[position] = self.heads[hash];
            }
            self.heads[hash] = position as u32;
        }
        self.cursor += 1;
        Ok(())
    }
    fn advance_to(&mut self, end: usize) -> Result<()> {
        if end > self.input.len() || end < self.cursor {
            return Err(invalid("match insertion range"));
        }
        while self.cursor < end {
            self.insert(self.cursor)?;
        }
        Ok(())
    }
}
fn common_prefix(a: &[u8], b: &[u8]) -> usize {
    let mut i = 0;
    while a.len() - i >= 8 {
        let x = u64::from_le_bytes([
            a[i],
            a[i + 1],
            a[i + 2],
            a[i + 3],
            a[i + 4],
            a[i + 5],
            a[i + 6],
            a[i + 7],
        ]);
        let y = u64::from_le_bytes([
            b[i],
            b[i + 1],
            b[i + 2],
            b[i + 3],
            b[i + 4],
            b[i + 5],
            b[i + 6],
            b[i + 7],
        ]);
        if x != y {
            return i + ((x ^ y).trailing_zeros() as usize / 8);
        }
        i += 8;
    }
    while i < a.len() && a[i] == b[i] {
        i += 1;
    }
    i
}
pub fn varint_size(mut value: u32) -> usize {
    let mut count = 1;
    while value >= 128 {
        value >>= 7;
        count += 1;
    }
    count
}
pub fn token_cost_bits(token: Token) -> Result<u32> {
    match token {
        Token::Literal(_) => Ok(9),
        Token::Match { length, distance }
            if (MIN_MATCH..=BLOCK_SIZE).contains(&length)
                && (1..=SOLID_WINDOW).contains(&distance) =>
        {
            Ok(1 + 8
                * (varint_size((length - MIN_MATCH) as u32) + varint_size((distance - 1) as u32))
                    as u32)
        }
        _ => Err(invalid("LZ token values")),
    }
}
fn best_match(candidates: [Match; 4]) -> Match {
    candidates
        .into_iter()
        // Four-byte distances can make a four-byte match larger than literals.
        .filter(|m| {
            m.length >= MIN_MATCH
                && token_cost_bits(Token::Match {
                    length: m.length,
                    distance: m.distance,
                })
                .is_ok_and(|cost| cost < 9 * m.length as u32)
        })
        .max_by_key(|m| (m.length, usize::MAX - m.distance))
        .unwrap_or_default()
}
fn parse_greedy(
    input: &[u8],
    finder: &mut MatchFinder<'_>,
    lazy: bool,
    range: Range<usize>,
    emit: &mut impl FnMut(Token) -> Result<()>,
) -> Result<()> {
    let mut position = range.start;
    while position < range.end {
        let current = best_match(finder.find(position, range.end - position)?);
        finder.insert(position)?;
        if current.length >= MIN_MATCH {
            if lazy && position + 1 < range.end {
                let next = best_match(finder.find(position + 1, range.end - position - 1)?);
                if next.length > current.length + 1 {
                    emit(Token::Literal(input[position]))?;
                    position += 1;
                    continue;
                }
            }
            emit(Token::Match {
                length: current.length,
                distance: current.distance,
            })?;
            position += current.length;
            finder.advance_to(position)?;
        } else {
            emit(Token::Literal(input[position]))?;
            position += 1;
        }
    }
    Ok(())
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct Pending {
    start: usize,
    cost: u32,
    origin: usize,
    distance: usize,
    end: usize,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct Active {
    cost: u32,
    origin: usize,
    distance: usize,
    end: usize,
}
#[derive(Debug, Default, Clone, Copy)]
struct Predecessor {
    origin: usize,
    distance: usize,
}

/// Interval relaxations cover every shorter match at its exact integer code cost.
/// Two priority queues avoid O(horizon^2) expansion of all match lengths.
fn parse_optimal(
    input: &[u8],
    finder: &mut MatchFinder<'_>,
    horizon: usize,
    range: Range<usize>,
    emit: &mut impl FnMut(Token) -> Result<()>,
) -> Result<()> {
    if !(4..=4096).contains(&horizon) {
        return Err(invalid("optimal horizon must be 4..4096"));
    }
    let mut costs = vector(horizon + 1, 0u32)?;
    let mut previous = vector(horizon + 1, Predecessor::default())?;
    let mut pending: BinaryHeap<Reverse<Pending>> = BinaryHeap::new();
    let mut active: BinaryHeap<Reverse<Active>> = BinaryHeap::new();
    pending
        .try_reserve(12 * horizon)
        .map_err(|_| CodecError::AllocationFailed)?;
    active
        .try_reserve(12 * horizon)
        .map_err(|_| CodecError::AllocationFailed)?;
    let mut reversed = Vec::new();
    reversed
        .try_reserve_exact(horizon)
        .map_err(|_| CodecError::AllocationFailed)?;
    for base in (range.start..range.end).step_by(horizon) {
        let count = horizon.min(range.end - base);
        pending.clear();
        active.clear();
        costs[0] = 0;
        for offset in 0..=count {
            while pending.peek().is_some_and(|p| p.0.start <= offset) {
                let Reverse(p) = pending
                    .pop()
                    .ok_or_else(|| invalid("optimal pending queue"))?;
                active.push(Reverse(Active {
                    cost: p.cost,
                    origin: p.origin,
                    distance: p.distance,
                    end: p.end,
                }));
            }
            while active.peek().is_some_and(|p| p.0.end < offset) {
                active.pop();
            }
            if offset > 0 {
                costs[offset] = costs[offset - 1] + 9;
                previous[offset] = Predecessor {
                    origin: offset - 1,
                    distance: 0,
                };
                if let Some(Reverse(edge)) = active.peek()
                    && edge.cost <= costs[offset]
                {
                    costs[offset] = edge.cost;
                    previous[offset] = Predecessor {
                        origin: edge.origin,
                        distance: edge.distance,
                    };
                }
            }
            if offset == count {
                break;
            }
            let candidates = finder.find(base + offset, count - offset)?;
            finder.insert(base + offset)?;
            for candidate in candidates {
                if candidate.length < MIN_MATCH {
                    continue;
                }
                // len-4 in [0,127], [128,16383], ... has constant ULEB cost.
                for (low, high) in [(4, 131), (132, 16_387), (16_388, BLOCK_SIZE)] {
                    let end = high.min(candidate.length);
                    if low > end {
                        continue;
                    }
                    let cost = costs[offset]
                        + token_cost_bits(Token::Match {
                            length: low,
                            distance: candidate.distance,
                        })?;
                    pending.push(Reverse(Pending {
                        start: offset + low,
                        end: offset + end,
                        origin: offset,
                        distance: candidate.distance,
                        cost,
                    }));
                }
            }
        }
        reversed.clear();
        let mut end = count;
        while end > 0 {
            let p = previous[end];
            reversed.push(if p.distance == 0 {
                Token::Literal(input[base + p.origin])
            } else {
                Token::Match {
                    length: end - p.origin,
                    distance: p.distance,
                }
            });
            end = p.origin;
        }
        for token in reversed.iter().rev() {
            emit(*token)?;
        }
    }
    Ok(())
}
fn visit(
    input: &[u8],
    mode: ParseMode,
    options: LzOptions,
    mut emit: impl FnMut(Token) -> Result<()>,
) -> Result<()> {
    let mut finder = MatchFinder::new(input, options)?;
    match mode {
        ParseMode::Greedy => parse_greedy(input, &mut finder, false, 0..input.len(), &mut emit),
        ParseMode::Lazy => parse_greedy(input, &mut finder, true, 0..input.len(), &mut emit),
        ParseMode::Optimal { horizon } => {
            parse_optimal(input, &mut finder, horizon, 0..input.len(), &mut emit)
        }
    }
}
pub fn parse(input: &[u8], mode: ParseMode, options: LzOptions) -> Result<Vec<Token>> {
    if input.len() > BLOCK_SIZE {
        return Err(CodecError::InputLimit);
    }
    let mut tokens = Vec::new();
    tokens
        .try_reserve_exact(input.len())
        .map_err(|_| CodecError::AllocationFailed)?;
    visit(input, mode, options, |token| {
        tokens.push(token);
        Ok(())
    })?;
    Ok(tokens)
}
fn write_varint(mut value: u32, out: &mut Vec<u8>) {
    while value >= 128 {
        out.push(value as u8 | 128);
        value >>= 7;
    }
    out.push(value as u8);
}
fn read_varint(reader: &mut Reader<'_>) -> Result<u32> {
    let mut value = 0;
    for i in 0..5 {
        let byte = reader.u8()?;
        if i == 4 && byte > 15 {
            return Err(invalid("ULEB128 overflow"));
        }
        value |= u32::from(byte & 127) << (7 * i);
        if byte < 128 {
            if i > 0 && byte == 0 {
                return Err(invalid("nonminimal ULEB128"));
            }
            return Ok(value);
        }
    }
    Err(invalid("unterminated ULEB128"))
}
struct TokenWriter {
    output: Vec<u8>,
    flag: usize,
    slot: usize,
    produced: usize,
    history: usize,
}
impl TokenWriter {
    fn new() -> Result<Self> {
        Ok(Self {
            output: bytes(MAX_LZ_SIZE)?,
            flag: 0,
            slot: 0,
            produced: 0,
            history: 0,
        })
    }
    fn push(&mut self, token: Token) -> Result<()> {
        let consumed = match token {
            Token::Literal(_) => 1,
            Token::Match { length, distance } => {
                if length < MIN_MATCH
                    || distance == 0
                    || distance > self.history + self.produced
                    || distance > SOLID_WINDOW
                {
                    return Err(invalid("invalid LZ reference"));
                }
                length
            }
        };
        if consumed > BLOCK_SIZE - self.produced {
            return Err(CodecError::OutputLimit);
        }
        if self.slot == 0 {
            self.flag = self.output.len();
            self.output.push(0);
        }
        match token {
            Token::Literal(byte) => self.output.push(byte),
            Token::Match { length, distance } => {
                self.output[self.flag] |= 1 << self.slot;
                write_varint((length - MIN_MATCH) as u32, &mut self.output);
                write_varint((distance - 1) as u32, &mut self.output);
            }
        }
        self.slot = (self.slot + 1) % 8;
        self.produced += consumed;
        if self.output.len() > MAX_LZ_SIZE {
            return Err(CodecError::OutputLimit);
        }
        Ok(())
    }
}
pub fn serialize_tokens(tokens: &[Token]) -> Result<Vec<u8>> {
    let mut writer = TokenWriter::new()?;
    for &token in tokens {
        writer.push(token)?;
    }
    Ok(writer.output)
}
pub fn encode(input: &[u8], mode: ParseMode, options: LzOptions) -> Result<Vec<u8>> {
    if input.len() > BLOCK_SIZE {
        return Err(CodecError::InputLimit);
    }
    let mut writer = TokenWriter::new()?;
    visit(input, mode, options, |token| writer.push(token))?;
    exact(writer.produced, input.len())?;
    Ok(writer.output)
}
/// Emits one block while retaining the finder over the complete solid input.
pub(super) fn encode_solid_block(
    finder: &mut MatchFinder<'_>,
    range: Range<usize>,
    mode: ParseMode,
) -> Result<Vec<u8>> {
    if range.start != finder.cursor
        || range.end > finder.input.len()
        || range.end < range.start
        || range.len() > BLOCK_SIZE
    {
        return Err(invalid("solid LZ block range"));
    }
    let mut writer = TokenWriter::new()?;
    writer.history = range.start;
    let expected = range.len();
    let input = finder.input;
    match mode {
        ParseMode::Greedy => parse_greedy(input, finder, false, range, &mut |t| writer.push(t))?,
        ParseMode::Lazy => parse_greedy(input, finder, true, range, &mut |t| writer.push(t))?,
        ParseMode::Optimal { horizon } => {
            parse_optimal(input, finder, horizon, range, &mut |t| writer.push(t))?
        }
    }
    exact(writer.produced, expected)?;
    Ok(writer.output)
}
pub fn decode(input: &[u8], expected_size: usize) -> Result<Vec<u8>> {
    let mut out = bytes(expected_size.min(BLOCK_SIZE))?;
    decode_append(input, expected_size, &mut out, false)?;
    Ok(out)
}
/// Appends exactly one block. History is read only from already validated output.
pub(super) fn decode_append(
    input: &[u8],
    expected_size: usize,
    out: &mut Vec<u8>,
    solid: bool,
) -> Result<()> {
    if input.len() > MAX_LZ_SIZE {
        return Err(CodecError::InputLimit);
    }
    if expected_size > BLOCK_SIZE {
        return Err(CodecError::OutputLimit);
    }
    let start = out.len();
    if (solid && start + expected_size > SOLID_WINDOW) || (!solid && start != 0) {
        return Err(CodecError::OutputLimit);
    }
    out.try_reserve_exact(expected_size)
        .map_err(|_| CodecError::AllocationFailed)?;
    let end = start + expected_size;
    let mut reader = Reader::new(input);
    while out.len() < end {
        let flags = reader.u8()?;
        for slot in 0..8 {
            if flags & (1 << slot) == 0 {
                out.push(reader.u8()?);
            } else {
                let length = (read_varint(&mut reader)? as usize)
                    .checked_add(MIN_MATCH)
                    .ok_or(CodecError::OutputLimit)?;
                let distance = (read_varint(&mut reader)? as usize)
                    .checked_add(1)
                    .ok_or(CodecError::OutputLimit)?;
                if distance > out.len() || distance > SOLID_WINDOW || length > end - out.len() {
                    return Err(invalid("LZ reference out of bounds"));
                }
                if distance >= length {
                    let start = out.len() - distance;
                    out.extend_from_within(start..start + length);
                } else {
                    // Copy a seed then double initialized data; handles distance=1 safely.
                    let start = out.len();
                    let seed = distance.min(length);
                    let from = start - distance;
                    out.extend_from_within(from..from + seed);
                    while out.len() - start < length {
                        let count = (out.len() - start).min(length - (out.len() - start));
                        out.extend_from_within(start..start + count);
                    }
                }
            }
            if out.len() == end {
                if (u16::from(flags) >> (slot + 1)) != 0 {
                    return Err(invalid("nonzero unused LZ flag bits"));
                }
                break;
            }
        }
    }
    reader.finish()?;
    Ok(())
}
