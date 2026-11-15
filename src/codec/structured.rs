//! Separate rANS streams and a fixed-model, bounded entropy-priced LZ parser.
use super::lz::{self, MIN_MATCH, MatchFinder};
use super::{BLOCK_SIZE, CodecError, Reader, Result, ans, bytes, exact, invalid, vector};
use std::{cmp::Reverse, collections::BinaryHeap, ops::Range};
const HEADER: usize = 44;
const HORIZON: usize = 1024;
const SCALE: u32 = 256;
const MAX_EDGES: usize = 29 * HORIZON * 11;
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) struct Token {
    pub length: u32,
    pub distance: u32,
}
fn slot(n: u32) -> u8 {
    (31 - n.leading_zeros()) as u8
}
fn price(f: u16) -> u32 {
    ((4096.0 / f64::from(f.max(1))).log2() * f64::from(SCALE)).ceil() as u32
}
// Contexts depend only on already decoded bytes and position, not on the parse.
fn bank(mode: u8, position: usize, previous: u8) -> usize {
    match mode {
        0 => 0,
        1 => position & 3,
        2 => (previous >> 6) as usize,
        3 => {
            if previous.is_ascii_whitespace() {
                0
            } else if previous.is_ascii_alphabetic() {
                1
            } else if previous.is_ascii_digit() {
                2
            } else {
                3
            }
        }
        4 => (previous >> 4) as usize,
        _ => unreachable!(),
    }
}
fn banks(mode: u8) -> Result<usize> {
    match mode {
        0 => Ok(1),
        1..=3 => Ok(4),
        4 => Ok(16),
        _ => Err(invalid("literal context mode")),
    }
}
#[derive(Clone, Copy, Default)]
struct Recent([u32; 4]);
impl Recent {
    fn touch(&mut self, distance: u32) {
        let index = self.0.iter().position(|&d| d == distance).unwrap_or(3);
        for i in (1..=index).rev() {
            self.0[i] = self.0[i - 1];
        }
        self.0[0] = distance;
    }
}
#[derive(Clone)]
pub(super) struct Prices {
    kind: [u32; 2],
    literal: [[u32; 256]; 16],
    context: u8,
    contextual: bool,
    length: [u32; 256],
    distance: [u32; 256],
}
impl Prices {
    fn literal(&self, input: &[u8], position: usize) -> u32 {
        let previous = position.checked_sub(1).map_or(0, |p| input[p]);
        self.kind[0]
            + self.literal[bank(self.context, position, previous)][input[position] as usize]
    }
    fn length(&self, n: usize) -> u32 {
        let s = slot((n - MIN_MATCH + 1) as u32);
        self.length[s as usize] + u32::from(s) * SCALE
    }
    fn distance(&self, d: usize, recent: Recent) -> u32 {
        let count = if self.contextual { 4 } else { 1 };
        if let Some(i) = recent.0[..count]
            .iter()
            .position(|&v| v as usize == d && d != 0)
        {
            self.distance[i]
        } else {
            let s = slot(d as u32);
            self.distance[s as usize + count] + u32::from(s) * SCALE
        }
    }
    fn matched(&self, n: usize, d: usize, recent: Recent) -> u32 {
        self.kind[1] + self.length(n) + self.distance(d, recent)
    }
    fn candidates(
        &self,
        finder: &MatchFinder<'_>,
        pos: usize,
        length: usize,
        recent: Recent,
    ) -> Result<([lz::Match; 29], usize)> {
        let mut out = [lz::Match::default(); 29];
        let count = if self.contextual {
            out[..25].copy_from_slice(&finder.find_priced(pos, length)?);
            25
        } else {
            out[..4].copy_from_slice(&finder.find(pos, length)?);
            4
        };
        let repeats = if self.contextual { 4 } else { 1 };
        for i in 0..repeats {
            out[count + i] = finder.at_distance(pos, length, recent.0[i] as usize)?;
        }
        Ok((out, count + repeats))
    }
}
struct Bits {
    data: Vec<u8>,
    count: usize,
}
impl Bits {
    fn new() -> Self {
        Self {
            data: Vec::new(),
            count: 0,
        }
    }
    fn put(&mut self, value: u32, count: u8) -> Result<()> {
        if count > 24 || value >> count != 0 {
            return Err(invalid("split extra bits"));
        }
        if self.count + count as usize > BLOCK_SIZE * 8 {
            return Err(CodecError::OutputLimit);
        }
        for k in 0..count {
            if self.count.is_multiple_of(8) {
                self.data
                    .try_reserve(1)
                    .map_err(|_| CodecError::AllocationFailed)?;
                self.data.push(0);
            }
            self.data[self.count / 8] |= (((value >> k) & 1) as u8) << (self.count % 8);
            self.count += 1;
        }
        Ok(())
    }
}
struct BitReader<'a> {
    data: &'a [u8],
    count: usize,
    position: usize,
}
impl BitReader<'_> {
    fn get(&mut self, n: u8) -> Result<u32> {
        if n > 24 || self.position + n as usize > self.count {
            return Err(invalid("truncated split extras"));
        }
        let mut v = 0;
        for k in 0..n {
            v |= u32::from((self.data[self.position / 8] >> (self.position % 8)) & 1) << k;
            self.position += 1;
        }
        Ok(v)
    }
}
pub(super) fn seed(data: &[u8], expected: usize) -> Result<Vec<Token>> {
    let mut r = Reader::new(data);
    let mut tokens = Vec::new();
    let mut produced = 0usize;
    while produced < expected {
        let flags = r.u8()?;
        for bit in 0..8 {
            let token = if flags & (1 << bit) == 0 {
                r.u8()?;
                Token {
                    length: 1,
                    distance: 0,
                }
            } else {
                Token {
                    length: lz::read_varint(&mut r)?
                        .checked_add(4)
                        .ok_or(CodecError::OutputLimit)?,
                    distance: lz::read_varint(&mut r)?
                        .checked_add(1)
                        .ok_or(CodecError::OutputLimit)?,
                }
            };
            if token.length as usize > expected - produced {
                return Err(invalid("seed token length"));
            }
            produced += token.length as usize;
            if tokens.len() == tokens.capacity() {
                tokens
                    .try_reserve(1)
                    .map_err(|_| CodecError::AllocationFailed)?;
            }
            tokens.push(token);
            if produced == expected {
                if u16::from(flags) >> (bit + 1) != 0 {
                    return Err(invalid("seed flags"));
                }
                break;
            }
        }
    }
    r.finish()?;
    Ok(tokens)
}
fn packed_kinds(data: &[u8]) -> Result<Vec<u8>> {
    let mut out = vector(data.len().div_ceil(8), 0u8)?;
    for (i, &b) in data.iter().enumerate() {
        out[i / 8] |= b << (i % 8);
    }
    Ok(out)
}
fn stream(data: &[u8], kinds: bool) -> Result<(Vec<u8>, bool, [u32; 256])> {
    let raw = if kinds {
        packed_kinds(data)?
    } else {
        data.to_vec()
    };
    let mut costs = [if kinds { SCALE } else { 8 * SCALE }; 256];
    if data.is_empty() {
        return Ok((raw, false, costs));
    }
    let coded = ans::encode(data)?;
    if coded.len() < raw.len() {
        let f = ans::normalized_frequencies(data)?;
        for i in 0..256 {
            costs[i] = price(f[i]);
        }
        Ok((coded, true, costs))
    } else {
        Ok((raw, false, costs))
    }
}
pub(super) struct Encoded {
    pub data: Vec<u8>,
    pub tokens: usize,
    pub matches: usize,
    pub prices: Prices,
}
pub(super) fn encode(input: &[u8], range: Range<usize>, tokens: &[Token]) -> Result<Encoded> {
    encode_mode(input, range, tokens, None)
}
pub(super) fn encode_context(
    input: &[u8],
    range: Range<usize>,
    tokens: &[Token],
) -> Result<Encoded> {
    let mut best = encode_mode(input, range.clone(), tokens, Some(0))?;
    for mode in 1..=4 {
        let next = encode_mode(input, range.clone(), tokens, Some(mode))?;
        if next.data.len() < best.data.len() {
            best = next;
        }
    }
    Ok(best)
}
fn encode_mode(
    input: &[u8],
    range: Range<usize>,
    tokens: &[Token],
    context: Option<u8>,
) -> Result<Encoded> {
    if range.len() > BLOCK_SIZE || range.end > input.len() || tokens.len() > range.len() {
        return Err(CodecError::InputLimit);
    }
    let mut kinds = bytes(tokens.len())?;
    let mut literals = bytes(range.len())?;
    let mode = context.unwrap_or(0);
    let bank_count = banks(mode)?;
    let mut literal_banks: [Vec<u8>; 16] = std::array::from_fn(|_| Vec::new());
    let mut lengths = bytes(range.len() / 4)?;
    let mut distances = bytes(range.len() / 4)?;
    let mut bits = Bits::new();
    let mut pos = range.start;
    let mut recent = Recent::default();
    for t in tokens {
        let n = t.length as usize;
        if n == 0 || n > range.end - pos {
            return Err(invalid("split token range"));
        }
        if t.distance == 0 {
            if n != 1 {
                return Err(invalid("split literal length"));
            }
            kinds.push(0);
            literals.push(input[pos]);
            if context.is_some() {
                let previous = pos.checked_sub(1).map_or(0, |p| input[p]);
                let v = &mut literal_banks[bank(mode, pos, previous)];
                if v.len() == v.capacity() {
                    v.try_reserve(1).map_err(|_| CodecError::AllocationFailed)?;
                }
                v.push(input[pos]);
            }
        } else {
            if n < 4 || t.distance as usize > pos || t.distance as usize > lz::SOLID_WINDOW {
                return Err(invalid("split match distance"));
            }
            kinds.push(1);
            let value = t.length - 3;
            let s = slot(value);
            lengths.push(s);
            bits.put(value - (1 << s), s)?;
            let repeats = if context.is_some() { 4 } else { 1 };
            if let Some(i) = recent.0[..repeats].iter().position(|&d| d == t.distance) {
                distances.push(i as u8);
            } else {
                let s = slot(t.distance);
                distances.push(s + repeats as u8);
                bits.put(t.distance - (1 << s), s)?;
            }
            recent.touch(t.distance);
        }
        pos += n;
    }
    exact(pos, range.end)?;
    let (kind, kc, kp) = stream(&kinds, true)?;
    let (literal, lc, lp) = if context.is_some() {
        let mut payload = bytes(4 + 12 * bank_count + literals.len() + bank_count * 520)?;
        payload.extend([bank_count as u8, 0, 0, 0]);
        let mut encoded = Vec::new();
        let mut prices = [[8 * SCALE; 256]; 16];
        for i in 0..bank_count {
            let (data, coded, costs) = stream(&literal_banks[i], false)?;
            prices[i] = costs;
            payload.extend_from_slice(&(literal_banks[i].len() as u32).to_le_bytes());
            payload.extend_from_slice(&(data.len() as u32).to_le_bytes());
            payload.extend([u8::from(coded), 0, 0, 0]);
            encoded.push(data);
        }
        for data in encoded {
            payload.extend_from_slice(&data);
        }
        (payload, false, prices)
    } else {
        let (data, coded, costs) = stream(&literals, false)?;
        let mut prices = [[8 * SCALE; 256]; 16];
        prices[0] = costs;
        (data, coded, prices)
    };
    let (length, nc, np) = stream(&lengths, false)?;
    let (distance, dc, dp) = stream(&distances, false)?;
    let mut out = bytes(
        HEADER + kind.len() + literal.len() + length.len() + distance.len() + bits.data.len(),
    )?;
    out.extend_from_slice(if context.is_some() {
        b"WXS\x02"
    } else {
        b"WXS\x01"
    });
    out.push(u8::from(kc) | (u8::from(lc) << 1) | (u8::from(nc) << 2) | (u8::from(dc) << 3));
    out.extend([mode, 0, 0]);
    for n in [
        tokens.len(),
        literals.len(),
        lengths.len(),
        bits.count,
        kind.len(),
        literal.len(),
        length.len(),
        distance.len(),
        bits.data.len(),
    ] {
        out.extend_from_slice(&(n as u32).to_le_bytes());
    }
    out.extend_from_slice(&kind);
    out.extend_from_slice(&literal);
    out.extend_from_slice(&length);
    out.extend_from_slice(&distance);
    out.extend_from_slice(&bits.data);
    Ok(Encoded {
        data: out,
        tokens: tokens.len(),
        matches: lengths.len(),
        prices: Prices {
            kind: [kp[0], kp[1]],
            literal: lp,
            context: mode,
            contextual: context.is_some(),
            length: np,
            distance: dp,
        },
    })
}
fn decoded(data: &[u8], count: usize, coded: bool, kinds: bool) -> Result<Vec<u8>> {
    if coded {
        if count == 0 {
            return Err(invalid("coded empty split stream"));
        }
        ans::decode(data, count)
    } else if kinds {
        exact(data.len(), count.div_ceil(8))?;
        if !count.is_multiple_of(8) && data.last().is_some_and(|b| b >> (count % 8) != 0) {
            return Err(invalid("unused split kind bits"));
        }
        let mut out = bytes(count)?;
        for i in 0..count {
            out.push((data[i / 8] >> (i % 8)) & 1);
        }
        Ok(out)
    } else {
        exact(data.len(), count)?;
        Ok(data.to_vec())
    }
}
pub(super) fn decode_append(
    data: &[u8],
    expected: usize,
    token_count: usize,
    solid: bool,
    out: &mut Vec<u8>,
) -> Result<()> {
    decode_version(data, expected, token_count, solid, false, out)
}
pub(super) fn decode_context_append(
    data: &[u8],
    expected: usize,
    token_count: usize,
    solid: bool,
    out: &mut Vec<u8>,
) -> Result<()> {
    decode_version(data, expected, token_count, solid, true, out)
}
fn decode_version(
    data: &[u8],
    expected: usize,
    token_count: usize,
    solid: bool,
    contextual: bool,
    out: &mut Vec<u8>,
) -> Result<()> {
    if expected == 0 || expected > BLOCK_SIZE || data.len() > BLOCK_SIZE * 2 {
        return Err(CodecError::InputLimit);
    }
    let mut r = Reader::new(data);
    if r.take(4)? != if contextual { b"WXS\x02" } else { b"WXS\x01" } {
        return Err(invalid("split magic"));
    }
    let modes = r.u8()?;
    let context = r.u8()?;
    let bank_count = banks(context)?;
    if modes & !15 != 0
        || r.take(2)? != [0, 0]
        || (!contextual && context != 0)
        || (contextual && modes & 2 != 0)
    {
        return Err(invalid("split flags"));
    }
    let count = r.u32()? as usize;
    let literal_count = r.u32()? as usize;
    let matches = r.u32()? as usize;
    let bit_count = r.u32()? as usize;
    let mut sizes = [0usize; 5];
    for s in &mut sizes {
        *s = r.u32()? as usize;
    }
    if count != token_count
        || count == 0
        || count > expected
        || literal_count > expected
        || matches > expected / 4
        || literal_count.checked_add(matches) != Some(count)
        || bit_count > expected * 8
        || sizes[4] != bit_count.div_ceil(8)
    {
        return Err(invalid("split counts"));
    }
    let mut streams = Vec::new();
    for s in sizes {
        streams.push(r.take(s)?);
    }
    r.finish()?;
    let kinds = decoded(streams[0], count, modes & 1 != 0, true)?;
    let mut literal_banks: [Vec<u8>; 16] = std::array::from_fn(|_| Vec::new());
    if contextual {
        let mut lr = Reader::new(streams[1]);
        if lr.u8()? as usize != bank_count || lr.take(3)? != [0, 0, 0] {
            return Err(invalid("literal bank header"));
        }
        let mut counts = [0usize; 16];
        let mut sizes = [0usize; 16];
        let mut codecs = [0u8; 16];
        let mut total = 0usize;
        for i in 0..bank_count {
            counts[i] = lr.u32()? as usize;
            sizes[i] = lr.u32()? as usize;
            codecs[i] = lr.u8()?;
            total = total
                .checked_add(counts[i])
                .ok_or(CodecError::OutputLimit)?;
            if counts[i] > literal_count
                || total > literal_count
                || codecs[i] > 1
                || lr.take(3)? != [0, 0, 0]
            {
                return Err(invalid("literal bank descriptor"));
            }
        }
        exact(total, literal_count)?;
        for i in 0..bank_count {
            literal_banks[i] = decoded(lr.take(sizes[i])?, counts[i], codecs[i] != 0, false)?;
        }
        lr.finish()?;
    } else {
        literal_banks[0] = decoded(streams[1], literal_count, modes & 2 != 0, false)?;
    }
    let mut cursors = [0usize; 16];
    let lengths = decoded(streams[2], matches, modes & 4 != 0, false)?;
    let distances = decoded(streams[3], matches, modes & 8 != 0, false)?;
    if !bit_count.is_multiple_of(8) && streams[4].last().is_some_and(|b| b >> (bit_count % 8) != 0)
    {
        return Err(invalid("unused split extra bits"));
    }
    let mut extras = BitReader {
        data: streams[4],
        count: bit_count,
        position: 0,
    };
    let start = out.len();
    let end = start.checked_add(expected).ok_or(CodecError::OutputLimit)?;
    if solid && end > lz::SOLID_WINDOW {
        return Err(CodecError::OutputLimit);
    }
    out.try_reserve_exact(expected)
        .map_err(|_| CodecError::AllocationFailed)?;
    let mut literal = 0;
    let mut matched = 0;
    let mut recent = Recent::default();
    for kind in kinds {
        if out.len() >= end {
            return Err(invalid("split output overflow"));
        }
        match kind {
            0 => {
                let position = if solid { out.len() } else { out.len() - start };
                let previous = if position == 0 { 0 } else { out[out.len() - 1] };
                let index = bank(context, position, previous);
                let b = *literal_banks[index]
                    .get(cursors[index])
                    .ok_or_else(|| invalid("split literal bank count"))?;
                out.push(b);
                cursors[index] += 1;
                literal += 1;
            }
            1 => {
                let s = *lengths
                    .get(matched)
                    .ok_or_else(|| invalid("split match count"))?;
                if s > 17 {
                    return Err(invalid("split length slot"));
                }
                let length = (1usize << s) + extras.get(s)? as usize + 3;
                let ds = distances[matched];
                let repeats = if contextual { 4 } else { 1 };
                let distance = if ds < repeats {
                    let d = recent.0[ds as usize] as usize;
                    if d == 0 {
                        return Err(invalid("empty repeat distance"));
                    }
                    d
                } else {
                    if ds > 24 + repeats {
                        return Err(invalid("split distance slot"));
                    }
                    let s = ds - repeats;
                    (1usize << s) + extras.get(s)? as usize
                };
                let available = if solid { out.len() } else { out.len() - start };
                if distance == 0
                    || distance > available
                    || distance > lz::SOLID_WINDOW
                    || length > end - out.len()
                {
                    return Err(invalid("split reference bounds"));
                }
                let begin = out.len();
                let seed = distance.min(length);
                let from = begin - distance;
                out.extend_from_within(from..from + seed);
                while out.len() - begin < length {
                    let count = (out.len() - begin).min(length - (out.len() - begin));
                    out.extend_from_within(begin..begin + count);
                }
                recent.touch(distance as u32);
                matched += 1;
            }
            _ => return Err(invalid("split token kind")),
        }
    }
    exact(out.len(), end)?;
    for i in 0..bank_count {
        exact(cursors[i], literal_banks[i].len())?;
    }
    exact(literal, literal_count)?;
    exact(matched, matches)?;
    exact(extras.position, bit_count)
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct Edge {
    cost: u32,
    origin: u16,
    distance: u32,
    start: u16,
    end: u16,
}
#[derive(Clone, Copy, Default)]
struct Back {
    origin: u16,
    distance: u32,
}
fn append(tokens: &mut Vec<Token>, t: Token) -> Result<()> {
    if tokens.len() == tokens.capacity() {
        tokens
            .try_reserve(1)
            .map_err(|_| CodecError::AllocationFailed)?;
    }
    tokens.push(t);
    Ok(())
}
fn fast_parse(
    finder: &mut MatchFinder<'_>,
    range: Range<usize>,
    prices: &Prices,
) -> Result<Vec<Token>> {
    let input = finder.source();
    let mut prefix = vector(range.len() + 1, 0u32)?;
    for i in 0..range.len() {
        prefix[i + 1] = prefix[i] + prices.literal(input, range.start + i);
    }
    let choose =
        |position: usize, recent: Recent, finder: &MatchFinder<'_>| -> Result<(lz::Match, u32)> {
            let (candidates, count) =
                prices.candidates(finder, position, range.end - position, recent)?;
            let mut best = lz::Match::default();
            let mut saving = 0;
            for &m in &candidates[..count] {
                if m.length < 4 {
                    continue;
                }
                for length in (0..=17)
                    .map(|s| ((1usize << (s + 1)) - 1) + 3)
                    .chain([m.length])
                    .filter(|&n| n <= m.length)
                {
                    let literal =
                        prefix[position - range.start + length] - prefix[position - range.start];
                    let cost = prices.matched(length, m.distance, recent);
                    let gain = literal.saturating_sub(cost);
                    if gain > saving || (gain == saving && gain > 0 && length > best.length) {
                        saving = gain;
                        best = lz::Match {
                            length,
                            distance: m.distance,
                        };
                    }
                }
            }
            Ok((best, saving))
        };
    let mut tokens = Vec::new();
    let mut pos = range.start;
    let mut last = Recent::default();
    while pos < range.end {
        let (current, gain) = choose(pos, last, finder)?;
        finder.insert(pos)?;
        if current.length >= 4 {
            if pos + 1 < range.end && choose(pos + 1, last, finder)?.1 > gain {
                append(
                    &mut tokens,
                    Token {
                        length: 1,
                        distance: 0,
                    },
                )?;
                pos += 1;
                continue;
            }
            append(
                &mut tokens,
                Token {
                    length: current.length as u32,
                    distance: current.distance as u32,
                },
            )?;
            pos += current.length;
            finder.advance_to(pos)?;
            last.touch(current.distance as u32);
        } else {
            append(
                &mut tokens,
                Token {
                    length: 1,
                    distance: 0,
                },
            )?;
            pos += 1;
        }
    }
    Ok(tokens)
}
pub(super) fn parse(
    finder: &mut MatchFinder<'_>,
    range: Range<usize>,
    prices: &Prices,
    optimal: bool,
) -> Result<Vec<Token>> {
    finder.rewind_to(range.start)?;
    if !optimal {
        return fast_parse(finder, range, prices);
    }
    let input = finder.source();
    let mut tokens = Vec::new();
    let mut base = range.start;
    let mut last = Recent::default();
    let mut costs = vector(HORIZON + 1, 0u32)?;
    let mut back = vector(HORIZON + 1, Back::default())?;
    let mut recent = vector(HORIZON + 1, Recent::default())?;
    let mut pending: BinaryHeap<Reverse<(u16, Edge)>> = BinaryHeap::new();
    let mut active: BinaryHeap<Reverse<Edge>> = BinaryHeap::new();
    let max_edges = if prices.contextual {
        MAX_EDGES
    } else {
        5 * HORIZON * 11
    };
    pending
        .try_reserve(max_edges)
        .map_err(|_| CodecError::AllocationFailed)?;
    active
        .try_reserve(max_edges)
        .map_err(|_| CodecError::AllocationFailed)?;
    let mut reversed = Vec::new();
    reversed
        .try_reserve_exact(HORIZON)
        .map_err(|_| CodecError::AllocationFailed)?;
    while base < range.end {
        let (candidates, candidate_count) =
            prices.candidates(finder, base, range.end - base, last)?;
        let long = candidates[..candidate_count]
            .iter()
            .copied()
            .filter(|m| m.length >= HORIZON)
            .max_by_key(|m| {
                (
                    m.length,
                    u32::MAX - prices.matched(m.length, m.distance, last),
                )
            });
        if let Some(m) = long {
            append(
                &mut tokens,
                Token {
                    length: m.length as u32,
                    distance: m.distance as u32,
                },
            )?;
            finder.advance_to(base + m.length)?;
            base += m.length;
            last.touch(m.distance as u32);
            continue;
        }
        let count = HORIZON.min(range.end - base);
        pending.clear();
        active.clear();
        costs[0] = 0;
        recent[0] = last;
        for offset in 0..=count {
            while pending.peek().is_some_and(|p| p.0.0 as usize <= offset) {
                let Reverse((_, edge)) = pending.pop().ok_or_else(|| invalid("priced queue"))?;
                active.push(Reverse(edge));
            }
            while active.peek().is_some_and(|p| (p.0.end as usize) < offset) {
                active.pop();
            }
            if offset > 0 {
                costs[offset] = costs[offset - 1] + prices.literal(input, base + offset - 1);
                back[offset] = Back {
                    origin: (offset - 1) as u16,
                    distance: 0,
                };
                recent[offset] = recent[offset - 1];
                if let Some(Reverse(e)) = active.peek()
                    && e.cost <= costs[offset]
                {
                    costs[offset] = e.cost;
                    back[offset] = Back {
                        origin: e.origin,
                        distance: e.distance,
                    };
                    recent[offset] = recent[e.origin as usize];
                    recent[offset].touch(e.distance);
                }
            }
            if offset == count {
                break;
            }
            let (candidates, candidate_count) =
                prices.candidates(finder, base + offset, count - offset, recent[offset])?;
            finder.insert(base + offset)?;
            for &m in &candidates[..candidate_count] {
                if m.length < 4 {
                    continue;
                }
                for s in 0..=10 {
                    let low = (1usize << s) + 3;
                    let high = (((1usize << (s + 1)) - 1) + 3).min(m.length);
                    if low > high {
                        continue;
                    }
                    if pending.len() + active.len() >= max_edges {
                        return Err(CodecError::OutputLimit);
                    }
                    let cost = costs[offset] + prices.matched(low, m.distance, recent[offset]);
                    pending.push(Reverse((
                        (offset + low) as u16,
                        Edge {
                            cost,
                            origin: offset as u16,
                            distance: m.distance as u32,
                            start: (offset + low) as u16,
                            end: (offset + high) as u16,
                        },
                    )));
                }
            }
        }
        reversed.clear();
        let mut end = count;
        while end > 0 {
            let b = back[end];
            reversed.push(Token {
                length: (end - b.origin as usize) as u32,
                distance: b.distance,
            });
            end = b.origin as usize;
        }
        for t in reversed.iter().rev() {
            append(&mut tokens, *t)?;
        }
        last = recent[count];
        base += count;
    }
    Ok(tokens)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn contextual_wire_golden_has_explicit_bank_counts_and_order() {
        let tokens = [Token {
            length: 1,
            distance: 0,
        }; 3];
        let e = encode_mode(b"a1!", 0..3, &tokens, Some(3)).unwrap();
        let mut wire = b"WXS\x02\x00\x03\x00\x00".to_vec();
        for n in [3u32, 3, 0, 0, 1, 55, 0, 0, 0] {
            wire.extend_from_slice(&n.to_le_bytes());
        }
        wire.push(0); // Three literal kind bits.
        wire.extend([4, 0, 0, 0]);
        for count in [0u32, 1, 1, 1] {
            wire.extend_from_slice(&count.to_le_bytes());
            wire.extend_from_slice(&count.to_le_bytes());
            wire.extend([0; 4]);
        }
        wire.extend(b"1!a");
        assert_eq!(e.data, wire);
        let mut out = Vec::new();
        decode_context_append(&wire, 3, 3, false, &mut out).unwrap();
        assert_eq!(out, b"a1!");
    }
    #[test]
    fn every_literal_bank_mode_roundtrips_with_history_and_block_reset() {
        let mut data = vec![0x4f; 37];
        for i in 0..4000 {
            data.extend_from_slice(&[
                b'a' + (i % 26) as u8,
                b'0' + (i % 10) as u8,
                b' ',
                (i % 256) as u8,
            ]);
        }
        let tokens = vec![
            Token {
                length: 1,
                distance: 0
            };
            data.len() - 37
        ];
        for mode in 0..=4 {
            let encoded = encode_mode(&data, 37..data.len(), &tokens, Some(mode)).unwrap();
            let mut out = data[..37].to_vec();
            decode_context_append(&encoded.data, tokens.len(), tokens.len(), true, &mut out)
                .unwrap();
            assert_eq!(out, data);
            assert!(
                decode_append(
                    &encoded.data,
                    tokens.len(),
                    tokens.len(),
                    true,
                    &mut Vec::new()
                )
                .is_err()
            );
            let encoded = encode_mode(&data[37..], 0..tokens.len(), &tokens, Some(mode)).unwrap();
            let mut out = vec![0x42; BLOCK_SIZE];
            decode_context_append(&encoded.data, tokens.len(), tokens.len(), false, &mut out)
                .unwrap();
            assert_eq!(&out[BLOCK_SIZE..], &data[37..]);
        }
    }
    #[test]
    fn four_repeat_distances_move_to_front_and_validate_absent_slots() {
        let data = b"abcd".repeat(48);
        let mut tokens = vec![
            Token {
                length: 1,
                distance: 0
            };
            16
        ];
        for distance in [4, 8, 12, 16, 4, 12, 8, 16, 4, 8, 12] {
            tokens.push(Token {
                length: 16,
                distance,
            });
        }
        let mut recent = Recent::default();
        for d in [4, 8, 12, 16, 4, 12] {
            recent.touch(d);
        }
        assert_eq!(recent.0, [12, 4, 16, 8]);
        let e = encode_mode(&data, 0..data.len(), &tokens, Some(0)).unwrap();
        let distance_at = HEADER
            + (0..3)
                .map(|i| {
                    u32::from_le_bytes(e.data[24 + i * 4..28 + i * 4].try_into().unwrap()) as usize
                })
                .sum::<usize>();
        assert_eq!(
            &e.data[distance_at..distance_at + 11],
            &[6, 7, 7, 8, 3, 2, 3, 3, 3, 2, 3]
        );
        let mut out = Vec::new();
        decode_context_append(&e.data, data.len(), tokens.len(), false, &mut out).unwrap();
        assert_eq!(out, data);
        let e = encode_mode(
            b"abcdabcd",
            0..8,
            &[Token {
                length: 1,
                distance: 0,
            }; 4]
                .into_iter()
                .chain([Token {
                    length: 4,
                    distance: 4,
                }])
                .collect::<Vec<_>>(),
            Some(0),
        )
        .unwrap();
        let mut bad = e.data.clone();
        let sizes: Vec<_> = (0..5)
            .map(|i| {
                u32::from_le_bytes(e.data[24 + i * 4..28 + i * 4].try_into().unwrap()) as usize
            })
            .collect();
        let distance_at = HEADER + sizes[0] + sizes[1] + sizes[2];
        bad[distance_at] = 3;
        assert!(decode_context_append(&bad, 8, 5, false, &mut Vec::new()).is_err());
    }
    #[test]
    fn contextual_bank_lengths_codecs_padding_and_truncation_are_checked() {
        let data = b"abc def ghi jkl 0123456789".repeat(12);
        let tokens = vec![
            Token {
                length: 1,
                distance: 0
            };
            data.len()
        ];
        let e = encode_mode(&data, 0..data.len(), &tokens, Some(3)).unwrap();
        for n in 0..e.data.len() {
            assert!(
                decode_context_append(
                    &e.data[..n],
                    data.len(),
                    tokens.len(),
                    false,
                    &mut Vec::new()
                )
                .is_err()
            );
        }
        let kind_size = u32::from_le_bytes(e.data[24..28].try_into().unwrap()) as usize;
        let literal_at = HEADER + kind_size;
        for (at, value) in [
            (4, 2),
            (5, 5),
            (6, 1),
            (literal_at, 16),
            (literal_at + 1, 1),
            (literal_at + 4, 255),
            (literal_at + 12, 2),
            (literal_at + 13, 1),
        ] {
            let mut bad = e.data.clone();
            bad[at] = value;
            assert!(
                decode_context_append(&bad, data.len(), tokens.len(), false, &mut Vec::new())
                    .is_err(),
                "offset {at}"
            );
        }
        let mut extra = e.data.clone();
        extra.push(0);
        assert!(
            decode_context_append(&extra, data.len(), tokens.len(), false, &mut Vec::new())
                .is_err()
        );
    }
    #[test]
    fn contextual_priced_parse_roundtrips_and_uses_log_distance_choices() {
        let input = include_bytes!("lz.rs").repeat(3);
        for optimal in [false, true] {
            let mut finder = MatchFinder::new(&input, lz::LzOptions::default()).unwrap();
            let seed_bytes =
                lz::encode_solid_block(&mut finder, 0..input.len(), lz::ParseMode::Lazy).unwrap();
            let tokens = seed(&seed_bytes, input.len()).unwrap();
            let e = encode_context(&input, 0..input.len(), &tokens).unwrap();
            let tokens = parse(&mut finder, 0..input.len(), &e.prices, optimal).unwrap();
            let e = encode_context(&input, 0..input.len(), &tokens).unwrap();
            let mut out = Vec::new();
            decode_context_append(&e.data, input.len(), tokens.len(), false, &mut out).unwrap();
            assert_eq!(out, input);
        }
    }
    #[test]
    fn separate_streams_repeat_distance_and_history_roundtrip() {
        let input = b"abc".repeat(200);
        let tokens = [Token {
            length: 1,
            distance: 0,
        }; 3]
            .into_iter()
            .chain([
                Token {
                    length: 100,
                    distance: 3,
                },
                Token {
                    length: 497,
                    distance: 3,
                },
            ])
            .collect::<Vec<_>>();
        let e = encode(&input, 0..input.len(), &tokens).unwrap();
        let mut out = Vec::new();
        decode_append(&e.data, input.len(), tokens.len(), false, &mut out).unwrap();
        assert_eq!(out, input);
        let mut history = b"abcdefgh".repeat(4096);
        let start = history.len();
        let tail = history[..4096].to_vec();
        let mut source = history.clone();
        source.extend_from_slice(&tail);
        let e = encode(
            &source,
            start..source.len(),
            &[Token {
                length: 4096,
                distance: start as u32,
            }],
        )
        .unwrap();
        decode_append(&e.data, 4096, 1, true, &mut history).unwrap();
        assert_eq!(history, source);
        assert!(decode_append(&e.data, 4096, 1, false, &mut Vec::new()).is_err());
    }
    #[test]
    fn split_stream_limits_truncation_reserved_bits_and_repeat_are_checked() {
        let input = b"abc".repeat(200);
        let t = [Token {
            length: 1,
            distance: 0,
        }; 3]
            .into_iter()
            .chain([Token {
                length: 597,
                distance: 3,
            }])
            .collect::<Vec<_>>();
        let e = encode(&input, 0..input.len(), &t).unwrap();
        for n in 0..e.data.len() {
            assert!(
                decode_append(&e.data[..n], input.len(), t.len(), false, &mut Vec::new()).is_err()
            );
        }
        let mut trailing = e.data.clone();
        trailing.push(0);
        assert!(decode_append(&trailing, input.len(), t.len(), false, &mut Vec::new()).is_err());
        for (at, value) in [
            (4, 0x80),
            (5, 1),
            (8, 0),
            (12, 255),
            (16, 255),
            (20, 255),
            (24, 255),
        ] {
            let mut bad = e.data.clone();
            bad[at] = value;
            assert!(
                decode_append(&bad, input.len(), t.len(), false, &mut Vec::new()).is_err(),
                "offset {at}"
            );
        }
        let mut bad = e.data.clone();
        let distance_at = HEADER + 1 + 3 + 1;
        bad[distance_at] = 0;
        assert!(decode_append(&bad, input.len(), t.len(), false, &mut Vec::new()).is_err());
        let mut bits = Bits::new();
        assert!(bits.put(1, 0).is_err());
        assert!(bits.put(0, 25).is_err());
    }
    #[test]
    fn entropy_prices_are_normalized_ans_bit_prices() {
        assert_eq!(price(4096), 0);
        assert_eq!(price(2048), 256);
        assert_eq!(price(1024), 512);
        assert_eq!(price(0), 3072);
    }
    #[test]
    fn rewind_and_priced_parser_preserve_dictionary_and_bytes() {
        let input = include_bytes!("lz.rs").repeat(5);
        let data = &input[..input.len().min(BLOCK_SIZE)];
        let mut f = MatchFinder::new(data, lz::LzOptions::default()).unwrap();
        let seed_bytes =
            lz::encode_solid_block(&mut f, 0..data.len(), lz::ParseMode::Lazy).unwrap();
        f.rewind_to(0).unwrap();
        assert_eq!(
            seed_bytes,
            lz::encode_solid_block(&mut f, 0..data.len(), lz::ParseMode::Lazy).unwrap()
        );
        let initial = seed(&seed_bytes, data.len()).unwrap();
        let e = encode(data, 0..data.len(), &initial).unwrap();
        let parsed = parse(&mut f, 0..data.len(), &e.prices, true).unwrap();
        let result = encode(data, 0..data.len(), &parsed).unwrap();
        let mut out = Vec::new();
        decode_append(&result.data, data.len(), parsed.len(), false, &mut out).unwrap();
        assert_eq!(out, data);
        assert!(f.rewind_to(data.len() + 1).is_err());
    }
    #[test]
    fn malformed_split_payloads_never_panic() {
        let mut state = 0x97a1_4189_1213_abefu64;
        for n in 0..1500 {
            let mut data = vec![0; n % 180];
            for b in &mut data {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                *b = (state >> 32) as u8;
            }
            if data.len() >= 4 {
                data[..4].copy_from_slice(b"WXS\x01");
            }
            assert!(
                std::panic::catch_unwind(|| decode_append(&data, 128, 64, false, &mut Vec::new()))
                    .is_ok()
            );
            if data.len() >= 4 {
                data[..4].copy_from_slice(b"WXS\x02");
            }
            assert!(
                std::panic::catch_unwind(|| decode_context_append(
                    &data,
                    128,
                    64,
                    false,
                    &mut Vec::new()
                ))
                .is_ok()
            );
        }
    }
}
