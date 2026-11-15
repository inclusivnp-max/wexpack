//! Static byte rANS. Frequencies sum to 4096; state renormalizes in radix 256.
use super::{CodecError, MAX_LZ_SIZE, Reader, Result, bytes, crc, exact, invalid};
pub const SCALE_BITS: u32 = 12;
pub const TOTAL: u32 = 1 << SCALE_BITS;
pub const RANS_L: u32 = 1 << 23;
const MAX_FRAME: usize = 2 * MAX_LZ_SIZE + 1024;

pub fn normalized_frequencies(input: &[u8]) -> Result<[u16; 256]> {
    if input.len() > MAX_LZ_SIZE {
        return Err(CodecError::InputLimit);
    }
    let mut counts = [0u32; 256];
    for &b in input {
        counts[b as usize] += 1;
    }
    let used = counts.iter().filter(|&&c| c != 0).count() as u32;
    let mut frequencies = [0u16; 256];
    if used == 0 {
        frequencies[0] = TOTAL as u16;
        return Ok(frequencies);
    }
    let budget = TOTAL - used;
    let length = input.len() as u64;
    let mut sum = 0;
    let mut ranked = Vec::new();
    ranked
        .try_reserve_exact(used as usize)
        .map_err(|_| CodecError::AllocationFailed)?;
    for (symbol, &count) in counts.iter().enumerate() {
        if count == 0 {
            continue;
        }
        let product = u64::from(count) * u64::from(budget);
        let frequency = 1 + (product / length) as u32;
        frequencies[symbol] = frequency as u16;
        sum += frequency;
        ranked.push((product % length, symbol));
    }
    ranked.sort_unstable_by(|a, b| b.0.cmp(&a.0).then(a.1.cmp(&b.1)));
    for &(_, symbol) in ranked.iter().take((TOTAL - sum) as usize) {
        frequencies[symbol] += 1;
    }
    Ok(frequencies)
}
pub fn encode(input: &[u8]) -> Result<Vec<u8>> {
    encode_model(input).map(|(data, _)| data)
}
/// Return the exact normalized model used on the wire, so pricing does not
/// scan and normalize the same bytes a second time.
pub(super) fn encode_model(input: &[u8]) -> Result<(Vec<u8>, [u16; 256])> {
    let frequencies = normalized_frequencies(input)?;
    let mut cumulative = [0u32; 256];
    let mut total = 0;
    for i in 0..256 {
        cumulative[i] = total;
        total += u32::from(frequencies[i]);
    }
    let mut emitted = bytes(2 * input.len() + 8)?;
    let mut state = RANS_L;
    for &symbol in input.iter().rev() {
        let frequency = u32::from(frequencies[symbol as usize]);
        let threshold = ((RANS_L >> SCALE_BITS) << 8) * frequency;
        while state >= threshold {
            emitted.push(state as u8);
            state >>= 8;
        }
        state =
            ((state / frequency) << SCALE_BITS) + state % frequency + cumulative[symbol as usize];
    }
    let symbols = frequencies.iter().filter(|&&f| f != 0).count();
    let mut out = bytes(20 + 3 * symbols + emitted.len())?;
    out.extend_from_slice(b"WAN\x01");
    out.extend_from_slice(&(input.len() as u32).to_le_bytes());
    out.extend_from_slice(&(symbols as u16).to_le_bytes());
    out.extend([SCALE_BITS as u8, 0]);
    out.extend_from_slice(&crc32fast::hash(input).to_le_bytes());
    for (symbol, &frequency) in frequencies.iter().enumerate() {
        if frequency != 0 {
            out.push(symbol as u8);
            out.extend_from_slice(&frequency.to_le_bytes());
        }
    }
    out.extend_from_slice(&state.to_le_bytes());
    out.extend(emitted.into_iter().rev());
    Ok((out, frequencies))
}
pub fn decode(input: &[u8], expected_size: usize) -> Result<Vec<u8>> {
    if input.len() > MAX_FRAME {
        return Err(CodecError::InputLimit);
    }
    if expected_size > MAX_LZ_SIZE {
        return Err(CodecError::OutputLimit);
    }
    let mut r = Reader::new(input);
    if r.take(4)? != b"WAN\x01" {
        return Err(invalid("rANS magic"));
    }
    exact(r.u32()? as usize, expected_size)?;
    let count = r.u16()? as usize;
    if !(1..=256).contains(&count) || r.u8()? != SCALE_BITS as u8 || r.u8()? != 0 {
        return Err(invalid("rANS alphabet or flags"));
    }
    let checksum = r.u32()?;
    let mut frequencies = [0u32; 256];
    let mut cumulative = [0u32; 256];
    let mut lookup = [0u8; TOTAL as usize];
    let mut total = 0usize;
    let mut previous = None;
    for _ in 0..count {
        let symbol = r.u8()?;
        let frequency = r.u16()? as usize;
        if previous.is_some_and(|p| symbol <= p)
            || frequency == 0
            || frequency > TOTAL as usize - total
        {
            return Err(invalid("rANS frequency table"));
        }
        previous = Some(symbol);
        frequencies[symbol as usize] = frequency as u32;
        cumulative[symbol as usize] = total as u32;
        lookup[total..total + frequency].fill(symbol);
        total += frequency;
    }
    if total != TOTAL as usize {
        return Err(invalid("rANS frequency sum"));
    }
    let mut state = r.u32()?;
    if !(RANS_L..RANS_L * 256).contains(&state) {
        return Err(invalid("rANS initial state"));
    }
    let mut out = bytes(expected_size)?;
    for _ in 0..expected_size {
        let slot = state & (TOTAL - 1);
        let symbol = lookup[slot as usize];
        out.push(symbol);
        state = frequencies[symbol as usize] * (state >> SCALE_BITS) + slot
            - cumulative[symbol as usize];
        while state < RANS_L {
            state = (state << 8) | u32::from(r.u8()?);
        }
    }
    if state != RANS_L {
        return Err(invalid("rANS final state"));
    }
    r.finish()?;
    crc(&out, checksum)?;
    Ok(out)
}
