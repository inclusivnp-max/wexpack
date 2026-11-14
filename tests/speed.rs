use wexpack::codec::{WexEngine, lz};

fn random(n: usize) -> Vec<u8> {
    let mut state = 0x1249_9356_affe_4173u64;
    (0..n)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            (state >> 32) as u8
        })
        .collect()
}
#[test]
fn bounded_solid_is_byte_identical_or_provably_over_budget() {
    for input in [
        vec![],
        vec![0xff],
        random(45),
        random(8192),
        b"shared content with a repeating dictionary;\n".repeat(200),
    ] {
        for level in [1, 5, 9] {
            let mut full = Vec::new();
            let codec = WexEngine::compress_solid_into(&input, level, &mut full).unwrap();
            for budget in [
                0,
                full.len().saturating_sub(1),
                full.len(),
                full.len() + 1,
                input.len(),
                usize::MAX,
            ] {
                let mut out = vec![99; 123];
                let result =
                    WexEngine::compress_solid_bounded_into(&input, level, &mut out, budget)
                        .unwrap();
                if full.len() <= budget {
                    assert_eq!(result, Some(codec));
                    assert_eq!(out, full);
                } else {
                    assert_eq!(result, None);
                    assert!(out.is_empty());
                }
            }
        }
    }
    let mut input = random(400_001);
    input.extend_from_slice(&b"repeat long structured block\n".repeat(16_000));
    let mut full = Vec::new();
    let codec = WexEngine::compress_solid_into(&input, 5, &mut full).unwrap();
    for budget in [100, full.len() - 1, full.len()] {
        let mut out = Vec::new();
        let result = WexEngine::compress_solid_bounded_into(&input, 5, &mut out, budget).unwrap();
        assert_eq!(
            result,
            if budget < full.len() {
                None
            } else {
                Some(codec)
            }
        );
        if result.is_some() {
            assert_eq!(out, full)
        } else {
            assert!(out.is_empty())
        }
    }
}
#[test]
fn tagged_collision_chains_match_the_untagged_reference() {
    let mut input = random(6007);
    for pos in (71..input.len() - 70).step_by(113) {
        for j in 0..70 {
            input[pos + j] = input[pos - 71 + j];
        }
    }
    for depth in [1, 16] {
        let options = lz::LzOptions {
            hash_bits: 8,
            chain_depth: depth,
            window_size: 4096,
        };
        let mut finder = lz::MatchFinder::new(&input, options).unwrap();
        let mut heads = vec![usize::MAX; 256];
        let mut prev = vec![usize::MAX; input.len()];
        for position in 0..input.len() {
            let limit = 64.min(input.len() - position);
            let mut expected = [lz::Match::default(); 4];
            let hash = if limit >= 4 {
                let b = &input[position..position + 4];
                Some(
                    (u32::from_le_bytes([b[0], b[1], b[2], b[3]]).wrapping_mul(0x9e37_79b1) >> 24)
                        as usize,
                )
            } else {
                None
            };
            if let Some(hash) = hash {
                let mut candidate = heads[hash];
                let mut examined = 0;
                while candidate != usize::MAX && examined < depth {
                    let distance = position - candidate;
                    if distance > options.window_size {
                        break;
                    }
                    let class = lz::varint_size((distance - 1) as u32) - 1;
                    let length = input[position..position + limit]
                        .iter()
                        .zip(&input[candidate..candidate + limit])
                        .take_while(|(a, b)| a == b)
                        .count();
                    if length >= 4 && length > expected[class].length {
                        expected[class] = lz::Match { length, distance };
                    }
                    if length == limit || depth == 1 {
                        break;
                    }
                    candidate = prev[candidate];
                    examined += 1;
                }
                prev[position] = heads[hash];
                heads[hash] = position;
            }
            assert_eq!(
                finder.find(position, 64).unwrap(),
                expected,
                "position {position} depth {depth}"
            );
            finder.insert(position).unwrap();
        }
    }
}
#[test]
fn tagged_ff_positions_reach_the_solid_boundary_without_none_collision() {
    let input = vec![0xff; lz::SOLID_WINDOW];
    let mut finder = lz::MatchFinder::new(
        &input,
        lz::LzOptions {
            hash_bits: 8,
            chain_depth: 1,
            window_size: lz::SOLID_WINDOW,
        },
    )
    .unwrap();
    for position in 0..input.len() - 4 {
        finder.insert(position).unwrap();
    }
    let matches = finder.find(input.len() - 4, 4).unwrap();
    assert_eq!(
        matches[0],
        lz::Match {
            length: 4,
            distance: 1
        }
    );
    for position in input.len() - 4..input.len() {
        finder.insert(position).unwrap();
    }
    assert_eq!(
        finder.find(input.len(), 64).unwrap(),
        [lz::Match::default(); 4]
    );
}
