use std::sync::Arc;
use std::thread;
use wexpack::codec::{
    BLOCK_SIZE, CodecError, CodecLimits, CompressionLevel, MAX_LZ_SIZE, WexEngine, ans, cm, lz,
};
use wexpack::filters::{ProfileHint, SmartTransform, invert_transform};
use wexpack::format::{ChunkFlags, ChunkHeader, ChunkId, CodecType};

fn random(length: usize) -> Vec<u8> {
    let mut state = 0x8b8b_8b8b_1234_5678u64;
    (0..length)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            (state >> 32) as u8
        })
        .collect()
}
fn options() -> lz::LzOptions {
    lz::LzOptions {
        hash_bits: 12,
        chain_depth: 256,
        window_size: BLOCK_SIZE,
    }
}
#[test]
fn levels_are_validated_and_mapped() {
    for level in 1..=9 {
        let l = CompressionLevel::new(level).unwrap();
        assert_eq!(l.get(), level);
        assert_eq!(
            l.codec(),
            match level {
                1..=3 => CodecType::WexTurbo,
                4..=7 => CodecType::WexBalanced,
                _ => CodecType::WexExtreme,
            }
        );
    }
    assert_eq!(CompressionLevel::new(0), Err(CodecError::InvalidLevel(0)));
    assert!(WexEngine::compress(b"test", 10).is_err());
}
#[test]
fn lz_wire_golden_literals_and_overlapping_match() {
    let tokens = [
        lz::Token::Literal(b'a'),
        lz::Token::Literal(b'b'),
        lz::Token::Literal(b'c'),
        lz::Token::Match {
            length: 9,
            distance: 3,
        },
    ];
    let wire = lz::serialize_tokens(&tokens).unwrap();
    assert_eq!(wire, [8, b'a', b'b', b'c', 5, 2]);
    assert_eq!(lz::decode(&wire, 12).unwrap(), b"abcabcabcabc");
    let wire = lz::serialize_tokens(&[
        lz::Token::Literal(42),
        lz::Token::Match {
            length: 10_000,
            distance: 1,
        },
    ])
    .unwrap();
    assert_eq!(lz::decode(&wire, 10_001).unwrap(), vec![42; 10_001]);
    assert_eq!(
        lz::encode(b"abc", lz::ParseMode::Greedy, options()).unwrap(),
        [0, b'a', b'b', b'c']
    );
    assert_eq!(lz::decode(&[], 0).unwrap(), Vec::<u8>::new());
}
#[test]
fn lz_roundtrips_greedy_lazy_and_optimal() {
    for length in [0, 1, 3, 4, 7, 8, 9, 127, 128, 129, 1023, 4097] {
        for source in [
            random(length),
            vec![7; length],
            b"abcdxyz".iter().copied().cycle().take(length).collect(),
        ] {
            for mode in [
                lz::ParseMode::Greedy,
                lz::ParseMode::Lazy,
                lz::ParseMode::Optimal { horizon: 128 },
            ] {
                let wire = lz::encode(&source, mode, options()).unwrap();
                assert!(wire.len() <= source.len() + source.len().div_ceil(8));
                assert_eq!(
                    lz::decode(&wire, source.len()).unwrap(),
                    source,
                    "{length} {mode:?}"
                );
            }
        }
    }
}
fn exhaustive_cost(source: &[u8]) -> u32 {
    let mut costs = vec![u32::MAX / 2; source.len() + 1];
    costs[0] = 0;
    for i in 0..source.len() {
        costs[i + 1] = costs[i + 1].min(costs[i] + 9);
        for distance in 1..=i {
            let mut length = 0;
            while i + length < source.len() && source[i + length] == source[i + length - distance] {
                length += 1;
            }
            for count in 4..=length {
                let cost = lz::token_cost_bits(lz::Token::Match {
                    length: count,
                    distance,
                })
                .unwrap();
                costs[i + count] = costs[i + count].min(costs[i] + cost);
            }
        }
    }
    costs[source.len()]
}
#[test]
fn optimal_parser_matches_exhaustive_dynamic_programming() {
    for seed in 0..128u32 {
        let mut source = Vec::new();
        let mut state = seed + 1;
        for _ in 0..48 {
            state = state.wrapping_mul(1664525).wrapping_add(1013904223);
            source.push(((state >> 24) % 3) as u8);
        }
        for source in [source, b"abcabcabcabcabdabcabcabcabcabc".to_vec()] {
            let tokens =
                lz::parse(&source, lz::ParseMode::Optimal { horizon: 128 }, options()).unwrap();
            let cost: u32 = tokens
                .iter()
                .map(|&t| lz::token_cost_bits(t).unwrap())
                .sum();
            assert_eq!(cost, exhaustive_cost(&source), "seed={seed}");
        }
    }
}
#[test]
fn match_finder_window_and_sequential_contract() {
    let source = b"abcdxxxxabcdyyyyabcd";
    let mut finder = lz::MatchFinder::new(
        source,
        lz::LzOptions {
            window_size: 8,
            ..options()
        },
    )
    .unwrap();
    assert!(finder.find(1, 8).is_err());
    assert!(finder.insert(1).is_err());
    for i in 0..16 {
        finder.find(i, 12).unwrap();
        finder.insert(i).unwrap();
    }
    let matches = finder.find(16, 4).unwrap();
    assert_eq!(
        matches[0],
        lz::Match {
            length: 4,
            distance: 8
        }
    );
    let mut finder = lz::MatchFinder::new(
        source,
        lz::LzOptions {
            window_size: 4,
            ..options()
        },
    )
    .unwrap();
    for i in 0..16 {
        finder.insert(i).unwrap();
    }
    assert!(finder.find(16, 4).unwrap().iter().all(|m| m.length == 0));
    assert!(
        lz::MatchFinder::new(
            b"",
            lz::LzOptions {
                hash_bits: 0,
                ..options()
            }
        )
        .is_err()
    );
    assert!(lz::encode(b"abc", lz::ParseMode::Optimal { horizon: 0 }, options()).is_err());
}
#[test]
fn lazy_matching_defers_when_next_position_has_longer_match() {
    // At final abcd..., a four-byte abcd hit precedes the longer bcd... match.
    let source = b"bcdEFGHIJK!abcdy?abcdEFGHIJK";
    let greedy = lz::parse(source, lz::ParseMode::Greedy, options()).unwrap();
    let lazy = lz::parse(source, lz::ParseMode::Lazy, options()).unwrap();
    assert_ne!(greedy, lazy);
    let cost = |tokens: &[lz::Token]| {
        tokens
            .iter()
            .map(|&t| lz::token_cost_bits(t).unwrap())
            .sum::<u32>()
    };
    assert!(cost(&lazy) < cost(&greedy));
    assert_eq!(
        lz::decode(&lz::serialize_tokens(&greedy).unwrap(), source.len()).unwrap(),
        source
    );
    assert_eq!(
        lz::decode(&lz::serialize_tokens(&lazy).unwrap(), source.len()).unwrap(),
        source
    );
}
#[test]
fn lz_rejects_unsafe_references_nonminimal_integers_and_tail_flags() {
    for (wire, expected) in [
        (vec![1, 0, 0], 4),
        (vec![2, b'a', 0, 1], 5),
        (vec![2, b'a', 255, 255, 255, 255, 15, 0], 5),
        (vec![2, b'a', 128, 0, 0], 5),
        (vec![128, b'a'], 1),
        (vec![0, b'a', 0], 1),
    ] {
        assert!(lz::decode(&wire, expected).is_err(), "accepted {wire:?}");
    }
    assert!(lz::decode(&[], BLOCK_SIZE + 1).is_err());
    assert!(
        lz::serialize_tokens(&[lz::Token::Match {
            length: 4,
            distance: 0
        }])
        .is_err()
    );
}
#[test]
fn rans_normalization_and_roundtrip_all_alphabets() {
    for length in [0, 1, 2, 255, 256, 257, 4096, 65_537] {
        for source in [
            random(length),
            vec![0; length],
            (0..256u32).map(|n| n as u8).cycle().take(length).collect(),
        ] {
            let frequencies = ans::normalized_frequencies(&source).unwrap();
            assert_eq!(frequencies.iter().map(|&f| u32::from(f)).sum::<u32>(), 4096);
            for &b in &source {
                assert_ne!(frequencies[b as usize], 0);
            }
            let wire = ans::encode(&source).unwrap();
            assert_eq!(ans::decode(&wire, source.len()).unwrap(), source);
        }
    }
}
#[test]
fn rans_rejects_bad_models_states_truncations_and_trailing_bytes() {
    let source = b"aabbabbabaacbbcabc";
    let wire = ans::encode(source).unwrap();
    for length in 0..wire.len() {
        assert!(ans::decode(&wire[..length], source.len()).is_err());
    }
    let mut bad = wire.clone();
    bad.push(0);
    assert!(ans::decode(&bad, source.len()).is_err());
    let mut bad = wire.clone();
    bad[17..19].copy_from_slice(&0u16.to_le_bytes());
    assert!(ans::decode(&bad, source.len()).is_err());
    let mut bad = wire.clone();
    bad[19] = bad[16];
    assert!(ans::decode(&bad, source.len()).is_err());
    let count = u16::from_le_bytes([wire[8], wire[9]]) as usize;
    let mut bad = wire.clone();
    bad[16 + 3 * count..20 + 3 * count].fill(0);
    assert!(ans::decode(&bad, source.len()).is_err());
    assert!(ans::decode(&wire, source.len() + 1).is_err());
}
#[test]
fn binary_range_coder_handles_extreme_probabilities_and_underflow() {
    let source = random(8192);
    for flavor in 0..4 {
        let mut encoder = cm::BinaryRangeEncoder::new().unwrap();
        let mut symbols = Vec::new();
        for (i, &byte) in source.iter().enumerate() {
            let p = match flavor {
                0 => 2048,
                1 => 1,
                2 => 4095,
                _ => (u16::from(byte) * 13 + i as u16 % 127) % 4095 + 1,
            };
            let bit = byte & 1 != 0;
            encoder.encode_bit(bit, p).unwrap();
            symbols.push((bit, p));
        }
        let stream = encoder.finish().unwrap();
        let mut decoder = cm::BinaryRangeDecoder::new(&stream.data, stream.bit_len).unwrap();
        for (bit, p) in symbols {
            assert_eq!(decoder.decode_bit(p).unwrap(), bit);
        }
        decoder.finish().unwrap();
    }
    let mut encoder = cm::BinaryRangeEncoder::new().unwrap();
    assert!(encoder.encode_bit(false, 0).is_err());
    assert!(encoder.encode_bit(false, 4096).is_err());
}
#[test]
fn context_mixer_is_adaptive_and_deterministic() {
    let mut a = cm::ContextMixer::new().unwrap();
    let mut b = cm::ContextMixer::new().unwrap();
    let original = a.weights();
    for byte in b"abcdefghabcdefghabcdefgh".repeat(40) {
        for shift in (0..8).rev() {
            assert_eq!(a.prediction(), b.prediction());
            let bit = byte & (1 << shift) != 0;
            a.update(bit).unwrap();
            b.update(bit).unwrap();
        }
    }
    assert_ne!(a.weights(), original);
    assert_eq!(a.weights(), b.weights());
}
#[test]
fn context_coder_roundtrips_and_compresses_predictable_data() {
    for length in [0, 1, 7, 128, 1025, 8192] {
        for source in [
            random(length),
            vec![0; length],
            b"function return payload\n"
                .iter()
                .copied()
                .cycle()
                .take(length)
                .collect(),
        ] {
            let wire = cm::encode(&source).unwrap();
            assert_eq!(cm::decode(&wire, source.len()).unwrap(), source);
        }
    }
    assert!(cm::encode(&vec![0; 8192]).unwrap().len() < 200);
}
#[test]
fn context_coder_rejects_corruption_truncation_and_padding() {
    let source = b"some repeated repeated repeated words";
    let wire = cm::encode(source).unwrap();
    for length in 0..wire.len() {
        assert!(cm::decode(&wire[..length], source.len()).is_err());
    }
    for byte in 0..wire.len() {
        let mut bad = wire.clone();
        bad[byte] ^= 1;
        assert!(cm::decode(&bad, source.len()).is_err(), "byte={byte}");
    }
    let mut bad = wire.clone();
    bad.push(0);
    assert!(cm::decode(&bad, source.len()).is_err());
    assert!(cm::decode(&wire, source.len() + 1).is_err());
}
#[test]
fn engine_roundtrips_every_level_and_tiny_inputs() {
    for level in 1..=9 {
        for source in [
            vec![],
            vec![0],
            b"tiny".to_vec(),
            random(4096),
            vec![42; 8192],
            b"the compression engine uses repeated context and matches\n".repeat(128),
        ] {
            let wire = WexEngine::compress(&source, level).unwrap();
            assert!(wire.data.len() <= source.len());
            assert_eq!(
                WexEngine::decompress(&wire.data, wire.codec, source.len()).unwrap(),
                source,
                "level={level}"
            );
            if source.len() > 8191 {
                assert_ne!(wire.codec, CodecType::Store);
            }
        }
    }
}
#[test]
fn engine_crosses_block_boundaries_and_resets_state() {
    for level in [1, 5, 9] {
        let mut source = vec![b'a'; BLOCK_SIZE];
        source.extend(random(1025));
        let wire = WexEngine::compress(&source, level).unwrap();
        assert_eq!(
            WexEngine::decompress(&wire.data, wire.codec, source.len()).unwrap(),
            source
        );
    }
}
#[test]
fn full_filter_codec_container_roundtrip() {
    let source = b"{\"sensorSerialNumber\":123,\"measurementQuality\":true}\n".repeat(256);
    let transformed = SmartTransform::prepare(&source, ProfileHint::Auto).unwrap();
    for level in [1, 5, 9] {
        let packed = WexEngine::compress(&transformed.data, level).unwrap();
        let header = ChunkHeader {
            chunk_id: ChunkId::new(0).unwrap(),
            uncompressed_size: source.len() as u32,
            transformed_size: transformed.data.len() as u32,
            compressed_size: packed.data.len() as u32,
            codec: packed.codec,
            transform: transformed.transform,
            flags: ChunkFlags::empty(),
            hash: *blake3::hash(&source).as_bytes(),
            crc32: crc32fast::hash(&packed.data),
        };
        let parsed = ChunkHeader::from_bytes(&header.to_bytes()).unwrap();
        parsed.verify_stored_payload(&packed.data).unwrap();
        let data =
            WexEngine::decompress(&packed.data, parsed.codec, parsed.transformed_size as usize)
                .unwrap();
        let restored = invert_transform(
            &data,
            parsed.transform,
            0,
            parsed.uncompressed_size as usize,
        )
        .unwrap();
        parsed.verify_original(&restored).unwrap();
        assert_eq!(restored, source);
    }
}
#[test]
fn engine_limits_and_buffer_reuse() {
    let source = b"abcdabcdabcdabcdabcdabcd".repeat(256);
    let mut out = Vec::with_capacity(2 * source.len() + 128);
    let pointer = out.as_ptr();
    let codec = WexEngine::compress_into(&source, 5, &mut out).unwrap();
    assert_eq!(out.as_ptr(), pointer);
    let mut decoded = Vec::with_capacity(source.len());
    let pointer = decoded.as_ptr();
    WexEngine::decompress_into(
        &out,
        codec,
        source.len(),
        CodecLimits::default(),
        &mut decoded,
    )
    .unwrap();
    assert_eq!(decoded.as_ptr(), pointer);
    assert_eq!(decoded, source);
    assert!(
        WexEngine::decompress_into(
            &out,
            codec,
            source.len(),
            CodecLimits {
                max_output_size: 1,
                ..CodecLimits::default()
            },
            &mut decoded
        )
        .is_err()
    );
    assert!(
        WexEngine::decompress_into(
            &out,
            codec,
            source.len(),
            CodecLimits {
                max_input_size: 1,
                ..CodecLimits::default()
            },
            &mut decoded
        )
        .is_err()
    );
    assert!(ans::decode(&[], MAX_LZ_SIZE + 1).is_err());
    assert!(cm::decode(&[], MAX_LZ_SIZE + 1).is_err());
}
#[test]
fn engine_rejects_modified_headers_corruption_and_trailing_bytes() {
    for level in [1, 5, 9] {
        let source = b"abcdefgabcdefghabcdefghabcdefg".repeat(128);
        let packed = WexEngine::compress(&source, level).unwrap();
        assert_ne!(packed.codec, CodecType::Store);
        for length in 0..packed.data.len() {
            assert!(
                WexEngine::decompress(&packed.data[..length], packed.codec, source.len()).is_err()
            );
        }
        for position in 0..packed.data.len() {
            let mut bad = packed.data.clone();
            bad[position] ^= 1;
            assert!(
                WexEngine::decompress(&bad, packed.codec, source.len()).is_err(),
                "level={level} offset={position}"
            );
        }
        let mut bad = packed.data.clone();
        bad.push(0);
        assert!(WexEngine::decompress(&bad, packed.codec, source.len()).is_err());
    }
}
#[test]
fn parallel_engine_workers_have_no_shared_adaptive_state() {
    let source = Arc::new(b"independent worker repeated words\n".repeat(128));
    let workers: Vec<_> = (0..4)
        .map(|_| {
            let source = source.clone();
            thread::spawn(move || WexEngine::compress(&source, 9).unwrap())
        })
        .collect();
    let wires: Vec<_> = workers.into_iter().map(|t| t.join().unwrap()).collect();
    for wire in &wires {
        assert_eq!(wire, &wires[0]);
    }
}
#[test]
fn malformed_frames_never_panic_or_allocate_from_unchecked_lengths() {
    for length in 0..512 {
        let input = random(length);
        for expected in [0, 1, 64] {
            assert!(std::panic::catch_unwind(|| ans::decode(&input, expected)).is_ok());
            assert!(std::panic::catch_unwind(|| cm::decode(&input, expected)).is_ok());
            assert!(std::panic::catch_unwind(|| lz::decode(&input, expected)).is_ok());
            assert!(
                std::panic::catch_unwind(|| WexEngine::decompress(
                    &input,
                    CodecType::WexExtreme,
                    expected
                ))
                .is_ok()
            );
        }
    }
}

#[test]
fn rans_matches_independent_wire_reference() {
    let expected: &[u8] = &[
        0x57, 0x41, 0x4e, 0x01, 0x0c, 0x00, 0x00, 0x00, 0x06, 0x00, 0x0c, 0x00, 0x05, 0x33, 0x79,
        0xcb, 0x21, 0x56, 0x01, 0x61, 0xa9, 0x06, 0x62, 0xab, 0x02, 0x63, 0x56, 0x01, 0x64, 0x56,
        0x01, 0x72, 0xaa, 0x02, 0xe1, 0x65, 0x50, 0x05, 0x18, 0x54, 0x58,
    ];
    assert_eq!(ans::encode(b"abracadabra!").unwrap(), expected);
    assert_eq!(ans::decode(expected, 12).unwrap(), b"abracadabra!");
}
#[test]
fn binary_range_golden_half_probability_bits() {
    let mut encoder = cm::BinaryRangeEncoder::new().unwrap();
    for shift in (0..8).rev() {
        encoder.encode_bit(0x5a & (1 << shift) != 0, 2048).unwrap();
    }
    let stream = encoder.finish().unwrap();
    assert_eq!(stream.bit_len, 42);
    assert_eq!(stream.data, [0x5a, 0x40, 0, 0, 0, 0]);
}
#[test]
fn optimal_parser_crosses_varint_price_boundaries() {
    let mut distant = random(129);
    distant.extend_from_within(..129);
    for source in [vec![b'a'; 260], distant] {
        let tokens =
            lz::parse(&source, lz::ParseMode::Optimal { horizon: 512 }, options()).unwrap();
        let cost = tokens
            .iter()
            .map(|&t| lz::token_cost_bits(t).unwrap())
            .sum::<u32>();
        assert_eq!(cost, exhaustive_cost(&source));
        assert_eq!(
            lz::decode(&lz::serialize_tokens(&tokens).unwrap(), source.len()).unwrap(),
            source
        );
    }
}
#[test]
fn engine_selects_real_entropy_coding_when_it_wins() {
    let source: Vec<_> = random(16_384).into_iter().map(|b| b % 5).collect();
    for level in [5, 9] {
        let encoded = WexEngine::compress(&source, level).unwrap();
        assert_eq!(encoded.codec, CompressionLevel::new(level).unwrap().codec());
        assert!(if level == 5 {
            matches!(encoded.data[24], 2 | 4)
        } else {
            matches!(encoded.data[24], 3 | 5)
        });
        assert_eq!(
            WexEngine::decompress(&encoded.data, encoded.codec, source.len()).unwrap(),
            source
        );
    }
}

#[test]
fn maximum_primitive_blocks_and_context_history_wrap() {
    let source = random(BLOCK_SIZE);
    let wire = lz::encode(&source, lz::ParseMode::Greedy, options()).unwrap();
    assert_eq!(lz::decode(&wire, source.len()).unwrap(), source);
    let source = random(MAX_LZ_SIZE);
    let wire = ans::encode(&source).unwrap();
    assert_eq!(ans::decode(&wire, source.len()).unwrap(), source);
    let source = random(65_797);
    let wire = cm::encode(&source).unwrap();
    assert_eq!(cm::decode(&wire, source.len()).unwrap(), source);
    assert!(ans::encode(&vec![0; MAX_LZ_SIZE + 1]).is_err());
    assert!(cm::encode(&vec![0; MAX_LZ_SIZE + 1]).is_err());
}
#[test]
fn hostile_declared_sizes_are_rejected_before_unbounded_allocation() {
    let source = vec![0; 8192];
    let encoded = WexEngine::compress(&source, 5).unwrap();
    for (offset, value) in [(8, u32::MAX), (12, u32::MAX)] {
        let mut bad = encoded.data.clone();
        bad[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
        let checksum = crc32fast::hash(&bad[..20]);
        bad[20..24].copy_from_slice(&checksum.to_le_bytes());
        assert!(WexEngine::decompress(&bad, encoded.codec, source.len()).is_err());
    }
    let mut bad = encoded.data.clone();
    bad[36..40].copy_from_slice(&u32::MAX.to_le_bytes());
    assert!(WexEngine::decompress(&bad, encoded.codec, source.len()).is_err());
    let mut bad = ans::encode(b"test").unwrap();
    bad[4..8].copy_from_slice(&u32::MAX.to_le_bytes());
    assert!(ans::decode(&bad, 4).is_err());
    let mut bad = cm::encode(b"test").unwrap();
    bad[8..12].copy_from_slice(&u32::MAX.to_le_bytes());
    assert!(cm::decode(&bad, 4).is_err());
    assert!(WexEngine::decompress(&[], CodecType::Store, usize::MAX).is_err());
}
