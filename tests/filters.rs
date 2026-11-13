use std::borrow::Cow;
use std::collections::HashSet;
use std::sync::Arc;
use std::thread;
use wexpack::filters::*;
use wexpack::format::{ChunkFlags, ChunkHeader, ChunkId, CodecType, MAX_CHUNK_SIZE, TransformType};

const TRANSFORMS: [TransformType; 6] = [
    TransformType::None,
    TransformType::ByteShuffle4,
    TransformType::ByteShuffle8,
    TransformType::BcjX86,
    TransformType::BcjArm64,
    TransformType::DictWord,
];
fn data(length: usize) -> Vec<u8> {
    let mut state = 0x1357_9bdf_2468_ace0u64;
    (0..length)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            (state >> 41) as u8
        })
        .collect()
}
fn dict_stream(words: &[&[u8]], body: &[u8]) -> Vec<u8> {
    let mut v = Vec::from(DICT_MAGIC);
    v.extend(DICT_REVISION.to_le_bytes());
    v.extend([words.len() as u8, 0]);
    for word in words {
        v.push(word.len() as u8);
        v.extend_from_slice(word);
    }
    v.extend_from_slice(body);
    v
}
fn elf(machine: u16, little_endian: bool) -> Vec<u8> {
    let mut bytes = vec![0; 64];
    bytes[..4].copy_from_slice(b"\x7fELF");
    bytes[4] = 2;
    bytes[5] = if little_endian { 1 } else { 2 };
    bytes[6] = 1;
    bytes[18..20].copy_from_slice(&if little_endian {
        machine.to_le_bytes()
    } else {
        machine.to_be_bytes()
    });
    bytes
}
fn pe(machine: u16) -> Vec<u8> {
    let mut bytes = vec![0; 512];
    bytes[..2].copy_from_slice(b"MZ");
    bytes[0x3c..0x40].copy_from_slice(&128u32.to_le_bytes());
    bytes[128..132].copy_from_slice(b"PE\0\0");
    bytes[132..134].copy_from_slice(&machine.to_le_bytes());
    bytes
}
#[test]
fn entropy_exact_distributions() {
    assert_eq!(DataProfiler::calculate_entropy(&[]), 0.0);
    assert_eq!(DataProfiler::calculate_entropy(&[4; 1024]), 0.0);
    assert!((DataProfiler::calculate_entropy(&[0, 1, 0, 1]) - 1.0).abs() < 1e-12);
    let uniform: Vec<_> = (0..4096).map(|i| i as u8).collect();
    assert!((DataProfiler::calculate_entropy(&uniform) - 8.0).abs() < 1e-12);
}
#[test]
fn entropy_fast_path_and_bounded_sampling() {
    let mut uniform: Vec<_> = (0..4096).map(|i| i as u8).collect();
    let result = DataProfiler::profile(&uniform);
    assert!(result.bypass_compression);
    assert_eq!(result.kind, DataKind::HighEntropy);
    assert_eq!(result.recommended_transform, TransformType::None);
    uniform.extend_from_slice(&[0; 20_000]);
    assert_eq!(DataProfiler::profile(&uniform), result);
    assert_eq!(result.sample_size, 4096);
    let prepared = SmartTransform::prepare(&uniform, ProfileHint::Auto).unwrap();
    assert!(matches!(prepared.data, Cow::Borrowed(_)));
    assert!(prepared.bypass_compression);
    assert_eq!(prepared.data.as_ptr(), uniform.as_ptr());
}
#[test]
fn known_containers_override_entropy_without_inventing_an_architecture() {
    let signatures: &[&[u8]] = &[
        b"PK\x03\x04",
        b"\x1f\x8b",
        b"7z\xbc\xaf\x27\x1c",
        b"Rar!\x1a\x07",
        b"\x28\xb5\x2f\xfd",
        b"\xfd7zXZ\0",
        b"WXP\x02",
        b"\x89PNG\r\n\x1a\n",
        b"%PDF-",
        b"fLaC",
    ];
    for magic in signatures {
        let mut bytes: Vec<_> = (0..4096).map(|i| i as u8).collect();
        bytes[..magic.len()].copy_from_slice(magic);
        let result = DataProfiler::profile(&bytes);
        assert_eq!(result.kind, DataKind::Container, "signature {magic:?}");
        assert!(!result.bypass_compression);
        assert_eq!(result.recommended_transform, TransformType::None);
    }
    let mut tar = vec![0; 512];
    tar[257..262].copy_from_slice(b"ustar");
    assert_eq!(DataProfiler::profile(&tar).kind, DataKind::Container);
}
#[test]
fn executable_architectures_are_read_from_headers() {
    for (bytes, expected) in [
        (elf(3, true), TransformType::BcjX86),
        (elf(62, true), TransformType::BcjX86),
        (elf(183, true), TransformType::BcjArm64),
        (elf(183, false), TransformType::None),
        (elf(40, true), TransformType::None),
        (pe(0x014c), TransformType::BcjX86),
        (pe(0x8664), TransformType::BcjX86),
        (pe(0xaa64), TransformType::BcjArm64),
        (pe(0xa641), TransformType::None),
    ] {
        assert_eq!(
            DataProfiler::profile(&bytes).recommended_transform,
            expected
        );
    }
    for (cpu, transform) in [
        (7u32, TransformType::BcjX86),
        (0x0100_0007, TransformType::BcjX86),
        (0x0100_000c, TransformType::BcjArm64),
    ] {
        let mut bytes = vec![0; 32];
        bytes[..4].copy_from_slice(&0xfeed_facfu32.to_le_bytes());
        bytes[4..8].copy_from_slice(&cpu.to_le_bytes());
        assert_eq!(
            DataProfiler::profile(&bytes).recommended_transform,
            transform
        );
    }
    let mut arm = elf(183, true);
    arm.extend_from_slice(&[0xe8; 1024]);
    assert_eq!(
        DataProfiler::profile(&arm).recommended_transform,
        TransformType::BcjArm64
    );
    let mut broken = pe(0x8664);
    broken[0x3c..0x40].copy_from_slice(&u32::MAX.to_le_bytes());
    assert_eq!(
        DataProfiler::profile(&broken).recommended_transform,
        TransformType::None
    );
    assert_eq!(
        DataProfiler::profile(b"\x7fELF").recommended_transform,
        TransformType::None
    );
    assert_eq!(
        DataProfiler::profile(b"MZ").recommended_transform,
        TransformType::None
    );
}
#[test]
fn text_and_unicode_are_not_mistaken_for_numeric_data() {
    let text = "{\"sensorSerialNumber\": 123, \"status\": true, \"описание\": \"Температура\"}\n"
        .repeat(128);
    let profile = DataProfiler::profile(text.as_bytes());
    assert_eq!(profile.kind, DataKind::Text);
    assert_eq!(profile.recommended_transform, TransformType::DictWord);
    let mut boundary = vec![b'a'; 4095];
    boundary.extend_from_slice("Ж".as_bytes());
    assert_eq!(DataProfiler::profile(&boundary).kind, DataKind::Text);
    let mut invalid = vec![b'a'; 4096];
    invalid[64] = 0xff;
    assert_ne!(DataProfiler::profile(&invalid).kind, DataKind::Text);
}
#[test]
fn numeric_lane_selection_requires_evidence() {
    let f32s: Vec<_> = (0..1024)
        .flat_map(|i| (100.0f32 + i as f32 * 0.125).to_le_bytes())
        .collect();
    let f64s: Vec<_> = (0..512)
        .flat_map(|i| (0.125f64 * i as f64 + 100.0).to_le_bytes())
        .collect();
    assert_eq!(
        DataProfiler::profile(&f32s).recommended_transform,
        TransformType::ByteShuffle4
    );
    assert_eq!(
        DataProfiler::profile(&f64s).recommended_transform,
        TransformType::ByteShuffle8
    );
    let constant = vec![0; 4096];
    assert_eq!(
        DataProfiler::profile(&constant).recommended_transform,
        TransformType::None
    );
    let random = data(4096);
    assert!(!matches!(
        DataProfiler::profile(&random).recommended_transform,
        TransformType::ByteShuffle4 | TransformType::ByteShuffle8
    ));
    let profile = DataProfiler::profile_with_hint(&random, ProfileHint::Numeric8);
    assert_eq!(profile.recommended_transform, TransformType::ByteShuffle8);
    assert!(!profile.bypass_compression);
}
#[test]
fn byte_shuffle_golden_vectors_and_partial_words() {
    assert_eq!(
        ByteShuffle::shuffle_4(&[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10]).unwrap(),
        [0, 4, 1, 5, 2, 6, 3, 7, 8, 9, 10]
    );
    assert_eq!(
        ByteShuffle::shuffle_8(&(0..19).collect::<Vec<_>>()).unwrap(),
        [
            0, 8, 1, 9, 2, 10, 3, 11, 4, 12, 5, 13, 6, 14, 7, 15, 16, 17, 18
        ]
    );
    let mut out = vec![];
    assert_eq!(
        ByteShuffle::shuffle_into(b"test", 2, &mut out),
        Err(FilterError::InvalidWordSize)
    );
    assert_eq!(
        ByteShuffle::unshuffle_into(b"test", 0, &mut out),
        Err(FilterError::InvalidWordSize)
    );
}
#[test]
fn shuffle_matches_independent_scalar_mapping() {
    for length in 0..2057 {
        let source = data(length);
        for width in [4, 8] {
            let words = length / width;
            let mut expected = source.clone();
            for i in 0..words * width {
                expected[i] = source[(i % words) * width + i / words];
            }
            let mut out = Vec::new();
            ByteShuffle::shuffle_into(&source, width, &mut out).unwrap();
            assert_eq!(out, expected);
            ByteShuffle::unshuffle_into(&expected, width, &mut out).unwrap();
            assert_eq!(out, source);
        }
    }
}
#[test]
fn x86_exact_vector_signed_offsets_and_wraparound() {
    let source = [
        0x90, 0xe8, 0xff, 0xff, 0xff, 0xff, 0xe9, 0xe8, 0xe9, 0, 0, 0xe8,
    ];
    let mut expected = source;
    expected[2..6].copy_from_slice(&0x1005u32.to_le_bytes());
    expected[7..11].copy_from_slice(&0xf9f3u32.to_le_bytes());
    assert_eq!(BcjFilter::encode_x86(&source, 0x1000).unwrap(), expected);
    for ip in [0, 1, 0x7fff_ffff, 0xffff_fffc, u32::MAX] {
        let converted = BcjFilter::encode_x86(&source, ip).unwrap();
        assert_eq!(BcjFilter::decode_x86(&converted, ip).unwrap(), source);
    }
    assert_eq!(
        BcjFilter::encode_x86(&[0xe8, 0, 0, 0, 0], u32::MAX).unwrap(),
        [0xe8, 4, 0, 0, 0]
    );
    for n in 0..5 {
        assert_eq!(
            BcjFilter::encode_x86(&source[..n], 123).unwrap(),
            source[..n]
        );
    }
}
#[test]
fn arm64_exact_vector_opcode_preservation_and_wraparound() {
    let words = [0x9400_0001u32, 0x17ff_ffff, 0xd503_201f, 0x97ff_ffff];
    let mut source: Vec<_> = words.iter().flat_map(|w| w.to_le_bytes()).collect();
    source.extend([0x94, 0x14, 0xff]);
    let converted = BcjFilter::encode_arm64(&source, 0x1000).unwrap();
    let expected: Vec<_> = [0x9400_0401u32, 0x1400_0400, 0xd503_201f, 0x9400_0402]
        .iter()
        .flat_map(|w| w.to_le_bytes())
        .chain([0x94, 0x14, 0xff])
        .collect();
    assert_eq!(converted, expected);
    for ip in [0, 4, 0x7fff_fffc, 0xffff_fffc] {
        let encoded = BcjFilter::encode_arm64(&source, ip).unwrap();
        assert_eq!(BcjFilter::decode_arm64(&encoded, ip).unwrap(), source);
    }
    assert_eq!(
        BcjFilter::encode_arm64(&source, 1),
        Err(FilterError::UnalignedArmIp)
    );
    assert_eq!(
        BcjFilter::decode_arm64(&source, 3),
        Err(FilterError::UnalignedArmIp)
    );
}
#[test]
fn all_filters_roundtrip_arbitrary_binary_lengths() {
    for length in (0..260).chain([511, 512, 513, 4095, 4096, 4097, 65_539]) {
        for source in [data(length), vec![0xe8; length], vec![0x02; length]] {
            for transform in TRANSFORMS {
                let encoded = apply_transform(&source, transform, 0).unwrap();
                let decoded = invert_transform(&encoded, transform, 0, source.len()).unwrap();
                assert_eq!(decoded, source, "length={length} transform={transform:?}");
            }
        }
    }
}
#[test]
fn dictionary_static_codes_are_frozen_and_single_byte() {
    assert_eq!(STATIC_DICT.len(), 128);
    // Pinned from an independent length-prefixed Python/zlib serialization.
    let vocabulary: Vec<_> = STATIC_DICT
        .iter()
        .flat_map(|word| std::iter::once(word.len() as u8).chain(word.iter().copied()))
        .collect();
    assert_eq!(crc32fast::hash(&vocabulary), 0x768f921b);
    let mut seen = HashSet::new();
    for (id, word) in STATIC_DICT.iter().enumerate() {
        assert!(word.is_ascii());
        assert!(!word.is_empty());
        assert!(seen.insert(*word));
        let encoded = DictTransform::encode(word).unwrap();
        assert_eq!(&encoded[..8], &[b'W', b'X', b'D', 1, 1, 0, 0, 0]);
        assert_eq!(&encoded[8..], &[0x80 + id as u8], "token={word:?}");
        assert_eq!(DictTransform::decode(&encoded, word.len()).unwrap(), *word);
    }
}
#[test]
fn dictionary_literal_escaping_is_unambiguous() {
    let literal: Vec<_> = (0..=255).collect();
    let encoded = DictTransform::encode(&literal).unwrap();
    assert_eq!(
        DictTransform::decode(&encoded, literal.len()).unwrap(),
        literal
    );
    let encoded = DictTransform::encode(&[0x02, 0x80, 0xff]).unwrap();
    assert_eq!(&encoded[8..], &[0x02, 0, 0x02, 0x80, 0x02, 0xff]);
    assert_eq!(
        DictTransform::decode(&encoded, 3).unwrap(),
        [0x02, 0x80, 0xff]
    );
}
#[test]
fn dictionary_uses_longest_match_and_identifier_boundaries() {
    assert_eq!(
        &DictTransform::encode(b"nullptr").unwrap()[8..],
        &[0x80 + 30]
    );
    assert_eq!(
        &DictTransform::encode(b"pub(crate)").unwrap()[8..],
        &[0x80 + 61]
    );
    for text in [
        b"returning_functionality".as_slice(),
        b"nullable",
        b"myclass",
        b"trueish",
    ] {
        let encoded = DictTransform::encode(text).unwrap();
        assert_eq!(&encoded[8..], text);
    }
}
#[test]
fn dictionary_learns_frequent_keys_and_counts_its_header_cost() {
    let source = b"{\"sensorSerialNumber\":123,\"measurementQuality\":true}\n".repeat(128);
    let encoded = DictTransform::encode(&source).unwrap();
    assert!(encoded[6] >= 2);
    assert!(encoded.len() < source.len() / 2);
    assert_eq!(
        DictTransform::decode(&encoded, source.len()).unwrap(),
        source
    );
    let once = DictTransform::encode(b"sensorSerialNumber").unwrap();
    assert_eq!(once[6], 0);
    let prepared = SmartTransform::prepare(&source, ProfileHint::Auto).unwrap();
    assert_eq!(prepared.transform, TransformType::DictWord);
    assert!(matches!(prepared.data, Cow::Owned(_)));
    assert_eq!(
        invert_transform(&prepared.data, prepared.transform, 0, source.len()).unwrap(),
        source
    );
}
#[test]
fn dictionary_training_is_deterministic() {
    let source = Arc::new(b"alphaLongKey betaLongKey gammaLongKey return true\n".repeat(256));
    let threads: Vec<_> = (0..8)
        .map(|_| {
            let source = source.clone();
            thread::spawn(move || DictTransform::encode(&source).unwrap())
        })
        .collect();
    let streams: Vec<_> = threads.into_iter().map(|t| t.join().unwrap()).collect();
    for stream in &streams {
        assert_eq!(stream, &streams[0]);
    }
}
#[test]
fn dictionary_rejects_malformed_headers_and_tokens() {
    for source in [
        vec![],
        b"WXD".to_vec(),
        b"WXD\x02\x01\0\0\0".to_vec(),
        dict_stream(&[], &[0x02]),
        dict_stream(&[], &[0x02, 1]),
        dict_stream(&[b"xy"], &[0x02, 1]),
        dict_stream(&[b"abc", b"abc"], &[0x02, 1]),
        dict_stream(&[b"return"], &[0x02, 1]),
        dict_stream(&[b"1abc"], &[0x02, 1]),
        dict_stream(&[b"ab-c"], &[0x02, 1]),
    ] {
        assert!(
            DictTransform::decode(&source, 3).is_err(),
            "accepted {source:?}"
        );
    }
    let mut source = dict_stream(&[], &[]);
    source[6] = 128;
    assert!(DictTransform::decode(&source, 0).is_err());
    let mut source = dict_stream(&[], &[]);
    source[7] = 1;
    assert!(DictTransform::decode(&source, 0).is_err());
    let mut source = dict_stream(&[], &[]);
    source[4] = 2;
    assert!(DictTransform::decode(&source, 0).is_err());
    let source = dict_stream(&[b"someLongKey"], &[0x02, 1]);
    for length in 0..source.len() {
        assert!(DictTransform::decode(&source[..length], 11).is_err());
    }
}
#[test]
fn dictionary_length_checks_precede_output_allocation() {
    let source = dict_stream(&[], &[0x80; 1024]);
    let mut out = vec![42, 43, 44];
    let capacity = out.capacity();
    assert!(matches!(
        DictTransform::decode_into(&source, 1, &mut out),
        Err(FilterError::LengthMismatch { .. })
    ));
    assert_eq!(out, [42, 43, 44]);
    assert_eq!(out.capacity(), capacity);
    assert!(matches!(
        DictTransform::decode(&source, MAX_CHUNK_SIZE as usize + 1),
        Err(FilterError::OutputTooLarge)
    ));
    let valid = DictTransform::encode(b"function").unwrap();
    assert!(DictTransform::decode(&valid, 7).is_err());
    assert!(DictTransform::decode(&valid, 9).is_err());
}
#[test]
fn dictionary_dynamic_code_limit_and_candidate_limit() {
    let source = (0..5000)
        .map(|n| format!("customLongIdentifier{n} "))
        .collect::<String>()
        .repeat(3);
    let encoded = DictTransform::encode(source.as_bytes()).unwrap();
    assert_eq!(encoded[6] as usize, MAX_DYNAMIC_WORDS);
    assert_eq!(
        DictTransform::decode(&encoded, source.len()).unwrap(),
        source.as_bytes()
    );
    let words: Vec<Vec<u8>> = (0..127)
        .map(|n| format!("customWord{n}").into_bytes())
        .collect();
    let refs: Vec<&[u8]> = words.iter().map(Vec::as_slice).collect();
    let source = dict_stream(&refs, &[0x02, 127]);
    assert_eq!(
        DictTransform::decode(&source, words[126].len()).unwrap(),
        words[126]
    );
}
#[test]
fn identity_and_unprofitable_dictionary_keep_borrowed_data() {
    for source in [b"".as_slice(), b"short", b"return"] {
        let prepared = SmartTransform::prepare(source, ProfileHint::Auto).unwrap();
        assert_eq!(prepared.transform, TransformType::None);
        assert!(matches!(prepared.data, Cow::Borrowed(_)));
        assert_eq!(prepared.data.as_ref(), source);
    }
}
#[test]
fn reusable_buffers_do_not_grow_when_capacity_suffices() {
    let source = b"function return true sensorSerialNumber ".repeat(256);
    let mut encoded = Vec::with_capacity(source.len() * 2 + 8192);
    let pointer = encoded.as_ptr();
    let mut decoded = Vec::with_capacity(source.len());
    let decoded_pointer = decoded.as_ptr();
    for transform in TRANSFORMS {
        apply_transform_into(&source, transform, 0, &mut encoded).unwrap();
        assert_eq!(encoded.as_ptr(), pointer);
        invert_transform_into(&encoded, transform, 0, source.len(), &mut decoded).unwrap();
        assert_eq!(decoded.as_ptr(), decoded_pointer);
        assert_eq!(decoded, source);
    }
    assert!(matches!(
        invert_transform(b"bad", TransformType::None, 0, 4),
        Err(FilterError::LengthMismatch { .. })
    ));
}
#[test]
fn filters_integrate_with_v2_chunk_metadata() {
    let invalid_header = ChunkHeader {
        chunk_id: ChunkId::new(0).unwrap(),
        uncompressed_size: 1,
        transformed_size: 8,
        compressed_size: 8,
        codec: CodecType::Store,
        transform: TransformType::DictWord,
        flags: ChunkFlags::empty(),
        hash: [0; 32],
        crc32: 0,
    };
    assert!(invalid_header.validate().is_err());
    let source = b"function return true sensorSerialNumber \n".repeat(64);
    for transform in TRANSFORMS {
        let encoded = apply_transform(&source, transform, 0).unwrap();
        let header = ChunkHeader {
            chunk_id: ChunkId::new(0).unwrap(),
            uncompressed_size: source.len() as u32,
            transformed_size: encoded.len() as u32,
            compressed_size: encoded.len() as u32,
            codec: CodecType::Store,
            transform,
            flags: ChunkFlags::empty(),
            hash: *blake3::hash(&source).as_bytes(),
            crc32: crc32fast::hash(&encoded),
        };
        let header = ChunkHeader::from_bytes(&header.to_bytes()).unwrap();
        header.verify_stored_payload(&encoded).unwrap();
        let decoded =
            invert_transform(&encoded, transform, 0, header.uncompressed_size as usize).unwrap();
        header.verify_original(&decoded).unwrap();
        assert_eq!(decoded, source);
    }
}
#[test]
fn classifier_and_decoder_do_not_panic_on_hostile_inputs() {
    for length in 0..2048 {
        let random = data(length);
        let _ = DataProfiler::profile(&random);
        for expected in [0, 1, 32, 4096] {
            assert!(std::panic::catch_unwind(|| DictTransform::decode(&random, expected)).is_ok());
        }
        let stream = dict_stream(&[], &random);
        assert!(std::panic::catch_unwind(|| DictTransform::decode(&stream, 64)).is_ok());
    }
}
