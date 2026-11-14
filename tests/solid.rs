use std::fs;
use wexpack::codec::{BLOCK_SIZE, CodecError, CodecLimits, WexEngine, lz};
use wexpack::format::{DecodeLimits, HeaderFlags, IndexFooter, MAX_SOLID_GROUP_SIZE};
use wexpack::pipeline::{self, ArchiveReader, PackOptions, ReadLimits};

fn random(n: usize) -> Vec<u8> {
    let mut state = 0x9187_7631_9a45_fed1u64;
    (0..n)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            (state >> 32) as u8
        })
        .collect()
}
fn options(solid: bool) -> PackOptions {
    PackOptions {
        solid,
        threads: 1,
        queue_depth: 1,
        memory_limit: 256 << 20,
        ..PackOptions::default()
    }
}
#[test]
fn solid_lz_reuses_stored_blocks_and_four_byte_distances() {
    let base = random((2 << 20) + 173);
    let mut input = base.clone();
    input.extend_from_slice(&base);
    let mut packed = Vec::new();
    let codec = WexEngine::compress_solid_into(&input, 5, &mut packed).unwrap();
    assert_eq!(&packed[..4], b"WXE\x02");
    assert!(packed.len() < input.len() * 3 / 5, "{}", packed.len());
    assert_eq!(
        WexEngine::decompress(&packed, codec, input.len()).unwrap(),
        input
    );
    // The legacy LZ entry point must not import an earlier frame's dictionary.
    assert!(lz::decode(&[1, 0, 0], 4).is_err());
    assert_eq!(
        WexEngine::compress_solid_into(&vec![0; MAX_SOLID_GROUP_SIZE + 1], 5, &mut Vec::new()),
        Err(CodecError::InputLimit)
    );
}
#[test]
fn solid_frame_roundtrips_all_levels_and_partial_blocks() {
    let input = b"class Widget { fun render(value: Int) = value + 17 }\n".repeat(6500);
    for level in 1..=9 {
        let mut packed = Vec::new();
        let codec = WexEngine::compress_solid_into(&input, level, &mut packed).unwrap();
        assert_eq!(
            WexEngine::decompress(&packed, codec, input.len()).unwrap(),
            input
        );
        let mut out = Vec::new();
        assert!(
            WexEngine::decompress_into(
                &packed,
                codec,
                input.len(),
                CodecLimits {
                    max_output_size: input.len() - 1,
                    max_input_size: packed.len()
                },
                &mut out
            )
            .is_err()
        );
        for pos in [0, 4, 8, 16, 20, 25, packed.len() - 1] {
            let mut damaged = packed.clone();
            damaged[pos] ^= 0x80;
            assert!(WexEngine::decompress(&damaged, codec, input.len()).is_err());
        }
        assert!(WexEngine::decompress(&packed[..packed.len() - 1], codec, input.len()).is_err());
    }
}
#[test]
fn cross_file_solid_is_real_and_selective_extraction_uses_ranges() {
    let tmp = tempfile::tempdir().unwrap();
    let source = tmp.path().join("data");
    fs::create_dir(&source).unwrap();
    let original = random(BLOCK_SIZE * 3 + 11);
    let mut edited = original.clone();
    edited[121..128].copy_from_slice(b"CHANGED");
    fs::write(source.join("a.bin"), &original).unwrap();
    fs::write(source.join("b.bin"), &edited).unwrap();
    let normal = tmp.path().join("normal.wxp");
    let solid = tmp.path().join("solid.wxp");
    let baseline =
        pipeline::pack(&normal, std::slice::from_ref(&source), options(false), None).unwrap();
    let report = pipeline::pack(&solid, &[source], options(true), None).unwrap();
    assert_eq!(report.chunks, 1);
    assert_eq!(report.unique_bytes, report.input_bytes);
    assert!(report.archive_bytes < baseline.archive_bytes * 3 / 5);
    let mut reader = ArchiveReader::open(&solid, None, ReadLimits::default()).unwrap();
    assert!(reader.header().flags.contains(HeaderFlags::SOLID_GROUPS));
    assert!(
        !reader
            .file_entry("data/b.bin")
            .unwrap()
            .chunk_ranges
            .is_empty()
    );
    for (name, expected) in [
        ("data/b.bin", &edited),
        ("data/a.bin", &original),
        ("data/b.bin", &edited),
    ] {
        let mut out = Vec::new();
        reader.extract_file(name, &mut out).unwrap();
        assert_eq!(&out, expected);
    }
    pipeline::verify(&solid, None, false, ReadLimits::default()).unwrap();
    let destination = tmp.path().join("selected");
    pipeline::unpack(
        &solid,
        &destination,
        Some("data/b.bin"),
        None,
        ReadLimits::default(),
    )
    .unwrap();
    assert_eq!(fs::read(destination.join("data/b.bin")).unwrap(), edited);
    assert!(!destination.join("data/a.bin").exists());
    let index = reader.index().clone();
    assert_eq!(
        IndexFooter::deserialize(&index.serialize().unwrap()).unwrap(),
        index
    );
    let mut invalid = index.clone();
    invalid
        .file_table
        .iter_mut()
        .find(|f| f.path == "data/b.bin")
        .unwrap()
        .chunk_ranges[0]
        .offset = MAX_SOLID_GROUP_SIZE as u32;
    assert!(invalid.serialize().is_err());
    let mut invalid = index.clone();
    invalid
        .file_table
        .iter_mut()
        .find(|f| f.path == "data/b.bin")
        .unwrap()
        .chunk_ranges
        .pop();
    assert!(invalid.serialize().is_err());
    let mut invalid = index.clone();
    invalid.flags.remove(HeaderFlags::SOLID_GROUPS);
    assert!(invalid.serialize().is_err());
    let limits = DecodeLimits {
        max_references: 1,
        ..DecodeLimits::default()
    };
    assert!(IndexFooter::deserialize_with_limits(&index.serialize().unwrap(), limits).is_err());
}
#[test]
fn solid_groups_are_bounded_and_file_ranges_cross_the_boundary() {
    let tmp = tempfile::tempdir().unwrap();
    let input = tmp.path().join("large.bin");
    let data = vec![b'x'; MAX_SOLID_GROUP_SIZE + 237];
    fs::write(&input, &data).unwrap();
    let archive = tmp.path().join("large.wxp");
    let report = pipeline::pack(
        &archive,
        &[input],
        PackOptions {
            level: 1,
            ..options(true)
        },
        None,
    )
    .unwrap();
    assert_eq!(report.chunks, 2);
    assert_eq!(report.peak_inflight, 1);
    let mut reader = ArchiveReader::open(&archive, None, ReadLimits::default()).unwrap();
    assert!(
        reader
            .index()
            .chunk_table
            .iter()
            .all(|g| g.header.uncompressed_size as usize <= MAX_SOLID_GROUP_SIZE)
    );
    let mut out = Vec::new();
    reader.extract_file("large.bin", &mut out).unwrap();
    assert_eq!(out, data);
    let parallel = tmp.path().join("parallel.wxp");
    pipeline::pack(
        &parallel,
        &[tmp.path().join("large.bin")],
        PackOptions {
            level: 1,
            threads: 4,
            queue_depth: 8,
            memory_limit: 512 << 20,
            ..options(true)
        },
        None,
    )
    .unwrap();
    assert_eq!(fs::read(&archive).unwrap(), fs::read(parallel).unwrap());
}
#[test]
fn solid_keeps_small_dedup_chunks_and_secrets_and_recovery_work() {
    let tmp = tempfile::tempdir().unwrap();
    let source = tmp.path().join("data");
    fs::create_dir(&source).unwrap();
    let data = random(300_001);
    fs::write(source.join("a"), &data).unwrap();
    fs::write(source.join("b"), &data).unwrap();
    let archive = tmp.path().join("encrypted.wxp");
    let config = PackOptions {
        dedup: true,
        recovery_percent: Some(5),
        kdf: wexpack::crypto::KdfParameters {
            memory_kib: 8192,
            iterations: 1,
            lanes: 1,
        },
        ..options(true)
    };
    let report = pipeline::pack(&archive, &[source], config, Some(b"solid-test-password")).unwrap();
    assert_eq!(report.unique_bytes, data.len() as u64);
    assert_eq!(report.dedup_saved, data.len() as u64);
    assert!(ArchiveReader::open(&archive, Some(b"wrong"), ReadLimits::default()).is_err());
    assert!(ArchiveReader::open(&archive, None, ReadLimits::default()).is_err());
    pipeline::verify(
        &archive,
        Some(b"solid-test-password"),
        false,
        ReadLimits::default(),
    )
    .unwrap();
    let mut reader = ArchiveReader::open(
        &archive,
        Some(b"solid-test-password"),
        ReadLimits::default(),
    )
    .unwrap();
    assert_eq!(
        reader.file_entry("data/a").unwrap().chunk_ids,
        reader.file_entry("data/b").unwrap().chunk_ids
    );
    assert_eq!(
        reader.file_entry("data/a").unwrap().chunk_ranges,
        reader.file_entry("data/b").unwrap().chunk_ranges
    );
    let mut out = Vec::new();
    reader.extract_file("data/b", &mut out).unwrap();
    assert_eq!(out, data);
}

#[test]
fn distant_short_matches_never_overflow_literal_bound() {
    let prefix = random((2 << 20) + 113);
    let mut input = prefix.clone();
    for word in prefix[..BLOCK_SIZE / 2].as_chunks::<4>().0 {
        input.extend_from_slice(word);
        input.extend_from_slice(b"!#@$^&*()");
    }
    let mut packed = Vec::new();
    let codec = WexEngine::compress_solid_into(&input, 5, &mut packed).unwrap();
    assert_eq!(
        WexEngine::decompress(&packed, codec, input.len()).unwrap(),
        input
    );
}

#[test]
fn solid_workspace_and_cdc_geometry_fail_before_publication() {
    let tmp = tempfile::tempdir().unwrap();
    let source = tmp.path().join("input");
    fs::write(&source, b"data").unwrap();
    let archive = tmp.path().join("rejected.wxp");
    assert!(
        pipeline::pack(
            &archive,
            std::slice::from_ref(&source),
            PackOptions {
                memory_limit: 64 << 20,
                ..options(true)
            },
            None
        )
        .is_err()
    );
    assert!(!archive.exists());
    let cdc = wexpack::cdc::FastCdcConfig::custom(1 << 14, 1 << 16, 1 << 26, 2).unwrap();
    assert!(
        pipeline::pack(
            &archive,
            &[source],
            PackOptions {
                chunking: Some(cdc),
                ..options(true)
            },
            None
        )
        .is_err()
    );
    assert!(!archive.exists());
}
