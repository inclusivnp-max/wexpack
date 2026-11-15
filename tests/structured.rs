use std::{fs, process::Command};
use wexpack::{
    codec::{CodecLimits, WexEngine},
    format::{CodecType, HeaderFlags},
    pipeline::{self, ArchiveReader, PackOptions, ReadLimits},
};
fn fixture() -> Vec<u8> {
    let mut data = Vec::new();
    let mut state = 0x0981_7361_7351_ab21u64;
    for _ in 0..2000 {
        data.extend_from_slice(
            b"some repeated source code with a shared fixed-distance reference pattern\n",
        );
        for _ in 0..7 {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            data.push((state >> 32) as u8);
        }
    }
    data
}
#[test]
fn structured_frames_roundtrip_and_retain_legacy_candidate() {
    let all_data = fixture();
    let mut chose_new = false;
    for level in [4, 5, 7, 8, 9] {
        let data = &all_data[..if level >= 8 { 12000 } else { all_data.len() }];
        for solid in [false, true] {
            let mut encoded = Vec::new();
            let codec =
                WexEngine::compress_structured_into(data, level, solid, &mut encoded).unwrap();
            assert_eq!(
                WexEngine::decompress(&encoded, codec, data.len())
                    .unwrap()
                    .as_slice(),
                data
            );
            let mut legacy = Vec::new();
            if solid {
                WexEngine::compress_solid_into(data, level, &mut legacy).unwrap();
            } else {
                WexEngine::compress_into(data, level, &mut legacy).unwrap();
            }
            assert!(encoded.len() <= legacy.len());
            if codec == CodecType::WexStructured {
                chose_new = true;
                assert_eq!(&encoded[..4], b"WXE\x03");
                for at in [0, 4, 6, 8, 16, 20, 24, encoded.len() - 1] {
                    let mut bad = encoded.clone();
                    bad[at] ^= 0x80;
                    assert!(WexEngine::decompress(&bad, codec, data.len()).is_err());
                }
            }
            let mut out = Vec::new();
            assert!(
                WexEngine::decompress_into(
                    &encoded,
                    codec,
                    data.len(),
                    CodecLimits {
                        max_output_size: data.len() - 1,
                        max_input_size: encoded.len()
                    },
                    &mut out
                )
                .is_err()
            );
            let budgets = if level == 5 {
                vec![0, encoded.len() - 1, encoded.len(), data.len()]
            } else {
                vec![encoded.len()]
            };
            for budget in budgets {
                let mut bounded = Vec::new();
                let result = WexEngine::compress_structured_bounded_into(
                    data,
                    level,
                    solid,
                    &mut bounded,
                    budget,
                )
                .unwrap();
                assert_eq!(
                    result,
                    if encoded.len() <= budget {
                        Some(codec)
                    } else {
                        None
                    }
                );
                if result.is_some() {
                    assert_eq!(bounded, encoded)
                } else {
                    assert!(bounded.is_empty())
                }
            }
        }
    }
    assert!(chose_new);
}
#[test]
fn feature_flag_selective_read_crypto_and_legacy_archive_stay_valid() {
    let temp = tempfile::tempdir().unwrap();
    let input = temp.path().join("source.rs");
    let data = fixture();
    fs::write(&input, &data).unwrap();
    let options = PackOptions {
        level: 5,
        solid: true,
        threads: 1,
        queue_depth: 1,
        memory_limit: 256 << 20,
        kdf: wexpack::crypto::KdfParameters {
            memory_kib: 8192,
            iterations: 1,
            lanes: 1,
        },
        ..PackOptions::default()
    };
    for encrypted in [false, true] {
        let archive = temp.path().join(if encrypted {
            "encrypted.wxp"
        } else {
            "plain.wxp"
        });
        let password = encrypted.then_some(b"structured-fixture-password".as_slice());
        pipeline::pack(
            &archive,
            std::slice::from_ref(&input),
            options.clone(),
            password,
        )
        .unwrap();
        let mut reader = ArchiveReader::open(&archive, password, ReadLimits::default()).unwrap();
        assert!(reader.header().flags.contains(HeaderFlags::STRUCTURED));
        let mut out = Vec::new();
        reader.extract_file("source.rs", &mut out).unwrap();
        assert_eq!(out, data);
        pipeline::verify(&archive, password, false, ReadLimits::default()).unwrap();
    }
    let legacy = temp.path().join("legacy.wxp");
    pipeline::pack(
        &legacy,
        &[input],
        PackOptions {
            level: 1,
            ..options
        },
        None,
    )
    .unwrap();
    let reader = ArchiveReader::open(&legacy, None, ReadLimits::default()).unwrap();
    assert!(!reader.header().flags.contains(HeaderFlags::STRUCTURED));
}
#[test]
fn structured_cli_uses_real_new_codec_not_an_empty_archive() {
    let temp = tempfile::tempdir().unwrap();
    let input = temp.path().join("data");
    fs::write(&input, fixture()).unwrap();
    let archive = temp.path().join("data.wxp");
    assert!(
        Command::new(env!("CARGO_BIN_EXE_wxp"))
            .args([
                "pack",
                archive.to_str().unwrap(),
                input.to_str().unwrap(),
                "--solid",
                "--threads",
                "1"
            ])
            .output()
            .unwrap()
            .status
            .success()
    );
    let mut reader = ArchiveReader::open(&archive, None, ReadLimits::default()).unwrap();
    assert!(
        reader
            .index()
            .chunk_table
            .iter()
            .any(|c| c.header.codec == CodecType::WexStructured)
    );
    let mut out = Vec::new();
    reader.extract_file("data", &mut out).unwrap();
    assert_eq!(out, fixture());
}

#[test]
fn structured_feature_marker_is_required_in_chunk_index() {
    let temp = tempfile::tempdir().unwrap();
    let input = temp.path().join("source");
    fs::write(&input, fixture()).unwrap();
    let archive = temp.path().join("new.wxp");
    pipeline::pack(
        &archive,
        &[input],
        PackOptions {
            solid: true,
            threads: 1,
            queue_depth: 1,
            memory_limit: 256 << 20,
            ..PackOptions::default()
        },
        None,
    )
    .unwrap();
    let reader = ArchiveReader::open(&archive, None, ReadLimits::default()).unwrap();
    let mut index = reader.index().clone();
    assert!(index.flags.contains(HeaderFlags::STRUCTURED));
    index.flags.remove(HeaderFlags::STRUCTURED);
    assert!(index.validate().is_err());
    assert_eq!(CodecType::from_u8(4).unwrap(), CodecType::WexStructured);
    assert!(CodecType::from_u8(5).is_err());
}
