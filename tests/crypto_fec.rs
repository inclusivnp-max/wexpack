use std::fs::{File, OpenOptions};
use std::io::{Cursor, Read, Seek, SeekFrom, Write};
use wexpack::codec::WexEngine;
use wexpack::crypto::{ArchiveOpener, ArchiveSealer, CryptoError, CryptoLimits, KdfParameters};
use wexpack::fec::{self, FecError, FecLimits, RecoveryConfig, ReedSolomon, gf256};
use wexpack::filters::{ProfileHint, SmartTransform, invert_transform};
use wexpack::format::*;

fn parameters() -> KdfParameters {
    KdfParameters {
        memory_kib: 8192,
        iterations: 1,
        lanes: 1,
    }
}
fn writer() -> ArchiveSealer {
    ArchiveSealer::new(b"crypto test password", parameters()).unwrap()
}
fn opener(writer: &ArchiveSealer) -> ArchiveOpener {
    ArchiveOpener::new(
        b"crypto test password",
        *writer.descriptor(),
        CryptoLimits::default(),
    )
    .unwrap()
}
fn chunk(id: u32, payload: &[u8]) -> ChunkHeader {
    ChunkHeader {
        chunk_id: ChunkId::new(id).unwrap(),
        uncompressed_size: payload.len() as u32,
        transformed_size: payload.len() as u32,
        compressed_size: payload.len() as u32,
        codec: CodecType::Store,
        transform: TransformType::None,
        flags: ChunkFlags::empty(),
        hash: *blake3::hash(payload).as_bytes(),
        crc32: crc32fast::hash(payload),
    }
}
fn index_envelope() -> IndexEnvelope {
    IndexEnvelope {
        codec: CodecType::Store,
        encrypted: false,
        decoded_size: 64,
        payload_size: 64,
    }
}
fn random(len: usize) -> Vec<u8> {
    let mut state = 0x96d1_0acf_724b_1833u64;
    (0..len)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            (state >> 32) as u8
        })
        .collect()
}
fn config() -> RecoveryConfig {
    RecoveryConfig {
        shard_size: 512,
        data_shards: 4,
        parity_shards: 3,
    }
}

#[test]
fn crypto_roundtrips_binary_chunks_including_maximum_id() {
    let mut w = writer();
    let r = opener(&w);
    for (id, data) in [
        (0, vec![0]),
        (1, random(8192)),
        (u32::MAX - 1, vec![255; 65_537]),
    ] {
        let (h, ciphertext) = w.seal_chunk(chunk(id, &data), &data).unwrap();
        assert_eq!(ciphertext.len(), data.len() + 16);
        assert!(h.flags.contains(ChunkFlags::ENCRYPTED));
        h.verify_stored_payload(&ciphertext).unwrap();
        assert_eq!(r.open_chunk(&h, &ciphertext).unwrap().as_slice(), data);
    }
}
#[test]
fn fresh_archives_have_distinct_salts_ids_and_ciphertexts() {
    let mut a = writer();
    let mut b = writer();
    assert_ne!(a.descriptor().salt, b.descriptor().salt);
    assert_ne!(a.descriptor().archive_id, b.descriptor().archive_id);
    let p = b"identical input";
    assert_ne!(
        a.seal_chunk(chunk(0, p), p).unwrap().1,
        b.seal_chunk(chunk(0, p), p).unwrap().1
    );
}
#[test]
fn nonce_reuse_out_of_order_and_post_index_writes_are_rejected() {
    let mut w = writer();
    let p = b"input";
    let (h, c) = w.seal_chunk(chunk(7, p), p).unwrap();
    assert!(matches!(
        w.seal_chunk(chunk(7, p), p),
        Err(CryptoError::InvalidState(_))
    ));
    assert!(w.seal_chunk(chunk(6, p), p).is_err());
    assert!(w.seal_chunk(h, &c).is_err());
    w.seal_chunk(chunk(8, p), p).unwrap();
    w.seal_index(index_envelope(), &[0; 64], DecodeLimits::default())
        .unwrap();
    assert!(
        w.seal_index(index_envelope(), &[0; 64], DecodeLimits::default())
            .is_err()
    );
    assert!(w.seal_chunk(chunk(9, p), p).is_err());
}
#[test]
fn prevalidation_failures_do_not_consume_ids() {
    let mut w = writer();
    let p = b"input";
    let mut h = chunk(0, p);
    h.crc32 ^= 1;
    assert!(w.seal_chunk(h, p).is_err());
    w.seal_chunk(chunk(0, p), p).unwrap();
    assert!(
        w.seal_index(index_envelope(), &[0; 63], DecodeLimits::default())
            .is_err()
    );
    w.seal_index(index_envelope(), &[0; 64], DecodeLimits::default())
        .unwrap();
}
#[test]
fn incorrect_password_archive_identity_and_metadata_fail_authentication() {
    let mut w = writer();
    let p = b"authenticated bytes";
    let (h, c) = w.seal_chunk(chunk(0, p), p).unwrap();
    let wrong =
        ArchiveOpener::new(b"wrong password", *w.descriptor(), CryptoLimits::default()).unwrap();
    assert!(matches!(
        wrong.open_chunk(&h, &c),
        Err(CryptoError::AuthenticationFailed)
    ));
    let mut desc = *w.descriptor();
    desc.archive_id[0] ^= 1;
    let wrong = ArchiveOpener::new(b"crypto test password", desc, CryptoLimits::default()).unwrap();
    assert!(matches!(
        wrong.open_chunk(&h, &c),
        Err(CryptoError::AuthenticationFailed)
    ));
    let r = opener(&w);
    let mut tampered = h;
    tampered.hash[0] ^= 1;
    assert!(matches!(
        r.open_chunk(&tampered, &c),
        Err(CryptoError::AuthenticationFailed)
    ));
    tampered = h;
    tampered.chunk_id = ChunkId::new(1).unwrap();
    assert!(matches!(
        r.open_chunk(&tampered, &c),
        Err(CryptoError::AuthenticationFailed)
    ));
}
#[test]
fn every_ciphertext_and_tag_byte_is_authenticated_even_with_forged_crc() {
    let mut w = writer();
    let p = b"authenticated bytes";
    let (h, c) = w.seal_chunk(chunk(0, p), p).unwrap();
    let r = opener(&w);
    for i in 0..c.len() {
        let mut bad = c.clone();
        bad[i] ^= 1;
        let mut bad_h = h;
        bad_h.crc32 = crc32fast::hash(&bad);
        assert!(matches!(
            r.open_chunk(&bad_h, &bad),
            Err(CryptoError::AuthenticationFailed)
        ));
    }
    for end in 0..c.len() {
        assert!(r.open_chunk(&h, &c[..end]).is_err());
    }
    assert!(r.open_chunk(&chunk(0, p), p).is_err());
}
#[test]
fn encrypted_index_authenticates_codec_sizes_and_payload() {
    let mut w = writer();
    let r = opener(&w);
    let (h, c) = w
        .seal_index(index_envelope(), &[42; 64], DecodeLimits::default())
        .unwrap();
    assert_eq!(
        r.open_index(&h, &c, DecodeLimits::default())
            .unwrap()
            .as_slice(),
        &[42; 64]
    );
    for i in 0..c.len() {
        let mut bad = c.clone();
        bad[i] ^= 1;
        assert!(r.open_index(&h, &bad, DecodeLimits::default()).is_err());
    }
    let mut bad = h;
    bad.codec = CodecType::WexTurbo;
    assert!(matches!(
        r.open_index(&bad, &c, DecodeLimits::default()),
        Err(CryptoError::AuthenticationFailed)
    ));
    bad.decoded_size += 1;
    assert!(r.open_index(&bad, &c, DecodeLimits::default()).is_err());
    assert!(
        r.open_index(&h, &c[..c.len() - 1], DecodeLimits::default())
            .is_err()
    );
}
#[test]
fn kdf_and_payload_budgets_are_enforced_before_expensive_work() {
    let descriptor = CryptoDescriptor {
        memory_kib: 1_048_576,
        iterations: 16,
        lanes: 32,
        salt: [0; 32],
        archive_id: [0; 16],
    };
    assert!(matches!(
        ArchiveOpener::new(b"password", descriptor, CryptoLimits::default()),
        Err(CryptoError::ResourceLimit(_))
    ));
    let mut d = descriptor;
    d.memory_kib = 8192;
    d.iterations = 1;
    d.lanes = 1;
    for limit in [
        CryptoLimits {
            max_memory_kib: 4096,
            ..CryptoLimits::default()
        },
        CryptoLimits {
            max_iterations: 0,
            ..CryptoLimits::default()
        },
        CryptoLimits {
            max_lanes: 0,
            ..CryptoLimits::default()
        },
        CryptoLimits {
            max_work_kib: 8191,
            ..CryptoLimits::default()
        },
    ] {
        assert!(ArchiveOpener::new(b"pw", d, limit).is_err());
    }
    assert!(
        ArchiveSealer::new(
            b"pw",
            KdfParameters {
                memory_kib: 8191,
                ..parameters()
            }
        )
        .is_err()
    );
    assert!(
        ArchiveSealer::new(
            &vec![0; wexpack::crypto::MAX_PASSWORD_BYTES + 1],
            parameters()
        )
        .is_err()
    );
    let mut w = ArchiveSealer::with_limits(
        b"pw",
        parameters(),
        CryptoLimits {
            max_payload_bytes: 16,
            ..CryptoLimits::default()
        },
    )
    .unwrap();
    assert!(w.seal_chunk(chunk(0, b"x"), b"x").is_err());
    let normal = writer();
    let r = ArchiveOpener::new(
        b"crypto test password",
        *normal.descriptor(),
        CryptoLimits {
            max_payload_bytes: 0,
            ..CryptoLimits::default()
        },
    )
    .unwrap();
    assert!(
        r.open_index(
            &IndexEnvelope {
                encrypted: true,
                payload_size: 80,
                ..index_envelope()
            },
            &[0; 80],
            DecodeLimits::default()
        )
        .is_err()
    );
}

fn reference_mul(mut a: u16, mut b: u8) -> u8 {
    let mut out = 0u16;
    while b != 0 {
        if b & 1 != 0 {
            out ^= a;
        }
        a <<= 1;
        if a & 256 != 0 {
            a ^= 0x11d;
        }
        b >>= 1;
    }
    out as u8
}
#[test]
fn gf256_matches_independent_polynomial_arithmetic_exhaustively() {
    for a in 0..=255u8 {
        for b in 0..=255u8 {
            assert_eq!(gf256::mul(a, b), reference_mul(a as u16, b));
        }
    }
    assert_eq!(gf256::inverse(0), None);
    for a in 1..=255 {
        assert_eq!(gf256::mul(a, gf256::inverse(a).unwrap()), 1);
        assert_eq!(gf256::pow(a, 255), 1);
    }
    assert_eq!(gf256::pow(0, 0), 1);
    assert_eq!(gf256::pow(0, 1), 0);
}
#[test]
fn vandermonde_generator_matches_independent_lagrange_vector() {
    let rs = ReedSolomon::new(4, 3).unwrap();
    assert_eq!(
        rs.generator_matrix(),
        &[
            1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0x52, 0xf7, 0x02, 0xa6, 0xf7, 0x07,
            0x04, 0xf5, 0x02, 0x04, 0xd5, 0xd2,
        ]
    );
    let data: Vec<_> = (0..4).map(|n| vec![n + 1; 17]).collect();
    let parity = rs.encode(&data).unwrap();
    for (row, parity_shard) in parity.iter().enumerate() {
        let value = (0..4).fold(0, |v, i| {
            v ^ reference_mul(rs.generator_matrix()[(row + 4) * 4 + i] as u16, data[i][0])
        });
        assert_eq!(*parity_shard, vec![value; 17]);
    }
}
#[test]
fn every_erasure_subset_up_to_parity_recovers_data_and_parity() {
    for k in 1..=5 {
        for p in 1..=3 {
            let rs = ReedSolomon::new(k, p).unwrap();
            let input = random(k as usize * 31);
            let data: Vec<_> = input
                .as_chunks::<31>()
                .0
                .iter()
                .map(|s| s.to_vec())
                .collect();
            let mut all = data.clone();
            all.extend(rs.encode(&data).unwrap());
            for mask in 0u32..(1 << (k + p)) {
                if mask.count_ones() > p as u32 {
                    continue;
                }
                let mut shards: Vec<_> = all
                    .iter()
                    .enumerate()
                    .map(|(i, s)| {
                        if mask & (1 << i) == 0 {
                            Some(s.clone())
                        } else {
                            None
                        }
                    })
                    .collect();
                assert_eq!(
                    rs.reconstruct(&mut shards).unwrap(),
                    mask.count_ones() as usize
                );
                assert_eq!(
                    shards.into_iter().map(Option::unwrap).collect::<Vec<_>>(),
                    all
                );
            }
        }
    }
}
#[test]
fn rs_validates_geometry_and_leaves_uncorrectable_shards_untouched() {
    for (k, p) in [(0, 1), (1, 0), (255, 1), (128, 128)] {
        assert!(ReedSolomon::new(k, p).is_err());
    }
    let rs = ReedSolomon::new(4, 2).unwrap();
    assert!(rs.encode(&[]).is_err());
    assert!(rs.encode(&vec![vec![]; 4]).is_err());
    assert!(rs.encode(&[vec![0], vec![0], vec![0], vec![0; 2]]).is_err());
    let mut shards = vec![Some(vec![0; 8]); 6];
    shards[0] = None;
    shards[1] = None;
    shards[2] = None;
    let saved = shards.clone();
    assert!(rs.reconstruct(&mut shards).is_err());
    assert_eq!(shards, saved);
    assert!(rs.reconstruct(&mut vec![None; 6]).is_err());
    assert!(rs.reconstruct(&mut [Some(vec![0])]).is_err());
}
#[test]
fn maximum_field_geometry_and_boundary_shard_size_work() {
    for (k, p) in [(1, 254), (254, 1)] {
        let rs = ReedSolomon::new(k, p).unwrap();
        let data = vec![vec![37; 3]; k as usize];
        let mut shards: Vec<_> = data
            .iter()
            .cloned()
            .chain(rs.encode(&data).unwrap())
            .map(Some)
            .collect();
        for shard in &mut shards[..p as usize] {
            *shard = None;
        }
        assert_eq!(rs.reconstruct(&mut shards).unwrap(), p as usize);
        assert!(shards.into_iter().all(|s| s == Some(vec![37; 3])));
    }
    let rs = ReedSolomon::new(1, 1).unwrap();
    let data = vec![vec![7; fec::MAX_SHARD_SIZE]];
    assert_eq!(rs.encode(&data).unwrap(), data);
    assert!(rs.encode(&[vec![0; fec::MAX_SHARD_SIZE + 1]]).is_err());
}

fn recovery_archive(payload: usize) -> Cursor<Vec<u8>> {
    let mut header = SuperBlock::new(HeaderFlags::REED_SOLOMON, 16, 18, 20).unwrap();
    if payload > 0 {
        header.chunk_count = 1;
        header.chunk_store_size = 64 + payload as u64;
        header.footer_offset = 64 + header.chunk_store_size;
    }
    header.refresh_checksum();
    let mut bytes = random((header.footer_offset + header.footer_comp_size) as usize);
    bytes[..64].copy_from_slice(&header.to_bytes());
    let mut archive = Cursor::new(bytes);
    fec::append_recovery(&mut archive, config(), FecLimits::default()).unwrap();
    archive
}
fn metadata(bytes: &[u8]) -> (ReedSolomonSentinel, FecHeader) {
    let s = ReedSolomonSentinel::from_bytes(bytes[bytes.len() - 32..].try_into().unwrap()).unwrap();
    let h = FecHeader::from_bytes(
        bytes[s.fec_offset as usize..s.fec_offset as usize + 64]
            .try_into()
            .unwrap(),
    )
    .unwrap();
    (s, h)
}
fn parity_start(bytes: &[u8]) -> usize {
    let (s, h) = metadata(bytes);
    (s.fec_offset + 64 + h.manifest_size) as usize
}
#[test]
fn recovery_roundtrips_empty_short_and_multiple_stripes() {
    for len in [0, 1, 511, 512, 1024, 4096, 8193] {
        let mut a = recovery_archive(len);
        let original = a.get_ref().clone();
        assert!(
            fec::verify_recovery(&mut a, FecLimits::default())
                .unwrap()
                .is_clean()
        );
        assert!(
            fec::repair_recovery(&mut a, FecLimits::default())
                .unwrap()
                .is_clean()
        );
        assert_eq!(a.into_inner(), original);
    }
}
#[test]
fn recovery_repairs_superblock_data_parity_and_tail_padding() {
    let mut a = recovery_archive(8193);
    let original = a.get_ref().clone();
    let (_, h) = metadata(&original);
    let ps = parity_start(&original);
    // Exactly p erasures in the first stripe, including the damaged superblock.
    a.get_mut()[0] ^= 1;
    a.get_mut()[512 + 13] ^= 2;
    a.get_mut()[ps + 9] ^= 4;
    // The last data byte is in a partially padded shard of another stripe.
    a.get_mut()[h.protected_size as usize - 1] ^= 8;
    let report = fec::verify_recovery(&mut a, FecLimits::default()).unwrap();
    assert_eq!(report.damaged_data_shards, 3);
    assert_eq!(report.damaged_parity_shards, 1);
    assert_eq!(
        fec::repair_recovery(&mut a, FecLimits::default()).unwrap(),
        report
    );
    assert_eq!(a.into_inner(), original);
}
#[test]
fn parity_only_erasures_are_restored() {
    let mut a = recovery_archive(4096);
    let original = a.get_ref().clone();
    let ps = parity_start(&original);
    for i in 0..3 {
        a.get_mut()[ps + i * 512] ^= 1;
    }
    let report = fec::repair_recovery(&mut a, FecLimits::default()).unwrap();
    assert_eq!(report.damaged_parity_shards, 3);
    assert_eq!(a.into_inner(), original);
}
#[test]
fn unrecoverable_later_stripe_does_not_partially_repair_earlier_stripes() {
    let mut a = recovery_archive(8193);
    a.get_mut()[100] ^= 1;
    for i in 0..4 {
        a.get_mut()[2048 + i * 512] ^= 1;
    }
    let saved = a.get_ref().clone();
    assert!(matches!(
        fec::repair_recovery(&mut a, FecLimits::default()),
        Err(FecError::TooManyErasures { stripe: 1, .. })
    ));
    assert_eq!(a.into_inner(), saved);
}
#[test]
fn manifest_corruption_is_detected_without_rewriting_valid_data() {
    let mut a = recovery_archive(4096);
    let (s, _) = metadata(a.get_ref());
    a.get_mut()[s.fec_offset as usize + 64] ^= 1;
    let saved = a.get_ref().clone();
    assert!(matches!(
        fec::repair_recovery(&mut a, FecLimits::default()),
        Err(FecError::ManifestMismatch { .. })
    ));
    assert_eq!(a.into_inner(), saved);
}
#[test]
fn damaged_metadata_truncation_trailing_bytes_and_resource_limits_are_rejected() {
    let a = recovery_archive(4096);
    let bytes = a.into_inner();
    let (s, _) = metadata(&bytes);
    for index in [
        s.fec_offset as usize,
        s.fec_offset as usize + 48,
        bytes.len() - 32,
        bytes.len() - 1,
    ] {
        let mut bad = bytes.clone();
        bad[index] ^= 1;
        assert!(fec::verify_recovery(&mut Cursor::new(bad), FecLimits::default()).is_err());
    }
    for length in [0, 31, 64, bytes.len() - 1] {
        assert!(
            fec::verify_recovery(&mut Cursor::new(&bytes[..length]), FecLimits::default()).is_err()
        );
    }
    let mut bad = bytes.clone();
    bad.push(0);
    assert!(fec::verify_recovery(&mut Cursor::new(bad), FecLimits::default()).is_err());
    for limits in [
        FecLimits {
            max_workspace_bytes: 1,
            ..FecLimits::default()
        },
        FecLimits {
            max_protected_bytes: 1,
            ..FecLimits::default()
        },
        FecLimits {
            max_fec_bytes: 1,
            ..FecLimits::default()
        },
        FecLimits {
            max_stripes: 0,
            ..FecLimits::default()
        },
    ] {
        assert!(matches!(
            fec::verify_recovery(&mut Cursor::new(&bytes), limits),
            Err(FecError::ResourceLimit(_))
        ));
    }
}
#[test]
fn append_requires_finalized_prefix_and_valid_percentage() {
    for p in 1..=30 {
        let c = RecoveryConfig::for_percent(p).unwrap();
        assert!(c.data_shards + c.parity_shards <= 255);
        assert!(u32::from(c.parity_shards) * 100 >= u32::from(c.data_shards) * u32::from(p));
    }
    assert!(RecoveryConfig::for_percent(0).is_err());
    assert!(RecoveryConfig::for_percent(31).is_err());
    let mut a = recovery_archive(1);
    let saved = a.get_ref().clone();
    assert!(fec::append_recovery(&mut a, config(), FecLimits::default()).is_err());
    assert_eq!(a.into_inner(), saved);
    let header = SuperBlock::new(HeaderFlags::empty(), 16, 18, 20).unwrap();
    let mut bytes = vec![0; 160];
    bytes[..64].copy_from_slice(&header.to_bytes());
    assert!(fec::append_recovery(&mut Cursor::new(bytes), config(), FecLimits::default()).is_err());
}

fn encrypted_archive(source: &[u8]) -> Vec<u8> {
    let mut w = writer();
    let transformed = SmartTransform::prepare(source, ProfileHint::Auto).unwrap();
    let compressed = WexEngine::compress(&transformed.data, 5).unwrap();
    let mut h = chunk(0, source);
    h.transformed_size = transformed.data.len() as u32;
    h.transform = transformed.transform;
    h.compressed_size = compressed.data.len() as u32;
    h.codec = compressed.codec;
    h.crc32 = crc32fast::hash(&compressed.data);
    let (h, c) = w.seal_chunk(h, &compressed.data).unwrap();
    let flags = HeaderFlags::ENCRYPTED_DATA
        | HeaderFlags::ENCRYPTED_INDEX
        | HeaderFlags::REED_SOLOMON
        | HeaderFlags::PRECOMP;
    let footer = IndexFooter::new(
        flags,
        vec![ChunkDescriptor {
            offset: 192,
            header: h,
        }],
        vec![FileEntry {
            path: "private/research.txt".into(),
            file_size: source.len() as u64,
            mode: 0o644,
            mtime_secs: 0,
            mtime_nanos: 0,
            file_hash: *blake3::hash(source).as_bytes(),
            flags: FileFlags::REGULAR,
            symlink_target: None,
            chunk_ids: vec![ChunkId::new(0).unwrap()],
            chunk_ranges: Vec::new(),
        }],
    )
    .unwrap();
    let raw = footer.serialize().unwrap();
    let index = WexEngine::compress(&raw, 5).unwrap();
    let envelope = IndexEnvelope {
        codec: index.codec,
        encrypted: false,
        decoded_size: raw.len() as u64,
        payload_size: index.data.len() as u64,
    };
    let (envelope, index) = w
        .seal_index(envelope, &index.data, DecodeLimits::default())
        .unwrap();
    let mut sb = SuperBlock::new(flags, 16, 18, 20).unwrap();
    sb.chunk_count = 1;
    sb.chunk_store_size = 64 + c.len() as u64;
    sb.footer_offset = 192 + sb.chunk_store_size;
    sb.footer_comp_size = 32 + index.len() as u64;
    sb.footer_uncomp_size = raw.len() as u64;
    sb.refresh_checksum();
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&sb.to_bytes());
    bytes.extend_from_slice(&w.descriptor().to_bytes());
    bytes.extend_from_slice(&h.to_bytes());
    bytes.extend_from_slice(&c);
    bytes.extend_from_slice(&envelope.to_bytes());
    bytes.extend_from_slice(&index);
    let mut archive = Cursor::new(bytes);
    fec::append_recovery(&mut archive, config(), FecLimits::default()).unwrap();
    archive.into_inner()
}
#[test]
fn real_file_roundtrip_filters_codec_stealth_aead_damage_repair_and_random_access() {
    let source = b"function const return research archive, reversible text payload\n".repeat(500);
    let bytes = encrypted_archive(&source);
    assert!(
        !bytes
            .windows(b"private/research.txt".len())
            .any(|s| s == b"private/research.txt")
    );
    let supplied = std::env::var_os("WEXPACK_STAGE4_DEMO_PATH");
    let path = supplied
        .as_ref()
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| {
            std::env::temp_dir().join(format!(
                "wexpack-fec-{}-{}.wxp",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ))
        });
    {
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&path)
            .unwrap();
        file.write_all(&bytes).unwrap();
        file.sync_all().unwrap();
        let mut damaged = bytes.clone();
        let ps = parity_start(&damaged);
        damaged[0] ^= 1;
        damaged[70] ^= 1;
        damaged[ps + 3] ^= 1;
        file.seek(SeekFrom::Start(0)).unwrap();
        file.write_all(&damaged).unwrap();
        assert!(
            !fec::verify_recovery(&mut file, FecLimits::default())
                .unwrap()
                .is_clean()
        );
        fec::repair_recovery(&mut file, FecLimits::default()).unwrap();
        file.sync_all().unwrap();
    }
    let mut file = File::open(&path).unwrap();
    let mut restored = Vec::new();
    file.read_to_end(&mut restored).unwrap();
    assert_eq!(restored, bytes);
    let sb = SuperBlock::from_bytes(restored[..64].try_into().unwrap()).unwrap();
    sb.validate_archive_len(restored.len() as u64, DecodeLimits::default())
        .unwrap();
    let descriptor = CryptoDescriptor::from_bytes(restored[64..192].try_into().unwrap()).unwrap();
    let reader =
        ArchiveOpener::new(b"crypto test password", descriptor, CryptoLimits::default()).unwrap();
    let start = sb.footer_offset as usize;
    let envelope = IndexEnvelope::from_bytes(
        restored[start..start + 32].try_into().unwrap(),
        DecodeLimits::default(),
    )
    .unwrap();
    envelope
        .validate_against(&sb, DecodeLimits::default())
        .unwrap();
    let raw = reader
        .open_index(
            &envelope,
            &restored[start + 32..start + sb.footer_comp_size as usize],
            DecodeLimits::default(),
        )
        .unwrap();
    let raw = WexEngine::decompress(&raw, envelope.codec, envelope.decoded_size as usize).unwrap();
    let footer = IndexFooter::deserialize(&raw).unwrap();
    footer.validate_against(&sb).unwrap();
    let lookup = footer.lookup().unwrap();
    let entry = lookup.file("private/research.txt").unwrap();
    let c = lookup.chunk(entry.chunk_ids[0]).unwrap();
    let offset = c.offset as usize;
    let h = ChunkHeader::from_bytes(restored[offset..offset + 64].try_into().unwrap()).unwrap();
    assert_eq!(h, c.header);
    let compressed = reader
        .open_chunk(
            &h,
            &restored[offset + 64..offset + 64 + h.compressed_size as usize],
        )
        .unwrap();
    let transformed =
        WexEngine::decompress(&compressed, h.codec, h.transformed_size as usize).unwrap();
    let plain =
        invert_transform(&transformed, h.transform, 0, h.uncompressed_size as usize).unwrap();
    h.verify_original(&plain).unwrap();
    assert_eq!(plain, source);
    if supplied.is_none() {
        std::fs::remove_file(path).unwrap();
    }
}
#[test]
fn hostile_fec_inputs_never_panic() {
    for size in 0..256 {
        let data = random(size);
        let result = std::panic::catch_unwind(|| {
            fec::verify_recovery(&mut Cursor::new(data), FecLimits::default())
        });
        assert!(result.is_ok());
        assert!(result.unwrap().is_err());
    }
}
