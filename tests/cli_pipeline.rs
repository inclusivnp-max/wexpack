use std::fs;
use std::path::Path;
use std::process::{Command, Output};
use wexpack::crypto::KdfParameters;
use wexpack::format::*;
use wexpack::pipeline::{self, ArchiveReader, PackOptions, ReadLimits};

fn options() -> PackOptions {
    PackOptions {
        threads: 2,
        queue_depth: 4,
        memory_limit: 256 << 20,
        kdf: KdfParameters {
            memory_kib: 8192,
            iterations: 1,
            lanes: 1,
        },
        ..PackOptions::default()
    }
}
fn random(size: usize) -> Vec<u8> {
    let mut x = 0x95f4_c7a2_183b_664du64;
    (0..size)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            (x >> 32) as u8
        })
        .collect()
}
fn write(path: &Path, data: &[u8]) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, data).unwrap();
}
fn fixture(root: &Path) {
    fs::create_dir_all(root.join("empty")).unwrap();
    write(&root.join("empty.txt"), b"");
    write(
        &root.join("nested/данные.json"),
        &b"{\"function\":\"return\",\"value\":123456}\n".repeat(150),
    );
    write(&root.join("random.bin"), &random(4097));
}
fn compare(a: &Path, b: &Path) {
    let mut names: Vec<_> = fs::read_dir(a)
        .unwrap()
        .map(|x| x.unwrap().file_name())
        .collect();
    names.sort();
    let mut other: Vec<_> = fs::read_dir(b)
        .unwrap()
        .map(|x| x.unwrap().file_name())
        .collect();
    other.sort();
    assert_eq!(names, other);
    for name in names {
        let left = a.join(&name);
        let right = b.join(&name);
        if left.is_dir() {
            compare(&left, &right);
        } else {
            assert_eq!(fs::read(left).unwrap(), fs::read(right).unwrap());
        }
    }
}
fn cli(args: &[&str], cwd: &Path) -> Output {
    Command::new(env!("CARGO_BIN_EXE_wxp"))
        .args(args)
        .current_dir(cwd)
        .output()
        .unwrap()
}
fn success(output: Output) -> String {
    assert!(
        output.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap()
}
fn damaged_parity_offset(bytes: &[u8]) -> (usize, usize) {
    let s = ReedSolomonSentinel::from_bytes(bytes[bytes.len() - 32..].try_into().unwrap()).unwrap();
    let h = FecHeader::from_bytes(
        bytes[s.fec_offset as usize..s.fec_offset as usize + 64]
            .try_into()
            .unwrap(),
    )
    .unwrap();
    (
        (s.fec_offset + 64 + h.manifest_size) as usize,
        h.shard_size as usize,
    )
}
#[test]
fn every_compression_level_roundtrips_directories_unicode_and_empty_files() {
    let root = tempfile::tempdir().unwrap();
    let source = root.path().join("source");
    fixture(&source);
    for level in 1..=9 {
        let archive = root.path().join(format!("level-{level}.wxp"));
        let output = root.path().join(format!("out-{level}"));
        let report = pipeline::pack(
            &archive,
            std::slice::from_ref(&source),
            PackOptions { level, ..options() },
            None,
        )
        .unwrap();
        assert_eq!(report.files, 6);
        assert!(report.chunks >= 2);
        assert!(report.peak_inflight <= 4);
        let verified = pipeline::verify(&archive, None, false, ReadLimits::default()).unwrap();
        assert_eq!(verified.files, 3);
        assert_eq!(
            pipeline::unpack(&archive, &output, None, None, ReadLimits::default()).unwrap(),
            3
        );
        compare(&source, &output.join("source"));
    }
}
#[test]
fn deduplication_is_global_and_optional_with_exact_accounting() {
    let root = tempfile::tempdir().unwrap();
    let source = root.path().join("source");
    let data = random(500_007);
    write(&source.join("a.bin"), &data);
    write(&source.join("b.bin"), &data);
    let mut counts = Vec::new();
    for dedup in [false, true] {
        let archive = root.path().join(format!("{dedup}.wxp"));
        let report = pipeline::pack(
            &archive,
            std::slice::from_ref(&source),
            PackOptions {
                dedup,
                level: 1,
                ..options()
            },
            None,
        )
        .unwrap();
        assert_eq!(
            report.dedup_saved,
            if dedup { data.len() as u64 } else { 0 }
        );
        let reader = ArchiveReader::open(&archive, None, ReadLimits::default()).unwrap();
        let stats = reader.stats();
        assert_eq!(stats.dedup_saved, report.dedup_saved);
        assert_eq!(stats.unique_bytes, report.unique_bytes);
        assert_eq!(stats.transform_saved, report.transform_saved);
        assert_eq!(stats.compression_saved, report.compression_saved);
        if dedup {
            assert_eq!(
                reader.file_entry("source/a.bin").unwrap().chunk_ids,
                reader.file_entry("source/b.bin").unwrap().chunk_ids
            );
        }
        counts.push(report.chunks);
    }
    assert_eq!(counts[0], counts[1] * 2);
}
#[test]
fn ordered_output_is_identical_across_worker_counts() {
    let root = tempfile::tempdir().unwrap();
    let source = root.path().join("data.bin");
    write(&source, &random(1_100_003));
    let mut archives = Vec::new();
    for threads in [1, 4] {
        let archive = root.path().join(format!("{threads}.wxp"));
        pipeline::pack(
            &archive,
            std::slice::from_ref(&source),
            PackOptions {
                threads,
                queue_depth: threads * 2,
                level: 1,
                ..options()
            },
            None,
        )
        .unwrap();
        archives.push(fs::read(archive).unwrap());
    }
    assert_eq!(archives[0], archives[1]);
}
#[test]
fn one_credit_bounds_reordering_and_reuses_buffers() {
    let root = tempfile::tempdir().unwrap();
    let source = root.path().join("data.bin");
    write(&source, &random(1_300_007));
    let archive = root.path().join("data.wxp");
    let report = pipeline::pack(
        &archive,
        &[source],
        PackOptions {
            threads: 1,
            queue_depth: 1,
            memory_limit: 64 << 20,
            level: 1,
            ..options()
        },
        None,
    )
    .unwrap();
    assert!(report.chunks > 8);
    assert_eq!(report.peak_inflight, 1);
    assert_eq!(report.streamed_files, 1);
    assert_eq!(report.mapped_files, 0);
}
#[test]
fn solid_uses_larger_independent_chunks_and_keeps_selective_access() {
    let root = tempfile::tempdir().unwrap();
    let source = root.path().join("data.bin");
    let data = random(900_003);
    write(&source, &data);
    let archive = root.path().join("solid.wxp");
    pipeline::pack(
        &archive,
        &[source],
        PackOptions {
            solid: true,
            level: 1,
            ..options()
        },
        None,
    )
    .unwrap();
    let mut reader = ArchiveReader::open(&archive, None, ReadLimits::default()).unwrap();
    assert!(reader.header().flags.contains(HeaderFlags::SOLID));
    assert_eq!(reader.header().chunk_avg_bits, 18);
    let mut output = Vec::new();
    reader.extract_file("data.bin", &mut output).unwrap();
    assert_eq!(output, data);
}
#[test]
fn empty_archive_content_needs_no_chunk_and_hashes_correctly() {
    let root = tempfile::tempdir().unwrap();
    let folder = root.path().join("empty");
    fs::create_dir(&folder).unwrap();
    let file = root.path().join("empty.txt");
    write(&file, b"");
    let archive = root.path().join("empty.wxp");
    let r = pipeline::pack(&archive, &[folder, file], options(), None).unwrap();
    assert_eq!(r.chunks, 0);
    assert_eq!(r.input_bytes, 0);
    pipeline::verify(&archive, None, false, ReadLimits::default()).unwrap();
    let out = root.path().join("out");
    pipeline::unpack(&archive, &out, None, None, ReadLimits::default()).unwrap();
    assert!(out.join("empty").is_dir());
    assert_eq!(fs::read(out.join("empty.txt")).unwrap(), b"");
}
#[test]
fn encryption_stealth_dedup_and_recovery_roundtrip_together() {
    let root = tempfile::tempdir().unwrap();
    let source = root.path().join("private");
    fixture(&source);
    let archive = root.path().join("encrypted.wxp");
    let r = pipeline::pack(
        &archive,
        std::slice::from_ref(&source),
        PackOptions {
            dedup: true,
            recovery_percent: Some(1),
            ..options()
        },
        Some(b"research password"),
    )
    .unwrap();
    assert!(r.archive_bytes > 0);
    let bytes = fs::read(&archive).unwrap();
    assert!(
        !bytes
            .windows(b"private/nested".len())
            .any(|w| w == b"private/nested")
    );
    assert!(ArchiveReader::open(&archive, None, ReadLimits::default()).is_err());
    assert!(ArchiveReader::open(&archive, Some(b"wrong"), ReadLimits::default()).is_err());
    pipeline::verify(
        &archive,
        Some(b"research password"),
        false,
        ReadLimits::default(),
    )
    .unwrap();
    let out = root.path().join("out");
    pipeline::unpack(
        &archive,
        &out,
        None,
        Some(b"research password"),
        ReadLimits::default(),
    )
    .unwrap();
    compare(&source, &out.join("private"));
}
#[test]
fn transactionally_repaired_archive_is_byte_identical_and_wrong_password_never_publishes() {
    let root = tempfile::tempdir().unwrap();
    let source = root.path().join("data.txt");
    write(&source, &b"return function constant value\n".repeat(100));
    let archive = root.path().join("repair.wxp");
    pipeline::pack(
        &archive,
        &[source],
        PackOptions {
            recovery_percent: Some(1),
            ..options()
        },
        Some(b"password"),
    )
    .unwrap();
    let original = fs::read(&archive).unwrap();
    let mut damaged = original.clone();
    let (parity, _) = damaged_parity_offset(&damaged);
    damaged[0] ^= 1;
    damaged[parity + 5] ^= 1;
    fs::write(&archive, &damaged).unwrap();
    assert!(pipeline::verify(&archive, Some(b"password"), false, ReadLimits::default()).is_err());
    assert!(pipeline::verify(&archive, Some(b"wrong"), true, ReadLimits::default()).is_err());
    assert_eq!(fs::read(&archive).unwrap(), damaged);
    let r = pipeline::verify(&archive, Some(b"password"), true, ReadLimits::default()).unwrap();
    assert_eq!(r.repaired_data_shards, 1);
    assert_eq!(r.repaired_parity_shards, 1);
    assert_eq!(fs::read(&archive).unwrap(), original);
    let r = pipeline::verify(&archive, Some(b"password"), true, ReadLimits::default()).unwrap();
    assert_eq!(r.repaired_data_shards, 0);
}
#[test]
fn unrecoverable_damage_and_bad_manifest_leave_original_untouched() {
    let root = tempfile::tempdir().unwrap();
    let source = root.path().join("x");
    write(&source, b"bytes");
    let archive = root.path().join("x.wxp");
    pipeline::pack(
        &archive,
        &[source],
        PackOptions {
            recovery_percent: Some(1),
            ..options()
        },
        None,
    )
    .unwrap();
    let original = fs::read(&archive).unwrap();
    let (parity, size) = damaged_parity_offset(&original);
    let mut damaged = original.clone();
    for i in [0, parity, parity + size] {
        damaged[i] ^= 1;
    }
    fs::write(&archive, &damaged).unwrap();
    assert!(pipeline::verify(&archive, None, true, ReadLimits::default()).is_err());
    assert_eq!(fs::read(&archive).unwrap(), damaged);
    let s = ReedSolomonSentinel::from_bytes(original[original.len() - 32..].try_into().unwrap())
        .unwrap();
    let mut bad = original.clone();
    bad[s.fec_offset as usize + 64] ^= 1;
    fs::write(&archive, &bad).unwrap();
    assert!(pipeline::verify(&archive, None, true, ReadLimits::default()).is_err());
    assert_eq!(fs::read(&archive).unwrap(), bad);
}
#[test]
fn selective_extraction_does_not_read_unrelated_corrupt_payload() {
    let root = tempfile::tempdir().unwrap();
    let source = root.path().join("source");
    write(&source.join("a"), b"alpha");
    write(&source.join("b"), b"bravo");
    let archive = root.path().join("select.wxp");
    pipeline::pack(&archive, &[source], options(), None).unwrap();
    let reader = ArchiveReader::open(&archive, None, ReadLimits::default()).unwrap();
    let id = reader.file_entry("source/a").unwrap().chunk_ids[0];
    let offset = reader.index().chunk_table[id.get() as usize].offset as usize + 64;
    drop(reader);
    let mut bytes = fs::read(&archive).unwrap();
    bytes[offset] ^= 1;
    fs::write(&archive, bytes).unwrap();
    let out = root.path().join("only-b");
    pipeline::unpack(
        &archive,
        &out,
        Some("source/b"),
        None,
        ReadLimits::default(),
    )
    .unwrap();
    assert_eq!(fs::read(out.join("source/b")).unwrap(), b"bravo");
    assert!(!out.join("source/a").exists());
    assert!(pipeline::verify(&archive, None, false, ReadLimits::default()).is_err());
    let bad = root.path().join("only-a");
    assert!(
        pipeline::unpack(
            &archive,
            &bad,
            Some("source/a"),
            None,
            ReadLimits::default()
        )
        .is_err()
    );
    assert!(!bad.exists());
}
#[test]
fn corrupt_local_header_and_index_are_rejected_before_publication() {
    let root = tempfile::tempdir().unwrap();
    let source = root.path().join("x");
    write(&source, b"content");
    let archive = root.path().join("x.wxp");
    pipeline::pack(&archive, &[source], options(), None).unwrap();
    let original = fs::read(&archive).unwrap();
    let reader = ArchiveReader::open(&archive, None, ReadLimits::default()).unwrap();
    let d = reader.index().chunk_table[0];
    let footer = reader.header().footer_offset as usize;
    drop(reader);
    let mut bad = original.clone();
    let mut h = d.header;
    h.hash[0] ^= 1;
    bad[d.offset as usize..d.offset as usize + 64].copy_from_slice(&h.to_bytes());
    fs::write(&archive, &bad).unwrap();
    let out = root.path().join("out");
    assert!(pipeline::unpack(&archive, &out, None, None, ReadLimits::default()).is_err());
    assert!(!out.exists());
    let mut bad = original;
    bad[footer + 32] ^= 1;
    fs::write(&archive, bad).unwrap();
    assert!(ArchiveReader::open(&archive, None, ReadLimits::default()).is_err());
}
#[test]
fn source_worker_and_reader_limits_fail_without_partial_archive_or_output() {
    let root = tempfile::tempdir().unwrap();
    let source = root.path().join("x");
    write(&source, &random(300_007));
    let mut variants = vec![
        PackOptions {
            threads: 0,
            ..options()
        },
        PackOptions {
            queue_depth: 0,
            ..options()
        },
        PackOptions {
            memory_limit: 1,
            ..options()
        },
        PackOptions {
            level: 0,
            ..options()
        },
        PackOptions {
            recovery_percent: Some(31),
            ..options()
        },
    ];
    for configure in [0, 1, 2, 3] {
        let mut o = options();
        match configure {
            0 => o.limits.decode.max_chunks = 1,
            1 => o.limits.decode.max_references = 1,
            2 => o.limits.max_total_output_bytes = 10,
            _ => o.limits.decode.max_index_bytes = 64,
        };
        variants.push(o);
    }
    for (i, o) in variants.into_iter().enumerate() {
        let archive = root.path().join(format!("bad-{i}.wxp"));
        assert!(
            pipeline::pack(&archive, std::slice::from_ref(&source), o, None).is_err(),
            "variant {i}"
        );
        assert!(!archive.exists());
    }
    let archive = root.path().join("good.wxp");
    pipeline::pack(&archive, &[source], options(), None).unwrap();
    let mut limits = ReadLimits {
        max_total_output_bytes: 1,
        ..ReadLimits::default()
    };
    assert!(ArchiveReader::open(&archive, None, limits).is_err());
    limits = ReadLimits::default();
    limits.decode.max_index_bytes = 64;
    assert!(ArchiveReader::open(&archive, None, limits).is_err());
}
#[test]
fn existing_archives_and_output_directories_are_never_overwritten() {
    let root = tempfile::tempdir().unwrap();
    let source = root.path().join("x");
    write(&source, b"original");
    let archive = root.path().join("x.wxp");
    pipeline::pack(&archive, std::slice::from_ref(&source), options(), None).unwrap();
    let before = fs::read(&archive).unwrap();
    assert!(pipeline::pack(&archive, &[source], options(), None).is_err());
    assert_eq!(fs::read(&archive).unwrap(), before);
    let out = root.path().join("out");
    write(&out.join("sentinel"), b"keep");
    assert!(pipeline::unpack(&archive, &out, None, None, ReadLimits::default()).is_err());
    assert_eq!(fs::read(out.join("sentinel")).unwrap(), b"keep");
}
fn empty_store(entries: Vec<FileEntry>) -> Vec<u8> {
    let footer = IndexFooter::new(HeaderFlags::empty(), vec![], entries).unwrap();
    let payload = IndexEnvelope::store(&footer).unwrap();
    let mut header = SuperBlock::new(HeaderFlags::empty(), 16, 16, 20).unwrap();
    header.footer_comp_size = payload.len() as u64;
    header.footer_uncomp_size = payload.len() as u64 - 32;
    header.refresh_checksum();
    let mut bytes = header.to_bytes().to_vec();
    bytes.extend(payload);
    bytes
}
fn empty_entry(name: &str) -> FileEntry {
    FileEntry {
        path: name.into(),
        file_size: 0,
        mode: 0o644,
        mtime_secs: 0,
        mtime_nanos: 0,
        file_hash: *blake3::hash(&[]).as_bytes(),
        flags: FileFlags::REGULAR,
        symlink_target: None,
        chunk_ids: vec![],
    }
}
#[test]
fn hostile_paths_and_case_collisions_never_escape_extraction() {
    let root = tempfile::tempdir().unwrap();
    let archive = root.path().join("bad.wxp");
    let mut bad = empty_store(vec![empty_entry("ok/escape")]);
    let at = bad.windows(9).position(|x| x == b"ok/escape").unwrap();
    bad[at..at + 9].copy_from_slice(b"../escape");
    let hash_start = bad.len() - 32;
    let digest = *blake3::hash(&bad[96..hash_start]).as_bytes();
    bad[hash_start..].copy_from_slice(&digest);
    fs::write(&archive, bad).unwrap();
    let out = root.path().join("out");
    assert!(pipeline::unpack(&archive, &out, None, None, ReadLimits::default()).is_err());
    assert!(!out.exists());
    assert!(!root.path().join("escape").exists());
    fs::write(
        &archive,
        empty_store(vec![empty_entry("Same"), empty_entry("same")]),
    )
    .unwrap();
    assert!(ArchiveReader::open(&archive, None, ReadLimits::default()).is_err());
}
#[test]
fn selection_rejects_missing_files_directories_and_unsafe_names() {
    let root = tempfile::tempdir().unwrap();
    let source = root.path().join("source");
    fixture(&source);
    let archive = root.path().join("x.wxp");
    pipeline::pack(&archive, &[source], options(), None).unwrap();
    for (i, name) in ["absent", "source", "../escape"].iter().enumerate() {
        let out = root.path().join(format!("{i}"));
        assert!(pipeline::unpack(&archive, &out, Some(name), None, ReadLimits::default()).is_err());
        assert!(!out.exists());
    }
}
#[test]
#[cfg(unix)]
fn symlinks_stay_inside_the_archive_and_existing_output_symlinks_are_rejected() {
    let root = tempfile::tempdir().unwrap();
    let source = root.path().join("source");
    write(&source.join("nested/data"), b"target");
    fs::create_dir(source.join("empty")).unwrap();
    std::os::unix::fs::symlink("nested/data", source.join("link")).unwrap();
    std::os::unix::fs::symlink("empty", source.join("directory-link")).unwrap();
    std::os::unix::fs::symlink(".", source.join("self-link")).unwrap();
    let archive = root.path().join("x.wxp");
    pipeline::pack(&archive, std::slice::from_ref(&source), options(), None).unwrap();
    let out = root.path().join("out");
    pipeline::unpack(&archive, &out, None, None, ReadLimits::default()).unwrap();
    assert_eq!(fs::read(out.join("source/link")).unwrap(), b"target");
    assert!(out.join("source/directory-link").is_dir());
    assert_eq!(
        fs::read_link(out.join("source/self-link")).unwrap(),
        Path::new(".")
    );
    assert!(
        fs::symlink_metadata(out.join("source/link"))
            .unwrap()
            .file_type()
            .is_symlink()
    );
    let outside = root.path().join("outside");
    write(&outside.join("sentinel"), b"keep");
    let link = root.path().join("output-link");
    std::os::unix::fs::symlink(&outside, &link).unwrap();
    assert!(pipeline::unpack(&archive, &link, None, None, ReadLimits::default()).is_err());
    assert_eq!(fs::read(outside.join("sentinel")).unwrap(), b"keep");
    std::os::unix::fs::symlink(&outside, source.join("external")).unwrap();
    let bad = root.path().join("bad.wxp");
    assert!(pipeline::pack(&bad, &[source], options(), None).is_err());
    assert!(!bad.exists());
}
#[test]
#[cfg(unix)]
fn timestamps_and_executable_permissions_roundtrip_without_privileged_bits() {
    use std::os::unix::fs::PermissionsExt;
    let root = tempfile::tempdir().unwrap();
    let source = root.path().join("script");
    write(&source, b"#!/bin/sh\nexit 0\n");
    fs::set_permissions(&source, fs::Permissions::from_mode(0o4750)).unwrap();
    let t = filetime::FileTime::from_unix_time(-1, 123_456_789);
    filetime::set_file_mtime(&source, t).unwrap();
    let archive = root.path().join("x.wxp");
    pipeline::pack(&archive, &[source], options(), None).unwrap();
    let out = root.path().join("out");
    pipeline::unpack(&archive, &out, None, None, ReadLimits::default()).unwrap();
    let m = fs::metadata(out.join("script")).unwrap();
    assert_eq!(m.permissions().mode() & 0o7777, 0o750);
    assert_eq!(filetime::FileTime::from_last_modification_time(&m), t);
}
#[test]
fn benchmarking_runs_all_levels_verifies_data_and_obeys_memory_limit() {
    let root = tempfile::tempdir().unwrap();
    let source = root.path().join("text");
    write(&source, &b"function return const value\n".repeat(100));
    let rows = pipeline::bench(&source, 64 << 20).unwrap();
    assert_eq!(rows.iter().map(|r| r.level).collect::<Vec<_>>(), [1, 5, 9]);
    for r in rows {
        assert!(r.ratio <= 1.0);
        assert!(r.pack_mib_s.is_finite());
        assert!(r.unpack_mib_s.is_finite());
    }
    let empty = root.path().join("empty");
    write(&empty, b"");
    for r in pipeline::bench(&empty, 64 << 20).unwrap() {
        assert_eq!(r.ratio, 1.0);
        assert_eq!(r.input_bytes, 0);
    }
    assert!(pipeline::bench(&source, 1).is_err());
    let large = root.path().join("large");
    std::fs::File::create(&large)
        .unwrap()
        .set_len((16 << 20) + 1)
        .unwrap();
    assert!(pipeline::bench(&large, 64 << 20).is_err());
}
#[test]
fn cli_pack_list_unpack_verify_bench_and_chunk_demo_are_real_commands() {
    let root = tempfile::tempdir().unwrap();
    fixture(&root.path().join("source"));
    let text = success(cli(
        &[
            "pack",
            "archive.wxp",
            "source",
            "--dedup",
            "--solid",
            "-l",
            "1",
            "--threads",
            "2",
        ],
        root.path(),
    ));
    assert!(text.contains("packed files=6"));
    let listing = success(cli(&["list", "archive.wxp", "--detailed"], root.path()));
    assert!(listing.contains("source/nested/данные.json"));
    assert!(listing.contains("codec="));
    assert!(listing.contains("dedup_saved_mib="));
    assert!(success(cli(&["verify", "archive.wxp"], root.path())).contains("verified files=3"));
    success(cli(&["unpack", "archive.wxp", "-o", "out"], root.path()));
    compare(&root.path().join("source"), &root.path().join("out/source"));
    success(cli(
        &[
            "unpack",
            "archive.wxp",
            "-o",
            "selected",
            "--file",
            "source/random.bin",
        ],
        root.path(),
    ));
    assert!(!root.path().join("selected/source/empty.txt").exists());
    let bench = success(cli(&["bench", "source/empty.txt"], root.path()));
    assert!(bench.contains("pack_MiB/s"));
    assert_eq!(bench.lines().count(), 4);
    assert!(success(cli(&["chunk-demo", "source/random.bin"], root.path())).contains("chunks="));
}
#[test]
fn cli_password_environment_and_repair_work_without_password_in_argv_or_output() {
    let root = tempfile::tempdir().unwrap();
    write(&root.path().join("secret.txt"), b"private contents");
    let result = Command::new(env!("CARGO_BIN_EXE_wxp"))
        .args([
            "pack",
            "secret.wxp",
            "secret.txt",
            "--password-env",
            "WXP_TEST_PASSWORD",
            "--recovery",
            "1%",
            "--threads",
            "1",
        ])
        .env("WXP_TEST_PASSWORD", "never print this password")
        .current_dir(root.path())
        .output()
        .unwrap();
    let text = success(result);
    assert!(!text.contains("never print"));
    assert!(!cli(&["list", "secret.wxp"], root.path()).status.success());
    let result = Command::new(env!("CARGO_BIN_EXE_wxp"))
        .args([
            "unpack",
            "secret.wxp",
            "-o",
            "out",
            "--password-env",
            "WXP_TEST_PASSWORD",
        ])
        .env("WXP_TEST_PASSWORD", "never print this password")
        .current_dir(root.path())
        .output()
        .unwrap();
    success(result);
    assert_eq!(
        fs::read(root.path().join("out/secret.txt")).unwrap(),
        b"private contents"
    );
    let mut bad = fs::read(root.path().join("secret.wxp")).unwrap();
    bad[0] ^= 1;
    fs::write(root.path().join("secret.wxp"), bad).unwrap();
    let result = Command::new(env!("CARGO_BIN_EXE_wxp"))
        .args([
            "verify",
            "secret.wxp",
            "--repair",
            "--password-env",
            "WXP_TEST_PASSWORD",
        ])
        .env("WXP_TEST_PASSWORD", "never print this password")
        .current_dir(root.path())
        .output()
        .unwrap();
    assert!(success(result).contains("repaired_data_shards=1"));
}
#[test]
fn cli_usage_failures_are_nonzero_and_publish_nothing() {
    let root = tempfile::tempdir().unwrap();
    write(&root.path().join("input"), b"data");
    for args in [
        vec!["pack", "x.wxp", "input", "-l", "0"],
        vec!["pack", "x.wxp", "input", "--recovery", "31%"],
        vec!["pack", "x.wxp", "missing"],
        vec![
            "pack",
            "x.wxp",
            "input",
            "--password-env",
            "WXP_UNDEFINED_TEST",
        ],
        vec!["pack", "x.wxp", "input", "--threads", "0"],
        vec!["unknown"],
    ] {
        let result = cli(&args, root.path());
        assert!(!result.status.success());
        assert!(!root.path().join("x.wxp").exists());
    }
    assert!(success(cli(&["--help"], root.path())).contains("pack"));
    assert!(success(cli(&["--version"], root.path())).starts_with("wxp "));
}
#[test]
fn malformed_short_archives_fail_without_panics() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("bad.wxp");
    for n in 0..128 {
        fs::write(&path, random(n)).unwrap();
        let result =
            std::panic::catch_unwind(|| ArchiveReader::open(&path, None, ReadLimits::default()));
        assert!(result.is_ok());
        assert!(result.unwrap().is_err());
    }
}
#[test]
fn targets_must_have_distinct_portable_names_and_regular_input_kinds() {
    let root = tempfile::tempdir().unwrap();
    let a = root.path().join("a/Same");
    let b = root.path().join("b/same");
    write(&a, b"a");
    write(&b, b"b");
    let out = root.path().join("x.wxp");
    assert!(pipeline::pack(&out, &[a, b], options(), None).is_err());
    assert!(!out.exists());
    assert!(pipeline::pack(&out, &[], options(), None).is_err());
    #[cfg(unix)]
    {
        let sock = root.path().join("socket");
        use std::os::unix::ffi::OsStringExt;
        let non_utf8 = root.path().join(std::ffi::OsString::from_vec(vec![0xff]));
        write(&non_utf8, b"data");
        assert!(pipeline::pack(&out, &[non_utf8], options(), None).is_err());
        let _socket = std::os::unix::net::UnixListener::bind(&sock).unwrap();
        assert!(pipeline::pack(&out, &[sock], options(), None).is_err());
    }
}

#[test]
fn dot_directory_target_and_spaces_in_archive_name_work() {
    let root = tempfile::tempdir().unwrap();
    let source = root.path().join("workspace");
    fixture(&source);
    success(cli(
        &[
            "pack",
            "../archive with spaces.wxp",
            ".",
            "-l",
            "1",
            "--threads",
            "1",
        ],
        &source,
    ));
    success(cli(
        &["unpack", "archive with spaces.wxp", "-o", "out"],
        root.path(),
    ));
    compare(&source, &root.path().join("out/workspace"));
}
#[test]
fn repair_on_a_clean_archive_without_parity_is_a_regular_verification() {
    let root = tempfile::tempdir().unwrap();
    let source = root.path().join("data");
    write(&source, b"content");
    let archive = root.path().join("x.wxp");
    pipeline::pack(&archive, &[source], options(), None).unwrap();
    let original = fs::read(&archive).unwrap();
    let report = pipeline::verify(&archive, None, true, ReadLimits::default()).unwrap();
    assert_eq!(report.repaired_data_shards, 0);
    assert_eq!(fs::read(&archive).unwrap(), original);
    let reader = ArchiveReader::open(&archive, None, ReadLimits::default()).unwrap();
    let offset = reader.index().chunk_table[0].offset as usize + 64;
    drop(reader);
    let mut bad = original;
    bad[offset] ^= 1;
    fs::write(&archive, &bad).unwrap();
    assert!(pipeline::verify(&archive, None, true, ReadLimits::default()).is_err());
    assert_eq!(fs::read(&archive).unwrap(), bad);
}
#[test]
fn file_hash_failure_after_decoding_never_publishes_a_partial_output() {
    let root = tempfile::tempdir().unwrap();
    let source = root.path().join("data");
    write(&source, b"valid chunk but invalid file hash");
    let archive = root.path().join("x.wxp");
    pipeline::pack(&archive, &[source], options(), None).unwrap();
    let reader = ArchiveReader::open(&archive, None, ReadLimits::default()).unwrap();
    let mut footer = reader.index().clone();
    let mut header = *reader.header();
    drop(reader);
    footer.file_table[0].file_hash[0] ^= 1;
    let index = IndexEnvelope::store(&footer).unwrap();
    let mut bad = fs::read(&archive).unwrap()[..header.footer_offset as usize].to_vec();
    header.footer_uncomp_size = (index.len() - 32) as u64;
    header.footer_comp_size = index.len() as u64;
    header.refresh_checksum();
    bad[..64].copy_from_slice(&header.to_bytes());
    bad.extend(index);
    fs::write(&archive, bad).unwrap();
    let out = root.path().join("out");
    assert!(pipeline::unpack(&archive, &out, None, None, ReadLimits::default()).is_err());
    assert!(!out.exists());
    assert!(!fs::read_dir(root.path()).unwrap().any(|p| {
        p.unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with(".wxp-extract-")
    }));
}
#[test]
fn parallel_encrypted_writer_reorders_slow_and_fast_jobs_without_nonce_reuse() {
    let root = tempfile::tempdir().unwrap();
    let source = root.path().join("source");
    write(
        &source.join("a-text"),
        &b"function const return data\n".repeat(8000),
    );
    write(&source.join("b-random"), &random(400_007));
    let archive = root.path().join("x.wxp");
    let report = pipeline::pack(
        &archive,
        std::slice::from_ref(&source),
        PackOptions {
            level: 9,
            ..options()
        },
        Some(b"secret"),
    )
    .unwrap();
    assert!(report.peak_inflight <= 4);
    let out = root.path().join("out");
    pipeline::unpack(&archive, &out, None, Some(b"secret"), ReadLimits::default()).unwrap();
    compare(&source, &out.join("source"));
}
