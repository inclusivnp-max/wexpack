use std::collections::HashSet;
use std::io::{self, Cursor, Read, Seek, SeekFrom};
use std::sync::{Arc, Barrier};
use std::thread;
use wexpack::cdc::*;
use wexpack::format::*;

fn data(length: usize) -> Vec<u8> {
    let mut state = 0x1234_5678_9abc_def0u64;
    (0..length)
        .map(|_| {
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
            (state >> 56) as u8
        })
        .collect()
}
fn file(path: &str, content: &[u8], ids: &[u32]) -> FileEntry {
    FileEntry {
        path: path.into(),
        file_size: content.len() as u64,
        mode: 0o644,
        mtime_secs: -1,
        mtime_nanos: 123,
        file_hash: *blake3::hash(content).as_bytes(),
        flags: FileFlags::REGULAR,
        symlink_target: None,
        chunk_ids: ids.iter().map(|&id| ChunkId::new(id).unwrap()).collect(),
        chunk_ranges: Vec::new(),
    }
}
fn chunk(id: u32, bytes: &[u8], offset: u64) -> ChunkDescriptor {
    ChunkDescriptor {
        offset,
        header: ChunkHeader {
            chunk_id: ChunkId::new(id).unwrap(),
            uncompressed_size: bytes.len() as u32,
            transformed_size: bytes.len() as u32,
            compressed_size: bytes.len() as u32,
            codec: CodecType::Store,
            transform: TransformType::None,
            flags: ChunkFlags::empty(),
            hash: *blake3::hash(bytes).as_bytes(),
            crc32: crc32fast::hash(bytes),
        },
    }
}
fn fixture() -> IndexFooter {
    IndexFooter::new(
        HeaderFlags::DEDUP,
        vec![chunk(0, b"alpha", 64), chunk(1, b"beta", 133)],
        vec![
            file("a.bin", b"alphabeta", &[0, 1]),
            file("copy.bin", b"alpha", &[0]),
            file("empty", b"", &[]),
        ],
    )
    .unwrap()
}
fn rehash(bytes: &mut [u8]) {
    let end = bytes.len() - 32;
    let digest = *blake3::hash(&bytes[..end]).as_bytes();
    bytes[end..].copy_from_slice(&digest);
}

#[test]
fn superblock_layout_and_endianness() {
    assert_eq!(std::mem::size_of::<SuperBlock>(), 64);
    assert_eq!(std::mem::align_of::<SuperBlock>(), 64);
    assert_eq!(std::mem::offset_of!(SuperBlock, chunk_store_offset), 16);
    assert_eq!(std::mem::offset_of!(SuperBlock, checksum), 56);
    let h = SuperBlock::new(HeaderFlags::DEDUP, 14, 16, 20).unwrap();
    let bytes = h.to_bytes();
    assert_eq!(
        &bytes[..16],
        &[87, 88, 80, 2, 2, 0, 1, 0, 14, 16, 20, 64, 0, 0, 0, 0]
    );
    assert_eq!(&bytes[16..24], &[64, 0, 0, 0, 0, 0, 0, 0]);
    assert_eq!(SuperBlock::from_bytes(&bytes).unwrap(), h);
    h.validate_archive_len(160, DecodeLimits::default())
        .unwrap();
}
#[test]
fn superblock_rejects_invalid_metadata() {
    for bits in [
        (0, 16, 20),
        (17, 16, 20),
        (14, 15, 20),
        (14, 20, 19),
        (14, 20, 27),
    ] {
        assert!(SuperBlock::new(HeaderFlags::empty(), bits.0, bits.1, bits.2).is_err());
    }
    assert!(SuperBlock::new(HeaderFlags::ENCRYPTED_INDEX, 14, 16, 20).is_err());
    let mut h = SuperBlock::new(HeaderFlags::empty(), 14, 16, 20).unwrap();
    for byte in 0..64 {
        let mut bytes = h.to_bytes();
        bytes[byte] ^= 1;
        assert!(SuperBlock::from_bytes(&bytes).is_err());
    }
    h.flags = HeaderFlags::from_bits_retain(0x8000);
    h.refresh_checksum();
    assert!(SuperBlock::from_bytes(&h.to_bytes()).is_err());
    h.flags = HeaderFlags::empty();
    h.footer_offset = u64::MAX;
    h.refresh_checksum();
    assert!(SuperBlock::from_bytes(&h.to_bytes()).is_err());
}
#[test]
fn header_bounds_and_stale_checksum() {
    let mut h = SuperBlock::new(HeaderFlags::empty(), 14, 16, 20).unwrap();
    assert!(
        h.validate_archive_len(159, DecodeLimits::default())
            .is_err()
    );
    assert!(
        h.validate_archive_len(161, DecodeLimits::default())
            .is_err()
    );
    h.chunk_count = 1;
    assert!(h.write_to(&mut Vec::new()).is_err());
    let mut h = SuperBlock::new(HeaderFlags::empty(), 14, 16, 20).unwrap();
    h.footer_uncomp_size = 1 << 40;
    h.refresh_checksum();
    assert!(matches!(
        h.validate_archive_len(160, DecodeLimits::default()),
        Err(FormatError::ResourceLimit(_))
    ));
}
#[test]
fn chunk_header_checks_payload_and_original() {
    let h = chunk(4, b"payload", 64).header;
    assert_eq!(ChunkHeader::from_bytes(&h.to_bytes()).unwrap(), h);
    h.verify_stored_payload(b"payload").unwrap();
    h.verify_original(b"payload").unwrap();
    assert!(h.verify_original(b"payloae").is_err());
    assert!(h.verify_stored_payload(b"payloae").is_err());
    for i in 0..64 {
        let mut b = h.to_bytes();
        b[i] ^= 1;
        assert!(ChunkHeader::from_bytes(&b).is_err());
    }
    let mut bad = h;
    bad.codec = CodecType::Store;
    bad.compressed_size -= 1;
    assert!(bad.validate().is_err());
    let mut bad = h;
    bad.flags = ChunkFlags::from_bits_retain(2);
    assert!(ChunkHeader::from_bytes(&bad.to_bytes()).is_err());
    let mut bytes = h.to_bytes();
    bytes[20] = 255;
    let crc = crc32fast::hash(&bytes[..60]);
    bytes[60..].copy_from_slice(&crc.to_le_bytes());
    assert!(matches!(
        ChunkHeader::from_bytes(&bytes),
        Err(FormatError::UnknownCodec(255))
    ));
    assert!(ChunkId::new(u32::MAX).is_err());
}
#[test]
fn index_roundtrip_offsets_and_lookup() {
    let index = fixture();
    let bytes = index.serialize().unwrap();
    assert_eq!(bytes.len() as u64, index.serialized_size().unwrap());
    assert_eq!(IndexFooter::deserialize(&bytes).unwrap(), index);
    // Fixed table records: offset 24 + ChunkID * 64. Chunk 1 starts at byte 133.
    assert_eq!(&bytes[88..96], &133u64.to_le_bytes());
    let lookup = index.lookup().unwrap();
    assert_eq!(lookup.file("a.bin").unwrap().file_size, 9);
    assert!(lookup.file("missing").is_none());
    assert_eq!(lookup.chunk(ChunkId::new(1).unwrap()).unwrap().offset, 133);
    let envelope = IndexEnvelope::store(&index).unwrap();
    assert_eq!(
        IndexEnvelope::open_store(&envelope, DecodeLimits::default()).unwrap(),
        index
    );
}
#[test]
fn index_validates_all_cross_references() {
    let mut index = fixture();
    index.file_table[0].chunk_ids[0] = ChunkId::new(12).unwrap();
    assert!(index.serialize().is_err());
    let mut index = fixture();
    index.chunk_table[1].header.chunk_id = ChunkId::new(0).unwrap();
    assert!(index.serialize().is_err());
    let mut index = fixture();
    index.chunk_table[1].offset -= 1;
    assert!(index.serialize().is_err());
    let mut index = fixture();
    index.file_table[1].path = "a.bin".into();
    assert!(index.serialize().is_err());
    let mut index = fixture();
    index.file_table[1].path = "a.bin/child".into();
    assert!(index.serialize().is_err());
    let mut index = fixture();
    index.file_table[0].file_size += 1;
    assert!(index.serialize().is_err());
    let mut index = fixture();
    index.total_uncompressed_bytes += 1;
    assert!(index.serialize().is_err());
    let mut index = fixture();
    index.chunk_table[0].header.transform = TransformType::BcjX86;
    assert!(index.serialize().is_err());
}
#[test]
fn index_rejects_truncation_corruption_and_trailing_data() {
    let bytes = fixture().serialize().unwrap();
    for length in 0..bytes.len() {
        assert!(IndexFooter::deserialize(&bytes[..length]).is_err());
    }
    for byte in 0..bytes.len() {
        let mut bad = bytes.clone();
        bad[byte] ^= 1;
        assert!(IndexFooter::deserialize(&bad).is_err());
    }
    let mut bad = bytes.clone();
    bad.insert(bad.len() - 32, 0);
    rehash(&mut bad);
    assert!(IndexFooter::deserialize(&bad).is_err());
    let mut bad = bytes.clone();
    bad[16..20].copy_from_slice(&u32::MAX.to_le_bytes());
    rehash(&mut bad);
    assert!(matches!(
        IndexFooter::deserialize(&bad),
        Err(FormatError::ResourceLimit(_))
    ));
    let mut bad = bytes.clone();
    bad[20..24].copy_from_slice(&u32::MAX.to_le_bytes());
    rehash(&mut bad);
    assert!(matches!(
        IndexFooter::deserialize(&bad),
        Err(FormatError::ResourceLimit(_))
    ));
    let mut bad = bytes.clone();
    bad[24 + 60] = 1;
    rehash(&mut bad);
    assert!(IndexFooter::deserialize(&bad).is_err());
    let mut bad = bytes.clone();
    let offsets = 24 + 2 * 64;
    bad[offsets + 8..offsets + 16].copy_from_slice(&u64::MAX.to_le_bytes());
    rehash(&mut bad);
    assert!(IndexFooter::deserialize(&bad).is_err());
}
#[test]
fn index_limits_are_enforced_before_allocating() {
    let bytes = fixture().serialize().unwrap();
    for limits in [
        DecodeLimits {
            max_index_bytes: 64,
            ..DecodeLimits::default()
        },
        DecodeLimits {
            max_chunks: 1,
            ..DecodeLimits::default()
        },
        DecodeLimits {
            max_files: 2,
            ..DecodeLimits::default()
        },
        DecodeLimits {
            max_references: 2,
            ..DecodeLimits::default()
        },
        DecodeLimits {
            max_path_bytes: 4,
            ..DecodeLimits::default()
        },
    ] {
        assert!(matches!(
            IndexFooter::deserialize_with_limits(&bytes, limits),
            Err(FormatError::ResourceLimit(_))
        ));
    }
    let mut record = Vec::new();
    file("x", b"", &[]).write_to(&mut record).unwrap();
    let last = record.len() - 4;
    record[last..].copy_from_slice(&u32::MAX.to_le_bytes());
    assert!(matches!(
        FileEntry::read_from(&mut Cursor::new(record), DecodeLimits::default()),
        Err(FormatError::ResourceLimit(_))
    ));
}
#[test]
fn portable_paths_and_file_kinds() {
    for path in [
        "",
        "/abs",
        "../out",
        "a/../b",
        "a//b",
        "a/./b",
        "C:/out",
        "a\\b",
        "x\0z",
        "CON",
        "a/LPT9.dat",
        "a.",
        "a ",
        "x?",
    ] {
        assert!(validate_path(path).is_err(), "accepted {path:?}");
    }
    for path in ["src/файл.rs", "a/b", "COM10", "weights/model.bin"] {
        validate_path(path).unwrap();
    }
    let mut entry = file("link", b"", &[]);
    entry.flags = FileFlags::SYMLINK;
    entry.symlink_target = Some("target".into());
    entry.file_hash = [0; 32];
    entry.validate().unwrap();
    let mut encoded = Vec::new();
    entry.write_to(&mut encoded).unwrap();
    assert_eq!(
        FileEntry::read_from(&mut Cursor::new(encoded), DecodeLimits::default()).unwrap(),
        entry
    );
    entry.symlink_target = Some("../outside".into());
    assert!(entry.validate().is_err());
    let mut entry = file("dir", b"", &[]);
    entry.flags = FileFlags::DIRECTORY;
    entry.file_hash = [0; 32];
    entry.validate().unwrap();
    entry.flags |= FileFlags::SYMLINK;
    assert!(entry.validate().is_err());
}
#[test]
fn index_envelope_roundtrip_and_bounds() {
    for codec in [
        CodecType::Store,
        CodecType::WexTurbo,
        CodecType::WexBalanced,
        CodecType::WexExtreme,
    ] {
        let e = IndexEnvelope {
            codec,
            encrypted: false,
            decoded_size: 100,
            payload_size: 100,
        };
        assert_eq!(
            IndexEnvelope::from_bytes(&e.to_bytes(), DecodeLimits::default()).unwrap(),
            e
        );
    }
    let bytes = IndexEnvelope::store(&fixture()).unwrap();
    assert!(IndexEnvelope::open_store(&bytes[..bytes.len() - 1], DecodeLimits::default()).is_err());
    let mut bad = bytes.clone();
    bad.push(0);
    assert!(IndexEnvelope::open_store(&bad, DecodeLimits::default()).is_err());
    for byte in 0..32 {
        let mut b: [u8; 32] = bytes[..32].try_into().unwrap();
        b[byte] ^= 1;
        assert!(IndexEnvelope::from_bytes(&b, DecodeLimits::default()).is_err());
    }
}
#[test]
fn crypto_and_fec_metadata_roundtrips() {
    let crypto = CryptoDescriptor {
        memory_kib: 65_536,
        iterations: 3,
        lanes: 4,
        salt: [1; 32],
        archive_id: [2; 16],
    };
    assert_eq!(
        CryptoDescriptor::from_bytes(&crypto.to_bytes()).unwrap(),
        crypto
    );
    for i in 0..128 {
        let mut b = crypto.to_bytes();
        b[i] ^= 1;
        assert!(CryptoDescriptor::from_bytes(&b).is_err());
    }
    let mut bad = crypto;
    bad.memory_kib = u32::MAX;
    assert!(bad.validate().is_err());
    let mut h = SuperBlock::new(HeaderFlags::REED_SOLOMON, 14, 16, 20).unwrap();
    let fec = FecHeader::new(160, 4096, 128, 16).unwrap();
    assert_eq!(FecHeader::from_bytes(&fec.to_bytes()).unwrap(), fec);
    assert_eq!(fec.stripes, 1);
    let sentinel = ReedSolomonSentinel::new(160, fec.payload_size().unwrap(), 16, 128).unwrap();
    assert_eq!(
        ReedSolomonSentinel::from_bytes(&sentinel.to_bytes()).unwrap(),
        sentinel
    );
    fec.validate_against(&sentinel).unwrap();
    let length = sentinel.fec_offset + sentinel.fec_size + 32;
    sentinel.validate_archive(&h, length).unwrap();
    h.validate_archive_len(length, DecodeLimits::default())
        .unwrap();
    for i in 0..64 {
        let mut b = fec.to_bytes();
        b[i] ^= 1;
        assert!(FecHeader::from_bytes(&b).is_err());
    }
    for i in 0..32 {
        let mut b = sentinel.to_bytes();
        b[i] ^= 1;
        assert!(ReedSolomonSentinel::from_bytes(&b).is_err());
    }
    assert!(FecHeader::new(160, 4096, 240, 16).is_err());
    assert!(FecHeader::new(160, 0, 128, 16).is_err());
    assert!(ReedSolomonSentinel::new(u64::MAX, 1, 16, 128).is_err());
    h.flags |= HeaderFlags::ENCRYPTED_DATA;
    h.chunk_store_offset = 192;
    h.footer_offset = 192;
    h.refresh_checksum();
    h.validate().unwrap();
}

#[test]
fn fastcdc_golden_vectors_from_independent_reference() {
    assert_eq!(GEAR_TABLE[0], 0xee77_9980_afc8_7c75);
    assert_eq!(GEAR_TABLE[1], 0xfec4_4549_145d_b43f);
    assert_eq!(GEAR_TABLE[255], 0xbf46_5a5b_cbcb_8d66);
    let config = FastCdcConfig::default();
    assert_eq!(config.strict_mask(), 0x3801_c01e_00f0_0780);
    assert_eq!(config.loose_mask(), 0x1801_c00e_0070_0380);
    let input = data(400_000);
    let lengths: Vec<_> = FastCdcIterator::new(&input, config)
        .map(|c| c.length)
        .collect();
    assert_eq!(lengths, [67_180, 73_765, 72_813, 72_155, 74_577, 39_510]);
}
#[test]
fn fastcdc_config_and_bounds() {
    for bounds in [
        (0, 64, 256, 2),
        (16, 63, 256, 2),
        (128, 64, 256, 2),
        (16, 64, 32, 2),
        (16, 64, 256, 7),
        (1, 1, 1, 0),
    ] {
        assert!(FastCdcConfig::custom(bounds.0, bounds.1, bounds.2, bounds.3).is_err());
    }
    for config in [
        FastCdcConfig::custom(16, 64, 256, 2).unwrap(),
        FastCdcConfig::custom(64, 64, 64, 2).unwrap(),
    ] {
        for length in [0, 1, 15, 16, 17, 63, 64, 65, 255, 256, 257, 4096, 16_384] {
            for bytes in [vec![0; length], vec![255; length], data(length)] {
                let chunks: Vec<_> = FastCdcIterator::new(&bytes, config).collect();
                assert_eq!(
                    chunks
                        .iter()
                        .flat_map(|c| c.data)
                        .copied()
                        .collect::<Vec<_>>(),
                    bytes
                );
                let mut offset = 0;
                for (n, c) in chunks.iter().enumerate() {
                    assert_eq!(c.offset, offset);
                    assert!(c.length > 0 && c.length <= config.max_size());
                    if n + 1 < chunks.len() {
                        assert!(c.length >= config.min_size());
                    }
                    assert_eq!(c.data.as_ptr(), bytes[c.offset..].as_ptr());
                    offset += c.length;
                }
            }
        }
    }
}
struct Fragmented<'a> {
    bytes: &'a [u8],
    width: usize,
    calls: usize,
}
impl Read for Fragmented<'_> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        self.calls += 1;
        if self.calls.is_multiple_of(7) {
            return Err(io::Error::from(io::ErrorKind::Interrupted));
        }
        let n = self.width.min(out.len()).min(self.bytes.len());
        out[..n].copy_from_slice(&self.bytes[..n]);
        self.bytes = &self.bytes[n..];
        Ok(n)
    }
}
#[test]
fn streaming_boundaries_ignore_short_reads_and_interrupts() {
    let bytes = data(100_003);
    let config = FastCdcConfig::custom(16, 64, 256, 2).unwrap();
    let expected: Vec<_> = FastCdcIterator::new(&bytes, config).collect();
    for width in [1, 3, 17, 65, 257, 4096, 65_536] {
        let mut stream = FastCdcStream::new(
            Fragmented {
                bytes: &bytes,
                width,
                calls: 0,
            },
            config,
        );
        for (ordinal, c) in expected.iter().enumerate() {
            let read = stream.next_chunk_ref().unwrap().unwrap();
            assert_eq!(read.ordinal, ordinal as u64);
            assert_eq!(read.offset, c.offset as u64);
            assert_eq!(read.data, c.data);
            assert_eq!(read.hash, *blake3::hash(c.data).as_bytes());
        }
        assert!(stream.next_chunk_ref().unwrap().is_none());
        assert!(stream.next_chunk_ref().unwrap().is_none());
    }
}
#[test]
fn owned_stream_matches_borrowed_and_handles_eof() {
    for length in [0, 1, 64, 256, 1025] {
        let bytes = data(length);
        let config = FastCdcConfig::custom(16, 64, 256, 2).unwrap();
        let mut stream = FastCdcStream::new(Cursor::new(&bytes), config);
        let mut restored = Vec::new();
        while let Some(chunk) = stream.next_chunk().unwrap() {
            restored.extend(chunk.data);
        }
        assert_eq!(restored, bytes);
    }
}
struct Broken;
impl Read for Broken {
    fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
        Err(io::Error::other("broken input"))
    }
}
#[test]
fn reader_failure_is_not_silently_treated_as_eof() {
    let mut stream = FastCdcStream::new(Broken, FastCdcConfig::default());
    assert!(stream.next_chunk_ref().is_err());
    assert!(stream.next_chunk_ref().is_err());
}
#[test]
fn fastcdc_resynchronizes_after_prefix_insertion() {
    let bytes = data(4 << 20);
    let mut edited = vec![42; 131];
    edited.extend_from_slice(&bytes);
    let config = FastCdcConfig::default();
    let original: HashSet<_> = FastCdcIterator::new(&bytes, config)
        .map(|c| *blake3::hash(c.data).as_bytes())
        .collect();
    let chunks: Vec<_> = FastCdcIterator::new(&edited, config).collect();
    let common = chunks
        .iter()
        .filter(|c| original.contains(blake3::hash(c.data).as_bytes()))
        .count();
    assert!(common * 100 > chunks.len() * 90);
}
#[test]
fn dedup_statistics_limits_and_duplicates() {
    let engine = DedupEngine::with_capacity_limit(2);
    let a = engine.process_chunk(b"alpha").unwrap();
    let b = engine.process_chunk(b"beta").unwrap();
    assert_eq!(a.chunk_id.get(), 0);
    assert_eq!(b.chunk_id.get(), 1);
    assert!(!a.is_duplicate);
    assert!(!b.is_duplicate);
    assert_eq!(engine.process_chunk(b"alpha").unwrap().chunk_id, a.chunk_id);
    assert!(engine.process_chunk(b"alpha").unwrap().is_duplicate);
    assert!(matches!(
        engine.process_chunk(b"gamma"),
        Err(CdcError::ChunkLimit)
    ));
    assert!(engine.process_chunk(&[]).is_err());
    let stats = engine.stats().unwrap();
    assert_eq!(
        stats,
        DedupStats {
            total_chunks: 4,
            unique_chunks: 2,
            duplicate_chunks: 2,
            total_input_bytes: 19,
            unique_bytes: 9,
            deduped_bytes: 10
        }
    );
    assert_eq!(engine.lookup(&a.hash), Some(a.chunk_id));
    assert_eq!(engine.unique_count(), 2);
    assert_eq!(DedupStats::default().dedup_factor(), 1.0);
    assert_eq!(DedupStats::default().savings_ratio(), 0.0);
}
#[test]
fn concurrent_dedup_assigns_exactly_one_id_per_fingerprint() {
    let engine = Arc::new(DedupEngine::new());
    let barrier = Arc::new(Barrier::new(12));
    let threads: Vec<_> = (0..12)
        .map(|_| {
            let engine = engine.clone();
            let barrier = barrier.clone();
            thread::spawn(move || {
                barrier.wait();
                (0..128u32)
                    .map(|n| engine.process_chunk(&n.to_le_bytes()).unwrap())
                    .collect::<Vec<_>>()
            })
        })
        .collect();
    let results: Vec<_> = threads.into_iter().map(|t| t.join().unwrap()).collect();
    for row in &results {
        for (n, value) in row.iter().enumerate() {
            assert_eq!(value.chunk_id, results[0][n].chunk_id);
        }
    }
    let ids: HashSet<_> = results[0].iter().map(|v| v.chunk_id).collect();
    assert_eq!(ids.len(), 128);
    assert_eq!(
        results.iter().flatten().filter(|v| !v.is_duplicate).count(),
        128
    );
    let stats = engine.stats().unwrap();
    assert_eq!(stats.total_chunks, 12 * 128);
    assert_eq!(stats.unique_chunks, 128);
    assert_eq!(
        stats.unique_chunks + stats.duplicate_chunks,
        stats.total_chunks
    );
    assert_eq!(
        stats.unique_bytes + stats.deduped_bytes,
        stats.total_input_bytes
    );
}
#[test]
fn random_access_store_archive_roundtrip() {
    let input = data(300_007);
    let config = FastCdcConfig::default();
    let engine = DedupEngine::new();
    let mut archive = Cursor::new(vec![0; 64]);
    archive.set_position(64);
    let mut descriptors = Vec::new();
    let mut ids = Vec::new();
    for c in FastCdcIterator::new(&input, config) {
        let outcome = engine.process_chunk(c.data).unwrap();
        ids.push(outcome.chunk_id.get());
        if !outcome.is_duplicate {
            let descriptor = chunk(outcome.chunk_id.get(), c.data, archive.position());
            descriptor.header.write_to(&mut archive).unwrap();
            std::io::Write::write_all(&mut archive, c.data).unwrap();
            descriptors.push(descriptor);
        }
    }
    let index = IndexFooter::new(
        HeaderFlags::DEDUP,
        descriptors,
        vec![file("original", &input, &ids), file("copy", &input, &ids)],
    )
    .unwrap();
    let envelope = IndexEnvelope::store(&index).unwrap();
    let mut header = SuperBlock::new(HeaderFlags::DEDUP, 14, 16, 20).unwrap();
    header.chunk_count = engine.unique_count();
    header.chunk_store_size = archive.position() - 64;
    header.footer_offset = archive.position();
    header.footer_comp_size = envelope.len() as u64;
    header.footer_uncomp_size = index.serialized_size().unwrap();
    header.refresh_checksum();
    index.validate_against(&header).unwrap();
    std::io::Write::write_all(&mut archive, &envelope).unwrap();
    archive.set_position(0);
    header.write_to(&mut archive).unwrap();
    let len = archive.get_ref().len() as u64;
    archive.set_position(0);
    let header = SuperBlock::read_from(&mut archive).unwrap();
    header
        .validate_archive_len(len, DecodeLimits::default())
        .unwrap();
    archive.seek(SeekFrom::Start(header.footer_offset)).unwrap();
    let mut index_bytes = vec![0; header.footer_comp_size as usize];
    archive.read_exact(&mut index_bytes).unwrap();
    let index = IndexEnvelope::open_store(&index_bytes, DecodeLimits::default()).unwrap();
    index.validate_against(&header).unwrap();
    let lookup = index.lookup().unwrap();
    let entry = lookup.file("copy").unwrap();
    let mut output = Vec::new();
    for &id in &entry.chunk_ids {
        let descriptor = lookup.chunk(id).unwrap();
        archive.seek(SeekFrom::Start(descriptor.offset)).unwrap();
        let h = ChunkHeader::read_from(&mut archive).unwrap();
        assert_eq!(h, descriptor.header);
        let mut bytes = vec![0; h.compressed_size as usize];
        archive.read_exact(&mut bytes).unwrap();
        h.verify_stored_payload(&bytes).unwrap();
        h.verify_original(&bytes).unwrap();
        output.extend(bytes);
    }
    assert_eq!(output, input);
    assert_eq!(*blake3::hash(&output).as_bytes(), entry.file_hash);
}
#[test]
fn malformed_index_payloads_never_panic() {
    for length in 64..600 {
        let mut bytes = data(length);
        bytes[..4].copy_from_slice(b"WXPI");
        bytes[4..8].copy_from_slice(&[2, 0, 0, 0]);
        rehash(&mut bytes);
        assert!(std::panic::catch_unwind(|| IndexFooter::deserialize(&bytes)).is_ok());
    }
}
