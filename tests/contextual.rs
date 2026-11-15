use std::fs;
use wexpack::{
    codec::WexEngine,
    format::{CodecType, HeaderFlags, SuperBlock},
    pipeline::{self, ArchiveReader, PackOptions, ReadLimits},
};
fn fixture() -> Vec<u8> {
    let mut out = Vec::new();
    let mut state = 0x617351923a891123u64;
    for _ in 0..600 {
        out.extend_from_slice(b"shared context header and repeated reference pattern\n");
        for _ in 0..40 {
            for (base, span) in [(b'a', 26), (b'0', 10), (b'A', 26), (b'!', 14)] {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                out.push(base + (state % span) as u8);
            }
        }
    }
    out
}
#[test]
fn contextual_frame_selects_real_codec_and_rejects_version_confusion() {
    let data = fixture().repeat(3);
    for solid in [false, true] {
        let mut encoded = Vec::new();
        let codec = WexEngine::compress_structured_into(&data, 5, solid, &mut encoded).unwrap();
        assert_eq!(codec, CodecType::WexContextual);
        assert_eq!(&encoded[..4], b"WXE\x04");
        assert_eq!(
            WexEngine::decompress(&encoded, codec, data.len()).unwrap(),
            data
        );
        assert!(WexEngine::decompress(&encoded, CodecType::WexStructured, data.len()).is_err());
        for revision in [1, 2, 3] {
            let mut bad = encoded.clone();
            bad[3] = revision;
            let crc = crc32fast::hash(&bad[..20]);
            bad[20..24].copy_from_slice(&crc.to_le_bytes());
            assert!(WexEngine::decompress(&bad, codec, data.len()).is_err());
        }
    }
}
#[test]
fn context_capability_is_required_for_chunk_and_header_and_crypto_roundtrip() {
    let temp = tempfile::tempdir().unwrap();
    let input = temp.path().join("source");
    let expected = fixture();
    fs::write(&input, &expected).unwrap();
    for encrypted in [false, true] {
        let archive = temp.path().join(if encrypted {
            "encrypted.wxp"
        } else {
            "plain.wxp"
        });
        let password = encrypted.then_some(b"contextual-fixture".as_slice());
        pipeline::pack(
            &archive,
            std::slice::from_ref(&input),
            PackOptions {
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
            },
            password,
        )
        .unwrap();
        let mut reader = ArchiveReader::open(&archive, password, ReadLimits::default()).unwrap();
        assert!(
            reader
                .header()
                .flags
                .contains(HeaderFlags::LITERAL_CONTEXT | HeaderFlags::STRUCTURED)
        );
        let mut index = reader.index().clone();
        index.flags.remove(HeaderFlags::LITERAL_CONTEXT);
        assert!(index.validate().is_err());
        let mut output = Vec::new();
        reader.extract_file("source", &mut output).unwrap();
        assert_eq!(output, expected);
        pipeline::verify(&archive, password, false, ReadLimits::default()).unwrap();
    }
    assert!(SuperBlock::new(HeaderFlags::LITERAL_CONTEXT, 14, 16, 18).is_err());
}
