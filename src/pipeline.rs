//! Bounded actor pipeline and complete archive operations for WXP v2.
//! The registration actor assigns deterministic IDs; Rayon compresses; a single
//! writer reorders a bounded window and owns encryption, offsets and publication.
mod archive;
mod buffer;
mod input;
pub use archive::{ArchiveReader, ArchiveStats, BenchResult, VerifyReport, bench, unpack, verify};
pub use buffer::BufferPool;

use crate::cdc::{CdcError, DedupEngine, FastCdcConfig};
use crate::codec::{CodecError, CompressionLevel, WexEngine};
use crate::crypto::{ArchiveSealer, CryptoError, CryptoLimits, KdfParameters};
use crate::fec::{self, FecError, FecLimits, RecoveryConfig};
use crate::filters::{FilterError, ProfileHint, SmartTransform};
use crate::format::*;
use buffer::BufferLease;
use crossbeam_channel::{Receiver, bounded, select};
use input::MappedSpan;
use std::collections::BTreeMap;
use std::fmt;
use std::fs::{self, File};
use std::io::{self, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tempfile::NamedTempFile;

pub type Result<T> = std::result::Result<T, PipelineError>;
#[derive(Debug)]
pub enum PipelineError {
    Io(io::Error),
    Path {
        operation: &'static str,
        path: PathBuf,
        source: io::Error,
    },
    Format(FormatError),
    Cdc(CdcError),
    Codec(CodecError),
    Filter(FilterError),
    Crypto(CryptoError),
    Fec(FecError),
    Invalid(String),
    ResourceLimit(&'static str),
    AllocationFailed,
    PasswordRequired,
    Cancelled,
    WorkerPanicked,
}
impl fmt::Display for PipelineError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "archive I/O: {e}"),
            Self::Path {
                operation,
                path,
                source,
            } => write!(f, "{operation} '{}': {source}", path.display()),
            Self::Format(e) => write!(f, "{e}"),
            Self::Cdc(e) => write!(f, "{e}"),
            Self::Codec(e) => write!(f, "{e}"),
            Self::Filter(e) => write!(f, "{e}"),
            Self::Crypto(e) => write!(f, "{e}"),
            Self::Fec(e) => write!(f, "{e}"),
            Self::Invalid(s) => f.write_str(s),
            Self::ResourceLimit(s) => write!(f, "pipeline resource limit: {s}"),
            Self::AllocationFailed => f.write_str("pipeline allocation failed"),
            Self::PasswordRequired => {
                f.write_str("encrypted archive requires --password or --password-env NAME")
            }
            Self::Cancelled => f.write_str("pipeline cancelled"),
            Self::WorkerPanicked => f.write_str("compression worker panicked"),
        }
    }
}
impl std::error::Error for PipelineError {}
macro_rules! conversion {
    ($from:ty,$variant:ident) => {
        impl From<$from> for PipelineError {
            fn from(e: $from) -> Self {
                Self::$variant(e)
            }
        }
    };
}
conversion!(io::Error, Io);
conversion!(FormatError, Format);
conversion!(CdcError, Cdc);
conversion!(CodecError, Codec);
conversion!(FilterError, Filter);
conversion!(CryptoError, Crypto);
conversion!(FecError, Fec);
pub(super) fn invalid(s: impl Into<String>) -> PipelineError {
    PipelineError::Invalid(s.into())
}
pub(super) fn at(operation: &'static str, path: &Path, e: io::Error) -> PipelineError {
    PipelineError::Path {
        operation,
        path: path.to_path_buf(),
        source: e,
    }
}
pub(super) fn bytes(size: usize) -> Result<Vec<u8>> {
    let mut v = Vec::new();
    v.try_reserve_exact(size)
        .map_err(|_| PipelineError::AllocationFailed)?;
    v.resize(size, 0);
    Ok(v)
}
pub(super) fn push<T>(v: &mut Vec<T>, value: T) -> Result<()> {
    if v.len() == v.capacity() {
        v.try_reserve(1)
            .map_err(|_| PipelineError::AllocationFailed)?;
    }
    v.push(value);
    Ok(())
}
pub(super) fn parent_of(path: &Path) -> &Path {
    path.parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."))
}

#[derive(Debug, Clone, Copy)]
pub struct ReadLimits {
    pub decode: DecodeLimits,
    pub crypto: CryptoLimits,
    pub fec: FecLimits,
    pub max_total_output_bytes: u64,
}
impl Default for ReadLimits {
    fn default() -> Self {
        Self {
            decode: DecodeLimits {
                max_index_bytes: 64 << 20,
                ..DecodeLimits::default()
            },
            crypto: CryptoLimits::default(),
            fec: FecLimits::default(),
            max_total_output_bytes: 1 << 40,
        }
    }
}
#[derive(Debug, Clone)]
pub struct PackOptions {
    pub level: u8,
    pub dedup: bool,
    pub solid: bool,
    pub recovery_percent: Option<u8>,
    pub threads: usize,
    pub queue_depth: usize,
    pub memory_limit: usize,
    pub mmap: bool,
    pub mmap_threshold: u64,
    pub chunking: Option<FastCdcConfig>,
    pub kdf: KdfParameters,
    pub limits: ReadLimits,
}
impl Default for PackOptions {
    fn default() -> Self {
        let threads = std::thread::available_parallelism()
            .map_or(1, usize::from)
            .min(4);
        Self {
            level: 5,
            dedup: false,
            solid: false,
            recovery_percent: None,
            threads,
            queue_depth: threads * 2,
            memory_limit: 512 << 20,
            mmap: true,
            mmap_threshold: 8 << 20,
            chunking: None,
            kdf: KdfParameters::default(),
            limits: ReadLimits::default(),
        }
    }
}
#[derive(Debug, Clone, Copy, Default)]
pub struct PackReport {
    pub files: usize,
    pub chunks: u32,
    pub input_bytes: u64,
    pub unique_bytes: u64,
    pub payload_bytes: u64,
    pub archive_bytes: u64,
    pub dedup_saved: u64,
    pub transform_saved: i128,
    pub compression_saved: i128,
    pub peak_inflight: usize,
    pub mapped_files: usize,
    pub streamed_files: usize,
}
struct Job {
    id: ChunkId,
    hash: Fingerprint,
    lease: BufferLease,
    mapped: Option<MappedSpan>,
}
struct Finished {
    header: ChunkHeader,
    lease: BufferLease,
}
struct ProducerSummary {
    files: Vec<FileEntry>,
    unique_bytes: u64,
    mapped_files: usize,
    streamed_files: usize,
}

fn compress(mut job: Job, level: u8, solid: bool) -> Result<Finished> {
    let buffers = job.lease.buffers_mut();
    let raw = job
        .mapped
        .as_ref()
        .map_or(buffers.input.as_slice(), MappedSpan::as_slice);
    let prepared = SmartTransform::prepare(raw, ProfileHint::Auto)?;
    let mut transform = prepared.transform;
    let mut transformed_size = prepared.data.len();
    let codec = if solid {
        // Word substitution often loses to the large raw LZ history. Numeric
        // shuffles and BCJ go first instead. Both orders retain the same winner:
        // a losing second pass stops only at a proven append-only size bound.
        if prepared.transform == TransformType::DictWord
            && prepared.data.len() <= MAX_SOLID_GROUP_SIZE
        {
            let identity_codec = WexEngine::compress_solid_into(raw, level, &mut buffers.output)?;
            let mut filtered = Vec::new();
            if let Some(filtered_codec) = WexEngine::compress_solid_bounded_into(
                &prepared.data,
                level,
                &mut filtered,
                buffers.output.len().saturating_sub(1),
            )? {
                buffers.output = filtered;
                filtered_codec
            } else {
                transform = TransformType::None;
                transformed_size = raw.len();
                identity_codec
            }
        } else if prepared.transform != TransformType::None
            && prepared.data.len() <= MAX_SOLID_GROUP_SIZE
        {
            let filtered_codec =
                WexEngine::compress_solid_into(&prepared.data, level, &mut buffers.output)?;
            let mut identity = Vec::new();
            if let Some(identity_codec) = WexEngine::compress_solid_bounded_into(
                raw,
                level,
                &mut identity,
                buffers.output.len(),
            )? {
                buffers.output = identity;
                transform = TransformType::None;
                transformed_size = raw.len();
                identity_codec
            } else {
                filtered_codec
            }
        } else {
            transform = TransformType::None;
            transformed_size = raw.len();
            WexEngine::compress_solid_into(raw, level, &mut buffers.output)?
        }
    } else if prepared.bypass_compression {
        buffers.output.clear();
        buffers.output.extend_from_slice(&prepared.data);
        CodecType::Store
    } else {
        WexEngine::compress_into(&prepared.data, level, &mut buffers.output)?
    };
    let header = ChunkHeader {
        chunk_id: job.id,
        uncompressed_size: raw.len() as u32,
        transformed_size: transformed_size as u32,
        compressed_size: buffers.output.len() as u32,
        codec,
        transform,
        flags: ChunkFlags::empty(),
        hash: job.hash,
        crc32: crc32fast::hash(&buffers.output),
    };
    header.validate()?;
    Ok(Finished {
        header,
        lease: job.lease,
    })
}
fn write_results(
    file: &mut File,
    rx: &Receiver<Result<Finished>>,
    sealer: &mut Option<ArchiveSealer>,
) -> Result<(Vec<ChunkDescriptor>, u64, i128, i128)> {
    let mut pending = BTreeMap::new();
    let mut expected = 0u32;
    let mut descriptors = Vec::new();
    let mut payload = 0;
    let mut filter_saved = 0i128;
    let mut codec_saved = 0i128;
    while let Ok(result) = rx.recv() {
        let finished = result?;
        let id = finished.header.chunk_id.get();
        if id < expected || pending.insert(id, finished).is_some() {
            return Err(invalid("duplicate compression result"));
        }
        while let Some(mut finished) = pending.remove(&expected) {
            let buffers = finished.lease.buffers_mut();
            let mut header = finished.header;
            filter_saved +=
                i128::from(header.uncompressed_size) - i128::from(header.transformed_size);
            codec_saved += i128::from(header.transformed_size) - i128::from(header.compressed_size);
            let encrypted;
            let stored = if let Some(sealer) = sealer {
                (header, encrypted) = sealer.seal_chunk(header, &buffers.output)?;
                &encrypted
            } else {
                &buffers.output
            };
            let offset = file.stream_position()?;
            header.write_to(file)?;
            file.write_all(stored)?;
            payload += u64::from(header.compressed_size);
            push(&mut descriptors, ChunkDescriptor { offset, header })?;
            expected = expected
                .checked_add(1)
                .ok_or(PipelineError::ResourceLimit("ChunkID count"))?;
        }
    }
    if !pending.is_empty() {
        return Err(invalid("missing ordered compression result"));
    }
    Ok((descriptors, payload, filter_saved, codec_saved))
}

/// Creates a new archive without overwriting an existing path. Publication follows
/// successful worker joins, index finalization, parity generation and file sync.
pub fn pack(
    archive: &Path,
    targets: &[PathBuf],
    options: PackOptions,
    password: Option<&[u8]>,
) -> Result<PackReport> {
    CompressionLevel::new(options.level)?;
    let cdc = options.chunking.unwrap_or_default();
    if !(1..=64).contains(&options.threads)
        || !(1..=256).contains(&options.queue_depth)
        || options.queue_depth < options.threads
        || options.memory_limit < 32 << 20
    {
        return Err(PipelineError::ResourceLimit(
            "threads/queue/memory configuration",
        ));
    }
    let metadata_budget = options.memory_limit / 4;
    if options.solid && cdc.max_size() > MAX_SOLID_GROUP_SIZE {
        return Err(PipelineError::ResourceLimit(
            "CDC chunk exceeds solid group",
        ));
    }
    if cdc.normalization() != 2 {
        return Err(invalid("WXP v2 uses FastCDC normalization=2"));
    }
    if password.is_some()
        && u64::from(options.kdf.memory_kib) * 1024 + (metadata_budget / 2) as u64
            > options.memory_limit as u64
    {
        return Err(PipelineError::ResourceLimit("KDF and manifest workspace"));
    }

    let chunk_capacity = if options.solid {
        MAX_SOLID_GROUP_SIZE
    } else {
        cdc.max_size()
    };
    let scratch = if options.solid {
        152 << 20
    } else if options.level >= 4 {
        32 << 20
    } else {
        8 << 20
    };
    // Threads/queue are upper bounds. A large solid history gets fewer concurrent
    // workers rather than silently exceeding the caller's memory budget.
    let mut workers = options.threads;
    let mut slots = options.queue_depth;
    loop {
        let working = workers
            .checked_mul(scratch)
            .and_then(|v| v.checked_add(slots.checked_mul(2 * chunk_capacity + (64 << 10))?))
            .and_then(|v| v.checked_add(3 * cdc.max_size() + (128 << 10)))
            .ok_or(PipelineError::ResourceLimit("workspace overflow"))?;
        if working <= options.memory_limit - metadata_budget {
            break;
        }
        if !options.solid || (workers == 1 && slots == 1) {
            return Err(PipelineError::ResourceLimit("worker and buffer workspace"));
        }
        if slots > workers {
            slots -= 1;
        } else {
            workers -= 1;
            slots = slots.min(workers * 2).max(workers);
        }
    }
    let recovery = options
        .recovery_percent
        .map(RecoveryConfig::for_percent)
        .transpose()?;
    match fs::symlink_metadata(archive) {
        Ok(_) => {
            return Err(invalid(format!(
                "archive already exists: {}",
                archive.display()
            )));
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(at("inspect archive", archive, e)),
    }
    let manifest = input::collect(targets, options.limits.decode.max_files, metadata_budget)?;
    let declared = manifest
        .iter()
        .try_fold(0u64, |sum, m| sum.checked_add(m.entry.file_size))
        .ok_or(PipelineError::ResourceLimit("declared input bytes"))?;
    if declared > options.limits.max_total_output_bytes {
        return Err(PipelineError::ResourceLimit("declared input bytes"));
    }
    let flags = HeaderFlags::PRECOMP
        | if options.dedup {
            HeaderFlags::DEDUP
        } else {
            HeaderFlags::empty()
        }
        | if options.solid {
            HeaderFlags::SOLID | HeaderFlags::SOLID_GROUPS
        } else {
            HeaderFlags::empty()
        }
        | if password.is_some() {
            HeaderFlags::ENCRYPTED_DATA | HeaderFlags::ENCRYPTED_INDEX
        } else {
            HeaderFlags::empty()
        }
        | if recovery.is_some() {
            HeaderFlags::REED_SOLOMON
        } else {
            HeaderFlags::empty()
        };
    let mut header = SuperBlock::new(
        flags,
        cdc.min_size().trailing_zeros() as u8,
        cdc.avg_size().trailing_zeros() as u8,
        chunk_capacity.trailing_zeros() as u8,
    )?;
    let mut sealer = password
        .map(|p| ArchiveSealer::with_limits(p, options.kdf, options.limits.crypto))
        .transpose()?;
    let mut temp = NamedTempFile::new_in(parent_of(archive))
        .map_err(|e| at("create archive temporary file", archive, e))?;
    let file = temp.as_file_mut();
    file.write_all(&[0; 64])?;
    if let Some(sealer) = &sealer {
        file.write_all(&sealer.descriptor().to_bytes())?;
    }
    let buffers = BufferPool::new(slots, chunk_capacity, password.is_some())?;
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(workers)
        .thread_name(|n| format!("wxp-codec-{n}"))
        .build()
        .map_err(|e| invalid(format!("create compression workers: {e}")))?;
    let (jobs_tx, jobs_rx) = bounded::<Job>(slots);
    let (done_tx, done_rx) = bounded::<Result<Finished>>(slots);
    let (cancel_tx, cancel_rx) = bounded::<()>(0);
    let ((descriptors, payload_bytes, transform_saved, compression_saved), summary) =
        std::thread::scope(|scope| -> Result<_> {
            let producer_buffers = buffers.clone();
            let producer_cancel = cancel_rx.clone();
            let producer_options = &options;
            let producer = scope.spawn(move || {
                input::produce(
                    manifest,
                    producer_options,
                    cdc,
                    metadata_budget,
                    &producer_buffers,
                    &producer_cancel,
                    &jobs_tx,
                )
            });
            let consumers=scope.spawn(move|| {
            pool.scope(|scope| {
                for _ in 0..workers {
                    let jobs=jobs_rx.clone();let done=done_tx.clone();let cancelled=cancel_rx.clone();let level=options.level;let solid=options.solid;
                    scope.spawn(move |_|loop {
                        let job=select! {recv(cancelled)->_=>break,recv(jobs)->job=>match job {Ok(j)=>j,Err(_)=>break}};
                        let result=std::panic::catch_unwind(std::panic::AssertUnwindSafe(||compress(job,level,solid)))
                            .unwrap_or(Err(PipelineError::WorkerPanicked));
                        let failed=result.is_err();
                        select! {recv(cancelled)->_=>break,send(done,result)->sent=>if sent.is_err() {break;}}
                        if failed {break;}
                    });
                }
            });
        });
            let result = write_results(file, &done_rx, &mut sealer);
            drop(cancel_tx);
            drop(done_rx);
            let produced = producer.join().map_err(|_| PipelineError::WorkerPanicked);
            let consumed = consumers.join().map_err(|_| PipelineError::WorkerPanicked);
            let written = result?;
            let summary = produced??;
            consumed?;
            Ok((written, summary))
        })?;
    let peak_inflight = buffers.peak_inflight();
    drop(buffers);
    let unique_bytes = descriptors
        .iter()
        .map(|d| u64::from(d.header.uncompressed_size))
        .sum::<u64>();
    if unique_bytes != summary.unique_bytes {
        return Err(invalid("incomplete chunk store"));
    }
    header.chunk_count = u32::try_from(descriptors.len())
        .map_err(|_| PipelineError::ResourceLimit("chunk count"))?;
    header.footer_offset = file.stream_position()?;
    header.chunk_store_size = header.footer_offset - header.chunk_store_offset;
    let footer = IndexFooter::new(flags, descriptors, summary.files)?;
    let index_size = footer.serialized_size()?;
    if index_size > options.limits.decode.max_index_bytes as u64
        || index_size > metadata_budget as u64 / 2
    {
        return Err(PipelineError::ResourceLimit("central directory size"));
    }
    let raw = zeroize::Zeroizing::new(footer.serialize()?);
    header.footer_uncomp_size = raw.len() as u64;
    let index = WexEngine::compress(&raw, options.level)?;
    let mut envelope = IndexEnvelope {
        codec: index.codec,
        encrypted: false,
        decoded_size: raw.len() as u64,
        payload_size: index.data.len() as u64,
    };
    let mut index = zeroize::Zeroizing::new(index.data);
    if let Some(sealer) = &mut sealer {
        let (sealed, ciphertext) = sealer.seal_index(envelope, &index, options.limits.decode)?;
        envelope = sealed;
        index = zeroize::Zeroizing::new(ciphertext);
    }
    envelope.validate(options.limits.decode)?;
    file.write_all(&envelope.to_bytes())?;
    file.write_all(&index)?;
    header.footer_comp_size = 32 + index.len() as u64;
    header.refresh_checksum();
    footer.validate_against(&header)?;
    file.seek(SeekFrom::Start(0))?;
    header.write_to(file)?;
    if let Some(recovery) = recovery {
        let mut limits = options.limits.fec;
        limits.max_workspace_bytes = limits
            .max_workspace_bytes
            .min((options.memory_limit - metadata_budget) as u64);
        fec::append_recovery(file, recovery, limits)?;
    }
    let archive_bytes = file.metadata()?.len();
    header.validate_archive_len(archive_bytes, options.limits.decode)?;
    file.sync_all()?;
    let report = PackReport {
        files: footer.file_table.len(),
        chunks: header.chunk_count,
        input_bytes: footer.total_uncompressed_bytes,
        unique_bytes,
        payload_bytes,
        archive_bytes,
        dedup_saved: footer.total_uncompressed_bytes - unique_bytes,
        transform_saved,
        compression_saved,
        peak_inflight,
        mapped_files: summary.mapped_files,
        streamed_files: summary.streamed_files,
    };
    temp.persist_noclobber(archive)
        .map_err(|e| at("publish archive", archive, e.error))?;
    Ok(report)
}
