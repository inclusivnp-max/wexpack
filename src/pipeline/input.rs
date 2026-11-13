use super::*;
use crate::cdc::{FastCdcIterator, FastCdcStream};
use crossbeam_channel::{Sender, TryRecvError};
use memmap2::Mmap;
use std::collections::{HashMap, HashSet};
use std::ops::Range;
use std::time::{SystemTime, UNIX_EPOCH};

pub(super) struct ManifestItem {
    source: PathBuf,
    pub(super) entry: FileEntry,
    modified: SystemTime,
}
pub(super) struct MappedSpan {
    mapping: Arc<Mmap>,
    range: Range<usize>,
}
impl MappedSpan {
    pub fn as_slice(&self) -> &[u8] {
        &self.mapping[self.range.clone()]
    }
}
fn cancelled(cancel: &Receiver<()>) -> Result<()> {
    match cancel.try_recv() {
        Err(TryRecvError::Empty) => Ok(()),
        _ => Err(PipelineError::Cancelled),
    }
}
fn mode(meta: &fs::Metadata) -> u32 {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        meta.mode() & 0o777
    }
    #[cfg(not(unix))]
    {
        if meta.is_dir() {
            0o755
        } else if meta.permissions().readonly() {
            0o444
        } else {
            0o644
        }
    }
}
fn timestamp(time: SystemTime) -> Result<(i64, u32)> {
    match time.duration_since(UNIX_EPOCH) {
        Ok(t) => Ok((
            i64::try_from(t.as_secs()).map_err(|_| invalid("mtime exceeds i64"))?,
            t.subsec_nanos(),
        )),
        Err(e) => {
            let t = e.duration();
            let secs = i64::try_from(t.as_secs()).map_err(|_| invalid("mtime exceeds i64"))?;
            if t.subsec_nanos() == 0 {
                Ok((-secs, 0))
            } else {
                Ok((-secs - 1, 1_000_000_000 - t.subsec_nanos()))
            }
        }
    }
}
pub(super) fn collect(
    targets: &[PathBuf],
    max_files: usize,
    budget: usize,
) -> Result<Vec<ManifestItem>> {
    if targets.is_empty() {
        return Err(invalid("pack needs at least one target"));
    }
    let mut pending = Vec::new();
    let mut items = Vec::new();
    let mut names = HashSet::new();
    let mut cost = 0usize;
    for target in targets {
        let resolved;
        let name = if let Some(name) = target.file_name() {
            name.to_str()
                .ok_or_else(|| invalid("non-UTF-8 target basename"))?
        } else {
            resolved =
                fs::canonicalize(target).map_err(|e| at("resolve target basename", target, e))?;
            match resolved.file_name() {
                Some(name) => name
                    .to_str()
                    .ok_or_else(|| invalid("non-UTF-8 target basename"))?,
                None => "root",
            }
        };
        validate_path(name)?;
        push(&mut pending, (target.clone(), name.to_owned()))?;
    }
    while let Some((source, name)) = pending.pop() {
        if items.len() + pending.len() >= max_files || !names.insert(name.to_lowercase()) {
            return Err(invalid("too many entries or colliding archive paths"));
        }
        cost = cost
            .checked_add(512 + 4 * (name.len() + source.as_os_str().len()))
            .ok_or(PipelineError::ResourceLimit("manifest size"))?;
        if cost > budget / 2 {
            return Err(PipelineError::ResourceLimit("input manifest"));
        }
        validate_path(&name)?;
        let meta = fs::symlink_metadata(&source).map_err(|e| at("inspect input", &source, e))?;
        let is_link = meta.file_type().is_symlink();
        if !meta.is_file() && !meta.is_dir() && !is_link {
            return Err(invalid(format!(
                "unsupported input kind: {}",
                source.display()
            )));
        }
        let modified = meta
            .modified()
            .map_err(|e| at("read input mtime", &source, e))?;
        let (mtime_secs, mtime_nanos) = timestamp(modified)?;
        let mode = mode(&meta);
        let mut flags = if is_link {
            FileFlags::SYMLINK
        } else if meta.is_dir() {
            FileFlags::DIRECTORY
        } else {
            FileFlags::REGULAR
        };
        if meta.permissions().readonly() {
            flags.insert(FileFlags::READONLY);
        }
        if meta.is_file() && mode & 0o111 != 0 {
            flags.insert(FileFlags::EXECUTABLE);
        }
        if meta.is_dir() {
            let mut children = Vec::new();
            for child in
                fs::read_dir(&source).map_err(|e| at("read input directory", &source, e))?
            {
                let child = child.map_err(|e| at("read directory entry", &source, e))?;
                let base = child
                    .file_name()
                    .into_string()
                    .map_err(|_| invalid("non-UTF-8 input name"))?;
                let child_name = format!("{name}/{base}");
                validate_path(&child_name)?;
                if items.len() + pending.len() + children.len() + 1 >= max_files
                    || (children.len() + pending.len() + 1).saturating_mul(512) > budget / 2
                {
                    return Err(PipelineError::ResourceLimit("directory entries"));
                }
                push(&mut children, (child.path(), child_name))?;
            }
            children.sort_by(|a, b| b.1.cmp(&a.1));
            pending.extend(children);
        }
        push(
            &mut items,
            ManifestItem {
                source,
                modified,
                entry: FileEntry {
                    path: name,
                    file_size: if meta.is_file() { meta.len() } else { 0 },
                    mode,
                    mtime_secs,
                    mtime_nanos,
                    file_hash: if meta.is_file() {
                        *blake3::hash(&[]).as_bytes()
                    } else {
                        [0; 32]
                    },
                    flags,
                    symlink_target: None,
                    chunk_ids: Vec::new(),
                },
            },
        )?;
    }
    items.sort_by(|a, b| a.entry.path.cmp(&b.entry.path));
    let mut sources = HashMap::new();
    for item in &items {
        if !item.entry.is_symlink() {
            let canonical =
                fs::canonicalize(&item.source).map_err(|e| at("resolve input", &item.source, e))?;
            sources
                .entry(canonical)
                .or_insert_with(|| item.entry.path.clone());
        }
    }
    for item in &mut items {
        if item.entry.is_symlink() {
            let target = fs::canonicalize(&item.source)
                .map_err(|e| at("resolve symlink target", &item.source, e))?;
            item.entry.symlink_target = Some(
                sources
                    .get(&target)
                    .ok_or_else(|| {
                        invalid(format!(
                            "symlink target is not included: {}",
                            item.source.display()
                        ))
                    })?
                    .clone(),
            );
        }
    }
    Ok(items)
}
fn safe_map(file: &File) -> Result<Option<Arc<Mmap>>> {
    // Mutable files use bounded reads. Only the OS-proven immutable case is
    // exposed as &[u8], retaining unsafe_code=forbid for the whole crate.
    match Mmap::map_if_safe(file) {
        Ok(map) => Ok(Some(Arc::new(map))),
        Err(e) if e.not_safe() || e.not_supported() => Ok(None),
        Err(e) => Err(PipelineError::Io(e.into())),
    }
}
struct Actor<'a> {
    options: &'a PackOptions,
    metadata_used: usize,
    metadata_budget: usize,
    pool: &'a BufferPool,
    cancel: &'a Receiver<()>,
    jobs: &'a Sender<Job>,
    registry: DedupEngine,
    next: u32,
    references: usize,
    total: u64,
    unique: u64,
}
impl Actor<'_> {
    fn chunk(
        &mut self,
        data: &[u8],
        mapped: Option<MappedSpan>,
        entry: &mut FileEntry,
        hasher: &mut blake3::Hasher,
    ) -> Result<()> {
        cancelled(self.cancel)?;
        hasher.update(data);
        self.references += 1;
        self.total = self
            .total
            .checked_add(data.len() as u64)
            .ok_or(PipelineError::ResourceLimit("input total"))?;
        if self.references > self.options.limits.decode.max_references
            || self.total > self.options.limits.max_total_output_bytes
        {
            return Err(PipelineError::ResourceLimit("references or input bytes"));
        }
        let (id, hash, duplicate) = if self.options.dedup {
            let d = self.registry.process_chunk(data)?;
            (d.chunk_id, d.hash, d.is_duplicate)
        } else {
            (
                ChunkId::new(self.next)?,
                *blake3::hash(data).as_bytes(),
                false,
            )
        };
        self.metadata_used = self
            .metadata_used
            .checked_add(if duplicate { 8 } else { 264 })
            .ok_or(PipelineError::ResourceLimit("metadata overflow"))?;
        if self.metadata_used > self.metadata_budget {
            return Err(PipelineError::ResourceLimit("dedup/index metadata"));
        }
        push(&mut entry.chunk_ids, id)?;
        if duplicate {
            return Ok(());
        }
        if self.next as usize >= self.options.limits.decode.max_chunks {
            return Err(PipelineError::ResourceLimit("chunk count"));
        }
        self.next = self
            .next
            .checked_add(1)
            .ok_or(PipelineError::ResourceLimit("ChunkID"))?;
        self.unique += data.len() as u64;
        let mut lease = self.pool.acquire(self.cancel)?;
        if mapped.is_none() {
            lease.buffers_mut().input.extend_from_slice(data);
        }
        let job = Job {
            id,
            hash,
            lease,
            mapped,
        };
        select! {recv(self.cancel)->_=>Err(PipelineError::Cancelled),send(self.jobs,job)->sent=>sent.map_err(|_|PipelineError::Cancelled)}
    }
}
pub(super) fn produce(
    manifest: Vec<ManifestItem>,
    options: &PackOptions,
    cdc: FastCdcConfig,
    metadata_budget: usize,
    pool: &BufferPool,
    cancel: &Receiver<()>,
    jobs: &Sender<Job>,
) -> Result<ProducerSummary> {
    let registry = DedupEngine::with_capacity_limit(
        u32::try_from(options.limits.decode.max_chunks).unwrap_or(u32::MAX),
    );
    let metadata_used = manifest
        .iter()
        .map(|m| 512 + 4 * (m.entry.path.len() + m.source.as_os_str().len()))
        .sum();
    let mut actor = Actor {
        options,
        metadata_used,
        metadata_budget,
        pool,
        cancel,
        jobs,
        registry,
        next: 0,
        references: 0,
        total: 0,
        unique: 0,
    };
    let mut files = Vec::new();
    let mut mapped_files = 0;
    let mut streamed_files = 0;
    for mut item in manifest {
        cancelled(cancel)?;
        if !item.entry.is_dir() && !item.entry.is_symlink() {
            let mut file =
                File::open(&item.source).map_err(|e| at("open input", &item.source, e))?;
            let meta = file.metadata()?;
            if !meta.is_file()
                || meta.len() != item.entry.file_size
                || meta.modified()? != item.modified
            {
                return Err(invalid(format!(
                    "input changed before reading: {}",
                    item.source.display()
                )));
            }
            let mut hash = blake3::Hasher::new();
            let before = actor.total;
            let mapping = if options.mmap
                && meta.len() >= options.mmap_threshold
                && meta.len() != 0
                && usize::try_from(meta.len()).is_ok()
            {
                safe_map(&file)?
            } else {
                None
            };
            if let Some(mapping) = mapping {
                mapped_files += 1;
                for c in FastCdcIterator::new(&mapping, cdc) {
                    actor.chunk(
                        c.data,
                        Some(MappedSpan {
                            mapping: mapping.clone(),
                            range: c.offset..c.offset + c.length,
                        }),
                        &mut item.entry,
                        &mut hash,
                    )?;
                }
            } else {
                streamed_files += 1;
                let mut stream = FastCdcStream::new(&mut file, cdc);
                while let Some(c) = stream
                    .next_chunk_ref()
                    .map_err(|e| at("read input", &item.source, e))?
                {
                    actor.chunk(c.data, None, &mut item.entry, &mut hash)?;
                }
            }
            if actor.total - before != meta.len()
                || file.metadata()?.len() != meta.len()
                || file.metadata()?.modified()? != item.modified
            {
                return Err(invalid(format!(
                    "input changed while reading: {}",
                    item.source.display()
                )));
            }
            item.entry.file_hash = *hash.finalize().as_bytes();
        }
        item.entry.validate()?;
        push(&mut files, item.entry)?;
    }
    Ok(ProducerSummary {
        files,
        unique_bytes: actor.unique,
        mapped_files,
        streamed_files,
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn mutable_files_use_streaming_without_unsafe_mapping() {
        let mut f = tempfile::tempfile().unwrap();
        f.write_all(b"mutable data").unwrap();
        assert!(safe_map(&f).unwrap().is_none());
    }
    #[test]
    #[cfg(target_os = "linux")]
    fn sealed_file_is_really_memory_mapped() {
        use rustix::fs::{MemfdFlags, SealFlags, fcntl_add_seals, memfd_create};
        let fd = memfd_create(
            c"wexpack-input",
            MemfdFlags::ALLOW_SEALING | MemfdFlags::CLOEXEC,
        )
        .unwrap();
        let mut file = File::from(fd);
        file.write_all(b"immutable mmap input").unwrap();
        fcntl_add_seals(
            &file,
            SealFlags::SHRINK | SealFlags::GROW | SealFlags::WRITE | SealFlags::SEAL,
        )
        .unwrap();
        let map = safe_map(&file).unwrap().unwrap();
        assert_eq!(map.as_ref().as_ref(), b"immutable mmap input");
        assert!(file.write_all(b"x").is_err());
    }
    #[test]
    #[cfg(target_os = "linux")]
    fn large_immutable_input_produces_zero_copy_mapped_jobs_with_backpressure() {
        use rustix::fs::{MemfdFlags, SealFlags, fcntl_add_seals, memfd_create};
        use std::os::fd::AsRawFd;
        let file = File::from(
            memfd_create(
                c"wxp-large",
                MemfdFlags::ALLOW_SEALING | MemfdFlags::CLOEXEC,
            )
            .unwrap(),
        );
        file.set_len(9 << 20).unwrap();
        fcntl_add_seals(
            &file,
            SealFlags::SHRINK | SealFlags::GROW | SealFlags::WRITE | SealFlags::SEAL,
        )
        .unwrap();
        let modified = file.metadata().unwrap().modified().unwrap();
        let (mtime_secs, mtime_nanos) = timestamp(modified).unwrap();
        let item = ManifestItem {
            source: PathBuf::from(format!("/proc/self/fd/{}", file.as_raw_fd())),
            modified,
            entry: FileEntry {
                path: "immutable.bin".into(),
                file_size: 9 << 20,
                mode: 0o600,
                mtime_secs,
                mtime_nanos,
                file_hash: [0; 32],
                flags: FileFlags::REGULAR,
                symlink_target: None,
                chunk_ids: Vec::new(),
            },
        };
        let options = PackOptions {
            threads: 1,
            queue_depth: 1,
            level: 1,
            ..PackOptions::default()
        };
        let pool = BufferPool::new(1, 1 << 20, false).unwrap();
        let (tx, rx) = crossbeam_channel::bounded(1);
        let (_cancel_tx, cancel) = crossbeam_channel::bounded(0);
        let mut total = 0u64;
        let mut hash = blake3::Hasher::new();
        std::thread::scope(|scope| {
            let worker = scope.spawn(|| {
                produce(
                    vec![item],
                    &options,
                    FastCdcConfig::default(),
                    1 << 20,
                    &pool,
                    &cancel,
                    &tx,
                )
            });
            // The producer borrows tx, so consume the exact known file size rather than waiting for EOF.
            while total < 9 << 20 {
                let mut job = rx.recv().unwrap();
                assert!(job.lease.buffers_mut().input.is_empty());
                let span = job.mapped.as_ref().unwrap();
                assert!(!span.as_slice().is_empty());
                total += span.as_slice().len() as u64;
                hash.update(span.as_slice());
                drop(job);
            }
            let summary = worker.join().unwrap().unwrap();
            assert_eq!(summary.mapped_files, 1);
            assert_eq!(summary.streamed_files, 0);
            assert_eq!(summary.files[0].file_hash, *hash.finalize().as_bytes());
        });
        assert_eq!(total, 9 << 20);
        assert_eq!(pool.peak_inflight(), 1);
    }
}
