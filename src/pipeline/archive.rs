use super::*;
use crate::crypto::ArchiveOpener;
use crate::filters::invert_transform;
use std::collections::{HashMap, HashSet};
use std::io::{Read, Seek};
use std::time::Instant;
use zeroize::Zeroizing;

#[derive(Debug, Clone, Copy, Default)]
pub struct ArchiveStats {
    pub logical_bytes: u64,
    pub unique_bytes: u64,
    pub stored_bytes: u64,
    pub dedup_saved: u64,
    pub transform_saved: i128,
    pub compression_saved: i128,
}
/// Loads only the central directory at open. File and chunk lookup do not scan
/// the payload; the FEC scan belongs to verify, never to selective extraction.
pub struct ArchiveReader {
    file: File,
    header: SuperBlock,
    index: IndexFooter,
    paths: HashMap<String, usize>,
    crypto: Option<ArchiveOpener>,
    limits: ReadLimits,
    solid_cache: Option<(ChunkId, Zeroizing<Vec<u8>>)>,
}
fn read_fixed<const N: usize>(file: &mut File, offset: u64) -> Result<[u8; N]> {
    let mut b = [0; N];
    file.seek(SeekFrom::Start(offset))?;
    file.read_exact(&mut b)?;
    Ok(b)
}
fn check_paths(index: &IndexFooter) -> Result<()> {
    let mut names = HashSet::new();
    let mut types = HashMap::new();
    for file in &index.file_table {
        if !names.insert(file.path.to_lowercase()) {
            return Err(invalid("case-colliding archive paths"));
        }
        types.insert(file.path.as_str(), file);
    }
    for file in &index.file_table {
        if let Some(target) = &file.symlink_target {
            let target = types
                .get(target.as_str())
                .ok_or_else(|| invalid("symlink target is absent from index"))?;
            if target.is_symlink() {
                return Err(invalid("symlink chains are not canonical archive targets"));
            }
        }
    }
    Ok(())
}
impl ArchiveReader {
    pub fn open(path: &Path, password: Option<&[u8]>, limits: ReadLimits) -> Result<Self> {
        if !fs::metadata(path)
            .map_err(|e| at("inspect archive", path, e))?
            .is_file()
        {
            return Err(invalid("archive input must be a regular file"));
        }
        let file = File::open(path).map_err(|e| at("open archive", path, e))?;
        Self::from_file(file, password, limits)
    }
    fn from_file(mut file: File, password: Option<&[u8]>, limits: ReadLimits) -> Result<Self> {
        let length = file.metadata()?.len();
        let header = SuperBlock::from_bytes(&read_fixed(&mut file, 0)?)?;
        header.validate_archive_len(length, limits.decode)?;
        if header.flags.contains(HeaderFlags::REED_SOLOMON) {
            let sentinel = ReedSolomonSentinel::from_bytes(&read_fixed(&mut file, length - 32)?)?;
            sentinel.validate_archive(&header, length)?;
            let fec = FecHeader::from_bytes(&read_fixed(&mut file, sentinel.fec_offset)?)?;
            fec.validate_against(&sentinel)?;
        }
        let crypto = if header.flags.contains(HeaderFlags::ENCRYPTED_DATA) {
            let descriptor = CryptoDescriptor::from_bytes(&read_fixed(&mut file, 64)?)?;
            Some(ArchiveOpener::new(
                password.ok_or(PipelineError::PasswordRequired)?,
                descriptor,
                limits.crypto,
            )?)
        } else {
            None
        };
        let envelope = IndexEnvelope::from_bytes(
            &read_fixed(&mut file, header.footer_offset)?,
            limits.decode,
        )?;
        envelope.validate_against(&header, limits.decode)?;
        let mut payload = Zeroizing::new(bytes(
            usize::try_from(envelope.payload_size)
                .map_err(|_| PipelineError::ResourceLimit("index address space"))?,
        )?);
        file.read_exact(&mut payload)?;
        let decoded = if envelope.encrypted {
            let compressed = crypto
                .as_ref()
                .ok_or(PipelineError::PasswordRequired)?
                .open_index(&envelope, &payload, limits.decode)?;
            WexEngine::decompress(&compressed, envelope.codec, envelope.decoded_size as usize)?
        } else {
            WexEngine::decompress(&payload, envelope.codec, envelope.decoded_size as usize)?
        };
        let decoded = Zeroizing::new(decoded);
        let index = IndexFooter::deserialize_with_limits(&decoded, limits.decode)?;
        index.validate_against(&header)?;
        check_paths(&index)?;
        if index.total_uncompressed_bytes > limits.max_total_output_bytes {
            return Err(PipelineError::ResourceLimit("total output bytes"));
        }
        let mut paths = HashMap::new();
        paths
            .try_reserve(index.file_table.len())
            .map_err(|_| PipelineError::AllocationFailed)?;
        for (i, entry) in index.file_table.iter().enumerate() {
            paths.insert(entry.path.clone(), i);
        }
        Ok(Self {
            file,
            header,
            index,
            paths,
            crypto,
            limits,
            solid_cache: None,
        })
    }
    pub fn header(&self) -> &SuperBlock {
        &self.header
    }
    pub fn index(&self) -> &IndexFooter {
        &self.index
    }
    pub fn file_entry(&self, name: &str) -> Option<&FileEntry> {
        self.paths.get(name).map(|&i| &self.index.file_table[i])
    }
    pub fn stats(&self) -> ArchiveStats {
        let mut stats = ArchiveStats {
            logical_bytes: self.index.total_uncompressed_bytes,
            ..ArchiveStats::default()
        };
        for chunk in &self.index.chunk_table {
            let h = &chunk.header;
            let plain_stored = u64::from(h.compressed_size)
                - if h.flags.contains(ChunkFlags::ENCRYPTED) {
                    16
                } else {
                    0
                };
            stats.unique_bytes += u64::from(h.uncompressed_size);
            stats.stored_bytes += u64::from(h.compressed_size);
            stats.transform_saved +=
                i128::from(h.uncompressed_size) - i128::from(h.transformed_size);
            stats.compression_saved += i128::from(h.transformed_size) - i128::from(plain_stored);
        }
        stats.dedup_saved = stats.logical_bytes.saturating_sub(stats.unique_bytes);
        stats
    }
    pub fn read_chunk(&mut self, id: ChunkId) -> Result<Zeroizing<Vec<u8>>> {
        let d = *self
            .index
            .chunk_table
            .get(id.get() as usize)
            .ok_or_else(|| invalid("unknown ChunkID"))?;
        let header = ChunkHeader::from_bytes(&read_fixed(&mut self.file, d.offset)?)?;
        if header != d.header {
            return Err(invalid(format!("local/index chunk header mismatch: {id}")));
        }
        let mut payload = Zeroizing::new(bytes(header.compressed_size as usize)?);
        self.file.read_exact(&mut payload)?;
        header.verify_stored_payload(&payload)?;
        let transformed = if header.flags.contains(ChunkFlags::ENCRYPTED) {
            let compressed = self
                .crypto
                .as_ref()
                .ok_or(PipelineError::PasswordRequired)?
                .open_chunk(&header, &payload)?;
            WexEngine::decompress(&compressed, header.codec, header.transformed_size as usize)?
        } else {
            WexEngine::decompress(&payload, header.codec, header.transformed_size as usize)?
        };
        let transformed = Zeroizing::new(transformed);
        let original = Zeroizing::new(invert_transform(
            &transformed,
            header.transform,
            0,
            header.uncompressed_size as usize,
        )?);
        header.verify_original(&original)?;
        Ok(original)
    }
    fn cache_solid_group(&mut self, id: ChunkId) -> Result<()> {
        if self
            .solid_cache
            .as_ref()
            .is_some_and(|(cached, _)| *cached == id)
        {
            return Ok(());
        }
        // Drop and wipe the previous group before allocating its replacement.
        self.solid_cache = None;
        self.solid_cache = Some((id, self.read_chunk(id)?));
        Ok(())
    }
    /// Streams one file, keeping at most one decoded solid group live.
    pub fn extract_file<W: Write>(&mut self, name: &str, output: &mut W) -> Result<u64> {
        let number = *self
            .paths
            .get(name)
            .ok_or_else(|| invalid(format!("file not found: {name}")))?;
        if self.index.file_table[number].is_dir() || self.index.file_table[number].is_symlink() {
            return Err(invalid("selection is not a regular file"));
        }
        let mut hash = blake3::Hasher::new();
        let mut size = 0;
        for n in 0..self.index.file_table[number].chunk_ids.len() {
            let id = self.index.file_table[number].chunk_ids[n];
            if self.header.flags.contains(HeaderFlags::SOLID_GROUPS) {
                self.cache_solid_group(id)?;
                let range = self.index.file_table[number].chunk_ranges[n];
                let group = &self
                    .solid_cache
                    .as_ref()
                    .ok_or_else(|| invalid("missing decoded solid group"))?
                    .1;
                let data = group
                    .get(range.offset as usize..range.offset as usize + range.size as usize)
                    .ok_or_else(|| invalid("solid extraction range"))?;
                output.write_all(data)?;
                hash.update(data);
                size += data.len() as u64;
            } else {
                let data = self.read_chunk(id)?;
                output.write_all(&data)?;
                hash.update(&data);
                size += data.len() as u64;
            }
        }
        let entry = &self.index.file_table[number];
        if size != entry.file_size || hash.finalize().as_bytes() != &entry.file_hash {
            return Err(invalid(format!("file BLAKE3 mismatch: {name}")));
        }
        Ok(size)
    }
    fn verify_all(&mut self) -> Result<VerifyReport> {
        let mut checked = bytes(self.index.chunk_table.len())?;
        let mut regular_files = 0;
        for n in 0..self.index.file_table.len() {
            let file = &self.index.file_table[n];
            if file.is_dir() || file.is_symlink() {
                continue;
            }
            let name = file.path.clone();
            let refs = file.chunk_ids.clone();
            self.extract_file(&name, &mut io::sink())?;
            regular_files += 1;
            for id in refs {
                checked[id.get() as usize] = 1;
            }
        }
        for (n, &seen) in checked.iter().enumerate() {
            if seen == 0 {
                self.read_chunk(ChunkId::new(n as u32)?)?;
            }
        }
        if self.header.flags.contains(HeaderFlags::REED_SOLOMON) {
            let report = fec::verify_recovery(&mut self.file, self.limits.fec)?;
            if !report.is_clean() {
                return Err(invalid(format!(
                    "recovery damage: data={} parity={}; use verify --repair",
                    report.damaged_data_shards, report.damaged_parity_shards
                )));
            }
        }
        Ok(VerifyReport {
            files: regular_files,
            chunks: self.index.chunk_table.len(),
            repaired_data_shards: 0,
            repaired_parity_shards: 0,
        })
    }
}
#[derive(Debug, Clone, Copy, Default)]
pub struct VerifyReport {
    pub files: usize,
    pub chunks: usize,
    pub repaired_data_shards: u64,
    pub repaired_parity_shards: u64,
}
fn copy_hash<R: Read, W: Write>(reader: &mut R, writer: &mut W) -> Result<blake3::Hash> {
    let mut buffer = Zeroizing::new(bytes(1 << 20)?);
    let mut hash = blake3::Hasher::new();
    loop {
        let count = match reader.read(&mut buffer) {
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e.into()),
        };
        if count == 0 {
            break;
        }
        writer.write_all(&buffer[..count])?;
        hash.update(&buffer[..count]);
    }
    Ok(hash.finalize())
}
/// Repair operates on a private copy; only a fully repaired and semantically
/// verified archive replaces the original. Password/authentication failures never publish.
pub fn verify(
    path: &Path,
    password: Option<&[u8]>,
    repair: bool,
    limits: ReadLimits,
) -> Result<VerifyReport> {
    if !repair {
        return ArchiveReader::open(path, password, limits)?.verify_all();
    }
    let metadata = fs::symlink_metadata(path).map_err(|e| at("inspect repair archive", path, e))?;
    if !metadata.is_file() {
        return Err(invalid(
            "repair requires a regular archive file, not a symlink",
        ));
    }
    let mut original = File::open(path).map_err(|e| at("open repair source", path, e))?;
    if let Ok(raw) = read_fixed::<64>(&mut original, 0)
        && let Ok(header) = SuperBlock::from_bytes(&raw)
        && !header.flags.contains(HeaderFlags::REED_SOLOMON)
    {
        return ArchiveReader::from_file(original, password, limits)?.verify_all();
    }
    original.seek(SeekFrom::Start(0))?;
    let mut temporary = NamedTempFile::new_in(parent_of(path))?;
    let max_archive = limits
        .fec
        .max_protected_bytes
        .checked_add(limits.fec.max_fec_bytes)
        .and_then(|n| n.checked_add(32))
        .ok_or(PipelineError::ResourceLimit("repair length overflow"))?;
    if metadata.len() > max_archive || metadata.len() == u64::MAX {
        return Err(PipelineError::ResourceLimit("repair source size"));
    }
    let original_hash = copy_hash(
        &mut (&mut original).take(metadata.len() + 1),
        temporary.as_file_mut(),
    )?;
    if temporary.as_file().metadata()?.len() != metadata.len() {
        return Err(invalid("archive size changed while copying"));
    }
    let repairs = fec::repair_recovery(temporary.as_file_mut(), limits.fec)?;
    let mut reader = ArchiveReader::from_file(temporary.reopen()?, password, limits)?;
    let mut report = reader.verify_all()?;
    drop(reader);
    report.repaired_data_shards = repairs.damaged_data_shards;
    report.repaired_parity_shards = repairs.damaged_parity_shards;
    if !repairs.is_clean() {
        original.seek(SeekFrom::Start(0))?;
        if copy_hash(&mut original, &mut io::sink())? != original_hash
            || fs::symlink_metadata(path)?.is_symlink()
            || fs::metadata(path)?.len() != metadata.len()
            || fs::metadata(path)?.modified()? != metadata.modified()?
        {
            return Err(invalid("archive changed concurrently during repair"));
        }
        temporary
            .as_file()
            .set_permissions(metadata.permissions())?;
        temporary.as_file().sync_all()?;
        drop(original);
        temporary
            .persist(path)
            .map_err(|e| at("publish repaired archive", path, e.error))?;
    }
    Ok(report)
}
fn apply_metadata(path: &Path, entry: &FileEntry) -> Result<()> {
    filetime::set_file_mtime(
        path,
        filetime::FileTime::from_unix_time(entry.mtime_secs, entry.mtime_nanos),
    )
    .map_err(|e| at("set extracted mtime", path, e))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut mode = entry.mode & 0o777;
        if entry.flags.contains(FileFlags::READONLY) {
            mode &= !0o222;
        }
        fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
    }
    #[cfg(not(unix))]
    {
        let mut p = fs::metadata(path)?.permissions();
        p.set_readonly(entry.flags.contains(FileFlags::READONLY));
        fs::set_permissions(path, p)?;
    }
    Ok(())
}
fn relative_link(link: &str, target: &str) -> PathBuf {
    let parent: Vec<_> = link.split('/').collect();
    let target: Vec<_> = target.split('/').collect();
    let parents = &parent[..parent.len() - 1];
    let mut common = 0;
    while common < parents.len().min(target.len()) && parents[common] == target[common] {
        common += 1;
    }
    let mut path = PathBuf::new();
    for _ in common..parents.len() {
        path.push("..");
    }
    for part in &target[common..] {
        path.push(part);
    }
    if path.as_os_str().is_empty() {
        path.push(".");
    }
    path
}
fn symlink(target: &Path, link: &Path, is_dir: bool) -> Result<()> {
    #[cfg(unix)]
    {
        let _ = is_dir;
        std::os::unix::fs::symlink(target, link)?;
    }
    #[cfg(windows)]
    {
        if is_dir {
            std::os::windows::fs::symlink_dir(target, link)?;
        } else {
            std::os::windows::fs::symlink_file(target, link)?;
        }
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (target, link, is_dir);
        return Err(invalid("symlinks are not supported on this platform"));
    }
    Ok(())
}
/// Extracts into a private staging directory. Output must not already exist.
/// Nothing is published before selected file hashes and all planned paths validate.
pub fn unpack(
    archive: &Path,
    output: &Path,
    selection: Option<&str>,
    password: Option<&[u8]>,
    limits: ReadLimits,
) -> Result<usize> {
    match fs::symlink_metadata(output) {
        Ok(_) => {
            return Err(invalid(format!(
                "output already exists: {}",
                output.display()
            )));
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(at("inspect output", output, e)),
    }
    let mut reader = ArchiveReader::open(archive, password, limits)?;
    if let Some(name) = selection {
        validate_path(name)?;
        let entry = reader
            .file_entry(name)
            .ok_or_else(|| invalid(format!("file not found: {name}")))?;
        if entry.is_dir() || entry.is_symlink() {
            return Err(invalid("--file requires a regular file"));
        }
    }
    let entries: Vec<_> = reader
        .index
        .file_table
        .iter()
        .filter(|f| selection.is_none_or(|name| f.path == name))
        .cloned()
        .collect();
    let stage = tempfile::Builder::new()
        .prefix(".wxp-extract-")
        .tempdir_in(parent_of(output))
        .map_err(|e| at("create extraction staging directory", output, e))?;
    let mut extracted = 0;
    for entry in &entries {
        let path = stage.path().join(&entry.path);
        if entry.is_dir() {
            fs::create_dir_all(&path)?;
            continue;
        }
        if entry.is_symlink() {
            continue;
        }
        fs::create_dir_all(parent_of(&path))?;
        let mut file = fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&path)?;
        reader.extract_file(&entry.path, &mut file)?;
        file.sync_all()?;
        drop(file);
        extracted += 1;
    }
    for entry in &entries {
        if !entry.is_symlink() {
            continue;
        }
        let target = entry
            .symlink_target
            .as_ref()
            .ok_or_else(|| invalid("missing symlink target"))?;
        let path = stage.path().join(&entry.path);
        fs::create_dir_all(parent_of(&path))?;
        let is_dir = reader
            .file_entry(target)
            .ok_or_else(|| invalid("missing symlink target entry"))?
            .is_dir();
        symlink(&relative_link(&entry.path, target), &path, is_dir)?;
    }
    // Set directory modes/times last; restrictive parent modes must not prevent writes.
    for entry in &entries {
        if !entry.is_dir() && !entry.is_symlink() {
            apply_metadata(&stage.path().join(&entry.path), entry)?;
        }
    }
    for entry in entries.iter().rev() {
        if entry.is_dir() {
            apply_metadata(&stage.path().join(&entry.path), entry)?;
        }
    }
    // create_dir reserves the destination without replacing a raced-in path.
    fs::create_dir(output).map_err(|e| at("reserve extraction output", output, e))?;
    let published = (|| -> Result<()> {
        for child in fs::read_dir(stage.path())? {
            let child = child?;
            fs::rename(child.path(), output.join(child.file_name()))?;
        }
        Ok(())
    })();
    if let Err(error) = published {
        // Only our just-created output is eligible for cleanup; pre-existing output
        // paths are never opened or overwritten by extraction.
        let _ = fs::remove_dir_all(output);
        return Err(error);
    }
    Ok(extracted)
}
#[derive(Debug, Clone, Copy)]
pub struct BenchResult {
    pub level: u8,
    pub input_bytes: u64,
    pub stored_bytes: u64,
    pub pack_mib_s: f64,
    pub unpack_mib_s: f64,
    pub ratio: f64,
}
/// In-memory timings include reversible filters and verify every decoded byte.
/// Data is chunked to respect codec limits; no comparison against other tools is implied.
pub fn bench(path: &Path, memory_limit: usize) -> Result<Vec<BenchResult>> {
    if memory_limit < 64 << 20 {
        return Err(PipelineError::ResourceLimit("benchmark memory"));
    }
    if !fs::metadata(path)
        .map_err(|e| at("inspect benchmark input", path, e))?
        .is_file()
    {
        return Err(invalid("benchmark input must be a regular file"));
    }
    let mut file = File::open(path).map_err(|e| at("open benchmark input", path, e))?;
    let meta = file.metadata()?;
    if !meta.is_file() || meta.len() > memory_limit as u64 / 4 {
        return Err(PipelineError::ResourceLimit(
            "benchmark input exceeds memory/4",
        ));
    }
    let mut source = Zeroizing::new(bytes(meta.len() as usize)?);
    file.read_exact(&mut source)?;
    let mut tail = [0; 1];
    if file.read(&mut tail)? != 0 || file.metadata()?.modified()? != meta.modified()? {
        return Err(invalid("benchmark input changed"));
    }
    let mut rows = Vec::new();
    for level in [1, 5, 9] {
        let start = Instant::now();
        let mut encoded = Vec::new();
        let mut stored = 0u64;
        for chunk in crate::cdc::FastCdcIterator::new(&source, FastCdcConfig::default()) {
            let prepared = SmartTransform::prepare(chunk.data, ProfileHint::Auto)?;
            let packed = if prepared.bypass_compression {
                crate::codec::CompressedChunk {
                    codec: CodecType::Store,
                    data: prepared.data.to_vec(),
                }
            } else {
                WexEngine::compress(&prepared.data, level)?
            };
            stored += packed.data.len() as u64;
            encoded.push((
                chunk.offset,
                chunk.length,
                prepared.transform,
                prepared.data.len(),
                packed,
            ));
        }
        let pack_time = start.elapsed().as_secs_f64().max(f64::MIN_POSITIVE);
        let start = Instant::now();
        for (offset, length, transform, size, packed) in encoded {
            let transformed =
                Zeroizing::new(WexEngine::decompress(&packed.data, packed.codec, size)?);
            let original = Zeroizing::new(invert_transform(&transformed, transform, 0, length)?);
            if original.as_slice() != &source[offset..offset + length] {
                return Err(invalid("benchmark roundtrip mismatch"));
            }
        }
        let unpack_time = start.elapsed().as_secs_f64().max(f64::MIN_POSITIVE);
        let mib = source.len() as f64 / (1 << 20) as f64;
        rows.push(BenchResult {
            level,
            input_bytes: source.len() as u64,
            stored_bytes: stored,
            pack_mib_s: mib / pack_time,
            unpack_mib_s: mib / unpack_time,
            ratio: if source.is_empty() {
                1.0
            } else {
                stored as f64 / source.len() as f64
            },
        });
    }
    Ok(rows)
}
