//! WXP v2 command-line interface. Password values never appear in command arguments.
use clap::{Args, Parser, Subcommand};
use std::error::Error;
use std::fs::File;
use std::io;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Instant;
use wexpack::cdc::{DedupEngine, FastCdcConfig, FastCdcStream};
use wexpack::pipeline::{self, ArchiveReader, PackOptions, ReadLimits};
use zeroize::Zeroizing;

#[derive(Parser)]
#[command(
    name = "wxp",
    version,
    about = "WexPack v2 — deduplicating authenticated archives",
    arg_required_else_help = true
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}
#[derive(Args)]
struct Password {
    /// Prompt on the terminal without echoing the password.
    #[arg(long, conflicts_with = "password_env")]
    password: bool,
    /// Read password bytes from this UTF-8 environment variable, not from argv.
    #[arg(long, value_name = "NAME")]
    password_env: Option<String>,
}
impl Password {
    fn read(&self, confirm: bool) -> Result<Option<Zeroizing<Vec<u8>>>, Box<dyn Error>> {
        let secret = if let Some(name) = &self.password_env {
            Some(Zeroizing::new(
                std::env::var(name)
                    .map_err(|_| {
                        io::Error::new(
                            io::ErrorKind::InvalidInput,
                            format!(
                                "password environment variable '{name}' is missing or not UTF-8"
                            ),
                        )
                    })?
                    .into_bytes(),
            ))
        } else if self.password {
            let first = Zeroizing::new(rpassword::prompt_password("Password: ")?.into_bytes());
            if confirm {
                let second =
                    Zeroizing::new(rpassword::prompt_password("Confirm password: ")?.into_bytes());
                if first != second {
                    return Err(
                        io::Error::new(io::ErrorKind::InvalidInput, "passwords differ").into(),
                    );
                }
            }
            Some(first)
        } else {
            None
        };
        if secret
            .as_ref()
            .is_some_and(|s| s.is_empty() || s.len() > wexpack::crypto::MAX_PASSWORD_BYTES)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "password must contain 1..1048576 bytes",
            )
            .into());
        }
        Ok(secret)
    }
}
#[derive(Subcommand)]
enum Command {
    /// Create a new archive; existing archives are never overwritten.
    Pack {
        archive: PathBuf,
        #[arg(required=true,num_args=1..)]
        targets: Vec<PathBuf>,
        #[arg(short='l',long,default_value_t=5,value_parser=clap::value_parser!(u8).range(1..=9))]
        level: u8,
        #[arg(long)]
        dedup: bool,
        /// Share LZ history across files in bounded 16 MiB groups; selective reads decode one group.
        #[arg(long)]
        solid: bool,
        #[command(flatten)]
        password: Password,
        #[arg(long,value_parser=parse_percent,value_name="1..30[%]")]
        recovery: Option<u8>,
        #[arg(long,value_parser=clap::value_parser!(u8).range(1..=64))]
        threads: Option<u8>,
        #[arg(long,default_value_t=512,value_parser=clap::value_parser!(u32).range(64..=8192))]
        memory_mib: u32,
        /// Read all inputs as bounded streams, including immutable files.
        #[arg(long)]
        no_mmap: bool,
    },
    /// Extract to a new output directory, optionally reading only one file's chunks.
    Unpack {
        archive: PathBuf,
        #[arg(short = 'o', long)]
        output: Option<PathBuf>,
        #[arg(long)]
        file: Option<String>,
        #[command(flatten)]
        password: Password,
    },
    /// List paths and separate deduplication, transform and codec savings.
    List {
        archive: PathBuf,
        #[arg(long)]
        detailed: bool,
        #[command(flatten)]
        password: Password,
    },
    /// Verify all chunk/file BLAKE3 hashes and parity; repair publishes a verified copy.
    Verify {
        archive: PathBuf,
        #[arg(long)]
        repair: bool,
        #[command(flatten)]
        password: Password,
    },
    /// Benchmark levels 1, 5 and 9 in memory, checking every round trip.
    Bench {
        file: PathBuf,
        #[arg(long,default_value_t=512,value_parser=clap::value_parser!(u32).range(4..=8192))]
        memory_mib: u32,
    },
    /// Inspect content-defined boundaries and deduplication without writing an archive.
    ChunkDemo { file: PathBuf },
}
fn parse_percent(value: &str) -> Result<u8, String> {
    let value = value.strip_suffix('%').unwrap_or(value);
    let n = value
        .parse::<u8>()
        .map_err(|_| "recovery must be 1..30 or 1%..30%".to_owned())?;
    if (1..=30).contains(&n) {
        Ok(n)
    } else {
        Err("recovery must be 1..30%".into())
    }
}
fn memory_bytes(mib: u32) -> Result<usize, Box<dyn Error>> {
    (mib as usize).checked_mul(1 << 20).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "memory limit exceeds address space",
        )
        .into()
    })
}
fn run(cli: Cli) -> Result<(), Box<dyn Error>> {
    match cli.command {
        Command::Pack {
            archive,
            targets,
            level,
            dedup,
            solid,
            password,
            recovery,
            threads,
            memory_mib,
            no_mmap,
        } => {
            let secret = password.read(true)?;
            let mut options = PackOptions {
                level,
                dedup,
                solid,
                recovery_percent: recovery,
                memory_limit: memory_bytes(memory_mib)?,
                mmap: !no_mmap,
                ..PackOptions::default()
            };
            if let Some(n) = threads {
                options.threads = usize::from(n);
                options.queue_depth = usize::from(n) * 2;
            }
            let start = Instant::now();
            let report = pipeline::pack(
                &archive,
                &targets,
                options,
                secret.as_ref().map(|s| s.as_slice()),
            )?;
            println!(
                "packed files={} chunks={} input={} archive={} dedup_saved={} transform_saved={} codec_saved={} peak_inflight={} mapped={} streamed={} elapsed={:.3}s",
                report.files,
                report.chunks,
                report.input_bytes,
                report.archive_bytes,
                report.dedup_saved,
                report.transform_saved,
                report.compression_saved,
                report.peak_inflight,
                report.mapped_files,
                report.streamed_files,
                start.elapsed().as_secs_f64()
            );
        }
        Command::Unpack {
            archive,
            output,
            file,
            password,
        } => {
            let secret = password.read(false)?;
            let output = output.unwrap_or_else(|| {
                PathBuf::from(
                    archive
                        .file_stem()
                        .unwrap_or(std::ffi::OsStr::new("unpacked")),
                )
            });
            let count = pipeline::unpack(
                &archive,
                &output,
                file.as_deref(),
                secret.as_ref().map(|s| s.as_slice()),
                ReadLimits::default(),
            )?;
            println!("unpacked files={count} output={}", output.display());
        }
        Command::List {
            archive,
            detailed,
            password,
        } => {
            let secret = password.read(false)?;
            let reader = ArchiveReader::open(
                &archive,
                secret.as_ref().map(|s| s.as_slice()),
                ReadLimits::default(),
            )?;
            for entry in &reader.index().file_table {
                let kind = if entry.is_dir() {
                    "dir"
                } else if entry.is_symlink() {
                    "link"
                } else {
                    "file"
                };
                println!("{kind}\t{}\t{}", entry.file_size, entry.path);
                if detailed {
                    for id in &entry.chunk_ids {
                        let h = &reader.index().chunk_table[id.get() as usize].header;
                        println!(
                            "  chunk={} codec={:?} transform={:?} raw={} transformed={} stored={} encrypted={}",
                            id,
                            h.codec,
                            h.transform,
                            h.uncompressed_size,
                            h.transformed_size,
                            h.compressed_size,
                            h.flags.contains(wexpack::format::ChunkFlags::ENCRYPTED)
                        );
                    }
                    if let Some(target) = &entry.symlink_target {
                        println!("  target={target}");
                    }
                }
            }
            let s = reader.stats();
            let mib = (1 << 20) as f64;
            println!(
                "files={} chunks={} logical={} unique={} stored={} dedup_saved={} transform_saved={} codec_saved={} dedup_saved_mib={:.3} codec_saved_mib={:.3}",
                reader.index().file_table.len(),
                reader.index().chunk_table.len(),
                s.logical_bytes,
                s.unique_bytes,
                s.stored_bytes,
                s.dedup_saved,
                s.transform_saved,
                s.compression_saved,
                s.dedup_saved as f64 / mib,
                s.compression_saved as f64 / mib
            );
        }
        Command::Verify {
            archive,
            repair,
            password,
        } => {
            let secret = password.read(false)?;
            let r = pipeline::verify(
                &archive,
                secret.as_ref().map(|s| s.as_slice()),
                repair,
                ReadLimits::default(),
            )?;
            println!(
                "verified files={} chunks={} repaired_data_shards={} repaired_parity_shards={}",
                r.files, r.chunks, r.repaired_data_shards, r.repaired_parity_shards
            );
        }
        Command::Bench { file, memory_mib } => {
            println!("level\tinput_bytes\tstored_bytes\tratio\tpack_MiB/s\tunpack_MiB/s");
            for r in pipeline::bench(&file, memory_bytes(memory_mib)?)? {
                println!(
                    "{}\t{}\t{}\t{:.6}\t{:.3}\t{:.3}",
                    r.level, r.input_bytes, r.stored_bytes, r.ratio, r.pack_mib_s, r.unpack_mib_s
                );
            }
        }
        Command::ChunkDemo { file } => {
            let mut chunks = FastCdcStream::new(File::open(file)?, FastCdcConfig::default());
            let registry = DedupEngine::new();
            let start = Instant::now();
            while let Some(chunk) = chunks.next_chunk_ref()? {
                registry.process_chunk(chunk.data)?;
            }
            let s = registry.stats()?;
            println!(
                "chunks={} unique={} input={} B dedup_saved={} B savings={:.2}% elapsed={:.3}s",
                s.total_chunks,
                s.unique_chunks,
                s.total_input_bytes,
                s.deduped_bytes,
                s.savings_ratio() * 100.0,
                start.elapsed().as_secs_f64()
            );
        }
    }
    Ok(())
}
fn main() -> ExitCode {
    match run(Cli::parse()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("wxp: {e}");
            ExitCode::FAILURE
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn cli_definitions_and_percent_parser_are_valid() {
        use clap::CommandFactory;
        Cli::command().debug_assert();
        assert_eq!(parse_percent("10%"), Ok(10));
        assert_eq!(parse_percent("1"), Ok(1));
        for value in ["0", "31", "%", "1%%", "-1"] {
            assert!(parse_percent(value).is_err());
        }
    }
}
