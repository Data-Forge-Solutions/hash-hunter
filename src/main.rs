#![deny(clippy::pedantic)]

use std::fs;
use std::path::PathBuf;

use clap::{Parser, ValueEnum};

#[derive(Parser, Debug)]
#[command(
    name = "hash-hunter",
    version,
    about = "Find files by matching hashes."
)]
struct Cli {
    /// Root directory to search
    #[arg(short, long, default_value = ".")]
    dir: PathBuf,

    /// Hash algorithm to use
    #[arg(short, long, value_enum, default_value_t = AlgorithmArg::Sha256)]
    algo: AlgorithmArg,

    /// Target hash in hex (required unless --batch is provided)
    #[arg(short = 'H', long)]
    hash: Option<String>,

    /// Optional file name to shortcut scanning
    #[arg(short, long)]
    name: Option<String>,

    /// Batch file with lines: <hash> [filename]
    #[arg(long)]
    batch: Option<PathBuf>,

    /// Number of hashing threads (defaults to logical CPUs)
    #[arg(long)]
    threads: Option<usize>,

    /// Write results to a text file at the given path
    #[arg(long)]
    output: Option<PathBuf>,
}

#[derive(Copy, Clone, Debug, ValueEnum)]
enum AlgorithmArg {
    Md5,
    Sha1,
    Sha256,
    Sha512,
    Sha3_256,
    Sha3_512,
    Blake2s,
    Blake2b,
    Blake3,
}

impl From<AlgorithmArg> for hash_hunter::Algorithm {
    /// Convert CLI arguments into the library [`hash_hunter::Algorithm`].
    ///
    /// This isolates CLI parsing from the library API so other callers can use
    /// the strongly-typed enum without pulling in clap types.
    fn from(value: AlgorithmArg) -> Self {
        match value {
            AlgorithmArg::Md5 => hash_hunter::Algorithm::Md5,
            AlgorithmArg::Sha1 => hash_hunter::Algorithm::Sha1,
            AlgorithmArg::Sha256 => hash_hunter::Algorithm::Sha256,
            AlgorithmArg::Sha512 => hash_hunter::Algorithm::Sha512,
            AlgorithmArg::Sha3_256 => hash_hunter::Algorithm::Sha3_256,
            AlgorithmArg::Sha3_512 => hash_hunter::Algorithm::Sha3_512,
            AlgorithmArg::Blake2s => hash_hunter::Algorithm::Blake2s,
            AlgorithmArg::Blake2b => hash_hunter::Algorithm::Blake2b,
            AlgorithmArg::Blake3 => hash_hunter::Algorithm::Blake3,
        }
    }
}

/// Parse CLI arguments, run a hash search, and report results.
///
/// This entry point orchestrates:
/// - parsing user input via [`Cli`],
/// - loading targets with [`hash_hunter::load_batch`] or
///   [`hash_hunter::parse_hex`],
/// - performing the search with [`hash_hunter::search`], and
/// - printing matches or missing targets to stdout (plus optional output file
///   writing).
///
/// # Errors
///
/// Returns an error if required arguments are missing, if hashes cannot be
/// parsed, if the search fails, or if output cannot be written.
fn main() -> std::io::Result<()> {
    let cli = Cli::parse();
    if cli.hash.is_none() && cli.batch.is_none() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "--hash is required unless --batch is provided",
        ));
    }

    let targets = if let Some(batch_path) = cli.batch.as_ref() {
        hash_hunter::load_batch(batch_path)?
    } else {
        let hash = hash_hunter::parse_hex(cli.hash.as_ref().expect("hash required"))?;
        vec![hash_hunter::Target {
            hash,
            name: cli.name.clone(),
        }]
    };

    let config = hash_hunter::SearchConfig {
        dir: cli.dir,
        algorithm: cli.algo.into(),
        targets: targets.clone(),
        threads: cli.threads,
    };
    let results = hash_hunter::search(&config)?;

    let mut found = vec![false; targets.len()];
    let mut output_lines = Vec::new();
    for result in results {
        if let Some((idx, _)) = targets.iter().enumerate().find(|(_, target)| {
            target.hash == result.target.hash && target.name == result.target.name
        }) && !found[idx]
        {
            let name_display = result
                .target
                .name
                .as_ref()
                .map(|value| format!(" ({value})"))
                .unwrap_or_default();
            let line = format!("match: {}{}", result.path.display(), name_display);
            println!("{line}");
            output_lines.push(line);
            found[idx] = true;
        }
    }

    for (idx, was_found) in found.iter().enumerate() {
        if !was_found {
            let target = &targets[idx];
            let name_display = target
                .name
                .as_ref()
                .map(|value| format!(" ({value})"))
                .unwrap_or_default();
            let line = format!("missing: {}{}", hex::encode(&target.hash), name_display);
            println!("{line}");
            output_lines.push(line);
        }
    }

    if let Some(path) = cli.output {
        let mut contents = output_lines.join("\n");
        if !contents.is_empty() {
            contents.push('\n');
        }
        fs::write(path, contents)?;
    }

    Ok(())
}
