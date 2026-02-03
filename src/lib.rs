#![deny(clippy::pedantic)]

use std::collections::BTreeMap;
use std::fs::File;
use std::io::{self, BufRead, BufReader, Read};
use std::path::{Path, PathBuf};

use blake2::{Blake2b512, Blake2s256};
use digest::Digest;
use rayon::prelude::*;
use walkdir::WalkDir;

/// Supported hashing algorithms.
#[derive(Copy, Clone, Debug)]
pub enum Algorithm {
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

/// A hash target with optional name metadata.
#[derive(Clone, Debug)]
pub struct Target {
    pub hash: Vec<u8>,
    pub name: Option<String>,
}

/// Configuration for a search across files.
pub struct SearchConfig {
    pub dir: PathBuf,
    pub algorithm: Algorithm,
    pub targets: Vec<Target>,
    pub threads: Option<usize>,
}

/// A matched target found on disk.
#[derive(Clone, Debug)]
pub struct MatchResult {
    pub path: PathBuf,
    pub target: Target,
}

/// Summary information from a [`search`] operation.
#[derive(Debug)]
pub struct SearchReport {
    pub matches: Vec<MatchResult>,
    pub total_files_checked: usize,
    pub failed_files: Vec<FileCheckFailure>,
}

/// Details for a file that could not be checked during search.
#[derive(Debug)]
pub struct FileCheckFailure {
    pub path: PathBuf,
    pub error: String,
}

/// Search a directory tree for files whose hashes match configured targets.
///
/// This walks the directory specified in [`SearchConfig::dir`] (without following
/// symlinks) and hashes only files that are relevant to the configured targets.
/// If a target includes a [`Target::name`], hashing is limited to files with the
/// same filename; otherwise all files are considered. Hashing uses the
/// [`Algorithm`] configured in [`SearchConfig::algorithm`].
///
/// # Examples
///
/// ```no_run
/// use std::path::PathBuf;
///
/// let config = hash_hunter::SearchConfig {
///     dir: PathBuf::from("."),
///     algorithm: hash_hunter::Algorithm::Sha256,
///     targets: vec![hash_hunter::Target {
///         hash: hash_hunter::parse_hex("d2d2d2d2")?,
///         name: Some("example.txt".to_string()),
///     }],
///     threads: Some(4),
/// };
///
/// let report = hash_hunter::search(&config)?;
/// println!("matched {} file(s)", report.matches.len());
/// # Ok::<(), std::io::Error>(())
/// ```
///
/// # Errors
///
/// Returns an error if:
/// - no targets are provided;
/// - the global Rayon thread pool cannot be created;
/// - or filesystem traversal fails.
///
/// Individual file hashing failures (for example, permission errors) are
/// reported on stderr and do not abort the search.
pub fn search(config: &SearchConfig) -> io::Result<SearchReport> {
    if config.targets.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "at least one target is required",
        ));
    }

    if let Some(threads) = config.threads {
        rayon::ThreadPoolBuilder::new()
            .num_threads(threads)
            .build_global()
            .map_err(io::Error::other)?;
    }

    let (name_map, hash_only) = split_targets(&config.targets);
    let search_root = config.dir.canonicalize()?;

    let results = WalkDir::new(&search_root)
        .follow_links(false)
        .into_iter()
        .par_bridge()
        .filter_map(Result::ok)
        .filter(|entry| entry.file_type().is_file())
        .filter_map(|entry| {
            let path = entry.path().to_path_buf();
            let file_name = entry.file_name().to_string_lossy().to_string();
            let name_targets = name_map.get(&file_name).cloned().unwrap_or_default();
            let needs_hash = !name_targets.is_empty() || !hash_only.is_empty();
            if !needs_hash {
                return None;
            }
            let hash = match compute_hash(&path, config.algorithm) {
                Ok(value) => value,
                Err(err) => return Some(ResultEntry::Error { path, err }),
            };
            let mut matches = Vec::new();
            for idx in name_targets.iter().chain(hash_only.iter()) {
                if config.targets[*idx].hash == hash {
                    matches.push(*idx);
                }
            }
            Some(ResultEntry::Hashed { path, matches })
        })
        .collect::<Vec<_>>();

    let mut output = Vec::new();
    let mut failures = Vec::new();
    let mut total_files_checked = 0usize;
    for result in results {
        total_files_checked += 1;
        match result {
            ResultEntry::Hashed { path, matches } => {
                for idx in matches {
                    output.push(MatchResult {
                        path: path.clone(),
                        target: config.targets[idx].clone(),
                    });
                }
            }
            ResultEntry::Error { path, err } => {
                failures.push(FileCheckFailure {
                    path: path.clone(),
                    error: err.to_string(),
                });
                eprintln!("failed to hash {}: {err}", path.display());
            }
        }
    }

    Ok(SearchReport {
        matches: output,
        total_files_checked,
        failed_files: failures,
    })
}

/// Load hash targets from a batch file.
///
/// Each non-empty, non-comment line in the file must contain a hexadecimal hash
/// followed by an optional filename:
///
/// ```text
/// <hex-hash> [filename]
/// ```
///
/// If the filename is present it is stored in [`Target::name`] and is later used
/// by [`search`] to limit hashing to files with the same basename.
///
/// # Examples
///
/// ```no_run
/// # use std::path::PathBuf;
/// # use std::fs;
/// let path = PathBuf::from("targets.txt");
/// fs::write(&path, "d2d2d2d2 example.txt\n# comment line\n")?;
/// let targets = hash_hunter::load_batch(&path)?;
/// assert_eq!(targets.len(), 1);
/// # Ok::<(), std::io::Error>(())
/// ```
///
/// # Errors
///
/// Returns an error if the file cannot be read, if a line is malformed, or if a
/// hash cannot be parsed by [`parse_hex`]. Line numbers are included in
/// formatting errors to aid debugging.
pub fn load_batch(path: &Path) -> io::Result<Vec<Target>> {
    let file = File::open(path)?;
    let reader = BufReader::new(file);
    let mut targets = Vec::new();
    for (line_number, line) in reader.lines().enumerate() {
        let line = line?;
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut parts = line.split_whitespace();
        let hash = parts
            .next()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing hash"))?;
        let name = parts.next().map(std::string::ToString::to_string);
        if parts.next().is_some() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("line {}: too many fields", line_number + 1),
            ));
        }
        let hash = parse_hex(hash).map_err(|err| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("line {}: {err}", line_number + 1),
            )
        })?;
        targets.push(Target { hash, name });
    }
    Ok(targets)
}

/// Parse a hexadecimal string into raw bytes.
///
/// The input is trimmed before decoding. This helper is used by [`load_batch`]
/// and the CLI to convert user-provided hex strings into byte arrays suitable
/// for hashing comparisons.
///
/// # Examples
///
/// ```
/// let bytes = hash_hunter::parse_hex("0a0b0c")?;
/// assert_eq!(bytes, vec![0x0a, 0x0b, 0x0c]);
/// # Ok::<(), std::io::Error>(())
/// ```
///
/// # Errors
///
/// Returns an error if the input is not valid hex.
pub fn parse_hex(input: &str) -> io::Result<Vec<u8>> {
    let cleaned = input.trim();
    hex::decode(cleaned).map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err))
}

enum ResultEntry {
    Hashed { path: PathBuf, matches: Vec<usize> },
    Error { path: PathBuf, err: io::Error },
}

/// Partition targets into a filename map and a hash-only list.
///
/// This returns:
/// - a map from filename to indices of [`Target`] entries with
///   [`Target::name`] set, and
/// - a list of indices for targets without filenames.
///
/// [`search`] uses this split to avoid hashing files that cannot possibly
/// satisfy any target.
fn split_targets(targets: &[Target]) -> (BTreeMap<String, Vec<usize>>, Vec<usize>) {
    let mut name_map: BTreeMap<String, Vec<usize>> = BTreeMap::new();
    let mut hash_only = Vec::new();
    for (idx, target) in targets.iter().enumerate() {
        if let Some(name) = &target.name {
            name_map.entry(name.clone()).or_default().push(idx);
        } else {
            hash_only.push(idx);
        }
    }
    (name_map, hash_only)
}

/// Compute the hash of a file using the selected [`Algorithm`].
///
/// This function opens the file at `path`, streams its contents into the
/// appropriate hash implementation, and returns the resulting digest bytes. For
/// BLAKE3, the specialized [`hash_blake3`] path is used; all other algorithms
/// use [`hash_with_digest`].
///
/// # Errors
///
/// Returns an error if the file cannot be opened or read.
fn compute_hash(path: &Path, algo: Algorithm) -> io::Result<Vec<u8>> {
    let file = File::open(path)?;
    let mut reader = BufReader::new(file);
    match algo {
        Algorithm::Md5 => hash_with_digest::<md5::Md5>(&mut reader),
        Algorithm::Sha1 => hash_with_digest::<sha1::Sha1>(&mut reader),
        Algorithm::Sha256 => hash_with_digest::<sha2::Sha256>(&mut reader),
        Algorithm::Sha512 => hash_with_digest::<sha2::Sha512>(&mut reader),
        Algorithm::Sha3_256 => hash_with_digest::<sha3::Sha3_256>(&mut reader),
        Algorithm::Sha3_512 => hash_with_digest::<sha3::Sha3_512>(&mut reader),
        Algorithm::Blake2s => hash_with_digest::<Blake2s256>(&mut reader),
        Algorithm::Blake2b => hash_with_digest::<Blake2b512>(&mut reader),
        Algorithm::Blake3 => hash_blake3(&mut reader),
    }
}

/// Hash a reader using a `Digest` implementation.
///
/// This helper is used by [`compute_hash`] for algorithms that implement the
/// [`Digest`] trait. It reads the input in 128 KiB chunks to limit memory usage.
///
/// # Errors
///
/// Returns an error if the underlying reader cannot be read.
fn hash_with_digest<D: Digest>(reader: &mut BufReader<File>) -> io::Result<Vec<u8>> {
    let mut hasher = D::new();
    let mut buffer = vec![0u8; 128 * 1024];
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hasher.finalize().to_vec())
}

/// Hash a reader using the BLAKE3 implementation.
///
/// BLAKE3 does not implement the [`Digest`] trait, so it uses its own hashing
/// API. The read loop mirrors [`hash_with_digest`] to keep behavior consistent.
///
/// # Errors
///
/// Returns an error if the underlying reader cannot be read.
fn hash_blake3(reader: &mut BufReader<File>) -> io::Result<Vec<u8>> {
    let mut hasher = blake3::Hasher::new();
    let mut buffer = vec![0u8; 128 * 1024];
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hasher.finalize().as_bytes().to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::io::Write;

    fn write_file(dir: &tempfile::TempDir, name: &str, contents: &[u8]) -> PathBuf {
        let path = dir.path().join(name);
        let mut file = File::create(&path).expect("create file");
        file.write_all(contents).expect("write file");
        path
    }

    #[test]
    fn parse_hex_trims_and_parses() {
        let bytes = parse_hex(" 0a0b0c ").expect("parse hex");
        assert_eq!(bytes, vec![0x0a, 0x0b, 0x0c]);
    }

    #[test]
    fn parse_hex_rejects_invalid() {
        let err = parse_hex("not-hex").expect_err("invalid hex should fail");
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn load_batch_parses_names_and_hash_only() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("batch.txt");
        fs::write(
            &path,
            "0a0b0c report.txt\n\n# comment line\n0d0e0f\n",
        )
        .expect("write batch");
        let targets = load_batch(&path).expect("load batch");
        assert_eq!(targets.len(), 2);
        assert_eq!(targets[0].hash, vec![0x0a, 0x0b, 0x0c]);
        assert_eq!(targets[0].name.as_deref(), Some("report.txt"));
        assert_eq!(targets[1].hash, vec![0x0d, 0x0e, 0x0f]);
        assert!(targets[1].name.is_none());
    }

    #[test]
    fn load_batch_reports_too_many_fields() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("batch.txt");
        fs::write(&path, "0a0b0c one two\n").expect("write batch");
        let err = load_batch(&path).expect_err("expected too many fields error");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("line 1"));
    }

    #[test]
    fn load_batch_reports_invalid_hex_with_line_number() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("batch.txt");
        fs::write(&path, "0a0b0c\nzzzz\n").expect("write batch");
        let err = load_batch(&path).expect_err("expected invalid hex");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("line 2"));
    }

    #[test]
    fn split_targets_separates_named_and_hash_only() {
        let targets = vec![
            Target {
                hash: vec![1],
                name: Some("a.txt".to_string()),
            },
            Target {
                hash: vec![2],
                name: None,
            },
            Target {
                hash: vec![3],
                name: Some("a.txt".to_string()),
            },
        ];
        let (name_map, hash_only) = split_targets(&targets);
        assert_eq!(hash_only, vec![1]);
        let entries = name_map.get("a.txt").expect("name entry");
        assert_eq!(entries, &vec![0, 2]);
    }

    #[test]
    fn compute_hash_errors_for_missing_file() {
        let path = PathBuf::from("missing-file");
        let err = compute_hash(&path, Algorithm::Sha256).expect_err("missing file");
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
    }

    #[test]
    fn hash_with_digest_matches_md5() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = write_file(&dir, "file.txt", b"hash-hunter");
        let file = File::open(&path).expect("open file");
        let mut reader = BufReader::new(file);
        let hash = hash_with_digest::<md5::Md5>(&mut reader).expect("hash");
        let expected = md5::Md5::digest(b"hash-hunter").to_vec();
        assert_eq!(hash, expected);
    }

    #[test]
    fn hash_blake3_matches_expected() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = write_file(&dir, "file.txt", b"hash-hunter");
        let file = File::open(&path).expect("open file");
        let mut reader = BufReader::new(file);
        let hash = hash_blake3(&mut reader).expect("hash");
        let expected = blake3::hash(b"hash-hunter").as_bytes().to_vec();
        assert_eq!(hash, expected);
    }

    #[test]
    fn compute_hash_supports_all_algorithms() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = write_file(&dir, "file.txt", b"hash-hunter");
        let cases = [
            (Algorithm::Md5, md5::Md5::digest(b"hash-hunter").to_vec()),
            (Algorithm::Sha1, sha1::Sha1::digest(b"hash-hunter").to_vec()),
            (Algorithm::Sha256, sha2::Sha256::digest(b"hash-hunter").to_vec()),
            (Algorithm::Sha512, sha2::Sha512::digest(b"hash-hunter").to_vec()),
            (
                Algorithm::Sha3_256,
                sha3::Sha3_256::digest(b"hash-hunter").to_vec(),
            ),
            (
                Algorithm::Sha3_512,
                sha3::Sha3_512::digest(b"hash-hunter").to_vec(),
            ),
            (Algorithm::Blake2s, Blake2s256::digest(b"hash-hunter").to_vec()),
            (Algorithm::Blake2b, Blake2b512::digest(b"hash-hunter").to_vec()),
            (
                Algorithm::Blake3,
                blake3::hash(b"hash-hunter").as_bytes().to_vec(),
            ),
        ];
        for (algo, expected) in cases {
            let digest = compute_hash(&path, algo).expect("compute hash");
            assert_eq!(digest, expected, "mismatch for {algo:?}");
        }
    }

    #[test]
    fn search_requires_targets() {
        let dir = tempfile::tempdir().expect("tempdir");
        let config = SearchConfig {
            dir: dir.path().to_path_buf(),
            algorithm: Algorithm::Sha256,
            targets: Vec::new(),
            threads: None,
        };
        let err = search(&config).expect_err("should require targets");
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn search_matches_named_and_hash_only_targets() {
        let dir = tempfile::tempdir().expect("tempdir");
        let alpha_path = write_file(&dir, "alpha.txt", b"alpha");
        let beta_path = write_file(&dir, "beta.txt", b"beta");
        let alpha_hash = compute_hash(&alpha_path, Algorithm::Sha256).expect("hash");
        let beta_hash = compute_hash(&beta_path, Algorithm::Sha256).expect("hash");
        let targets = vec![
            Target {
                hash: alpha_hash.clone(),
                name: Some("alpha.txt".to_string()),
            },
            Target {
                hash: beta_hash.clone(),
                name: None,
            },
            Target {
                hash: vec![0xff],
                name: Some("missing.txt".to_string()),
            },
        ];
        let config = SearchConfig {
            dir: dir.path().to_path_buf(),
            algorithm: Algorithm::Sha256,
            targets: targets.clone(),
            threads: None,
        };
        let report = search(&config).expect("search");
        assert_eq!(report.matches.len(), 2);
        let mut matched_paths: Vec<_> = report
            .matches
            .iter()
            .map(|result| result.path.clone())
            .collect();
        matched_paths.sort();
        let mut expected = vec![alpha_path, beta_path];
        expected.sort();
        assert_eq!(matched_paths, expected);
        let matched_targets: Vec<_> = report
            .matches
            .into_iter()
            .map(|result| result.target)
            .collect();
        assert!(matched_targets.iter().any(|target| {
            target.hash == targets[0].hash && target.name == targets[0].name
        }));
        assert!(matched_targets.iter().any(|target| {
            target.hash == targets[1].hash && target.name == targets[1].name
        }));
    }
}
