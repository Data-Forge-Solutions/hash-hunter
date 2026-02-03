use std::collections::BTreeMap;
use std::fs::File;
use std::io::{self, BufRead, BufReader, Read};
use std::path::{Path, PathBuf};

use blake2::{Blake2b512, Blake2s256};
use digest::Digest;
use rayon::prelude::*;
use walkdir::WalkDir;

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

#[derive(Clone, Debug)]
pub struct Target {
    pub hash: Vec<u8>,
    pub name: Option<String>,
}

pub struct SearchConfig {
    pub dir: PathBuf,
    pub algorithm: Algorithm,
    pub targets: Vec<Target>,
    pub threads: Option<usize>,
}

#[derive(Clone, Debug)]
pub struct MatchResult {
    pub path: PathBuf,
    pub target: Target,
}

pub fn search(config: SearchConfig) -> io::Result<Vec<MatchResult>> {
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
            .map_err(|err| io::Error::new(io::ErrorKind::Other, err))?;
    }

    let (name_map, hash_only) = split_targets(&config.targets);

    let results = WalkDir::new(&config.dir)
        .follow_links(false)
        .into_iter()
        .par_bridge()
        .filter_map(|entry| entry.ok())
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
            if matches.is_empty() {
                None
            } else {
                Some(ResultEntry::Match { path, matches })
            }
        })
        .collect::<Vec<_>>();

    let mut output = Vec::new();
    for result in results {
        match result {
            ResultEntry::Match { path, matches } => {
                for idx in matches {
                    output.push(MatchResult {
                        path: path.clone(),
                        target: config.targets[idx].clone(),
                    });
                }
            }
            ResultEntry::Error { path, err } => {
                eprintln!("failed to hash {}: {err}", path.display());
            }
        }
    }

    Ok(output)
}

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
        let name = parts.next().map(|value| value.to_string());
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

pub fn parse_hex(input: &str) -> io::Result<Vec<u8>> {
    let cleaned = input.trim();
    hex::decode(cleaned).map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err))
}

enum ResultEntry {
    Match { path: PathBuf, matches: Vec<usize> },
    Error { path: PathBuf, err: io::Error },
}

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

fn hash_with_digest<D: Digest>(reader: &mut BufReader<File>) -> io::Result<Vec<u8>> {
    let mut hasher = D::new();
    let mut buffer = [0u8; 128 * 1024];
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hasher.finalize().to_vec())
}

fn hash_blake3(reader: &mut BufReader<File>) -> io::Result<Vec<u8>> {
    let mut hasher = blake3::Hasher::new();
    let mut buffer = [0u8; 128 * 1024];
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hasher.finalize().as_bytes().to_vec())
}
