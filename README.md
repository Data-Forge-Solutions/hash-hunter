# hash-hunter

[![Crates.io](https://img.shields.io/crates/v/hash-hunter.svg)](https://crates.io/crates/hash-hunter)
[![Documentation](https://docs.rs/hash-hunter/badge.svg)](https://docs.rs/hash-hunter)
[![CI](https://github.com/Data-Forge-Solutions/hash-hunter/actions/workflows/CI.yml/badge.svg)](https://github.com/Data-Forge-Solutions/hash-hunter/actions)
[![License](https://img.shields.io/crates/l/hash-hunter)](LICENSE)
[![GitHub](https://img.shields.io/github/stars/Data-Forge-Solutions/hash-hunter?style=social)](https://github.com/Data-Forge-Solutions/hash-hunter)

hash-hunter is a Rust CLI and library for locating files by cryptographic hash.
It supports common algorithms, optional name matching to avoid unnecessary
hashing, and batch searches for multiple targets.

## Features

- Search directories for a target hash with optional file name filtering.
- Batch mode for multiple hashes and hash/name pairs.
- Multiple hashing algorithms (for example, SHA-256 and SHA3-256).
- Results can be streamed to stdout or written to a file.
- Library API for embedding search logic in other applications.

## Installation

Install from crates.io:

```bash
cargo install hash-hunter
```

## Usage

Search a directory for a SHA-256 hash (default):

```bash
hashhunter --dir ./data --hash <hex-hash>
```

Provide a file name to shortcut hashing when possible:

```bash
hashhunter --dir ./data --hash <hex-hash> --name report.pdf
```

Use a different algorithm:

```bash
hashhunter --dir ./data --algo sha3-256 --hash <hex-hash>
```

Batch mode (one target per line):

```
# batch.txt
<hash1> report.pdf
<hash2>
```

```bash
hashhunter --dir ./data --algo sha256 --batch batch.txt
```

Write results to a text file:

```bash
hashhunter --dir ./data --hash <hex-hash> --output results.txt
```

## Output

Results are written to stdout and optionally to `--output`. Matches are printed
as `match: <path> (name)` and missing targets are printed as
`missing: <hash> (name)`. The summary includes total checked files plus any
unchecked files that failed to hash.

## Library usage

The core logic is available as a library via `hash_hunter::search` for
applications that need to embed the search behavior directly.

## Notes

- Hash inputs must be hexadecimal without a leading prefix.
- File name filtering is an optimization and does not replace hash validation.
