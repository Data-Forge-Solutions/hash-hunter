# Hash-Hunter

Search for files by hash (and optionally file name) with support for common
hashing algorithms. You can search for a single hash or provide a batch file of
hash/name pairs.

The core logic is available as a library via `hash_hunter::search` if you'd like
to embed the search in another application.

## Usage

Search a directory for a SHA-256 hash (default):

```bash
cargo run -- --dir ./data --hash <hex-hash>
```

Provide a file name to shortcut hashing when possible:

```bash
cargo run -- --dir ./data --hash <hex-hash> --name report.pdf
```

Use a different algorithm:

```bash
cargo run -- --dir ./data --algo sha3-256 --hash <hex-hash>
```

Batch mode (one target per line):

```
# batch.txt
<hash1> report.pdf
<hash2>
```

```bash
cargo run -- --dir ./data --algo sha256 --batch batch.txt
```
