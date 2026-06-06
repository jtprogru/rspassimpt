# rspassimpt

[![CI](https://github.com/jtprogru/rspassimpt/actions/workflows/ci.yml/badge.svg)](https://github.com/jtprogru/rspassimpt/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/jtprogru/rspassimpt?include_prereleases&sort=semver)](https://github.com/jtprogru/rspassimpt/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-edition_2024-orange.svg)](https://www.rust-lang.org/)
[![Platforms](https://img.shields.io/badge/platforms-macOS%20%7C%20Linux-lightgrey)](https://github.com/jtprogru/rspassimpt/releases)

Fast, secure importer that ingests a macOS Passwords CSV export and writes each record straight into the local [`pass`](https://www.passwordstore.org/) store. Designed to keep up with a million-row export without blowing through gpg-agent prompts or leaking plaintext beyond what `gpg(1)` itself touches.

## Highlights

- **Conforms to passwordstore.org on-disk format.** Writes `<entry>.gpg` directly using `gpg --encrypt -r <id>` with the recipient(s) from `$PASSWORD_STORE_DIR/.gpg-id` (hierarchical `.gpg-id` files in sub-directories are honoured, same as `pass`).
- **No master passphrase prompts during import.** Encryption uses only the recipient's public key — `gpg-agent` is never asked for the secret key, so a 1M-row import does not trigger pinentry storms.
- **Plaintext is short-lived.** Secrets are kept in [`Zeroizing<Vec<u8>>`](https://docs.rs/zeroize) buffers wiped on drop, fed to `gpg` via stdin (never argv, never a temp file), and the encrypted blob is written atomically (`tempfile` → fsync → `chmod 0600` → rename).
- **Built for scale.** Streaming CSV reader with a 1 MiB buffer; encryption is parallelised through `rayon`; recipients are cached per directory; existence checks hit the filesystem instead of `pass show`.
- **Bilingual UI.** `en` / `ru` are selected from `LC_ALL` / `LC_MESSAGES` / `LANG` (gettext order). All errors, help text, and the progress spinner switch languages at runtime.
- **Pre-built binaries** for `aarch64-apple-darwin`, `x86_64-apple-darwin`, `aarch64-unknown-linux-gnu`, `x86_64-unknown-linux-gnu` published on every tag.

## Install

### Homebrew (macOS, Linux)

```bash
brew tap jtprogru/tap
brew install rspassimpt
```

This pulls in `gnupg` and `pass` automatically.

### Pre-built binary

Grab the right archive from the [latest release](https://github.com/jtprogru/rspassimpt/releases/latest) and drop the binary onto your `$PATH`.

### From source

Requires a stable Rust toolchain (edition 2024).

```bash
git clone https://github.com/jtprogru/rspassimpt
cd rspassimpt
cargo install --path . --locked
```

## Usage

The CSV is expected in the format macOS Passwords produces: columns `Title,URL,Username,Password,Notes,OTPAuth`. Only `Title` and `Password` are required.

```bash
# Dry-run first — print what would be written without touching the store.
rspassimpt passwords.csv --dry-run

# Real import.
rspassimpt passwords.csv

# Place imported entries under a sub-directory in the store.
rspassimpt passwords.csv --prefix imported/macos

# Skip entries that already exist (instead of erroring).
rspassimpt passwords.csv --skip-existing

# Overwrite existing entries.
rspassimpt passwords.csv --force

# Custom store directory (defaults to $PASSWORD_STORE_DIR or ~/.password-store).
rspassimpt passwords.csv --store-dir /path/to/store

# Force language regardless of locale.
LANG=en_US.UTF-8 rspassimpt passwords.csv --help
LANG=ru_RU.UTF-8 rspassimpt passwords.csv --help
```

Run `rspassimpt --help` for the full list of options.

### Entry format

Each entry is laid out per passwordstore.org convention:

```
<password>
user: <Username>
url: <URL>
otpauth: <OTPAuth>
notes: |
  <multi-line Notes>
```

Empty fields are omitted. Multi-line `Notes` are correctly preserved through CSV escaping.

## Security notes

- `gpg --encrypt -r <id>` uses only the recipient public key. No passphrase is required for the import itself; the secret key only comes into play later when *reading* an entry via `pass show`.
- Paths are sanitised: `..` components and absolute paths in `Title` are rejected before the encryption step, so a hostile CSV cannot write `.gpg` files outside the store.
- The encrypted blob is written via a temp file in the same directory, fsynced, chmodded to `0600`, then renamed onto the final path — readers never observe a half-written file.
- This tool does not auto-commit to the pass git repository. Run `git add . && git commit` (or `pass git ...`) yourself after an import — that way you stay in control of the audit log.

## Performance

CSV pipeline throughput on an Apple Silicon laptop (release build, Criterion):

| Bench                              | Throughput      |
|------------------------------------|-----------------|
| `sanitize_path/mixed`              | ~5.6M elem/s    |
| `build_entry/1024_rows`            | ~7.9M elem/s    |
| `pipeline_csv/parse_sanitize_build/1k`   | ~240 MiB/s |
| `pipeline_csv/parse_sanitize_build/100k` | ~228 MiB/s |

End-to-end `--dry-run` on synthetic fixtures:

| Rows      | Wall time |
|-----------|----------:|
| 1 000     | < 0.01 s  |
| 100 000   |   0.36 s  |
| 1 000 000 |   3.43 s  |

A real import is bound by `gpg` subprocess throughput rather than by the pipeline; parallelism scales with `--jobs` (defaults to your CPU count).

## Development

The included `Makefile` wraps the common loops:

```bash
make help          # list all targets
make build         # debug build (all targets)
make test          # 8 unit tests
make fmt           # cargo fmt
make lint          # clippy with -D warnings
make gen-1k        # synthesise tests/fixtures/passwd_1k.csv (1,000 rows)
make gen-100k      # 100,000 rows
make gen-1m        # 1,000,000 rows (~100 MiB)
make bench         # Criterion benches (generates 1k+100k fixtures if missing)
make full-test     # fmt-check + lint + test + gen-data + bench + end-to-end dry-run
make clean         # cargo clean + remove fixtures
```

The synthetic test data generator lives at `src/bin/gen_passwd.rs`; it uses an inline xorshift64\* PRNG so the workspace does not need a `rand` dependency, and the value pools are deliberately disjoint from any real-world export.

### Project layout

```
src/
  cli.rs           # clap CLI definition
  gpg.rs           # gpg subprocess + atomic file write
  i18n.rs          # in-house en/ru localization
  pipeline.rs      # streaming CSV + rayon + indicatif
  sanitize.rs      # title sanitisation, RawRow, entry builder
  store.rs         # PASSWORD_STORE_DIR + .gpg-id resolution
  lib.rs           # re-exports for benches/tests
  main.rs          # thin CLI entry point
  bin/
    gen_passwd.rs  # synthetic CSV generator
benches/
  parse.rs         # Criterion benches
.github/
  workflows/       # CI + tagged release pipeline
```

## License

[MIT](LICENSE)
