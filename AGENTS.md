# AGENTS.md - Waterfalls Developer Guide

Waterfalls is a Rust project providing blockchain data to Liquid and Bitcoin light-client wallets.

## Development Environment

Use Nix (defined in `flake.nix`): `nix develop` or `direnv allow`.
Provides: Rust toolchain (via rust-overlay), RocksDB, OpenSSL, bitcoind, elementsd, libclang.

When the nix env is not already active (e.g. sandbox), prefer `direnv exec . <command>`
(e.g. `direnv exec . cargo check`) over `nix develop --command <command>` — it uses the
cached nix-direnv environment and avoids flake re-evaluation overhead.

## Build & Check Commands

```bash
cargo build                              # Debug build
cargo build --release                    # Release build
cargo check                              # Fast type-check
cargo check --no-default-features        # Check without default features
cargo check --no-default-features --features test_env
cargo check --benches
cargo check --tests
```

## Test Commands

```bash
cargo test                               # Run all tests (uses default features: test_env, db)
cargo test test_name                     # Run a single test by name
cargo test test_name -- --exact          # Run exactly one test (no substring match)
cargo test -- --nocapture                # Show stdout/stderr
cargo test -- --ignored                  # Run ignored tests (require internet)
cargo test --test integration            # Run only integration tests
cargo bench --features bench_test        # Run benchmarks (criterion)
```

### Feature Flags

- `test_env` (default) — enables `bitcoind` dep for tests requiring local nodes
- `db` (default) — enables RocksDB storage backend
- `synced_node` — tests requiring a locally running synced node
- `bench_test` — long-running benchmark tests
- `examine_logs` — log inspection tests

### Required Environment Variables for Tests

```bash
export BITCOIND_EXEC=/path/to/bitcoind   # Provided by nix develop
export ELEMENTSD_EXEC=/path/to/elementsd # Provided by nix develop
export RUST_LOG=debug                    # Optional: enable debug logging
```

## Formatting & Linting

```bash
cargo fmt                                # Format code (default rustfmt settings)
cargo clippy                             # Lint
cargo clippy -- -D warnings              # Lint, fail on warnings (CI enforced)
```

No `rustfmt.toml` or `clippy.toml` — default settings are used.

## Code Style Guidelines

### Imports

Grouped in this order (separated by blank lines when practical):

1. `std::` — standard library
2. External crates — `anyhow`, `elements`, `hyper`, `serde`, `tokio`, etc.
3. `crate::` / `super::` — internal modules

Use absolute paths: `use waterfalls::be::Address` (in tests/benches), `use crate::be::Address` (within the crate).

### Error Handling

- **Application-level**: `anyhow::Result` for fallible operations in fetch, threads, startup.
- **Server routes**: custom `Error` enum in `src/server/mod.rs` mapped to HTTP status codes.
  - `CannotDecrypt` → 422, `BodyTooLarge` → 413, `BodyReadTimeout` → 408, input errors → 400, others → 500.
- **Fetch layer**: custom `Error` enum in `src/fetch.rs` (`TxNotFound`, `BlockNotFound`, etc.).
- **Unrecoverable**: `error_panic!` macro (defined in `src/lib.rs`) — logs via `log::error!` then panics.
- Log errors with `log::error!` before returning them.

### Logging

- Use the `log` crate: `log::info!`, `log::warn!`, `log::error!`, `log::debug!`
- Initialized via `env_logger` in `main.rs` (default filter: `info`)
- For systemd integration: set `RUST_LOG_STYLE=SYSTEMD`

### Async Code

- Runtime: `tokio` with `rt-multi-thread`
- Use `tokio::select!` for concurrent operations (e.g., signal handling)
- Use `#[tokio::test]` for async tests

### Serialization

- JSON: `serde` / `serde_json` with `Serialize`/`Deserialize` derives
- CBOR: `minicbor` with `Encode`/`Decode` derives and custom `with` helpers in `src/cbor.rs`
- Field annotations: `#[cbor(n(X))]` for CBOR field indices, `#[serde(skip_serializing_if = ...)]`

### Testing Patterns

- `#[tokio::test]` for async tests
- `#[cfg(feature = "test_env")]` gates tests needing bitcoind/elementsd
- `#[cfg(all(feature = "test_env", feature = "db"))]` for DB-backed integration tests
- `#[ignore = "requires internet"]` for tests hitting remote endpoints
- `env_logger::try_init()` at test start (ignore the error if already initialized)
- Test infrastructure in `src/test_env.rs`: `TestEnv`, `WaterfallClient`, `launch()`, `launch_with_node()`
- Integration tests in `tests/integration.rs` use `launch_memory()` / `test_env::launch()` to spin up node + server

## Project Structure

```
src/
├── lib.rs              # Library root: types, error_panic! macro, prometheus metrics
├── main.rs             # Binary entry: clap parsing, logging, signal handling
├── fetch.rs            # Blockchain data fetching (esplora / local node REST)
├── cbor.rs             # CBOR encoding helpers for block hashes
├── test_env.rs         # Test utilities (TestEnv, WaterfallClient)
├── be/                 # Backend types (Address, Block, BlockHeader, Descriptor, Tx, Txid)
├── server/             # HTTP server: Arguments (clap), Network, Error enum, routing,
│                       #   state, mempool, signing, encryption, derivation_cache, preload
├── store/              # Store trait + AnyStore, memory.rs, db.rs (RocksDB, behind `db` feature)
└── threads/            # Background tasks: block indexing, mempool sync
build.rs                # Injects GIT_COMMIT_HASH at build time
tests/integration.rs    # Integration tests
benches/benches.rs      # Criterion benchmarks
```

## CI

### Rust checks (`.github/workflows/rust.yml`)

Runs on push/PR to `master`:

- **tests**: downloads bitcoind 28.0 & elementsd 23.2.4, runs `cargo test` and `cargo test -- --ignored`
- **checks**: `cargo check` with various feature combinations
- **nix**: `nix build .` with cachix

### Docker publish (`.github/workflows/docker-publish.yml`)

Runs on push to `master`, tag creation, and manual dispatch:

- Push to `master` publishes `blockstream/waterfalls:latest`
- Tag push publishes `blockstream/waterfalls:<git-tag>`

The workflow builds native images on:

- `ubuntu-latest` for `linux/amd64`
- `ubuntu-24.04-arm` for `linux/arm64`

Then it creates a multi-arch manifest tag from per-arch tags:

- `blockstream/waterfalls:<final-tag>-amd64`
- `blockstream/waterfalls:<final-tag>-arm64`
- `blockstream/waterfalls:<final-tag>` (manifest list with both architectures)

Required GitHub repository secret:

- `DOCKERHUB_TOKEN`

## Cursor Rules

From `.cursor/rules/my-custom-rule.mdc` (always applied):

1. The developer uses a Nix environment from `flake.nix` — use it when proposing commands
2. Add new structs at the end of files, or just before `#[cfg(test)] mod tests` if present
3. Never add new dependencies unless explicitly asked

## Common Tasks

```bash
cargo run -- --network liquid --use-esplora   # Run server against esplora
cargo test --features "test_env db"           # Run tests with DB backend
nix build .#dockerImage && docker load < result  # Build Docker image
cargo bench --features bench_test             # Run benchmarks
```
