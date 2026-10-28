# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/2.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `--metrics-listen <ip:port>` (`METRICS_LISTEN` environment variable) starts a dedicated
  listener serving only the prometheus `/metrics` endpoint, so it can be bound to a loopback
  or private interface separate from the public one. When set, the public listener no
  longer serves `/metrics` and returns 404.

### Changed

- Startup now fails with a clear error when `--node-url` (`NODE_URL`) does not start with `http://`.
  Waterfalls talks plain HTTP to the node and has no TLS support: an `https://` URL used to
  fail the backend preflight and be retried forever instead of being reported.
- `/metrics` responses no longer carry a `Cache-Control` header: it reused the
  `--cache-control-seconds` value meant for blockchain data, which could let a caching proxy
  serve stale metrics to scrapers.
- Block indexing no longer computes every transaction id twice: the txids computed while
  indexing a block are reused to drop its transactions from the mempool view.

### Deprecated

- Serving `/metrics` on the public listener. It still happens when `--metrics-listen` is
  not set, with a warning at startup, but a future release will stop doing it by default.
  Set `--metrics-listen` to keep scraping metrics.

### Fixed

- Descriptor expansion and script derivation errors in HTTP handlers now return an error
  response instead of panicking the connection task.
- Store (RocksDB) reads and writes no longer run directly on the async runtime: HTTP handlers,
  the mempool sync and the block indexing loop now offload them to tokio's blocking thread
  pool. A slow disk read stalled every other task on the same worker, and could hang the
  whole server under load on a `current_thread` runtime (#53). Store errors in HTTP handlers
  now return a 500 response instead of panicking the connection task.
- A transaction confirmed by a new block no longer disappears from responses for up to
  about a second, between leaving the node mempool and its block being indexed. Wallets
  syncing in that window dropped it, and their balance briefly jumped.

### Removed

- **Breaking:** the Esplora backend. The `--use-esplora` and `--esplora-url` options
  (`USE_ESPLORA` and `ESPLORA_URL` environment variables) are gone: waterfalls now always
  fetches data from a bitcoind/elementsd node through its REST and RPC interfaces, so node
  RPC credentials are always required. Configurations still passing the removed options,
  as flags or environment variables, fail to start.
- The `esplora` Cargo feature and the `esplora` and `dockerImageEsplora` Nix outputs.

[Unreleased]: https://github.com/Blockstream/waterfalls/compare/0.10.0...HEAD
