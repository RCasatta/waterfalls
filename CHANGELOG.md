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
- `--allow-legacy-script-hash` (`ALLOW_LEGACY_SCRIPT_HASH` environment variable) allows
  starting on a database created by a previous release, see the breaking change below.
- The database records a format version, and a database with a format version newer than the
  running binary supports is refused at startup.
- `--max-descriptor-paths` (`MAX_DESCRIPTOR_PATHS`, default 2) and `--max-descriptor-keys`
  (`MAX_DESCRIPTOR_KEYS`, default 20) bound the descriptors accepted by the descriptor
  endpoints: the number of paths a descriptor expands to (2 with `<0;1>`), and the number of
  keys it contains.
- `--max-derivations-per-request` (`MAX_DERIVATIONS_PER_REQUEST`) bounds the derivation
  indexes a descriptor request can derive, over all its paths. Indexes already in the
  derivation cache are not counted, and the cost of an index is bounded by
  `--max-descriptor-keys`. The default is `--max-descriptor-paths` times the 1000 indexes
  scanned per path in a page, 2000 with the default paths, so that a full page fits.

### Changed

- **Breaking:** new databases hash scripts with SipHash-2-4 and a random 128-bit key, instead
  of FxHash with a random 64-bit salt. The script hash cannot change without reindexing, so
  starting on a database created by a previous release fails: point `--db-dir` to an empty
  directory to reindex with the keyed script hash, or pass `--allow-legacy-script-hash` to keep
  using the existing database. To avoid downtime, index into a new `--db-dir` with a second
  instance while the current one keeps serving, then switch. A new database has format
  version 2, stored in a new `meta` column family: previous releases refuse to open it, so
  a deployment on a new database cannot be rolled back to them. A database of a previous
  release opened with `--allow-legacy-script-hash` is left unchanged.
- **Breaking:** descriptors expanding to more than 2 paths (e.g. `<0;1;2>`) or with more than
  20 keys are rejected with HTTP 400 by default. Raise `--max-descriptor-paths` or
  `--max-descriptor-keys` to accept them.
- **Breaking:** descriptor requests needing to derive more indexes than
  `--max-derivations-per-request` (2000 by default) fail with HTTP 400 (`TooManyDerivations`).
  Raise it to allow them. Subscriptions are not expanded by a request that has used up its
  derivations, a later request expands them.
- Waterfalls responses no longer mix data from before and after a block indexed or reorged
  while the request is served: the tip, the history and its block hashes now always come
  from the same indexed blocks. The request is retried internally; if blocks keep changing
  it fails with `503 Service Unavailable` and `Retry-After: 1`, a new transient error
  clients should retry. The same applies to `/address/{address}/txs`, which no longer
  returns confirmed entries with a null `block_hash`. See `docs/consistency.md`.
- With `--add-cors`, responses carry `Access-Control-Expose-Headers: Retry-After`, so
  browser clients can read when to retry a 503.
- The process now exits with an error when the block indexing task panics. It used to keep
  serving data no longer following the chain; with the block snapshot it would have answered
  every waterfalls request with a 503 after a 2 seconds wait.
- Startup now fails with a clear error when `--node-url` (`NODE_URL`) does not start with `http://`.
  Waterfalls talks plain HTTP to the node and has no TLS support: an `https://` URL used to
  fail the backend preflight and be retried forever instead of being reported.
- `/metrics` responses no longer carry a `Cache-Control` header: it reused the
  `--cache-control-seconds` value meant for blockchain data, which could let a caching proxy
  serve stale metrics to scrapers.
- Block indexing no longer computes every transaction id twice: the txids computed while
  indexing a block are reused to drop its transactions from the mempool view.
- Script derivation runs on tokio's blocking thread pool instead of the async workers, at most
  one derivation per core at a time, so requests deriving many scripts don't delay the other
  requests.

### Deprecated

- Serving `/metrics` on the public listener. It still happens when `--metrics-listen` is
  not set, with a warning at startup, but a future release will stop doing it by default.
  Set `--metrics-listen` to keep scraping metrics.

### Fixed

- Rolling back a block now atomically removes its stored hash and timestamp, so restarting
  before a replacement block is indexed cannot restore the rolled-back block as the tip.
- An age-encrypted descriptor whose header is valid but whose payload is corrupted now returns
  HTTP 422 instead of panicking the connection task.
- Script derivation no longer holds the shared derivation cache lock, so a request deriving
  many scripts does not block the other requests needing the cache.
- Descriptors longer than 8192 bytes are rejected with HTTP 400 before any scan, bounding the
  work a single request can cause.
- Descriptors nested deeper than 64 levels, counting parentheses and miniscript wrappers
  (e.g. `elnnnn…:1`), are rejected with HTTP 400 before parsing. elements-miniscript recursed
  once per wrapper letter while parsing, which could overflow the stack.
- Descriptors with a hardened wildcard (`/*h` or `/*'`) or a hardened step after the xpub
  (e.g. `xpub/0'/*`) are rejected with HTTP 400. They cannot be derived from public keys, and
  deriving one panicked the request task. Hardened steps in the key origin are still accepted.
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
- `/v1/subscribe` checks `--max-scripts-per-subscription` before doing the work for the
  request, reducing the resources a refused request uses.

### Removed

- **Breaking:** the Esplora backend. The `--use-esplora` and `--esplora-url` options
  (`USE_ESPLORA` and `ESPLORA_URL` environment variables) are gone: waterfalls now always
  fetches data from a bitcoind/elementsd node through its REST and RPC interfaces, so node
  RPC credentials are always required. Configurations still passing the removed options,
  as flags or environment variables, fail to start.
- The `esplora` Cargo feature and the `esplora` and `dockerImageEsplora` Nix outputs.

[Unreleased]: https://github.com/Blockstream/waterfalls/compare/0.10.0...HEAD
