# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/2.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Removed

- **Breaking:** the Esplora backend. The `--use-esplora` and `--esplora-url` options
  (`USE_ESPLORA` and `ESPLORA_URL` environment variables) are gone: waterfalls now always
  fetches data from a bitcoind/elementsd node through its REST and RPC interfaces, so
  `--rpc-user-password-file` is always required. Configurations still passing the removed
  options fail to start.

[Unreleased]: https://github.com/Blockstream/waterfalls/compare/0.10.0...HEAD
