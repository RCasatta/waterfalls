# HyperClockCache vs LRUCache Benchmark

RocksDB offers two block cache implementations: **LRUCache** (mutex-protected doubly-linked list) and **HyperClockCache** (lock-free clock eviction over a contiguous structure). This benchmark evaluates the switch from LRU to HyperClockCache using waterfalls' actual access pattern: `multi_get_cf` with 100 keys per batch.

## Setup

Two scenarios model production data-to-cache ratios:

| Scenario | History keys | UTXO keys | Data size | Cache | Ratio |
|----------|-------------|-----------|-----------|-------|-------|
| **Liquid** | 100K | 200K | ~21 MB | 2 MB | ~9% |
| **Bitcoin** | 500K | 300K | ~76 MB | 2 MB | ~2.6% |

- Production Liquid: 1 GB history, 37 MB utxo, 64 MB cache (~6%)
- Production Bitcoin: 251 GB history, 5.5 GB utxo, 200 MB cache (~0.08% overall, ~3.6% for utxo)

DB configuration matches production: 16 KB blocks, bloom filters on history CF, `cache_index_and_filter_blocks` enabled, shared block cache across CFs.

## Results

### Liquid scenario

| Threads | LRU | HyperClock | Improvement |
|---------|-----|------------|-------------|
| 1 | 46.3 µs | 44.4 µs | 4.2% |
| 4 | 58.4 µs | 55.9 µs | 4.3% |
| 16 | 183.2 µs | 172.1 µs | 6.0% |

### Bitcoin scenario

| Threads | LRU | HyperClock | Improvement |
|---------|-----|------------|-------------|
| 1 | 81.0 µs | 48.2 µs | 40.5% |
| 4 | 104.3 µs | 60.7 µs | 41.8% |
| 16 | 220.7 µs | 204.4 µs | 7.4% |

## Key takeaways

1. **HyperClockCache wins in every data point** -- no regressions in any scenario or concurrency level.

2. **The biggest gain is per-operation overhead, not just lock contention.** The Bitcoin single-threaded result (81 µs vs 48 µs, +40%) proves this: with 1 thread there is no lock contention, yet HyperClockCache is dramatically faster. Low cache-to-data ratios cause frequent evictions, and LRU's linked-list manipulation (pointer chasing, poor CPU cache locality) is expensive compared to HyperClockCache's contiguous clock sweep.

3. **The advantage narrows under high concurrency** (Bitcoin: 40% at 1t down to 7% at 16t). At 16 threads the bottleneck shifts to disk I/O contention (all threads reading SST files), making both caches equally limited.

4. **Liquid gains are modest but consistent** (~4-6%). Higher cache hit rates mean fewer evictions, so LRU pays less linked-list overhead.

## Reproduce

```bash
cargo bench -- block_cache
```

Benchmark source: `benches/benches.rs` (`block_cache` function).
