# Response consistency across new blocks

A waterfalls response (`/v{1,2,4}/waterfalls[.cbor]`) is built from several reads: the
history of every derived script, the mempool, the tip and the hash and timestamp of every
block referenced by the history. A new block or a reorg may happen while those reads run.

## Within a response

Every waterfalls response reflects a single state of the indexed blocks: the history, the
`block_hash`/`block_timestamp` of each confirmed entry and the returned tip (`tip` in v2,
`tip_meta` in v4) all come from the same chain. Every confirmed entry has a `block_hash` at
a height not above the returned tip.

Indexing a block writes the store first and then updates the in-memory list of block
hashes; a reorg does the opposite. Neither is atomic for readers, so the blocks thread
increments a counter (`State::block_update_seq`) when an update starts and again when it
ends: the counter is odd while an update is in progress.

A request waits for the counter to be even, does all its reads, then checks the counter
again. If it changed, a block was indexed or reorged in the meantime, the result is
discarded and the reads are done again. After 3 attempts, or if an update does not finish
within 2 seconds, the server answers `503 Service Unavailable` with `Retry-After: 1`. The
condition is transient and the request can be retried as is.

Since blocks are rare and indexing one is fast, a retry is seldom needed and a 503 is
seldom seen once the server is synced. While the server is catching up with the node,
blocks are indexed back to back and long descriptor scans can get a 503.

The mempool is not covered by the counter: mempool entries are read before the store and
transactions confirmed in between are removed from the mempool part, so a transaction is
never missing, nor reported both confirmed and unconfirmed in the same response.

## Across pages

Pages are independent requests and the server keeps no state between them, so the chain
can change between page `N` and page `N+1`. Clients that need more than one request
(descriptor `page`, `to_index`, or the `addresses` endpoint following `has_more`) should:

1. use v2 or v4, which carry the tip in every response;
2. remember the tip of the first response and compare it with the tip of each following
   one;
3. restart the scan from the first request when it differs.

v1 has no tip, so a v1 client cannot detect a change between pages. v4 is preferable to
v2: the tip height also tells a new block from a reorg, which is useful for logging and
for deciding how much cached data to drop.

Single-address history pages are ordered from the oldest entry, so a new block appends
entries at the end and does not shift earlier pages; a reorg removing entries does.
