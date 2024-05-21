# Waterfall


## db schema

- txid:vout -> hash(script) # for uxtos
- hash(script) -> [height1, height2] # for handling address_history
- height sync / height tip / salt

## in memory

- `Vec<BlockHash>` # to quickly convert from height to hash
- `HashMap<hash(script), Txid>` mempool 
- `LRU<BlocKHash, Block>` when elements_slices -> slice cache

the row `hash(script)` is written if script is found as output in block h1
hash(script) -> h1
in block h2 the output X is spend, the row will be updated and the value will contain 2 elements:
hash(script) -> [h1, h2]

updating the row instead of having two rows requires more effort during indexing (get and update the rows). However, it has been chosen because:
- searching can be be done on exact values, enabling the use of multi_get
- space saving

