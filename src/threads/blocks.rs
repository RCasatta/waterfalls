use crate::{fetch::Client, state::State, store::BlockMeta, store::TxSeen, Error};
use elements::{OutPoint, Txid};
use std::{
    collections::{HashMap, HashSet},
    str::FromStr,
    sync::Arc,
    time::Instant,
};

pub(crate) async fn blocks_infallible(shared_state: Arc<State>, client: Client) {
    if let Err(e) = index(shared_state, client).await {
        log::error!("{:?}", e);
    }
}

pub async fn index(state: Arc<State>, client: Client) -> Result<(), Error> {
    let db = &state.db;
    let next_height = state.blocks_hash_ts.lock().await.len() as u32;

    let skip_outpoint = generate_skip_outpoint();

    let mut txs_count = 0u64;

    let start = Instant::now();
    for block_height in next_height.. {
        let mut history_map = HashMap::new();
        let mut utxo_created = HashMap::new();
        let mut utxo_spent = vec![];
        if block_height % 10_000 == 0 {
            let speed = (block_height - next_height) as f64 / start.elapsed().as_secs() as f64;
            println!("{block_height} {speed:.2} blocks/s {txs_count} txs");
        }
        let block_hash = client.block_hash_or_wait(block_height).await;

        let block = client.block_or_wait(block_hash).await;

        for tx in block.txdata.iter() {
            txs_count += 1;
            let txid = tx.txid();
            for (j, output) in tx.output.iter().enumerate() {
                if output.is_null_data() || output.is_fee() {
                    continue;
                }
                let script_hash = db.hash(&output.script_pubkey);
                // println!("{} hash is {script_hash}", &output.script_pubkey.to_hex());
                let el = history_map.entry(script_hash).or_insert(vec![]);
                el.push(TxSeen::new(txid, block_height));

                let out_point = OutPoint::new(txid, j as u32);
                // println!("inserting {out_point}");
                utxo_created.insert(out_point, script_hash);
            }

            if !tx.is_coinbase() {
                for input in tx.input.iter() {
                    if input.is_pegin() {
                        continue;
                    }
                    match utxo_created.remove(&input.previous_output) {
                        Some(_) => {
                            // println!("spent same block, avoiding {}", &input.previous_output);
                            // spent in the same block:
                            // - no need to remove from the persisted utxo
                            // - this height already inserted for this script from the relative same-height output
                        }
                        None => {
                            // println!("removing {}", &input.previous_output);
                            if !skip_outpoint.contains(&input.previous_output) {
                                utxo_spent.push((input.previous_output, txid))
                            }
                        }
                    }
                }
            }
        }

        let meta = BlockMeta::new(block_height, block.block_hash(), block.header.time);
        state.set_hash_ts(&meta).await;
        db.update(&meta, utxo_spent, history_map, utxo_created);
    }
    Ok(())
}

fn generate_skip_outpoint() -> HashSet<OutPoint> {
    let mut skip_outpoint = HashSet::new();
    let s = "0c52d2526a5c9f00e9fb74afd15dd3caaf17c823159a514f929ae25193a43a52";
    // policy asset emission in testnet
    skip_outpoint.insert(OutPoint::new(Txid::from_str(s).expect("static"), 0));
    skip_outpoint
}
