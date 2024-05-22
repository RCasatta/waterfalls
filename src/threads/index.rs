// pub(crate) start()

use std::{collections::HashMap, sync::Arc, time::Instant};

use elements::OutPoint;

use crate::{
    esplora::{self, Client},
    state::State,
    Error,
};

pub(crate) async fn index_infallible(shared_state: Arc<State>) {
    if let Err(e) = index(shared_state).await {
        log::error!("{:?}", e);
    }
}

pub async fn index(shared_state: Arc<State>) -> Result<(), Error> {
    let db = &shared_state.db;
    let indexed_height = db.get_to_index_height().unwrap();
    let tip_height = shared_state.tip_height;
    println!("indexed/tip: {indexed_height}/{tip_height}");
    let client = Client::new();

    let mut txs_count = 0u64;

    let start = Instant::now();
    for block_height in indexed_height.. {
        let mut history_map = HashMap::new();
        let mut utxo_created = HashMap::new();
        let mut utxo_spent = vec![];
        if block_height % 10_000 == 0 {
            let speed = (block_height - indexed_height) as f64 / start.elapsed().as_secs() as f64;
            println!("{block_height} {speed:.2} blocks/s {txs_count} txs");
        }
        let block_hash = shared_state.hash_from_height(block_height).await.unwrap(); // TODO
        let block = client.block(block_hash).await.unwrap();
        for tx in block.txdata {
            txs_count += 1;
            let txid = tx.txid();
            for (j, output) in tx.output.iter().enumerate() {
                if output.is_null_data() || output.is_fee() {
                    continue;
                }
                let script_hash = db.hash(&output.script_pubkey);
                // println!("{} hash is {script_hash}", &output.script_pubkey.to_hex());
                let el = history_map.entry(script_hash).or_insert(vec![]);
                el.push(block_height);

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
                            utxo_spent.push(input.previous_output)
                        }
                    }
                }
            }
        }

        db.update(block_height, utxo_spent, history_map, utxo_created);
    }
    Ok(())
}
