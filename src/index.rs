// pub(crate) start()

use std::{collections::HashMap, sync::Arc};

use elements::OutPoint;

use crate::{esplora, state::State, Error};

pub(crate) async fn index_infallible(shared_state: Arc<State>) {
    if let Err(e) = index(shared_state).await {
        log::error!("{:?}", e);
    }
}

pub async fn index(shared_state: Arc<State>) -> Result<(), Error> {
    let db = &shared_state.db;
    let indexed_height = db.get_indexed_height().unwrap();
    let tip_height = shared_state.tip_height;
    println!("indexed/tip: {indexed_height}/{tip_height}");
    let mut history_map = HashMap::new();
    let mut utxo_new = HashMap::new();
    let mut utxo_del = vec![];

    for block_height in indexed_height.. {
        history_map.clear();
        utxo_new.clear();
        utxo_del.clear();
        let block_hash = esplora::block_hash(block_height).await.unwrap();
        let block = esplora::block(block_hash).await.unwrap();
        for tx in block.txdata {
            let txid = tx.txid();
            for (j, output) in tx.output.iter().enumerate() {
                if output.is_null_data() || output.is_fee() {
                    continue;
                }
                let script_hash = db.hash(&output.script_pubkey);
                let el = history_map.entry(script_hash).or_insert(vec![]);
                el.push(block_height);

                let out_point = OutPoint::new(txid, j as u32);
                utxo_new.insert(out_point, script_hash);
            }

            if !tx.is_coinbase() {
                for input in tx.input.iter() {
                    if input.is_pegin() {
                        continue;
                    }
                    match utxo_new.remove(&input.previous_output) {
                        Some(_) => {
                            // spent in the same block:
                            // - no need to remove from the persisted utxo
                            // - this height already inserted for this script from the relative same-height output
                        }
                        None => utxo_del.push(input.previous_output),
                    }
                }

                let script_hashes = db.get_utxos(&utxo_del, true).unwrap();
                for script_hash in script_hashes {
                    let el = history_map.entry(script_hash).or_insert(vec![]);
                    el.push(block_height);
                }
            }
        }

        db.update_history(&history_map).unwrap();
        db.update_utxos(&utxo_new, &utxo_del).unwrap();
        db.set_indexed_height(block_height + 1).unwrap()
    }

    // update_history(&self, add: &HashMap<ScriptH, Vec<Height>>)

    // update_utxos(
    //     &self,
    //     adds: &[(OutPoint, ScriptH)],
    //     removes: &[OutPoint],
    Ok(())
}
