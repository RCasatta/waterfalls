use crate::{
    be::Family,
    fetch::Client,
    server::{Error, State},
    store::{BlockMeta, Store},
    TxSeen, V,
};
use elements::{hex::ToHex, OutPoint, Txid};
use std::{
    collections::{HashMap, HashSet},
    str::FromStr,
    sync::Arc,
    time::Instant,
};

pub(crate) async fn blocks_infallible(shared_state: Arc<State>, client: Client, family: Family) {
    if let Err(e) = index(shared_state, client, family).await {
        log::error!("{:?}", e);
    }
}

pub async fn index(state: Arc<State>, client: Client, family: Family) -> Result<(), Error> {
    let db = &state.store;
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
            log::info!("{block_height} {speed:.2} blocks/s {txs_count} txs");
        }
        let block_hash = client.block_hash_or_wait(block_height).await;

        let block = client.block_or_wait(block_hash, family).await;

        let time = block.time();

        for tx in block.transactions().into_iter() {
            txs_count += 1;
            let txid = tx.txid();
            for (j, output) in tx.outputs().into_iter().enumerate() {
                if output.skip_indexing() {
                    continue;
                }
                let script_hash = db.hash(output.script_pubkey().as_bytes());
                let el = history_map.entry(script_hash).or_insert(vec![]);
                el.push(TxSeen::new(txid, block_height, V::Vout(j as u32)));

                let out_point = OutPoint::new(txid, j as u32);
                log::debug!("inserting {out_point}");
                utxo_created.insert(out_point, script_hash);
            }

            if !tx.is_coinbase() {
                for (vin, input) in tx.inputs().into_iter().enumerate() {
                    if input.skip_indexing() {
                        continue;
                    }
                    let previous_output = input.previous_output();
                    match utxo_created.remove(&previous_output) {
                        Some(script_hash) => {
                            // also the spending tx must be indexed
                            let el = history_map.entry(script_hash).or_insert(vec![]);
                            el.push(TxSeen::new(txid, block_height, V::Vin(vin as u32)));
                        }
                        None => {
                            log::debug!("removing {}", &previous_output);
                            if !skip_outpoint.contains(&previous_output) {
                                utxo_spent.push((vin as u32, previous_output, txid))
                            }
                        }
                    }
                }
            }
        }

        let meta = BlockMeta::new(block_height, block.block_hash(), time);
        state.set_hash_ts(&meta).await;
        db.update(&meta, utxo_spent, history_map, utxo_created)
            .map_err(|e| Error::String(format!("error updating db: {e}")))?;
    }
    Ok(())
}

fn generate_skip_outpoint() -> HashSet<OutPoint> {
    let mut skip_outpoint = HashSet::new();
    let outpoint = |txid, vout| OutPoint::new(Txid::from_str(txid).expect("static"), vout);

    // policy asset emission in testnet
    let s = "0c52d2526a5c9f00e9fb74afd15dd3caaf17c823159a514f929ae25193a43a52";
    skip_outpoint.insert(outpoint(s, 0));

    // policy asset emission in regtest
    let s = "50cdc410c9d0d61eeacc531f52d2c70af741da33af127c364e52ac1ee7c030a5";
    skip_outpoint.insert(outpoint(s, 0));

    skip_outpoint
}
