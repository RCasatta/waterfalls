use crate::{
    be::Family,
    fetch::{ChainStatus, Client},
    server::{Error, State},
    store::{BlockMeta, Store},
    TxSeen, V,
};
use elements::{OutPoint, Txid};
use std::{
    collections::{BTreeMap, HashSet},
    future::Future,
    str::FromStr,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::time::sleep;

pub(crate) async fn blocks_infallible(
    shared_state: Arc<State>,
    client: Client,
    family: Family,
    initial_sync_tx: tokio::sync::oneshot::Sender<()>,
    shutdown_signal: impl Future<Output = ()>,
    logs_rocksdb_stat_every_minutes: u64,
) {
    if let Err(e) = index(
        shared_state,
        client,
        family,
        initial_sync_tx,
        shutdown_signal,
        logs_rocksdb_stat_every_minutes,
    )
    .await
    {
        log::error!("{:?}", e);
    }
}

async fn get_next_block_to_index(
    last_indexed: &mut Option<BlockMeta>,
    client: &Client,
    family: Family,
    state: &Arc<State>,
    initial_sync_tx: &mut Option<tokio::sync::oneshot::Sender<()>>,
) -> Option<BlockMeta> {
    match last_indexed.as_ref() {
        Some(last) => {
            match client.get_next(&last, family).await {
                Ok(ChainStatus::NewBlock(next)) => {
                    return Some(next);
                }
                Ok(ChainStatus::Reorg) => {
                    log::warn!("reorg happened! {last:?} removed from the chain");
                    let previous_height = last.height - 1;
                    let blocks_hash_ts = state
                        .blocks_hash_ts
                        .lock()
                        .await
                        .get(previous_height as usize)
                        .cloned()
                        .expect("can't get previous block_hash");
                    let previous_block_meta =
                        BlockMeta::new(previous_height, blocks_hash_ts.0, blocks_hash_ts.1);
                    *last_indexed = Some(previous_block_meta);
                    state.store.reorg();
                    return None;
                }
                Ok(ChainStatus::Tip) => {
                    // Signal initial sync completion the first time we hit the tip
                    if let Some(tx) = initial_sync_tx.take() {
                        let _ = tx.send(());
                        log::info!("Initial block download completed, signaling mempool thread");
                    }
                    sleep(Duration::from_secs(1)).await;
                    return None;
                }
                Err(e) => {
                    log::warn!("error getting next block {e}, sleeping for 1 second and retrying");
                    sleep(Duration::from_secs(1)).await;
                    return None;
                }
            }
        }
        None => {
            if let Ok(Some(next)) = client.block_hash(0).await {
                return Some(BlockMeta::new(0, next, 0)); // TODO timestamp
            }
        }
    }
    sleep(Duration::from_secs(1)).await;
    None
}

pub async fn index(
    state: Arc<State>,
    client: Client,
    family: Family,
    initial_sync_tx: tokio::sync::oneshot::Sender<()>,
    shutdown_signal: impl Future<Output = ()>,
    logs_rocksdb_stat_every_minutes: u64,
) -> Result<(), Error> {
    let db = &state.store;

    let mut last_indexed = state
        .blocks_hash_ts
        .lock()
        .await
        .iter()
        .enumerate()
        .last()
        .map(|(height, (hash, ts))| BlockMeta::new(height as u32, *hash, *ts));

    log::info!("last indexed block is: {last_indexed:?}");
    let initial_height = last_indexed.as_ref().map(|b| b.height).unwrap_or(0);

    let skip_outpoint = generate_skip_outpoint();

    let mut txs_count = 0u64;
    let mut initial_sync_tx = Some(initial_sync_tx);

    let start = Instant::now();
    let mut last_logging = Instant::now();
    let mut last_rocksdb_stats_logging = Instant::now();
    let rocksdb_stats_interval = Duration::from_secs(logs_rocksdb_stat_every_minutes * 60);
    let mut signal = std::pin::pin!(shutdown_signal);

    loop {
        let block_to_index = loop {
            tokio::select! {
                _ = &mut signal => {
                    log::info!("blocks thread received shutdown signal");
                    return Ok(());
                }
                result = get_next_block_to_index(&mut last_indexed, &client, family, &state, &mut initial_sync_tx) => {
                    if let Some(block) = result {
                        break block;
                    }
                }
            }
        };

        if initial_sync_tx.is_none() {
            log::info!(
                "indexing: {} {}",
                block_to_index.height,
                block_to_index.hash
            );
        }

        if initial_sync_tx.is_some() && last_logging.elapsed().as_secs() > 60 {
            let speed =
                (block_to_index.height - initial_height) as f64 / start.elapsed().as_secs() as f64;
            log::info!(
                "{} {speed:.2} blocks/s {txs_count} txs",
                block_to_index.height
            );

            last_logging = Instant::now();
        }

        // Log RocksDB stats at the specified interval (independent of initial sync)
        if last_rocksdb_stats_logging.elapsed() >= rocksdb_stats_interval {
            if let Some(stats) = db.stats() {
                log::info!("RocksDB Stats:\n{}", stats);
            }
            last_rocksdb_stats_logging = Instant::now();
        }

        let mut history_map = BTreeMap::new();
        let mut utxo_created = BTreeMap::new();
        let mut utxo_spent = vec![];

        let block = match client.block(block_to_index.hash, family).await {
            Ok(block) => block,
            Err(e) => {
                log::error!("error getting block: {e}");
                sleep(Duration::from_secs(1)).await;
                continue;
            }
        };

        for tx in block.transactions_iter() {
            txs_count += 1;
            let txid = tx.txid();
            for (j, output) in tx.outputs_iter().enumerate() {
                if output.skip_indexing() {
                    if output.script_pubkey_bytes().is_empty() {
                        // while we don't want to index this, we need to add it to the UTXO set because an empty script is spendable.
                        // see for example mainnet 4fb1ee7b2e8121baf400b4a947508b431c39d64e2192059ff482624ba58f01d2
                        let out_point = OutPoint::new(txid, j as u32);
                        utxo_created.insert(out_point, db.hash(b""));
                    }
                    continue;
                }
                let script_hash = db.hash(output.script_pubkey_bytes());
                let el = history_map.entry(script_hash).or_insert(vec![]);
                el.push(TxSeen::new(txid, block_to_index.height, V::Vout(j as u32)));

                let out_point = OutPoint::new(txid, j as u32);
                log::debug!("inserting {out_point}");
                utxo_created.insert(out_point, script_hash);
            }

            if !tx.is_coinbase() {
                for (vin, input) in tx.inputs_iter().enumerate() {
                    if input.skip_indexing() {
                        continue;
                    }
                    let previous_output = input.previous_output();
                    match utxo_created.remove(&previous_output) {
                        Some(script_hash) => {
                            // also the spending tx must be indexed
                            let el = history_map.entry(script_hash).or_insert(vec![]);
                            el.push(TxSeen::new(txid, block_to_index.height, V::Vin(vin as u32)));
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
        state.set_hash_ts(&block_to_index).await;
        db.update(&block_to_index, utxo_spent, history_map, utxo_created)
            .unwrap_or_else(|e| error_panic!("error updating db: {e}"));
        last_indexed = Some(block_to_index);
    }
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
