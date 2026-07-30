use crate::{
    be::Family,
    fetch::{ChainStatus, Client},
    server::{Error, State, SubscriptionEvent},
    store::{BlockMeta, Store},
    OutPoint, TxSeen, V,
};
use std::{
    collections::BTreeMap,
    future::Future,
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
            match client.get_next(last, family).await {
                Ok(ChainStatus::NewBlock(next)) => Some(next),
                Ok(ChainStatus::Reorg) => {
                    log::warn!("reorg happened! {last:?} removed from the chain");

                    // TEST ONLY: Allow test to inject a crash before reorg is processed.
                    // This demonstrates the problem: reorg data is only in memory, so if
                    // the process crashes here, the reorg data is lost forever.
                    // Only enabled with the 'reorg_crash_test' feature flag.
                    #[cfg(feature = "reorg_crash_test")]
                    if std::env::var("WATERFALLS_TEST_CRASH_ON_REORG").is_ok() {
                        log::error!("WATERFALLS_TEST_CRASH_ON_REORG is set, intentionally panicking before processing reorg");
                        panic!("TEST CRASH: Simulating crash before reorg processing (reorg data will be lost)");
                    }

                    let reorged_height = last.height;
                    let previous_height = reorged_height - 1;
                    let previous_block_meta = {
                        let mut blocks_hash_ts = state.blocks_hash_ts.lock().await;
                        let (hash, ts) = blocks_hash_ts
                            .get(previous_height as usize)
                            .cloned()
                            .expect("can't get previous block_hash");
                        blocks_hash_ts.truncate(reorged_height as usize);
                        BlockMeta::new(previous_height, hash, ts)
                    };
                    log::info!(
                        "reorg: rolling back to previous block {:?}, calling store.reorg()",
                        previous_block_meta
                    );
                    *last_indexed = Some(previous_block_meta);
                    state.store.reorg(reorged_height);
                    state
                        .notify_all_subscriptions(SubscriptionEvent::Reorg)
                        .await;
                    log::info!(
                        "reorg: store.reorg() completed, will re-fetch block at height {}",
                        reorged_height
                    );
                    None
                }
                Ok(ChainStatus::Tip) => {
                    // Signal initial sync completion the first time we hit the tip
                    if let Some(tx) = initial_sync_tx.take() {
                        let _ = tx.send(());
                        log::info!("Initial block download completed, signaling mempool thread");
                    }
                    sleep(Duration::from_secs(1)).await;
                    None
                }
                Err(e) => {
                    log::warn!("error getting next block {e}, sleeping for 1 second and retrying");
                    sleep(Duration::from_secs(1)).await;
                    None
                }
            }
        }
        None => {
            match client.block_hash(0).await {
                Ok(Some(next)) => {
                    Some(BlockMeta::new(0, next, 0)) // TODO timestamp
                }
                Ok(None) => {
                    log::info!("block hash 0 is not found");
                    sleep(Duration::from_secs(1)).await;
                    None
                }
                Err(e) => {
                    log::warn!("error getting next block {e}, sleeping for 1 second and retrying");
                    sleep(Duration::from_secs(1)).await;
                    None
                }
            }
        }
    }
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

        let block = match client.block(block_to_index.hash, family).await {
            Ok(block) => block,
            Err(e) => {
                log::error!("error getting block: {e}");
                sleep(Duration::from_secs(1)).await;
                continue;
            }
        };

        let (changed_script_hashes, indexed_txs) =
            index_block_transactions(db, &block_to_index, block.transactions_iter())
                .unwrap_or_else(|e| error_panic!("error updating db: {e}"));
        txs_count += indexed_txs;
        state.set_hash_ts(&block_to_index).await;
        state
            .notify_block_tip_subscriptions(changed_script_hashes)
            .await;

        crate::BLOCKCHAIN_TIP.set(block_to_index.height as i64);
        last_indexed = Some(block_to_index);
    }
}

fn index_block_transactions<'a>(
    db: &impl Store,
    block_meta: &BlockMeta,
    transactions: impl Iterator<Item = crate::be::TransactionRef<'a>>,
) -> anyhow::Result<(Vec<crate::ScriptHash>, u64)> {
    let mut history_map = BTreeMap::new();
    let mut utxo_created = BTreeMap::new();
    let mut utxo_spent = vec![];
    let mut txs_count = 0;

    for tx in transactions {
        txs_count += 1;
        let txid = tx.txid();
        for (vout, output) in tx.outputs_iter().enumerate() {
            if !output.skip_utxo() {
                // Use an empty-bytes hash as a placeholder: outputs that are spendable
                // but non-standard (e.g. bare OP_TRUE) won't pass skip_indexing() below,
                // so their real script hash never overwrites this. When spent, the
                // spending tx lands under this dummy hash that no wallet will ever query.
                let outpoint = OutPoint::new(txid, vout as u32);
                utxo_created.insert(outpoint, db.hash(b""));
            }
            if output.skip_indexing() {
                continue;
            }
            let script_hash = db.hash(output.script_pubkey_bytes());
            history_map
                .entry(script_hash)
                .or_insert(vec![])
                .push(TxSeen::new(txid, block_meta.height(), V::Vout(vout as u32)));

            let outpoint = OutPoint::new(txid, vout as u32);
            log::debug!("inserting {outpoint}");
            utxo_created.insert(outpoint, script_hash);
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
                        history_map
                            .entry(script_hash)
                            .or_insert(vec![])
                            .push(TxSeen::new(txid, block_meta.height(), V::Vin(vin as u32)));
                    }
                    None if block_meta.height() == 0 => {
                        // Elements genesis creates the policy asset with an issuance
                        // input backed by a synthetic outpoint, not a preceding UTXO.
                        // Its value depends on the genesis parameters (including the
                        // fedpeg script), so it cannot be identified by a fixed txid.
                        log::debug!("ignoring genesis input {previous_output}");
                    }
                    None => {
                        log::debug!("removing {previous_output}");
                        utxo_spent.push((vin as u32, previous_output, txid));
                    }
                }
            }
        }
    }

    let changed_script_hashes = db.update(block_meta, utxo_spent, history_map, utxo_created)?;
    Ok((changed_script_hashes, txs_count))
}

#[cfg(test)]
mod indexing_tests {
    use std::str::FromStr;

    use elements::{encode::deserialize, hashes::Hash, BlockHash, Transaction};

    use super::*;
    use crate::{
        be::TransactionRef,
        store::{memory::MemoryStore, Store},
    };

    const CUSTOM_GENESIS_COINBASE: &str = "0100000000010000000000000000000000000000000000000000000000000000000000000000ffffffff2120bc6224b5d6e9c00462bb241cbc3b630c5be97038ed6a0b32c675496b8fceae74ffffffff0101000000000000000000000000000000000000000000000000000000000000000001000000000000000000016a00000000";
    const CUSTOM_GENESIS_ISSUANCE: &str = "010000000001bc6224b5d6e9c00462bb241cbc3b630c5be97038ed6a0b32c675496b8fceae740000008000ffffffff000000000000000000000000000000000000000000000000000000000000000006226e46111a0b59caaf126043eb5bbf28c34f3a5e332a1fc7b2b73cf188910f01000000007d2b7500010000000000000000010167d5ceb159844af010727a9aee019922909228a561236ede23faa8a6787fdc8701000000007d2b750000015100000000";
    const INITIAL_FREE_COINS_SWEEP: &str = "02000000000186832196e41526f82373860b04ffe58c2887315111d7cf7e1dd7bee8c26d5ef30000000000fdffffff020167d5ceb159844af010727a9aee019922909228a561236ede23faa8a6787fdc8701000000007d2b6ea20017a914913aeded70454a1752c64bb1b44577b2c50dbca5870167d5ceb159844af010727a9aee019922909228a561236ede23faa8a6787fdc8701000000000000065e000001000000";

    #[test]
    fn custom_genesis_issuance_and_sweep_memory() {
        assert_custom_genesis_issuance_and_sweep(&MemoryStore::new());
    }

    #[cfg(feature = "db")]
    #[test]
    fn custom_genesis_issuance_and_sweep_db() {
        let tempdir = tempfile::TempDir::new().unwrap();
        let store = crate::store::db::DBStore::open(tempdir.path(), 64, true, 6).unwrap();
        assert_custom_genesis_issuance_and_sweep(&store);
    }

    fn assert_custom_genesis_issuance_and_sweep(store: &impl Store) {
        let genesis_txs = [
            transaction(CUSTOM_GENESIS_COINBASE),
            transaction(CUSTOM_GENESIS_ISSUANCE),
        ];
        let genesis_meta = BlockMeta::new(
            0,
            BlockHash::from_str("1ce1ce1f2e97552f43f89dc97427cff12ce533491ddc3e9db2d4dc2dd52aef9e")
                .unwrap(),
            1_296_688_602,
        );
        let (_, txs_count) = index_block_transactions(
            store,
            &genesis_meta,
            genesis_txs.iter().map(TransactionRef::Elements),
        )
        .unwrap();
        assert_eq!(txs_count, 2);

        let issuance_outpoint = OutPoint::new(genesis_txs[1].txid().into(), 0);
        let nonstandard_script_hash = store.hash(b"");
        assert_eq!(
            store.get_utxos(&[issuance_outpoint]).unwrap(),
            vec![Some(nonstandard_script_hash)]
        );

        let empty_meta = BlockMeta::new(1, BlockHash::all_zeros(), 1_296_688_603);
        index_block_transactions(store, &empty_meta, std::iter::empty()).unwrap();

        store.ibd_finished();
        let sweep = transaction(INITIAL_FREE_COINS_SWEEP);
        let sweep_meta = BlockMeta::new(2, BlockHash::all_zeros(), 1_296_688_604);
        index_block_transactions(
            store,
            &sweep_meta,
            std::iter::once(TransactionRef::Elements(&sweep)),
        )
        .unwrap();

        let sweep_outpoint = OutPoint::new(sweep.txid().into(), 0);
        let sweep_script_hash = store.hash(sweep.output[0].script_pubkey.as_bytes());
        assert_eq!(
            store
                .get_utxos(&[issuance_outpoint, sweep_outpoint])
                .unwrap(),
            vec![None, Some(sweep_script_hash)]
        );
        assert_eq!(
            store
                .get_history(&[nonstandard_script_hash, sweep_script_hash])
                .unwrap(),
            vec![
                vec![TxSeen::new(
                    sweep.txid().into(),
                    sweep_meta.height(),
                    V::Vin(0)
                )],
                vec![TxSeen::new(
                    sweep.txid().into(),
                    sweep_meta.height(),
                    V::Vout(0)
                )],
            ]
        );

        store.reorg(sweep_meta.height());
        assert_eq!(
            store
                .get_utxos(&[issuance_outpoint, sweep_outpoint])
                .unwrap(),
            vec![Some(nonstandard_script_hash), None]
        );
        assert_eq!(
            store
                .get_history(&[nonstandard_script_hash, sweep_script_hash])
                .unwrap(),
            vec![vec![], vec![]]
        );
    }

    fn transaction(hex: &str) -> Transaction {
        deserialize(&hex_simd::decode_to_vec(hex.as_bytes()).unwrap()).unwrap()
    }
}

#[cfg(all(test, feature = "esplora"))]
mod tests {
    use std::{collections::BTreeMap, net::SocketAddr, str::FromStr, sync::Arc};

    use age::x25519::Identity;
    use bitcoin::{NetworkKind, PrivateKey};
    use elements::BlockHash;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };

    use super::*;
    use crate::{
        server::{Arguments, Network, StateConfig, SubscriptionLimits},
        store::{memory::MemoryStore, AnyStore},
    };

    #[tokio::test]
    async fn test_reorg_truncates_blocks_hash_ts() {
        let state = Arc::new(test_state());
        let hash_0 =
            BlockHash::from_str("0000000000000000000000000000000000000000000000000000000000000000")
                .unwrap();
        let hash_1 =
            BlockHash::from_str("1111111111111111111111111111111111111111111111111111111111111111")
                .unwrap();
        let hash_2 =
            BlockHash::from_str("2222222222222222222222222222222222222222222222222222222222222222")
                .unwrap();

        for meta in [
            BlockMeta::new(0, hash_0, 100),
            BlockMeta::new(1, hash_1, 200),
            BlockMeta::new(2, hash_2, 300),
        ] {
            state.set_hash_ts(&meta).await;
            state
                .store
                .update(&meta, vec![], BTreeMap::new(), BTreeMap::new())
                .unwrap();
        }
        assert_eq!(state.tip_height().await, Some(2));
        assert_eq!(state.tip_hash().await, Some(hash_2));

        let client = reorg_client().await;
        let mut last_indexed = Some(BlockMeta::new(2, hash_2, 300));
        let mut initial_sync_tx = None;

        assert!(get_next_block_to_index(
            &mut last_indexed,
            &client,
            Family::Bitcoin,
            &state,
            &mut initial_sync_tx,
        )
        .await
        .is_none());

        let last_indexed = last_indexed.expect("last indexed block");
        assert_eq!(last_indexed.height, 1);
        assert_eq!(last_indexed.hash, hash_1);
        assert_eq!(last_indexed.timestamp, 200);
        assert_eq!(state.tip_height().await, Some(1));
        assert_eq!(state.tip_hash().await, Some(hash_1));
        assert_eq!(state.block_hash(2).await, None);
    }

    fn test_state() -> State {
        State::new(
            AnyStore::Mem(MemoryStore::new()),
            Identity::generate(),
            PrivateKey::generate(NetworkKind::Test),
            StateConfig {
                max_addresses: 100,
                max_txs_seen: 100,
                cache_control_seconds: 5,
                server_timing: false,
                derivation_cache_capacity: 1000,
                subscription_limits: SubscriptionLimits {
                    max_active_subscriptions: 100,
                    max_scripts_per_subscription: 100,
                },
            },
        )
        .unwrap()
    }

    async fn reorg_client() -> Client {
        let address = spawn_reorg_server().await;
        Client::new(&Arguments {
            network: Network::BitcoinRegtest,
            use_esplora: true,
            esplora_url: Some(format!("http://{address}")),
            request_timeout_seconds: 30,
            ..Default::default()
        })
        .unwrap()
    }

    async fn spawn_reorg_server() -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buffer = [0; 1024];
            let _ = stream.read(&mut buffer).await.unwrap();
            stream
                .write_all(
                    b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                )
                .await
                .unwrap();
        });
        address
    }
}
