use crate::{
    be::Family,
    cache_counter,
    fetch::Client,
    server::{Error, State},
    store::Store,
};
use std::{
    collections::HashSet,
    future::Future,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::time::{sleep, timeout};

const BIG_MEMPOOL_DELTA_THRESHOLD: usize = 1_000;

pub(crate) async fn mempool_sync_infallible(
    state: Arc<State>,
    client: Client,
    family: Family,
    sleep_between_cycles: Duration,
    initial_sync_rx: tokio::sync::oneshot::Receiver<()>,
    shutdown_signal: impl Future<Output = ()>,
) {
    if let Err(e) = mempool_sync(
        state,
        client,
        family,
        sleep_between_cycles,
        initial_sync_rx,
        shutdown_signal,
    )
    .await
    {
        log::error!("{:?}", e);
    }
}

async fn sync_mempool_once(
    client: &Client,
    support_verbose: bool,
    mempool_txids: &mut HashSet<crate::be::Txid>,
    state: &Arc<State>,
    family: Family,
) -> Result<MempoolSyncStats, Error> {
    let start = Instant::now();
    match client.mempool(support_verbose).await {
        Ok(current) => {
            let client_mempool_elapsed = start.elapsed();
            crate::MEMPOOL_CLIENT_DURATION.set(client_mempool_elapsed.as_millis() as i64);
            crate::MEMPOOL_TXS_COUNT.set(current.len() as i64);

            let db = &state.store;
            let tip = state.tip_height().await;
            let new: Vec<_> = current.difference(mempool_txids).cloned().collect();
            let removed: Vec<_> = mempool_txids.difference(&current).cloned().collect();
            crate::MEMPOOL_NEW_TXS_COUNTER.inc_by(new.len() as u64);
            let is_big_delta = new.len() >= BIG_MEMPOOL_DELTA_THRESHOLD
                || removed.len() >= BIG_MEMPOOL_DELTA_THRESHOLD;
            if !new.is_empty() {
                log::debug!("new txs in mempool {:?}, tip: {tip:?}", new);
            }
            if is_big_delta {
                log::info!(
                    "mempool big delta detected: tip={tip:?}, new={}, removed={}, current_txs={}, previous_tracked_txs={}",
                    new.len(),
                    removed.len(),
                    current.len(),
                    mempool_txids.len(),
                );
            }

            // we keep this lock because we are the critical path
            // it's fine if the zmq thread wait for us.
            // and it's also beneficial so that the final mempool_cache.clear() does not delete tx we didn't use yet
            let mut mempool_cache = state.mempool_cache.lock().await;
            for new_txid in &new {
                let cached_tx = mempool_cache.get(new_txid).cloned();
                cache_counter("mempool_cache", cached_tx.is_some());
                let tx = if let Some(tx) = cached_tx {
                    Ok(tx)
                } else {
                    client.tx(*new_txid, family).await
                };
                match tx {
                    Ok(tx) => {
                        mempool_cache.insert(*new_txid, tx);
                    }
                    Err(e) => {
                        let err_msg =
                            format!("failing fetching {new_txid} in mempool loop, error is: {e}");
                        if let Some(crate::fetch::Error::TxNotFound(_, _)) = e.downcast_ref() {
                            // tx not found, it was replaced from mempool with RBF for example
                            log::info!("{err_msg}");
                        } else {
                            log::error!("{err_msg}");
                        }
                        return Err(Error::String(err_msg));
                    }
                }
            }
            let txs: Vec<_> = new
                .iter()
                .filter_map(|txid| mempool_cache.get(txid).map(|tx| (*txid, tx)))
                .collect();
            {
                let mut m = state.mempool.lock().await;
                m.update(db, &removed, &txs);
                mempool_txids.clear();
                mempool_txids.extend(m.txids_iter());
                if is_big_delta {
                    let stats = m.stats();
                    log::info!(
                        "mempool big delta applied: tip={tip:?}, tracked_txs={}, script_hashes={}, positions={}, outpoints_created={}, fetched_txs={}",
                        stats.txids,
                        stats.script_hashes,
                        stats.positions,
                        stats.outpoints_created,
                        txs.len(),
                    );
                }
            }
            mempool_cache.clear();
            let processing_time = start.elapsed();
            if is_big_delta {
                log::info!(
                    "mempool big delta processed: tip={tip:?}, loop_ms={}, client_fetch_ms={}",
                    processing_time.as_millis(),
                    client_mempool_elapsed.as_millis(),
                );
            }
            crate::MEMPOOL_LOOP_DURATION.set(processing_time.as_millis() as i64);
            Ok(MempoolSyncStats {
                tip,
                mempool_txs: current.len(),
                processing_time,
            })
        }
        Err(e) => {
            let err_msg =
                format!("mempool sync error, is the node running and has rest=1 ? error: {e:?}");
            log::warn!("{err_msg}");
            Err(Error::String(err_msg))
        }
    }
}

async fn sleep_between_cycles(delay: Duration) {
    sleep(delay).await;
}

async fn mempool_sync(
    state: Arc<State>,
    client: Client,
    family: Family,
    sleep_between_cycles_delay: Duration,
    initial_sync_rx: tokio::sync::oneshot::Receiver<()>,
    shutdown_signal: impl Future<Output = ()>,
) -> Result<(), Error> {
    // Wait for initial block download to complete
    log::info!("Mempool thread waiting for initial block download to complete...");

    let mut signal = std::pin::pin!(shutdown_signal);

    tokio::select! {
        _ = &mut signal => {
            log::info!("mempool thread received shutdown signal before initial sync completed");
            return Ok(());
        }
        result = initial_sync_rx => {
            match result {
                Ok(_) => {
                    log::info!("Initial block download completed, starting mempool sync");
                    state.store.ibd_finished();
                }
                Err(e) => {
                    // RecvError indicates the sender was dropped. Check if this is due to expected shutdown
                    // or an unexpected crash of the blocks thread by testing if shutdown signal is ready
                    if timeout(std::time::Duration::from_millis(1), &mut signal).await.is_ok() {
                        log::info!("Initial sync channel closed during shutdown - exiting gracefully");
                        return Ok(());
                    } else {
                        // Shutdown signal not received, so this is likely an unexpected crash
                        error_panic!("Initial sync channel closed unexpectedly (blocks thread may have crashed): {e}");
                    }
                }
            }
        }
    }

    let mut mempool_txids = HashSet::new();
    let support_vebose = client.mempool(true).await.is_ok();
    log::info!("mempool support verbose: {support_vebose}");
    let mut last_summary = Instant::now();
    let mut processing_since_last_summary = Duration::ZERO;
    let mut latest_stats = None;

    loop {
        tokio::select! {
            _ = &mut signal => {
                log::info!("mempool thread received shutdown signal");
                return Ok(());
            }
            _ = async {
                if let Ok(stats) =
                    sync_mempool_once(&client, support_vebose, &mut mempool_txids, &state, family)
                        .await
                {
                    processing_since_last_summary += stats.processing_time;
                    latest_stats = Some(stats);
                }
                if last_summary.elapsed() >= Duration::from_secs(60) {
                    if let Some(stats) = latest_stats {
                        log::info!(
                            "mempool summary: tip={:?}, txs={}, processing_time_ms={}",
                            stats.tip,
                            stats.mempool_txs,
                            processing_since_last_summary.as_millis()
                        );
                    }
                    last_summary = Instant::now();
                    processing_since_last_summary = Duration::ZERO;
                }
                sleep_between_cycles(sleep_between_cycles_delay).await;
            } => {}
        }
    }
}

#[derive(Clone, Copy)]
struct MempoolSyncStats {
    tip: Option<u32>,
    mempool_txs: usize,
    processing_time: Duration,
}
