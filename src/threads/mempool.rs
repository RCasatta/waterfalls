use crate::{
    be::Family,
    fetch::Client,
    server::{Error, State},
    store::Store,
};
use std::{collections::HashSet, future::Future, sync::Arc};
use tokio::time::{sleep, timeout};

pub(crate) async fn mempool_sync_infallible(
    state: Arc<State>,
    client: Client,
    family: Family,
    initial_sync_rx: tokio::sync::oneshot::Receiver<()>,
    shutdown_signal: impl Future<Output = ()>,
) {
    if let Err(e) = mempool_sync(state, client, family, initial_sync_rx, shutdown_signal).await {
        log::error!("{:?}", e);
    }
}

async fn sync_mempool_once(
    client: &Client,
    support_verbose: bool,
    mempool_txids: &mut HashSet<crate::be::Txid>,
    state: &Arc<State>,
    family: Family,
) {
    match client.mempool(support_verbose).await {
        Ok(current) => {
            let _timer = crate::MEMPOOL_LOOP_DURATION.start_timer();
            crate::MEMPOOL_TXS_COUNT.set(current.len() as i64);

            let db = &state.store;
            let tip = state.tip_height().await;
            let new: Vec<_> = current.difference(&mempool_txids).collect();
            let removed: Vec<_> = mempool_txids.difference(&current).cloned().collect();
            if !new.is_empty() {
                log::debug!("new txs in mempool {:?}, tip: {tip:?}", new);
            }
            if removed.len() > 1 {
                log::info!(
                    "removed {} txs from mempool, tip: {tip:?}, still in mempool: {}",
                    removed.len(),
                    current.len()
                );
            }

            let mut txs = vec![];
            for new_txid in new {
                match client.tx(*new_txid, family).await {
                    Ok(tx) => txs.push((*new_txid, tx)),
                    Err(e) => {
                        if let Some(crate::fetch::Error::TxNotFound(_, _)) = e.downcast_ref() {
                            // tx not found, it was replaced from mempool with RBF for example
                            log::info!("{e}");
                        } else {
                            log::error!("{e}");
                        }
                    }
                }
            }
            {
                let mut m = state.mempool.lock().await;
                m.remove(&removed);
                m.add(db, &txs);
                mempool_txids.clear();
                mempool_txids.extend(m.txids_iter());
            }
        }
        Err(e) => {
            log::warn!("mempool sync error, is the node running and has rest=1 ?\n{e:?}")
        }
    }
    sleep(std::time::Duration::from_secs(1)).await;
}

async fn mempool_sync(
    state: Arc<State>,
    client: Client,
    family: Family,
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

    loop {
        tokio::select! {
            _ = &mut signal => {
                log::info!("mempool thread received shutdown signal");
                return Ok(());
            }
            _ = async {
                sync_mempool_once(&client, support_vebose, &mut mempool_txids, &state, family).await;
            } => {}
        }
    }
}
