use crate::{
    be::Family,
    fetch::Client,
    server::{Error, State},
};
use std::{collections::HashSet, sync::Arc};
use tokio::time::sleep;

pub(crate) async fn mempool_sync_infallible(
    state: Arc<State>,
    client: Client,
    family: Family,
    initial_sync_rx: tokio::sync::oneshot::Receiver<()>,
) {
    if let Err(e) = mempool_sync(state, client, family, initial_sync_rx).await {
        log::error!("{:?}", e);
    }
}

async fn mempool_sync(
    state: Arc<State>,
    client: Client,
    family: Family,
    initial_sync_rx: tokio::sync::oneshot::Receiver<()>,
) -> Result<(), Error> {
    // Wait for initial block download to complete
    log::info!("Mempool thread waiting for initial block download to complete...");
    match initial_sync_rx.await {
        Ok(_) => log::info!("Initial block download completed, starting mempool sync"),
        Err(e) => error_panic!("Initial sync channel closed unexpectedly: {e}"),
    }

    let db = &state.store;
    let mut mempool_txids = HashSet::new();
    let support_vebose = client.mempool(true).await.is_ok();
    log::info!("mempool support verbose: {support_vebose}");
    loop {
        match client.mempool(support_vebose).await {
            Ok(current) => {
                let tip = state.tip().await;
                let new: Vec<_> = current.difference(&mempool_txids).collect();
                let removed: Vec<_> = mempool_txids.difference(&current).cloned().collect();
                if !new.is_empty() {
                    log::debug!("new txs in mempool {:?}, tip: {tip:?}", new);
                }
                if !removed.is_empty() {
                    log::info!(
                        "removed {} txs from mempool, tip: {tip:?}, still in mempool: {}",
                        removed.len(),
                        current.len()
                    );
                }

                let mut txs = vec![];
                for new_txid in new {
                    match client.tx(*new_txid, family).await {
                        Ok(tx) => txs.push(tx),
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
                    mempool_txids = m.txids();
                }
            }
            Err(e) => {
                log::warn!("mempool sync error, is the node running and has rest=1 ?\n{e:?}")
            }
        }
        sleep(std::time::Duration::from_secs(1)).await;
    }
}
