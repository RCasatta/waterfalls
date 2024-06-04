use crate::{fetch::Client, state::State, Error};
use std::{collections::HashSet, sync::Arc};
use tokio::time::sleep;

pub(crate) async fn mempool_sync_infallible(state: Arc<State>, client: Client) {
    if let Err(e) = mempool_sync(state, client).await {
        log::error!("{:?}", e);
    }
}

async fn mempool_sync(state: Arc<State>, client: Client) -> Result<(), Error> {
    let db = &state.db;
    let mut mempool_txids = HashSet::new();
    loop {
        match client.mempool().await {
            Ok(current) => {
                let tip = state.tip().await;
                let new: Vec<_> = current.difference(&mempool_txids).collect();
                let removed: Vec<_> = mempool_txids.difference(&current).cloned().collect();
                if !new.is_empty() {
                    println!("new txs in mempool {:?}, tip: {tip:?}", new);
                }
                if !removed.is_empty() {
                    println!("removed txs from mempool {:?}, tip: {tip:?}", removed);
                }

                let mut txs = vec![];
                for new_txid in new {
                    let tx = client.tx_or_wait(*new_txid).await;
                    txs.push(tx)
                }
                {
                    let mut m = state.mempool.lock().await;
                    m.remove(&removed);
                    m.add(db, &txs);
                    mempool_txids = m.txids();
                }
            }
            Err(e) => println!("mempool sync {e:?}"),
        }
        sleep(std::time::Duration::from_secs(1)).await;
    }
}
