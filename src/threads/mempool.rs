use std::{collections::HashSet, sync::Arc};

use tokio::{sync::Mutex, time::sleep};

use crate::{db::DBStore, fetch::Client, mempool::Mempool, Error};

pub(crate) async fn mempool_sync_infallible(
    db: Arc<DBStore>,
    mempool: Arc<Mutex<Mempool>>,
    client: Client,
) {
    if let Err(e) = mempool_sync(db, mempool, client).await {
        log::error!("{:?}", e);
    }
}

async fn mempool_sync(
    db: Arc<DBStore>,
    mempool: Arc<Mutex<Mempool>>,
    client: Client,
) -> Result<(), Error> {
    let mut mempool_txids = HashSet::new();
    loop {
        match client.mempool().await {
            Ok(current) => {
                let new: Vec<_> = current.difference(&mempool_txids).collect();
                let removed: Vec<_> = mempool_txids.difference(&current).cloned().collect();
                if !new.is_empty() {
                    let tip = db.tip().unwrap_or(0);
                    println!("new txs in mempool {:?}, tip: {tip}", new);
                }
                if !removed.is_empty() {
                    let tip = db.tip().unwrap_or(0);
                    println!("removed txs from mempool {:?}, tip: {tip}", removed);
                }

                let mut txs = vec![];
                for new_txid in new {
                    let tx = client.tx(*new_txid).await.unwrap(); // TODO
                    txs.push(tx)
                }
                {
                    let mut m = mempool.lock().await;
                    m.remove(&removed);
                    m.add(&db, &txs);
                    mempool_txids = m.txids();
                }
            }
            Err(e) => println!("{e:?}"),
        }
        sleep(std::time::Duration::from_secs(1)).await;
    }
}
