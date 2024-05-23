use std::{collections::HashSet, sync::Arc};

use tokio::{sync::Mutex, time::sleep};

use crate::{db::DBStore, esplora::Client, mempool::Mempool, Error};

pub(crate) async fn mempool_sync_infallible(db: Arc<DBStore>, mempool: Arc<Mutex<Mempool>>) {
    if let Err(e) = mempool_sync(db, mempool).await {
        log::error!("{:?}", e);
    }
}

async fn mempool_sync(db: Arc<DBStore>, mempool: Arc<Mutex<Mempool>>) -> Result<(), Error> {
    let mut mempool_txids = HashSet::new();
    let client = Client::new();

    loop {
        match client.mempool().await {
            Ok(current) => {
                let new: Vec<_> = current.difference(&mempool_txids).collect();
                let removed: Vec<_> = mempool_txids.difference(&current).cloned().collect();
                if !new.is_empty() {
                    println!("new txs in mempool {:?}", new);
                }
                if !removed.is_empty() {
                    println!("removed txs from mempool {:?}", removed);
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
                }
                mempool_txids.extend(&current);
            }
            Err(e) => println!("{e:?}"),
        }
        sleep(std::time::Duration::from_secs(1)).await;
    }
}
