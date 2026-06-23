use std::{future::Future, sync::Arc, time::Duration};

use futures_util::StreamExt;
use tmq::{subscribe, Context, Multipart};
use tokio::time::{interval_at, Instant as TokioInstant, MissedTickBehavior};

use crate::{
    be::Family,
    server::{Error, State},
    store::Store,
};

const RAWTX_SUMMARY_INTERVAL: Duration = Duration::from_secs(5 * 60);

pub(crate) async fn rawtx_listener_infallible(
    state: Arc<State>,
    endpoint: String,
    family: Family,
    shutdown_signal: impl Future<Output = ()>,
) {
    if let Err(e) = rawtx_listener(state, endpoint, family, shutdown_signal).await {
        log::error!("{:?}", e);
    }
}

async fn rawtx_listener(
    state: Arc<State>,
    endpoint: String,
    family: Family,
    shutdown_signal: impl Future<Output = ()>,
) -> Result<(), Error> {
    let mut received_txs = 0u64;
    let ctx = Context::new();
    let socket_builder = subscribe(&ctx)
        .connect(&endpoint)
        .map_err(|e| Error::String(format!("failed connecting ZMQ socket to {endpoint}: {e}")))?;
    let mut socket = socket_builder
        .subscribe(b"rawtx")
        .map_err(|e| Error::String(format!("failed subscribing to rawtx on {endpoint}: {e}")))?;

    log::info!("ZMQ rawtx thread listening on {endpoint}");

    let mut signal = std::pin::pin!(shutdown_signal);
    let mut summary_interval = interval_at(
        TokioInstant::now() + RAWTX_SUMMARY_INTERVAL,
        RAWTX_SUMMARY_INTERVAL,
    );
    summary_interval.set_missed_tick_behavior(MissedTickBehavior::Skip);

    loop {
        tokio::select! {
            _ = &mut signal => {
                log::info!("zmq rawtx thread received shutdown signal");
                return Ok(());
            }
            message = socket.next() => {
                match message {
                    Some(Ok(message)) => {
                        process_rawtx_message(&state, message, family).await?;
                        received_txs += 1;
                    }
                    Some(Err(e)) => log::error!("error receiving ZMQ message from {endpoint}: {e}"),
                    None => {
                        return Err(Error::String(format!(
                            "ZMQ socket closed unexpectedly for endpoint {endpoint}"
                        )));
                    }
                }
            }
            _ = summary_interval.tick() => {
                log::info!("zmq rawtx summary: received_txs={received_txs}");
                received_txs = 0;
            }
        }
    }
}

async fn process_rawtx_message(
    state: &Arc<State>,
    message: Multipart,
    family: Family,
) -> Result<(), Error> {
    let mut parts = message.iter().map(|part| part.as_ref());
    let Some(topic) = parts.next() else {
        log::warn!("received ZMQ message without topic");
        return Ok(());
    };
    let Some(payload) = parts.next() else {
        log::warn!("received ZMQ message without payload for topic {:?}", topic);
        return Ok(());
    };

    if topic != b"rawtx" {
        log::debug!("ignoring ZMQ topic {:?}", topic);
        return Ok(());
    }

    let tx = crate::be::Transaction::from_bytes(payload, family)
        .map_err(|e| Error::String(format!("failed decoding rawtx payload from ZMQ: {e}")))?;
    let txid = tx.txid();
    let mempool_tx = crate::be::MempoolTx::new(&tx, |script| state.store.hash(script));
    // Intentionally wait on the shared mempool_cache lock here. The mempool thread keeps
    // it for the whole sync cycle so it can safely clear the cache at the end without
    // racing with concurrent ZMQ inserts. We considered a small local queue here, but
    // without a separate drain trigger/worker it could leave transactions sitting there
    // until another ZMQ message arrives, so stalling on the lock is the simpler tradeoff.
    state.mempool_cache.lock().await.insert(txid, mempool_tx);
    log::debug!("zmq rawtx txid={txid}");

    Ok(())
}
