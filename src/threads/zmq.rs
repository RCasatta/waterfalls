use std::{future::Future, sync::Arc};

use futures_util::StreamExt;
use tmq::{subscribe, Context, Multipart};

use crate::{
    be::Family,
    server::{Error, State},
};

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
    let ctx = Context::new();
    let socket_builder = subscribe(&ctx)
        .connect(&endpoint)
        .map_err(|e| Error::String(format!("failed connecting ZMQ socket to {endpoint}: {e}")))?;
    let mut socket = socket_builder
        .subscribe(b"rawtx")
        .map_err(|e| Error::String(format!("failed subscribing to rawtx on {endpoint}: {e}")))?;

    log::info!("ZMQ rawtx thread listening on {endpoint}");

    let mut signal = std::pin::pin!(shutdown_signal);

    loop {
        tokio::select! {
            _ = &mut signal => {
                log::info!("zmq rawtx thread received shutdown signal");
                return Ok(());
            }
            message = socket.next() => {
                match message {
                    Some(Ok(message)) => process_rawtx_message(&state, message, family).await?,
                    Some(Err(e)) => log::error!("error receiving ZMQ message from {endpoint}: {e}"),
                    None => {
                        return Err(Error::String(format!(
                            "ZMQ socket closed unexpectedly for endpoint {endpoint}"
                        )));
                    }
                }
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
    // Intentionally wait on the shared mempool_cache lock here. The mempool thread keeps
    // it for the whole sync cycle so it can safely clear the cache at the end without
    // racing with concurrent ZMQ inserts. We considered a small local queue here, but
    // without a separate drain trigger/worker it could leave transactions sitting there
    // until another ZMQ message arrives, so stalling on the lock is the simpler tradeoff.
    state.mempool_cache.lock().await.insert(txid, tx);
    log::debug!("zmq rawtx txid={txid}");

    Ok(())
}
