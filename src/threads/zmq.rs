use std::future::Future;

use futures_util::StreamExt;
use tmq::{subscribe, Context, Multipart};

use crate::{be::Family, server::Error};

pub(crate) async fn rawtx_listener_infallible(
    endpoint: String,
    family: Family,
    shutdown_signal: impl Future<Output = ()>,
) {
    if let Err(e) = rawtx_listener(endpoint, family, shutdown_signal).await {
        log::error!("{:?}", e);
    }
}

async fn rawtx_listener(
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
                    Some(Ok(message)) => process_rawtx_message(message, family)?,
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

fn process_rawtx_message(message: Multipart, family: Family) -> Result<(), Error> {
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
    log::debug!("zmq rawtx txid={}", tx.txid());

    Ok(())
}
