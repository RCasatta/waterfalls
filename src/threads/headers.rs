use std::sync::Arc;

use elements::{hashes::Hash, BlockHash};
use tokio::time::sleep;

use crate::{
    esplora::{Client},
    state::State,
    Error,
};

pub(crate) async fn headers_infallible(shared_state: Arc<State>) {
    if let Err(e) = headers(shared_state).await {
        log::error!("{:?}", e);
    }
}

pub async fn headers(shared_state: Arc<State>) -> Result<(), Error> {
    // TODO bulk load first chunk of headers!
    let mut height = 0usize;
    let client = Client::new();
    loop {
        match client.block_hash(height as u32).await {
            Ok(block_hash) => {
                let mut headers = shared_state.headers.lock().await;
                if headers.len() >= height {
                    let new_len = headers.len() + 1000;
                    headers.resize(new_len, BlockHash::all_zeros());
                }
                headers[height] = block_hash;
                height += 1;
                if height % 10_000 == 0 {
                    println!("headers {}/{}", height, shared_state.tip_height);
                }
            }
            Err(_e) => {
                sleep(std::time::Duration::from_secs(1)).await;
            }
        }
    }
}
