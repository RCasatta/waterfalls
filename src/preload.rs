use std::sync::Arc;

use crate::{state::State, store::Store, Error};

pub async fn headers(state: Arc<State>) -> Result<(), Error> {
    let mut blocks_hash_ts = state.blocks_hash_ts.lock().await;
    let mut i = 0usize;
    for meta in state.store.iter_hash_ts() {
        assert_eq!(i as u32, meta.height());
        blocks_hash_ts.push((meta.hash(), meta.timestamp()));
        i += 1;
    }
    log::info!("{i} block meta preloaded");

    Ok(())
}
