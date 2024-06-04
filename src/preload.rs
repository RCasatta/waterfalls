use std::sync::Arc;

use crate::{state::State, Error};

pub async fn headers(state: Arc<State>) -> Result<(), Error> {
    let mut blocks_hash_ts = state.blocks_hash_ts.lock().await;
    let mut i = 0usize;
    for (height, hash, ts) in state.db.iter_hash_ts() {
        if i % 100_000 == 0 {
            println!("{i} preloaded");
        }

        assert_eq!(i as u32, height);
        blocks_hash_ts.push((hash, ts));
        i += 1;
    }
    Ok(())
}
