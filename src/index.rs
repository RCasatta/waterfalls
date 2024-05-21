// pub(crate) start()

use std::sync::Arc;

use crate::{state::State, Error};

pub(crate) async fn index_infallible(shared_state: Arc<State>) {
    if let Err(e) = index(shared_state).await {
        log::error!("{:?}", e);
    }
}

pub async fn index(shared_state: Arc<State>) -> Result<(), Error> {
    todo!()
}
