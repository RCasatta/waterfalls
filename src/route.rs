use std::sync::Arc;

use http_body_util::Full;
use hyper::{body::Bytes, Request, Response};

use crate::{esplora, state::State, Error};

pub(crate) async fn route(
    state: &Arc<State>,
    req: Request<hyper::body::Incoming>,
) -> Result<Response<Full<Bytes>>, Error> {
    println!("{:?}", state);
    println!("{:?}", req);
    let hash = esplora::tip_hash().await.unwrap();
    // let block = esplora::block(hash).await.unwrap();

    Ok(Response::new(Full::new(Bytes::from(format!(
        "Last block is {}",
        hash,
        // block.txdata.len(),
        // block.header.height
    )))))
}
