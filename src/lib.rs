use std::net::SocketAddr;
use std::sync::Arc;

use elements::hashes::Hash;
use elements::BlockHash;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use state::State;
use tokio::net::TcpListener;

mod esplora;
mod route;
mod state;

#[derive(clap::Parser)]
#[command(author, version, about, long_about = None)]
pub struct Arguments {}

#[derive(Debug)]
pub enum Error {}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}
impl std::error::Error for Error {}

pub async fn inner_main(_args: Arguments) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // TODO load persisted state
    let state = Arc::new(State::new(BlockHash::all_zeros())); // TODO genesis hash

    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));

    let listener = TcpListener::bind(addr).await?;

    loop {
        let (stream, _) = listener.accept().await?;

        let io = TokioIo::new(stream);
        let state: Arc<State> = state.clone();

        tokio::task::spawn(async move {
            let state = &state;
            let service = service_fn(move |req| route::route(state, req));

            if let Err(err) = http1::Builder::new().serve_connection(io, service).await {
                println!("Error serving connection: {:?}", err);
            }
        });
    }
}
