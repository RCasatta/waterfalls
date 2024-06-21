//! Inside this module everything is needed to run the service providing the waterfalls protocol

use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;

use crate::fetch::Client;
use crate::server::preload::headers;
use crate::store::memory::MemoryStore;
use crate::store::AnyStore;
use crate::threads::blocks::blocks_infallible;
use crate::threads::mempool::mempool_sync_infallible;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;
use tokio::sync::Mutex;

mod mempool;
pub mod preload;
pub mod route;
mod state;

pub use mempool::Mempool;
pub use state::State;

#[derive(clap::Parser, Clone, Default)]
#[command(author, version, about, long_about = None)]
pub struct Arguments {
    /// if specified, use liquid testnet
    #[arg(long)]
    pub testnet: bool,

    /// if specified, it uses esplora instead of local node to get data
    #[arg(long)]
    pub use_esplora: bool,

    /// If `use_esplora` is true will use this address to fetch data from esplora or a default url according to the used network if not provided.
    #[arg(long)]
    pub esplora_url: Option<String>,

    /// If `use_esplora` is false will use this address to fetch data from the local rest-enabled elements node or a default url according to the used network if not provided.
    #[arg(long)]
    pub node_url: Option<String>,

    #[arg(long)]
    pub listen: Option<SocketAddr>,

    #[cfg(feature = "db")]
    #[arg(long)]
    pub datadir: Option<std::path::PathBuf>,
}

#[derive(Debug)]
pub enum Error {
    WrongNetwork,
    Other,
    DescriptorFieldMandatory,
    CannotParseHeight,
    InvalidTxid,
    CannotFindTx,
    InvalidBlockHash,
    CannotFindBlockHeader,
    DBOpen,
    CannotLoadEncryptionKey,
    CannotDecrypt,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}
impl std::error::Error for Error {}

#[cfg(not(feature = "db"))]
fn get_store(_args: &Arguments) -> Result<AnyStore, Error> {
    Ok(AnyStore::Mem(MemoryStore::new()))
}
#[cfg(feature = "db")]
fn get_store(args: &Arguments) -> Result<AnyStore, Error> {
    use crate::store;

    Ok(match args.datadir.as_ref() {
        Some(p) => {
            let mut path = p.clone();
            path.push("db");
            if args.testnet {
                path.push("testnet");
            } else {
                path.push("mainnet");
            }
            AnyStore::Db(store::db::DBStore::open(&path).map_err(|_| Error::DBOpen)?)
        }
        None => AnyStore::Mem(MemoryStore::new()),
    })
}

pub async fn inner_main(
    args: Arguments,
    shutdown_signal: impl Future<Output = ()>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // TODO test rest connection to the node

    let store = get_store(&args)?;

    let state = Arc::new(State::new(store)?);

    {
        let state = state.clone();
        headers(state).await.unwrap();
    }

    let _h1 = {
        let state = state.clone();
        let client: Client = Client::new(&args);
        tokio::spawn(async move { blocks_infallible(state, client).await })
    };

    let _h2 = {
        let state = state.clone();
        let client = Client::new(&args);
        tokio::spawn(async move { mempool_sync_infallible(state, client).await })
    };

    let addr = args.listen.unwrap_or(SocketAddr::from((
        [127, 0, 0, 1],
        3100 + args.testnet as u16,
    )));
    log::info!("Starting on http://{addr}");

    let listener = TcpListener::bind(addr).await?;
    let client = Client::new(&args);
    let client = Arc::new(Mutex::new(client));
    let mut signal = std::pin::pin!(shutdown_signal);

    loop {
        tokio::select! {
            Ok( (stream, _)) = listener.accept() => {
                let io = TokioIo::new(stream);
                let state = state.clone();
                let client = client.clone();

                tokio::task::spawn(async move {
                    let state = &state;
                    let is_testnet = args.testnet;
                    let client = &client;

                    let service = service_fn(move |req| route::route(state, client, req, is_testnet));

                    if let Err(err) = http1::Builder::new().serve_connection(io, service).await {
                        log::error!("Error serving connection: {:?}", err);
                    }
                });
            },

            _ = &mut signal => {
                log::error!("graceful shutdown signal received");
                // stop the accept loop
                break;
            }
        }
    }
    Ok(())
}
