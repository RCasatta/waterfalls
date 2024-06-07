use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use db::DBStore;
use fetch::Client;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use mempool::Mempool;
use preload::headers;
use state::State;
use threads::blocks::blocks_infallible;
use threads::mempool::mempool_sync_infallible;
use tokio::net::TcpListener;
use tokio::sync::Mutex;

mod db;
mod fetch;
mod mempool;
mod preload;
mod route;
mod state;
mod threads;

type ScriptHash = u64;
type Height = u32;
type Timestamp = u32;

#[derive(clap::Parser)]
#[command(author, version, about, long_about = None)]
pub struct Arguments {
    /// if specified, use liquid testnet
    #[arg(long)]
    testnet: bool,

    /// if specified, it uses esplora instead of local node to get data
    #[arg(long)]
    use_esplora: bool,

    #[arg(long)]
    listen: Option<SocketAddr>,

    #[arg(long)]
    datadir: Option<PathBuf>,
}

#[derive(Debug)]
pub enum Error {
    WrongNetwork,
    Other,
    DescriptorFieldMandatory,
    CannotParseHeight,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}
impl std::error::Error for Error {}

pub async fn inner_main(args: Arguments) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // TODO test rest connection to the node

    let mut path = match args.datadir.as_ref() {
        Some(p) => p.clone(),
        None => PathBuf::new(),
    };
    path.push("db");
    if args.testnet {
        path.push("testnet");
    } else {
        path.push("mainnet");
    }

    let state = Arc::new(State {
        db: DBStore::open(&path)?,
        mempool: Mutex::new(Mempool::new()),
        blocks_hash_ts: Mutex::new(Vec::new()),
    });

    {
        let state = state.clone();
        headers(state).await.unwrap();
    }

    let _h1 = {
        let state = state.clone();
        let client: Client = Client::new(args.testnet, args.use_esplora);
        tokio::spawn(async move { blocks_infallible(state, client).await })
    };

    let _h2 = {
        let state = state.clone();
        let client = Client::new(args.testnet, args.use_esplora);
        tokio::spawn(async move { mempool_sync_infallible(state, client).await })
    };

    let addr = args.listen.unwrap_or(SocketAddr::from((
        [127, 0, 0, 1],
        3100 + args.testnet as u16,
    )));
    println!("Starting on http://{addr}");

    let listener = TcpListener::bind(addr).await?;

    loop {
        let (stream, _) = listener.accept().await?;

        let io = TokioIo::new(stream);
        let state = state.clone();

        tokio::task::spawn(async move {
            let state = &state;
            let is_testnet = args.testnet;

            let service = service_fn(move |req| route::route(state, req, is_testnet));

            if let Err(err) = http1::Builder::new().serve_connection(io, service).await {
                println!("Error serving connection: {:?}", err);
            }
        });
    }
}
