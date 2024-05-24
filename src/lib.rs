use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use db::DBStore;
use fetch::Client;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use mempool::Mempool;
use threads::headers::headers_infallible;
use threads::index::index_infallible;
use threads::mempool::mempool_sync_infallible;
use tokio::net::TcpListener;
use tokio::sync::Mutex;

mod db;
mod fetch;
mod mempool;
mod route;
mod threads;

type ScriptHash = u64;
type Height = u32;

#[derive(clap::Parser)]
#[command(author, version, about, long_about = None)]
pub struct Arguments {
    /// if specified, use liquid testnet
    #[arg(long)]
    testnet: bool,

    /// if specified, it uses a local node exposing the rest interface on the default port
    #[arg(long)]
    local_node: bool,
}

#[derive(Debug)]
pub enum Error {
    WrongNetwork,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}
impl std::error::Error for Error {}

pub async fn inner_main(args: Arguments) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut path = PathBuf::new();
    path.push("db");
    if args.testnet {
        path.push("testnet");
    } else {
        path.push("mainnet");
    }

    let db = Arc::new(DBStore::open(&path)?);
    let mempool = Arc::new(Mutex::new(Mempool::new()));

    let addr = SocketAddr::from(([127, 0, 0, 1], 3100 + args.testnet as u16));
    println!("Starting on http://{addr}");

    let listener = TcpListener::bind(addr).await?;

    let _h1 = {
        let db = db.clone();
        let client: Client = Client::new(args.testnet, args.local_node);
        tokio::spawn(async move { index_infallible(db, client).await })
    };

    let _h2 = {
        let db = db.clone();
        let client: Client = Client::new(args.testnet, args.local_node);
        tokio::spawn(async move { headers_infallible(db, client).await })
    };

    let _h3 = {
        let db = db.clone();
        let mempool = mempool.clone();
        let client = Client::new(args.testnet, args.local_node);
        tokio::spawn(async move { mempool_sync_infallible(db, mempool, client).await })
    };

    loop {
        let (stream, _) = listener.accept().await?;

        let io = TokioIo::new(stream);
        let db: Arc<DBStore> = db.clone();
        let mempool: Arc<Mutex<Mempool>> = mempool.clone();

        tokio::task::spawn(async move {
            let db = &db;
            let mempool = &mempool;
            let is_testnet = args.testnet;

            let service = service_fn(move |req| route::route(db, mempool, req, is_testnet));

            if let Err(err) = http1::Builder::new().serve_connection(io, service).await {
                println!("Error serving connection: {:?}", err);
            }
        });
    }
}
