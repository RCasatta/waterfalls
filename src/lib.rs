use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;

use db::DBStore;
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
mod esplora;
mod mempool;
mod route;
mod threads;

type ScriptHash = u64;
type Height = u32;

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
    let path = Path::new("db");

    let db = Arc::new(DBStore::open(path)?); // TODO genesis hash
    let mempool = Arc::new(Mutex::new(Mempool::new()));

    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));

    let listener = TcpListener::bind(addr).await?;

    let _h1 = {
        let db = db.clone();
        tokio::spawn(async move { index_infallible(db).await })
    };

    let _h2 = {
        let db = db.clone();
        tokio::spawn(async move { headers_infallible(db).await })
    };

    let _h3 = {
        let db = db.clone();
        let mempool = mempool.clone();
        tokio::spawn(async move { mempool_sync_infallible(db, mempool).await })
    };

    loop {
        let (stream, _) = listener.accept().await?;

        let io = TokioIo::new(stream);
        let db: Arc<DBStore> = db.clone();
        let mempool: Arc<Mutex<Mempool>> = mempool.clone();

        tokio::task::spawn(async move {
            let db = &db;
            let mempool = &mempool;

            let service = service_fn(move |req| route::route(db, mempool, req));

            if let Err(err) = http1::Builder::new().serve_connection(io, service).await {
                println!("Error serving connection: {:?}", err);
            }
        });
    }
}
