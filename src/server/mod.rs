//! Inside this module everything is needed to run the service providing the waterfalls protocol

use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use crate::fetch::Client;
use crate::server::preload::headers;
use crate::store::memory::MemoryStore;
use crate::store::AnyStore;
use crate::threads::blocks::blocks_infallible;
use crate::threads::mempool::mempool_sync_infallible;
use age::x25519::Identity;
use bitcoin::{NetworkKind, PrivateKey};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::{TokioIo, TokioTimer};
use route::infallible_route;
use tokio::net::TcpListener;
use tokio::sync::Mutex;

mod derivation_cache;
pub mod encryption;
mod mempool;
pub mod preload;
pub mod route;
pub mod sign;
mod state;

pub use mempool::Mempool;
pub use state::State;

#[derive(Clone, clap::ValueEnum, Debug, PartialEq, Eq, Copy)]
pub enum Network {
    Liquid,
    LiquidTestnet,
    ElementsRegtest,
    Bitcoin,
    BitcoinTestnet,
    BitcoinRegtest,
    BitcoinSignet,
}

#[derive(clap::Parser, Clone, Default)]
#[command(author, version, about, long_about = None)]
pub struct Arguments {
    /// network to use, default on liquid mainnet
    #[arg(env, long)]
    pub network: Network,

    /// if specified, it uses esplora instead of local node to get data
    #[arg(env, long)]
    pub use_esplora: bool,

    /// If `use_esplora` is true will use this address to fetch data from esplora or a default url according to the used network if not provided.
    #[arg(env, long)]
    pub esplora_url: Option<String>,

    /// If `use_esplora` is false will use this address to fetch data from the local rest-enabled elements node or a default url according to the used network if not provided.
    #[arg(env, long)]
    pub node_url: Option<String>,

    /// Socket address where to listen to serve requests
    #[arg(env, long)]
    pub listen: Option<SocketAddr>,

    /// Directory where to save the database
    #[cfg(feature = "db")]
    #[arg(env, long)]
    pub db_dir: Option<std::path::PathBuf>,

    /// An optional age server key to decrypt descriptor query string.
    /// If not provided is randomly generated.
    #[arg(long, env)]
    pub server_key: Option<Identity>,

    /// An optional server private key in WIF format to sign responses using the bitcoin sign message standard (same as `bitcoin-cli signmessage`).
    /// If not provided is randomly generated.
    #[arg(long, env)]
    pub wif_key: Option<PrivateKey>,

    /// Elements node rpc user and password, separated by ':' (same as the content of the cookie file)
    ///
    /// RPC connection is needed for broadcasting transaction via the `sendrawtransaction` call which is not present in the REST interface.
    /// It's an error if `use_esplora` is false and this is missing.
    #[arg(long, env)]
    pub rpc_user_password: Option<String>,

    /// Maximum number of addresses that can be specified in the query string.
    #[arg(env, long, default_value = "100")]
    pub max_addresses: usize,

    /// If true, add CORS headers to responses
    #[arg(env, long)]
    pub add_cors: bool,

    /// Maximum capacity for the derivation cache
    #[arg(env, long, default_value = "1000000")]
    pub derivation_cache_capacity: usize,

    /// Interval in minutes to log RocksDB statistics
    #[arg(env, long, default_value = "120")]
    pub logs_rocksdb_stat_every: u64,

    /// Force a manual RocksDB compaction at startup
    #[arg(env, long)]
    pub do_compaction: bool,

    // TODO make rocksdb parameter conditional on feature db
    /// RocksDB point lookup cache size in MB for UTXO and HISTORY column families
    #[arg(env, long, default_value = "64")]
    pub shared_db_cache_mb: u64,

    /// Enable RocksDB statistics collection for detailed metrics
    #[arg(env, long)]
    pub enable_db_statistics: bool,

    /// Cache control duration in seconds for waterfalls endpoints. Set to 0 to disable cache control headers.
    #[arg(env, long, default_value = "5")]
    pub cache_control_seconds: u32,

    /// Timeout in seconds for connect and for reques HTTP requests and  to the node or esplora
    #[arg(env, long, default_value = "30")]
    pub request_timeout_seconds: u64,

    /// Timeout in seconds for reading incoming HTTP request headers (protects against slowloris attacks)
    #[arg(env, long, default_value = "10")]
    pub header_read_timeout_seconds: u64,
}

// We can't automatically derive Debug for Arguments because the server_key and wif_key are sensitive data
impl std::fmt::Debug for Arguments {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut d = f.debug_struct("Arguments");
        let mut d = d
            .field("network", &self.network)
            .field("use_esplora", &self.use_esplora)
            .field("esplora_url", &self.esplora_url)
            .field("node_url", &self.node_url)
            .field("listen", &self.listen)
            .field(
                "server_key",
                &self.server_key.as_ref().map(|_| "Some(<redacted>)"),
            ) // Show presence without revealing key
            .field(
                "wif_key",
                &self.wif_key.as_ref().map(|_| "Some(<redacted>)"),
            ) // Show presence without revealing key
            .field(
                "rpc_user_password",
                &self.rpc_user_password.as_ref().map(|_| "Some(<redacted>)"),
            )
            .field("max_addresses", &self.max_addresses)
            .field("add_cors", &self.add_cors)
            .field("derivation_cache_capacity", &self.derivation_cache_capacity)
            .field("logs_rocksdb_stat_every", &self.logs_rocksdb_stat_every)
            .field("do_compaction", &self.do_compaction)
            .field("shared_db_cache_mb", &self.shared_db_cache_mb)
            .field("enable_db_statistics", &self.enable_db_statistics)
            .field("cache_control_seconds", &self.cache_control_seconds)
            .field("request_timeout_seconds", &self.request_timeout_seconds)
            .field("header_read_timeout_seconds", &self.header_read_timeout_seconds);

        #[cfg(feature = "db")]
        {
            d = d.field("db_dir", &self.db_dir);
        }

        d.finish()
    }
}

impl Arguments {
    pub fn is_valid(&self) -> Result<(), Error> {
        if !self.use_esplora && self.rpc_user_password.is_none() {
            Err(Error::String(
                "When using the node you must specify --rpc-user-password".to_string(),
            ))
        } else if self.request_timeout_seconds == 0 {
            Err(Error::String(
                "Request timeout must be greater than 0".to_string(),
            ))
        } else {
            Ok(())
        }
    }
}

impl std::str::FromStr for Network {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "liquid" => Ok(Self::Liquid),
            "liquid-testnet" => Ok(Self::LiquidTestnet),
            "elements-regtest" => Ok(Self::ElementsRegtest),
            _ => Err(Error::String(format!("Invalid network: {}", s))),
        }
    }
}

impl std::fmt::Display for Network {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Network::Liquid => "liquid",
            Network::LiquidTestnet => "liquid-testnet",
            Network::ElementsRegtest { .. } => "elements-regtest",
            Network::Bitcoin => "bitcoin",
            Network::BitcoinTestnet => "bitcoin-testnet",
            Network::BitcoinRegtest => "bitcoin-regtest",
            Network::BitcoinSignet => "bitcoin-signet",
        };
        write!(f, "{}", s)
    }
}

impl Default for Network {
    fn default() -> Self {
        Self::Liquid
    }
}

impl Network {
    pub fn as_network_kind(&self) -> NetworkKind {
        match self {
            Network::Liquid => NetworkKind::Main,
            _ => NetworkKind::Test,
        }
    }

    pub fn default_node_listen_port(&self) -> u16 {
        match self {
            Network::Liquid => 7041,
            Network::LiquidTestnet => 7039,
            Network::ElementsRegtest => 7043, // TODO: check this
            Network::Bitcoin => 8332,
            Network::BitcoinTestnet => 18332,
            Network::BitcoinRegtest => 18443,
            Network::BitcoinSignet => 38332,
        }
    }

    pub fn default_listen_port(&self) -> u16 {
        match self {
            Network::Liquid => 3100,
            Network::LiquidTestnet => 3101,
            Network::ElementsRegtest => 3102,
            Network::Bitcoin => 3103,
            Network::BitcoinTestnet => 3104,
            Network::BitcoinRegtest => 3105,
            Network::BitcoinSignet => 3106,
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    WrongNetwork,
    Other,
    CannotParseHeight,
    InvalidTxid,
    CannotFindTx,
    InvalidBlockHash,
    CannotFindBlockHeader,
    DBOpen(String),
    CannotLoadEncryptionKey,
    CannotDecrypt,
    CannotEncrypt,
    InvalidTx,
    InvalidOutpoint,
    String(String),
    InvalidAddress(String),
    CannotSpecifyBothDescriptorAndAddresses,
    AtLeastOneFieldMandatory,
    NotYetImplemented,
    AddressCannotBeBlinded,
    TooManyAddresses,
    DescriptorMustHaveWildcard,
    BodyTooLarge,
    BodyReadTimeout,
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

    Ok(match args.db_dir.as_ref() {
        Some(p) => {
            let mut path = p.clone();
            path.push("db");
            path.push(args.network.to_string());
            let db_store =
                store::db::DBStore::open(&path, args.shared_db_cache_mb, args.enable_db_statistics)
                    .map_err(|e| Error::DBOpen(format!("{e:?}")))?;

            // Perform manual compaction if requested
            if args.do_compaction {
                db_store
                    .compact_database()
                    .map_err(|e| Error::DBOpen(format!("Compaction failed: {e:?}")))?;
            }

            AnyStore::Db(db_store)
        }
        None => AnyStore::Mem(MemoryStore::new()),
    })
}

pub async fn inner_main(
    args: Arguments,
    shutdown_signal: impl Future<Output = ()>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    log::info!("starting waterfalls with args: {:?}", args);

    let store = get_store(&args)?;

    let key = args.server_key.clone().unwrap_or_else(Identity::generate);

    let network_kind = args.network.as_network_kind();

    if let Some(wif_key) = args.wif_key.as_ref() {
        if wif_key.network != network_kind {
            panic!(
                "WIF key network {:?} does not match network kind {:?}",
                wif_key.network, network_kind
            );
        }
    }

    let wif_key = args
        .wif_key
        .unwrap_or_else(|| PrivateKey::generate(network_kind));

    let state = Arc::new(State::new(
        store,
        key,
        wif_key,
        args.max_addresses,
        args.cache_control_seconds,
        args.derivation_cache_capacity,
    )?);

    {
        let state = state.clone();
        headers(state).await.unwrap();
    }

    // Create oneshot channel to signal when initial block download is complete
    let (initial_sync_tx, initial_sync_rx) = tokio::sync::oneshot::channel::<()>();

    // Create broadcast channel for shutdown signal
    let (shutdown_tx, _) = tokio::sync::broadcast::channel::<()>(1);

    let h1 = {
        let state = state.clone();
        let client: Client =
            Client::new(&args).unwrap_or_else(|e| error_panic!("Failed to create client: {e}"));
        log::info!(
            "Client for blocks task created, chain info: {:?}",
            client.chain_info().await
        );
        let shutdown_rx = shutdown_tx.subscribe();
        tokio::spawn(async move {
            let shutdown_future = async {
                let mut rx = shutdown_rx;
                let _ = rx.recv().await;
            };
            blocks_infallible(
                state,
                client,
                args.network.into(),
                initial_sync_tx,
                shutdown_future,
                args.logs_rocksdb_stat_every,
            )
            .await
        })
    };

    let h2 = {
        let state = state.clone();
        let client =
            Client::new(&args).unwrap_or_else(|e| error_panic!("Failed to create client: {e}"));
        log::info!(
            "Client for mempool task created, chain info: {:?}",
            client.chain_info().await
        );
        let shutdown_rx = shutdown_tx.subscribe();
        tokio::spawn(async move {
            let shutdown_future = async {
                let mut rx = shutdown_rx;
                let _ = rx.recv().await;
            };
            mempool_sync_infallible(
                state,
                client,
                args.network.into(),
                initial_sync_rx,
                shutdown_future,
            )
            .await
        })
    };

    let addr = args.listen.unwrap_or(SocketAddr::from((
        [127, 0, 0, 1],
        args.network.default_listen_port(),
    )));
    log::info!("Starting on http://{addr}");

    let listener = TcpListener::bind(addr).await?;
    let client = Client::new(&args)?;
    log::info!(
        "Client for server tasks created, chain info: {:?}",
        client.chain_info().await
    );
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
                    let network = args.network;
                    let add_cors = args.add_cors;
                    let header_read_timeout = args.header_read_timeout_seconds;
                    let client = &client;

                    let service = service_fn(move |req| infallible_route(state, client, req, network, add_cors));

                    let result = http1::Builder::new()
                        .timer(TokioTimer::new())
                        .header_read_timeout(Duration::from_secs(header_read_timeout))
                        .serve_connection(io, service)
                        .await;

                    if let Err(err) = result {
                        let msg = format!("{err:?}");
                        if msg.contains("HeaderTimeout") {
                            log::warn!("Header read timeout (possible scanner/slowloris): {msg}");
                        } else {
                            log::error!("Error serving connection: {msg}");
                        }
                    }
                });
            },

            _ = &mut signal => {
                log::info!("graceful shutdown signal received");
                // Signal all background tasks to shutdown
                let _ = shutdown_tx.send(());
                // stop the accept loop
                break;
            }
        }
    }

    h1.await.unwrap();
    h2.await.unwrap();

    log::info!("shutting down gracefully");
    Ok(())
}
