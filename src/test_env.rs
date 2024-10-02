use crate::{
    server::{inner_main, Arguments},
    WaterfallResponse,
};
use std::{
    error::Error,
    ffi::OsStr,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::PathBuf,
    str::FromStr,
};

use age::x25519::{Identity, Recipient};
use anyhow::bail;
use bitcoind::{bitcoincore_rpc::RpcApi, get_available_port, BitcoinD, Conf};
use elements::{
    bitcoin::{Amount, Denomination},
    encode::Decodable,
    Address, BlockHash, BlockHeader, Txid,
};
use serde_json::Value;
use tokio::sync::oneshot::{self, Receiver, Sender};

pub struct TestEnv {
    #[allow(dead_code)]
    elementsd: BitcoinD,
    handle: tokio::task::JoinHandle<Result<(), Box<dyn Error + Send + Sync>>>,
    tx: Sender<()>,
    client: WaterfallClient,
    base_url: String,
    server_key: Identity,
}

#[cfg(feature = "db")]
pub async fn launch<S: AsRef<OsStr>>(exe: S, path: Option<PathBuf>) -> TestEnv {
    inner_launch(exe, path).await
}

#[cfg(not(feature = "db"))]
pub async fn launch<S: AsRef<OsStr>>(exe: S) -> TestEnv {
    inner_launch(exe, None).await
}

#[cfg(feature = "db")]
pub async fn launch_with_node(elementsd: BitcoinD, path: Option<PathBuf>) -> TestEnv {
    inner_launch_with_node(elementsd, path).await
}

#[cfg(not(feature = "db"))]
pub async fn launch_with_node(elementsd: BitcoinD) -> TestEnv {
    inner_launch_with_node(elementsd, None).await
}

async fn inner_launch_with_node(elementsd: BitcoinD, path: Option<PathBuf>) -> TestEnv {
    let mut args = Arguments::default();
    args.node_url = Some(elementsd.rpc_url());
    let available_port = get_available_port().unwrap();
    let socket_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), available_port);
    let base_url = format!("http://{socket_addr}");
    args.listen = Some(socket_addr);
    args.testnet = true;
    let server_key = Identity::generate();
    args.server_key = Some(server_key.clone());

    let cookie = std::fs::read_to_string(&elementsd.params.cookie_file).unwrap();
    args.rpc_user_password = Some(cookie);

    #[cfg(feature = "db")]
    {
        args.datadir = path;
    }
    #[cfg(not(feature = "db"))]
    {
        if let Some(_) = path {
            panic!("specifying path without db feature");
        }
    }

    let (tx, rx) = oneshot::channel();
    let handle = tokio::spawn(inner_main(args, shutdown_signal(rx)));

    let client = WaterfallClient::new(base_url.to_string());

    let test_env = TestEnv {
        elementsd,
        handle,
        tx,
        client,
        base_url,
        server_key,
    };

    test_env.node_generate(1).await;
    test_env
        .elementsd
        .client
        .call::<Value>("rescanblockchain", &[])
        .unwrap();
    test_env.node_generate(1).await;

    test_env
}

async fn inner_launch<S: AsRef<OsStr>>(exe: S, path: Option<PathBuf>) -> TestEnv {
    let mut conf = Conf::default();
    let args = vec![
        "-fallbackfee=0.0001",
        "-dustrelayfee=0.00000001",
        "-chain=liquidregtest",
        "-initialfreecoins=2100000000",
        "-validatepegin=0",
        "-txindex=1",
        "-rest=1",
    ];
    conf.args = args;
    conf.view_stdout = std::env::var("RUST_LOG").is_ok();
    conf.network = "liquidregtest";

    let elementsd = BitcoinD::with_conf(exe, &conf).unwrap();
    inner_launch_with_node(elementsd, path).await
}

impl TestEnv {
    pub async fn shutdown(self) {
        self.tx.send(()).unwrap();
        let _ = self.handle.await.unwrap();
    }

    pub fn client(&self) -> &WaterfallClient {
        &self.client
    }

    pub fn server_recipient(&self) -> Recipient {
        self.server_key.to_public()
    }

    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    pub fn send_to(&self, address: &elements::Address, satoshis: u64) -> Txid {
        let amount = Amount::from_sat(satoshis);
        let btc = amount.to_string_in(Denomination::Bitcoin);
        let val = self
            .elementsd
            .client
            .call::<Value>("sendtoaddress", &[address.to_string().into(), btc.into()])
            .unwrap();
        Txid::from_str(val.as_str().unwrap()).unwrap()
    }

    pub fn get_new_address(&self, kind: Option<&str>) -> Address {
        let kind = kind.unwrap_or("p2sh-segwit");
        let addr: Value = self
            .elementsd
            .client
            .call("getnewaddress", &["label".into(), kind.into()])
            .unwrap();
        Address::from_str(addr.as_str().unwrap()).unwrap()
    }

    /// generate `block_num` blocks and wait the waterfalls server had indexed them
    pub async fn node_generate(&self, block_num: u32) {
        let (prev_height, _) = self.client.wait_tip_height_hash(None).await.unwrap();
        let address = self.get_new_address(None).to_string();
        self.elementsd
            .client
            .call::<Value>("generatetoaddress", &[block_num.into(), address.into()])
            .unwrap();
        self.client
            .wait_tip_height_hash(Some(prev_height + block_num))
            .await
            .unwrap();
    }
}

async fn shutdown_signal(rx: Receiver<()>) {
    rx.await.unwrap()
}

pub struct WaterfallClient {
    client: reqwest::Client,
    base_url: String,
}

impl WaterfallClient {
    pub fn new(base_url: String) -> Self {
        let client = reqwest::Client::new();
        Self { client, base_url }
    }

    /// Call the waterfalls endpoint
    ///
    /// it can accept the bitcoin descriptor part of the ct descriptor in plaintext
    /// or encrypted with the server key
    pub async fn waterfalls(&self, desc: &str) -> anyhow::Result<WaterfallResponse> {
        let descriptor_url = format!("{}/v1/waterfalls", self.base_url);

        let response = self
            .client
            .get(&descriptor_url)
            .query(&[("descriptor", desc)])
            .send()
            .await?;

        let body = response.text().await?;
        Ok(serde_json::from_str(&body)?)
    }

    pub async fn wait_waterfalls_non_empty(
        &self,
        bitcoin_desc: &str,
    ) -> anyhow::Result<WaterfallResponse> {
        for _ in 0..50 {
            if let Ok(res) = self.waterfalls(&bitcoin_desc).await {
                if !res.is_empty() {
                    return Ok(res);
                }
            }

            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        }
        panic!("no non-empty result after 10s")
    }

    pub async fn tip_hash(&self) -> anyhow::Result<BlockHash> {
        let url = format!("{}/blocks/tip/hash", self.base_url);
        let response = self.client.get(&url).send().await?;
        let text = response.text().await?;
        Ok(BlockHash::from_str(&text)?)
    }

    pub async fn tip_height_hash(&self) -> anyhow::Result<(u32, BlockHash)> {
        let hash = self.tip_hash().await?;
        let height = self.height(hash).await?;
        Ok((height, hash))
    }

    pub async fn wait_tip_height_hash(
        &self,
        up_to: Option<u32>,
    ) -> anyhow::Result<(u32, BlockHash)> {
        for _ in 0..50 {
            if let Ok((height, hash)) = self.tip_height_hash().await {
                match up_to.as_ref() {
                    Some(expected) => {
                        if height == *expected {
                            return Ok((height, hash));
                        }
                    }
                    None => return Ok((height, hash)),
                }
            }

            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        }
        panic!("no tip height after 10s")
    }

    pub async fn height(&self, block_hash: BlockHash) -> anyhow::Result<u32> {
        Ok(self.header(block_hash).await?.height)
    }
    pub async fn header(&self, block_hash: BlockHash) -> anyhow::Result<BlockHeader> {
        let url = format!("{}/block/{}/header", self.base_url, block_hash);
        let response = self.client.get(&url).send().await?;
        let text = response.text().await?;
        let bytes = hex::decode(&text)?;
        let header = BlockHeader::consensus_decode(&bytes[..])?;
        Ok(header)
    }

    pub async fn server_recipient(&self) -> anyhow::Result<Recipient> {
        let url = format!("{}/v1/server_recipient", self.base_url);
        let response = self.client.get(&url).send().await?;
        let status_code = response.status().as_u16();
        if status_code != 200 {
            bail!("server_recipient response is not 200 but: {}", status_code);
        }
        let text = response.text().await?;

        Recipient::from_str(&text).or_else(|e| bail!("cannot parse recipient {}", e))
    }
}
