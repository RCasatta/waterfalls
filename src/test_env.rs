use crate::{
    server::{inner_main, sign::p2pkh, Arguments, Network},
    WaterfallResponse, WaterfallResponseV3,
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
use bitcoin::{key::Secp256k1, secp256k1::All, NetworkKind, PrivateKey};
use bitcoind::{
    bitcoincore_rpc::{bitcoin::hex::FromHex, Client, RpcApi},
    get_available_port, BitcoinD, Conf,
};
use elements::{
    bitcoin::{Amount, Denomination},
    encode::{serialize_hex, Decodable},
    Address, BlockHash, BlockHeader, Transaction, Txid,
};
use hyper::HeaderMap;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::sync::oneshot::{self, Receiver, Sender};

pub struct TestEnv<'a> {
    #[allow(dead_code)]
    elementsd: &'a BitcoinD,
    handle: tokio::task::JoinHandle<Result<(), Box<dyn Error + Send + Sync>>>,
    tx: Sender<()>,
    client: WaterfallClient,
    base_url: String,
    server_key: Identity,
    wif_key: PrivateKey,
    secp: Secp256k1<All>,
}

#[cfg(feature = "db")]
pub async fn launch<S: AsRef<OsStr>>(exe: S, path: Option<PathBuf>) -> TestEnv<'static> {
    inner_launch(exe, path).await
}

#[cfg(not(feature = "db"))]
pub async fn launch<S: AsRef<OsStr>>(exe: S) -> TestEnv<'static> {
    inner_launch(exe, None).await
}

#[cfg(feature = "db")]
pub async fn launch_with_node(elementsd: &BitcoinD, path: Option<PathBuf>) -> TestEnv {
    inner_launch_with_node(elementsd, path).await
}

#[cfg(not(feature = "db"))]
pub async fn launch_with_node(elementsd: &BitcoinD) -> TestEnv {
    inner_launch_with_node(elementsd, None).await
}

async fn inner_launch_with_node(elementsd: &BitcoinD, path: Option<PathBuf>) -> TestEnv {
    let mut args = Arguments {
        node_url: Some(elementsd.rpc_url()),
        ..Default::default()
    };
    let available_port = get_available_port().unwrap();
    let socket_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), available_port);
    let base_url = format!("http://{socket_addr}");
    args.listen = Some(socket_addr);
    args.network = Network::ElementsRegtest;
    let server_key = Identity::generate();
    args.server_key = Some(server_key.clone());
    let wif_key = PrivateKey::generate(NetworkKind::Test);
    args.wif_key = Some(wif_key);
    args.max_addresses = 100;

    let cookie = std::fs::read_to_string(&elementsd.params.cookie_file).unwrap();
    args.rpc_user_password = Some(cookie);

    #[cfg(feature = "db")]
    {
        args.db_dir = path;
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
    let secp = Secp256k1::new();

    let test_env = TestEnv {
        elementsd,
        handle,
        tx,
        client,
        base_url,
        server_key,
        wif_key,
        secp,
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

async fn inner_launch<S: AsRef<OsStr>>(exe: S, path: Option<PathBuf>) -> TestEnv<'static> {
    let mut conf = Conf::default();
    let args = vec![
        "-fallbackfee=0.0001",
        "-dustrelayfee=0.00000001",
        "-chain=liquidregtest",
        "-initialfreecoins=2100000000",
        "-validatepegin=0",
        "-acceptdiscountct=1",
        "-txindex=1",
        "-rest=1",
    ];
    conf.args = args;
    conf.view_stdout = std::env::var("RUST_LOG").is_ok();
    conf.network = "liquidregtest";

    let elementsd = BitcoinD::with_conf(exe, &conf).unwrap();
    // Use Box::leak to create a static reference
    let elementsd_ref = Box::leak(Box::new(elementsd));
    inner_launch_with_node(elementsd_ref, path).await
}

impl<'a> TestEnv<'a> {
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

    pub fn server_address(&self) -> bitcoin::Address {
        p2pkh(&self.secp, &self.wif_key)
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

    pub fn list_unspent(&self) -> Vec<Input> {
        let val = self.elementsd.client.call("listunspent", &[]).unwrap();
        serde_json::from_value(val).unwrap()
    }

    pub fn create_self_transanction(&self) -> elements::Transaction {
        let inputs = self.list_unspent();
        let inputs_sum: f64 = inputs.iter().map(|i| i.amount).sum();
        let change = self.get_new_address(None);
        let fee = 0.00001000;
        let to_send = inputs_sum - fee;

        let param1 = serde_json::to_value(inputs).unwrap();
        let param2 = serde_json::json!([{change.to_string(): to_send},{"fee": fee}]);

        let val = self
            .elementsd
            .client
            .call::<Value>("createrawtransaction", &[param1, param2])
            .unwrap();
        let tx_hex = val.as_str().unwrap();
        let bytes = Vec::<u8>::from_hex(tx_hex).unwrap();
        elements::Transaction::consensus_decode(&bytes[..]).unwrap()
    }

    pub fn blind_raw_transanction(&self, tx: &elements::Transaction) -> elements::Transaction {
        let hex = serialize_hex(tx);
        let val = self
            .elementsd
            .client
            .call::<Value>(
                "blindrawtransaction",
                &[serde_json::Value::String(hex), false.into()],
            )
            .unwrap();
        let tx_hex = val.as_str().unwrap();
        let bytes = Vec::<u8>::from_hex(tx_hex).unwrap();
        elements::Transaction::consensus_decode(&bytes[..]).unwrap()
    }

    pub fn create_other_wallet(&self) -> Client {
        self.elementsd.create_wallet("other_wallet").unwrap()
    }

    pub fn sign_raw_transanction_with_wallet(
        &self,
        tx: &elements::Transaction,
    ) -> elements::Transaction {
        let hex = serialize_hex(tx);
        let val = self
            .elementsd
            .client
            .call::<Value>(
                "signrawtransactionwithwallet",
                &[serde_json::Value::String(hex)],
            )
            .unwrap();
        let tx_hex = val.get("hex").unwrap().as_str().unwrap();
        let bytes = Vec::<u8>::from_hex(tx_hex).unwrap();
        elements::Transaction::consensus_decode(&bytes[..]).unwrap()
    }
}

async fn shutdown_signal(rx: Receiver<()>) {
    rx.await.unwrap()
}

#[derive(Serialize, Deserialize)]
pub struct Input {
    pub txid: String,
    pub vout: u32,
    pub amount: f64,
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
    pub async fn waterfalls(&self, desc: &str) -> anyhow::Result<(WaterfallResponseV3, HeaderMap)> {
        // this code is duplicated from waterfalls_version but we need to use the v3 endpoint which return a different object
        let descriptor_url = format!("{}/v3/waterfalls", self.base_url);

        let response = self
            .client
            .get(&descriptor_url)
            .query(&[("descriptor", desc)])
            .send()
            .await?;

        let headers = response.headers().clone();

        let body = response.text().await?;
        Ok((serde_json::from_str(&body)?, headers))
    }

    /// Call the waterfalls endpoint
    ///
    /// it accepts a list of addresses to search in the mempool and in the blockchain
    pub async fn waterfalls_addresses(
        &self,
        addressess: &[Address],
    ) -> anyhow::Result<(WaterfallResponseV3, HeaderMap)> {
        // this code is duplicated from waterfalls_version but we need to use the v3 endpoint which return a different object
        let descriptor_url = format!("{}/v3/waterfalls", self.base_url);

        let addresses_str = addressess
            .iter()
            .map(|a| a.to_string())
            .collect::<Vec<String>>()
            .join(",");
        let response = self
            .client
            .get(&descriptor_url)
            .query(&[("addresses", addresses_str)])
            .send()
            .await?;

        let headers = response.headers().clone();

        let body = response.text().await?;
        Ok((serde_json::from_str(&body)?, headers))
    }

    pub async fn waterfalls_v2(
        &self,
        desc: &str,
    ) -> anyhow::Result<(WaterfallResponse, HeaderMap)> {
        self.waterfalls_version(desc, 2, None, None, false).await
    }

    pub async fn waterfalls_v1(
        &self,
        desc: &str,
    ) -> anyhow::Result<(WaterfallResponse, HeaderMap)> {
        self.waterfalls_version(desc, 1, None, None, false).await
    }

    pub async fn waterfalls_v2_utxo_only(
        &self,
        desc: &str,
    ) -> anyhow::Result<(WaterfallResponse, HeaderMap)> {
        self.waterfalls_version(desc, 2, None, None, true).await
    }

    pub async fn waterfalls_version(
        &self,
        desc: &str,
        version: u8,
        page: Option<u32>,
        to_index: Option<u32>,
        utxo_only: bool,
    ) -> anyhow::Result<(WaterfallResponse, HeaderMap)> {
        let descriptor_url = format!("{}/v{}/waterfalls", self.base_url, version);

        let mut builder = self.client.get(&descriptor_url).query(&[
            ("descriptor", desc),
            ("utxo_only", utxo_only.to_string().as_str()),
        ]);

        if let Some(to_index) = to_index {
            builder = builder.query(&[("to_index", to_index.to_string().as_str())]);
        }
        if let Some(page) = page {
            builder = builder.query(&[("page", page.to_string().as_str())]);
        }

        let response = builder.send().await?;

        let headers = response.headers().clone();

        let body = response.text().await?;
        Ok((serde_json::from_str(&body)?, headers))
    }

    pub async fn wait_waterfalls_non_empty(
        &self,
        bitcoin_desc: &str,
    ) -> anyhow::Result<WaterfallResponse> {
        for _ in 0..50 {
            if let Ok(res) = self.waterfalls_v2(bitcoin_desc).await {
                if !res.0.is_empty() {
                    return Ok(res.0);
                }
            }

            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        }
        log::error!("no non-empty result after 10s");
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
        log::error!("no tip height after 10s");
        panic!("no tip height after 10s")
    }

    pub async fn height(&self, block_hash: BlockHash) -> anyhow::Result<u32> {
        Ok(self.header(block_hash).await?.height)
    }
    pub async fn header(&self, block_hash: BlockHash) -> anyhow::Result<BlockHeader> {
        let url = format!("{}/block/{}/header", self.base_url, block_hash);
        let response = self.client.get(&url).send().await?;
        let text = response.text().await?;
        let bytes = hex::decode(text)?;
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

    pub async fn server_address(&self) -> anyhow::Result<bitcoin::Address> {
        let url = format!("{}/v1/server_address", self.base_url);
        let response = self.client.get(&url).send().await?;
        let status_code = response.status().as_u16();
        if status_code != 200 {
            bail!("server_address response is not 200 but: {}", status_code);
        }
        let text = response.text().await?;

        bitcoin::Address::from_str(&text)
            .or_else(|e| bail!("cannot parse address {}", e))
            .map(|a| a.assume_checked())
    }

    pub async fn tx(&self, txid: Txid) -> anyhow::Result<Transaction> {
        let url = format!("{}/tx/{}/raw", self.base_url, txid);
        let response = self.client.get(&url).send().await?;
        let status_code = response.status().as_u16();
        if status_code != 200 {
            bail!("tx response for {url} is not 200 but: {status_code}");
        }
        let bytes = response.bytes().await?;

        Transaction::consensus_decode(bytes.as_ref()).or_else(|e| bail!("cannot parse tx {}", e))
    }

    pub async fn broadcast(&self, tx: &elements::Transaction) -> anyhow::Result<Txid> {
        let url = format!("{}/tx", self.base_url);
        let tx_hex = serialize_hex(tx);
        let response = self.client.post(&url).body(tx_hex).send().await?;
        let status_code = response.status().as_u16();
        let text = response.text().await?;
        if status_code == 200 {
            let txid = Txid::from_str(&text)?;
            Ok(txid)
        } else {
            bail!("broadcast response is not 200 but: {status_code} text: {text}");
        }
    }

    pub async fn address_txs(&self, address: &elements::Address) -> anyhow::Result<String> {
        let url = format!("{}/address/{}/txs", self.base_url, address);
        println!("url: {}", url);
        let response = self.client.get(&url).send().await?;
        let status_code = response.status().as_u16();
        let text = response.text().await?;

        if status_code != 200 {
            bail!(
                "address_txs response is not 200 but: {} text: {}",
                status_code,
                text
            );
        }
        Ok(text)
    }
}
