use crate::{
    be::{self, Family},
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
use anyhow::{bail, Context};
use bitcoin::{key::Secp256k1, secp256k1::All, NetworkKind, PrivateKey};
use bitcoind::{
    bitcoincore_rpc::{bitcoin::hex::FromHex, Client, RpcApi},
    get_available_port, BitcoinD, Conf,
};
use elements::{
    bitcoin::{Amount, Denomination},
    encode::{serialize_hex, Decodable},
    BlockHash, BlockHeader, Txid,
};
use hyper::HeaderMap;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::sync::oneshot::{self, Receiver, Sender};

pub struct TestEnv<'a> {
    #[allow(dead_code)]
    node: &'a BitcoinD,
    handle: tokio::task::JoinHandle<Result<(), Box<dyn Error + Send + Sync>>>,
    tx: Sender<()>,
    client: WaterfallClient,
    base_url: String,
    server_key: Identity,
    wif_key: PrivateKey,
    secp: Secp256k1<All>,
    pub family: Family,
}

#[cfg(feature = "db")]
pub async fn launch<S: AsRef<OsStr>>(
    exe: S,
    path: Option<PathBuf>,
    family: Family,
) -> TestEnv<'static> {
    inner_launch(exe, path, family).await
}

#[cfg(not(feature = "db"))]
pub async fn launch<S: AsRef<OsStr>>(exe: S, family: Family) -> TestEnv<'static> {
    inner_launch(exe, None, family).await
}

#[cfg(feature = "db")]
pub async fn launch_with_node(
    elementsd: &BitcoinD,
    path: Option<PathBuf>,
    family: Family,
) -> TestEnv {
    inner_launch_with_node(elementsd, path, family).await
}

#[cfg(not(feature = "db"))]
pub async fn launch_with_node(elementsd: &BitcoinD, family: Family) -> TestEnv {
    inner_launch_with_node(elementsd, None, family).await
}

async fn inner_launch_with_node(node: &BitcoinD, path: Option<PathBuf>, family: Family) -> TestEnv {
    let mut args = Arguments {
        node_url: Some(node.rpc_url()),
        derivation_cache_capacity: 10000,
        ..Default::default()
    };
    let available_port = get_available_port().unwrap();
    let socket_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), available_port);
    let base_url = format!("http://{socket_addr}");
    args.listen = Some(socket_addr);
    args.network = match family {
        Family::Bitcoin => Network::BitcoinRegtest,
        Family::Elements => Network::ElementsRegtest,
    };
    let server_key = Identity::generate();
    args.server_key = Some(server_key.clone());
    let wif_key = PrivateKey::generate(NetworkKind::Test);
    args.wif_key = Some(wif_key);
    args.max_addresses = 100;

    let cookie = std::fs::read_to_string(&node.params.cookie_file).unwrap();
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

    let client = WaterfallClient::new(base_url.to_string(), family);
    let secp = Secp256k1::new();

    let test_env = TestEnv {
        node,
        handle,
        tx,
        client,
        base_url,
        server_key,
        wif_key,
        secp,
        family,
    };

    test_env.node_generate(1).await;

    test_env
        .node
        .client
        .call::<Value>("rescanblockchain", &[])
        .unwrap();

    test_env.node_generate(101).await;

    test_env
}

pub fn launch_bitcoin<S: AsRef<OsStr>>(exe: S) -> BitcoinD {
    let mut conf = Conf::default();
    conf.args = vec!["-regtest", "-fallbackfee=0.0001", "-rest=1", "-txindex=1"];
    BitcoinD::with_conf(exe, &conf).unwrap()
}
pub fn launch_elements<S: AsRef<OsStr>>(exe: S) -> BitcoinD {
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

    BitcoinD::with_conf(exe, &conf).unwrap()
}

async fn inner_launch<S: AsRef<OsStr>>(
    exe: S,
    path: Option<PathBuf>,
    family: Family,
) -> TestEnv<'static> {
    let elementsd = match family {
        Family::Bitcoin => launch_bitcoin(exe),
        Family::Elements => launch_elements(exe),
    };
    // Use Box::leak to create a static reference
    let elementsd_ref = Box::leak(Box::new(elementsd));
    inner_launch_with_node(elementsd_ref, path, family).await
}

impl<'a> TestEnv<'a> {
    pub async fn shutdown(self) {
        self.tx.send(()).unwrap();
        let _ = self.handle.await.unwrap();
    }

    pub fn network(&self) -> Network {
        match self.family {
            Family::Bitcoin => Network::BitcoinRegtest,
            Family::Elements => Network::ElementsRegtest,
        }
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

    pub fn send_to(&self, address: &be::Address, satoshis: u64) -> Txid {
        let amount = Amount::from_sat(satoshis);
        let btc = amount.to_string_in(Denomination::Bitcoin);
        let val = self
            .node
            .client
            .call::<Value>("sendtoaddress", &[address.to_string().into(), btc.into()])
            .unwrap();
        Txid::from_str(val.as_str().unwrap()).unwrap()
    }

    pub fn get_new_address(&self, kind: Option<&str>) -> be::Address {
        let kind = kind.unwrap_or("p2sh-segwit");
        let addr: Value = self
            .node
            .client
            .call("getnewaddress", &["label".into(), kind.into()])
            .unwrap();
        be::Address::from_str(addr.as_str().unwrap(), self.network()).unwrap()
    }

    /// generate `block_num` blocks and wait the waterfalls server had indexed them
    pub async fn node_generate(&self, block_num: u32) {
        let address = self.get_new_address(None);
        let hash = self
            .node
            .client
            .call::<Value>(
                "generatetoaddress",
                &[block_num.into(), address.to_string().into()],
            )
            .unwrap();
        let hash = hash.as_array().unwrap().last().unwrap().as_str().unwrap();
        let hash = BlockHash::from_str(hash).unwrap();

        self.client.wait_tip_hash(hash).await.unwrap();
    }

    pub fn list_unspent(&self) -> Vec<Input> {
        let val = self.node.client.call("listunspent", &[]).unwrap();
        serde_json::from_value(val).unwrap()
    }

    pub fn create_self_transanction(&self) -> be::Transaction {
        let inputs = self.list_unspent();
        let inputs_sum: f64 = inputs.iter().map(|i| i.amount).sum();
        let change = self.get_new_address(None).to_string();
        let fee = 0.00001000;
        let to_send = inputs_sum - fee;

        let param1 = serde_json::to_value(inputs).unwrap();

        let param2 = match self.family {
            Family::Bitcoin => serde_json::json!([{change: to_send}]),
            Family::Elements => serde_json::json!([{change: to_send},{"fee": fee}]),
        };

        let val = self
            .node
            .client
            .call::<Value>("createrawtransaction", &[param1, param2])
            .unwrap();
        let tx_hex = val.as_str().unwrap();
        be::Transaction::from_str(tx_hex, self.family).unwrap()
    }

    pub fn blind_raw_transanction(&self, tx: &elements::Transaction) -> elements::Transaction {
        let hex = serialize_hex(tx);
        let val = self
            .node
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
        self.node.create_wallet("other_wallet").unwrap()
    }

    pub fn sign_raw_transanction_with_wallet(&self, tx: &be::Transaction) -> be::Transaction {
        let hex = tx.serialize_hex();
        let val = self
            .node
            .client
            .call::<Value>(
                "signrawtransactionwithwallet",
                &[serde_json::Value::String(hex)],
            )
            .unwrap();
        let tx_hex = val.get("hex").unwrap().as_str().unwrap();
        be::Transaction::from_str(tx_hex, self.family).unwrap()
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
    family: Family,
}

impl WaterfallClient {
    pub fn new(base_url: String, family: Family) -> Self {
        let client = reqwest::Client::new();
        Self {
            client,
            base_url,
            family,
        }
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
        addressess: &[be::Address],
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
        Ok((
            serde_json::from_str(&body)
                .with_context(|| format!("failing parsing json for {desc} body:{body}"))?,
            headers,
        ))
    }

    pub async fn wait_waterfalls_non_empty(
        &self,
        bitcoin_desc: &str,
    ) -> anyhow::Result<WaterfallResponse> {
        for _ in 0..50 {
            let res = self.waterfalls_v2(bitcoin_desc).await.unwrap();
            if !res.0.is_empty() {
                return Ok(res.0);
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

    pub async fn wait_tip_hash(&self, hash: BlockHash) -> anyhow::Result<()> {
        for _ in 0..50 {
            if let Ok(current) = self.tip_hash().await {
                if current == hash {
                    return Ok(());
                }
            }

            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        }
        log::error!("no tip hash after 10s");
        panic!("no tip hash after 10s")
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

    pub async fn tx(&self, txid: Txid) -> anyhow::Result<be::Transaction> {
        let url = format!("{}/tx/{}/raw", self.base_url, txid);
        let response = self.client.get(&url).send().await?;
        let status_code = response.status().as_u16();
        if status_code != 200 {
            bail!("tx response for {url} is not 200 but: {status_code}");
        }
        let bytes = response.bytes().await?;
        be::Transaction::from_bytes(&bytes, self.family)
    }

    pub async fn broadcast(&self, tx: &be::Transaction) -> anyhow::Result<Txid> {
        let url = format!("{}/tx", self.base_url);
        let tx_hex = tx.serialize_hex();
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

    pub async fn address_txs(&self, address: &be::Address) -> anyhow::Result<String> {
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
