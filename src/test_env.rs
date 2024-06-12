use crate::{inner_main, Arguments};
use std::{
    error::Error,
    ffi::OsStr,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::PathBuf,
    str::FromStr,
};

use bitcoind::{bitcoincore_rpc::RpcApi, get_available_port, BitcoinD, Conf};
use elements::{
    bitcoin::{Amount, Denomination},
    Address,
};
use serde_json::Value;
use tokio::sync::oneshot::{self, Receiver, Sender};

pub struct TestEnv {
    #[allow(dead_code)]
    elementsd: BitcoinD,
    handle: tokio::task::JoinHandle<Result<(), Box<dyn Error + Send + Sync>>>,
    tx: Sender<()>,
    base_url: String,
}

#[cfg(feature = "db")]
pub async fn launch<S: AsRef<OsStr>>(exe: S, path: Option<PathBuf>) -> TestEnv {
    inner_launch(exe, path).await
}

#[cfg(not(feature = "db"))]
pub async fn launch<S: AsRef<OsStr>>(exe: S) -> TestEnv {
    inner_launch(exe, None).await
}

async fn inner_launch<S: AsRef<OsStr>>(exe: S, path: Option<PathBuf>) -> TestEnv {
    let mut conf = Conf::default();
    let args = vec![
        "-fallbackfee=0.0001",
        "-dustrelayfee=0.00000001",
        "-chain=liquidregtest",
        "-initialfreecoins=2100000000",
        "-validatepegin=0",
        "-rest=1",
    ];
    conf.args = args;
    conf.view_stdout = std::env::var("RUST_LOG").is_ok();
    conf.network = "liquidregtest";

    let elementsd = BitcoinD::with_conf(exe, &conf).unwrap();
    let mut args = Arguments::default();
    args.node_url = Some(elementsd.rpc_url());
    let available_port = get_available_port().unwrap();
    let socket_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), available_port);
    let base_url = format!("http://{socket_addr}");
    args.listen = Some(socket_addr);
    args.testnet = true;

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

    let test_env = TestEnv {
        elementsd,
        handle,
        tx,
        base_url,
    };

    test_env.node_generate(1);
    test_env
        .elementsd
        .client
        .call::<Value>("rescanblockchain", &[])
        .unwrap();
    test_env.node_generate(1);

    tokio::time::sleep(std::time::Duration::from_secs(2)).await; // give some time to start the server

    test_env
}

impl TestEnv {
    pub async fn shutdown(self) {
        self.tx.send(()).unwrap();
        let _ = self.handle.await.unwrap();
    }

    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    pub fn send_to(&self, address: &elements::Address, satoshis: u64) {
        let amount = Amount::from_sat(satoshis);
        let btc = amount.to_string_in(Denomination::Bitcoin);

        let val = self
            .elementsd
            .client
            .call::<Value>("sendtoaddress", &[address.to_string().into(), btc.into()])
            .unwrap();
        println!("{val:?}");
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

    pub fn node_generate(&self, block_num: u32) {
        let address = self.get_new_address(None).to_string();
        self.elementsd
            .client
            .call::<Value>("generatetoaddress", &[block_num.into(), address.into()])
            .unwrap();
    }
}

async fn shutdown_signal(rx: Receiver<()>) {
    rx.await.unwrap()
}
