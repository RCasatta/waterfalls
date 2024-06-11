use crate::{inner_main, Arguments};
use std::{
    error::Error,
    ffi::OsStr,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::PathBuf,
};

use bitcoind::{get_available_port, BitcoinD, Conf};
use tokio::sync::oneshot::{self, Receiver, Sender};

pub struct TestEnv {
    #[allow(dead_code)]
    elementsd: BitcoinD,
    handle: tokio::task::JoinHandle<Result<(), Box<dyn Error + Send + Sync>>>,
    tx: Sender<()>,
}

#[cfg(feature = "db")]
pub fn launch<S: AsRef<OsStr>>(exe: S, path: Option<PathBuf>) -> TestEnv {
    inner_launch(exe, path)
}

#[cfg(not(feature = "db"))]
pub fn launch<S: AsRef<OsStr>>(exe: S) -> TestEnv {
    inner_launch(exe, None)
}

fn inner_launch<S: AsRef<OsStr>>(exe: S, path: Option<PathBuf>) -> TestEnv {
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
    args.listen = Some(SocketAddr::new(
        IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
        available_port,
    ));

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

    TestEnv {
        elementsd,
        handle,
        tx,
    }
}

impl TestEnv {
    pub async fn shutdown(self) {
        self.tx.send(()).unwrap();
        let _ = self.handle.await.unwrap();
    }
}

async fn shutdown_signal(rx: Receiver<()>) {
    rx.await.unwrap()
}
