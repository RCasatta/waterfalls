use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    time::Duration,
};

use bitcoind::{get_available_port, BitcoinD, Conf};
use tokio::{
    sync::oneshot::{self, Receiver},
    time::sleep,
};
use waterfall::Arguments;

#[tokio::test]
async fn integration() {
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

    let exe = std::env::var("ELEMENTSD_EXEC").unwrap();
    let node = BitcoinD::with_conf(exe, &conf).unwrap();
    let mut args = Arguments::default();
    args.node_url = Some(node.rpc_url());
    let available_port = get_available_port().unwrap();
    args.listen = Some(SocketAddr::new(
        IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
        available_port,
    ));
    let (tx, rx) = oneshot::channel();
    let handle = tokio::spawn(waterfall::inner_main(args, shutdown_signal(rx)));

    sleep(Duration::from_secs(2)).await;
    tx.send(()).unwrap();
    let _ = handle.await.unwrap();
    assert!(true);
}

async fn shutdown_signal(rx: Receiver<()>) {
    rx.await.unwrap()
}
