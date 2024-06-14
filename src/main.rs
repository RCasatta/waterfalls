use clap::Parser;
use env_logger::Env;
use waterfalls::server::{inner_main, Arguments};

#[tokio::main]
async fn main() {
    env_logger::Builder::from_env(Env::default().default_filter_or("info")).init();
    let args = Arguments::parse();

    if let Err(e) = inner_main(args, shutdown_signal()).await {
        log::error!("{:?}", e);
    }
}

async fn shutdown_signal() {
    // Wait for the CTRL+C signal
    tokio::signal::ctrl_c()
        .await
        .expect("failed to install CTRL+C signal handler");
}
