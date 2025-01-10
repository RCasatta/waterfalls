use clap::Parser;
use env_logger::Env;
use std::io::Write;
use waterfalls::server::{inner_main, Arguments};

#[tokio::main(flavor = "current_thread")]
async fn main() {
    init_logging();

    let args = Arguments::parse();

    inner_main(args, shutdown_signal()).await.unwrap(); // we want to panic in case of error so that the process exit with non-zero value
}

async fn shutdown_signal() {
    // Wait for the CTRL+C signal
    tokio::signal::ctrl_c()
        .await
        .expect("failed to install CTRL+C signal handler");
}

fn init_logging() {
    let mut builder = env_logger::Builder::from_env(Env::default().default_filter_or("info"));
    if let Ok(s) = std::env::var("RUST_LOG_STYLE") {
        if s == "SYSTEMD" {
            builder.format(|buf, record| {
                let level = match record.level() {
                    log::Level::Error => 3,
                    log::Level::Warn => 4,
                    log::Level::Info => 6,
                    log::Level::Debug => 7,
                    log::Level::Trace => 7,
                };
                writeln!(buf, "<{}>{}: {}", level, record.target(), record.args())
            });
        }
    }

    builder.init();
}
