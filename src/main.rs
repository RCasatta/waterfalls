use clap::Parser;
use env_logger::Env;
use std::io::Write;
use waterfalls::server::{inner_main, Arguments};

#[tokio::main]
async fn main() {
    init_logging();

    let removed = removed_esplora_env_vars(|name| std::env::var_os(name).is_some());
    if !removed.is_empty() {
        log::error!(
            "The Esplora backend has been removed: unset {} and point waterfalls to a node with --node-url and --rpc-user-password-file",
            removed.join(", ")
        );
        std::process::exit(1);
    }

    let args = Arguments::parse();

    inner_main(args, shutdown_signal()).await.unwrap(); // we want to panic in case of error so that the process exit with non-zero value
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};

        let mut sigterm =
            signal(SignalKind::terminate()).expect("failed to install SIGTERM signal handler");
        let mut sigint =
            signal(SignalKind::interrupt()).expect("failed to install SIGINT signal handler");

        tokio::select! {
            _ = sigterm.recv() => {
                log::info!("Received SIGTERM signal");
            }
            _ = sigint.recv() => {
                log::info!("Received SIGINT signal");
            }
        }
    }

    #[cfg(windows)]
    {
        // On Windows, we only have Ctrl-C signal
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install CTRL+C signal handler");
        log::info!("Received Ctrl-C signal");
    }
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

/// Environment variables of the removed Esplora backend. Clap ignores environment variables of
/// undeclared arguments, so without this check a leftover `USE_ESPLORA=true` would be silently
/// ignored instead of failing at startup.
const REMOVED_ESPLORA_ENV_VARS: [&str; 2] = ["USE_ESPLORA", "ESPLORA_URL"];

fn removed_esplora_env_vars(is_set: impl Fn(&str) -> bool) -> Vec<&'static str> {
    REMOVED_ESPLORA_ENV_VARS
        .into_iter()
        .filter(|name| is_set(name))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::removed_esplora_env_vars;

    #[test]
    fn removed_esplora_env_vars_are_reported() {
        assert!(removed_esplora_env_vars(|_| false).is_empty());
        assert_eq!(
            removed_esplora_env_vars(|name| name == "USE_ESPLORA"),
            vec!["USE_ESPLORA"]
        );
        assert_eq!(
            removed_esplora_env_vars(|_| true),
            vec!["USE_ESPLORA", "ESPLORA_URL"]
        );
    }
}
