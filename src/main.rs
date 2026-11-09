use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

use anyhow::Context as _;
use clap::Parser;
use quinsock::config::{self, Config, LogFormat};
use quinsock::{Server, ShutdownHandle};
use tokio::signal::unix::{Signal, SignalKind, signal};
use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;

const DEFAULT_CONFIG: &str = "config.toml";

#[derive(Parser)]
#[command(version, about = "High-performance SOCKS5 proxy server (RFC 1928)")]
struct Cli {
    /// Configuration file [default: ./config.toml, or built-in defaults if it does not exist]
    #[arg(short, long, value_name = "PATH")]
    config: Option<PathBuf>,
    /// Validate the configuration and exit
    #[arg(long)]
    check_config: bool,
    /// Print the annotated default configuration and exit
    #[arg(long)]
    print_default_config: bool,
    /// Log filter overriding the config file and RUST_LOG, e.g. "debug"
    #[arg(long, value_name = "FILTER")]
    log_level: Option<String>,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    if cli.print_default_config {
        print!("{}", config::EXAMPLE);
        return ExitCode::SUCCESS;
    }
    let (cfg, warnings) = match load_config(cli.config.as_deref()) {
        Ok(loaded) => loaded,
        Err(e) => {
            eprintln!("error: {e:#}");
            return ExitCode::FAILURE;
        }
    };
    if cli.check_config {
        for w in &warnings {
            eprintln!("warning: {w}");
        }
        println!("configuration OK");
        return ExitCode::SUCCESS;
    }
    if let Err(e) = init_logging(&cfg, cli.log_level.as_deref()) {
        eprintln!("error: {e:#}");
        return ExitCode::FAILURE;
    }
    for w in &warnings {
        warn!("{w}");
    }
    match run(cfg) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            error!("{e:#}");
            ExitCode::FAILURE
        }
    }
}

fn load_config(path: Option<&Path>) -> anyhow::Result<(Config, Vec<String>)> {
    let mut warnings = Vec::new();
    let path = match path {
        Some(p) => Some(p.to_path_buf()),
        None if Path::new(DEFAULT_CONFIG).exists() => Some(PathBuf::from(DEFAULT_CONFIG)),
        None => {
            warnings.push(format!(
                "no --config given and ./{DEFAULT_CONFIG} not found; using built-in defaults"
            ));
            None
        }
    };
    let mut cfg = match &path {
        Some(p) => Config::load(p)?,
        None => Config::default(),
    };
    warnings.extend(cfg.validate()?);
    if let Some(p) = &path {
        warnings.extend(config::permission_warning(p, &cfg));
    }
    Ok((cfg, warnings))
}

fn init_logging(cfg: &Config, cli_filter: Option<&str>) -> anyhow::Result<()> {
    let directive = match (cli_filter, std::env::var("RUST_LOG")) {
        (Some(f), _) => f.to_owned(),
        (None, Ok(env)) if !env.is_empty() => env,
        _ => cfg.log.level.clone(),
    };
    let filter = EnvFilter::try_new(&directive)
        .with_context(|| format!("invalid log filter {directive:?}"))?;
    let builder = tracing_subscriber::fmt().with_env_filter(filter);
    match cfg.log.format {
        LogFormat::Full => builder.init(),
        LogFormat::Compact => builder.compact().init(),
    }
    Ok(())
}

fn run(cfg: Config) -> anyhow::Result<()> {
    if cfg.server.raise_nofile_limit {
        match quinsock::net::raise_nofile_limit() {
            Ok((soft, hard)) => {
                // A lower bound: two sockets per TCP relay; a UDP association holds its
                // control connection and up to three UDP sockets, two more than a relay;
                // each concurrent DNS lookup may hold one more. Connection attempts in
                // flight and BIND listeners briefly need extra.
                let connections = cfg.server.max_connections as u64;
                let associations = cfg.udp.max_associations.min(cfg.server.max_connections) as u64;
                let needed =
                    connections * 2 + associations * 2 + cfg.dns.max_concurrent as u64 + 64;
                info!(soft, hard, "open files limit");
                if soft < needed {
                    warn!(
                        soft,
                        needed,
                        "open files limit is below what the configured limits need; raise LimitNOFILE / ulimit -n"
                    );
                }
            }
            Err(e) => warn!(error = %e, "cannot raise the open files limit"),
        }
    }

    let mut builder = tokio::runtime::Builder::new_multi_thread();
    if cfg.server.worker_threads > 0 {
        builder.worker_threads(cfg.server.worker_threads);
    }
    let runtime = builder
        .max_blocking_threads(cfg.server.max_blocking_threads)
        .thread_name("quinsock-worker")
        .enable_all()
        .build()
        .context("cannot start the async runtime")?;

    let result = runtime.block_on(async move {
        // Installed before binding, so a server that could not be stopped gracefully
        // never starts.
        let term = signal(SignalKind::terminate()).context("cannot install the SIGTERM handler")?;
        let int = signal(SignalKind::interrupt()).context("cannot install the SIGINT handler")?;
        let server = Server::bind(cfg)?;
        tokio::spawn(handle_signals(term, int, server.shutdown_handle()));
        server.run().await;
        anyhow::Ok(())
    });
    // Do not wait for DNS lookups stuck in the blocking pool.
    runtime.shutdown_timeout(Duration::from_secs(1));
    result
}

/// First SIGTERM/SIGINT: graceful shutdown. Second: exit immediately.
async fn handle_signals(mut term: Signal, mut int: Signal, handle: ShutdownHandle) {
    tokio::select! {
        _ = term.recv() => {}
        _ = int.recv() => {}
    }
    info!("shutdown requested; send the signal again to exit immediately");
    handle.shutdown();
    tokio::select! {
        _ = term.recv() => {}
        _ = int.recv() => {}
    }
    warn!("second shutdown signal, exiting immediately");
    std::process::exit(1);
}
