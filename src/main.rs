//! Shell: wiring, signals, shutdown ordering. Decisions live in the pure core.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use arc_swap::ArcSwap;
use clap::{Parser, Subcommand};
use guestpass::config::{RawConfig, compile};
use guestpass::domain::MIN_TOKEN_CHARS;
use guestpass::ha::{HaLink, Readings, run_poller};
use guestpass::http::{AppState, bind_socket, router};
use guestpass::policy::{Registry, reachable};
use guestpass::{tex, tunnel};
use rand::Rng as _;

#[derive(Parser)]
#[command(name = "guestpass", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Serve the guest surface and supervise the tunnel.
    Serve {
        #[arg(long, default_value = "/config/guestpass.yaml")]
        config: PathBuf,
    },
    /// Print every URL the config denotes, with the call each one makes.
    Explain {
        #[arg(long, default_value = "/config/guestpass.yaml")]
        config: PathBuf,
    },
    /// Write a printable LaTeX document to stdout.
    Tex {
        #[arg(long, default_value = "/config/guestpass.yaml")]
        config: PathBuf,
    },
    /// Print a fresh 128-bit token.
    GenToken,
}

fn main() -> std::process::ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_env("GUESTPASS_LOG")
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();
    let result = match cli.command {
        Some(Command::GenToken) => {
            println!("{}", gen_token());
            Ok(())
        }
        Some(Command::Explain { config }) => load(&config).map(|(reg, _)| explain(&reg)),
        Some(Command::Tex { config }) => load(&config).map(|(reg, raw)| {
            print!("{}", tex::document(&reg, &head_tokens(&raw)));
        }),
        Some(Command::Serve { config }) => serve(&config),
        None => serve(Path::new("/config/guestpass.yaml")),
    };

    match result {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("{e}");
            std::process::ExitCode::FAILURE
        }
    }
}

fn gen_token() -> String {
    let bytes: [u8; 16] = rand::rng().random();
    base32::encode(base32::Alphabet::Rfc4648 { padding: false }, &bytes)
}

fn load(path: &Path) -> Result<(Registry, RawConfig), String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let raw: RawConfig =
        serde_yaml_ng::from_str(&text).map_err(|e| format!("{}: {e}", path.display()))?;
    let registry = compile(&raw).map_err(|e| format!("{} rejected:\n{}", path.display(), e.0))?;
    Ok((registry, raw))
}

/// Head tokens, in config order. Only the head is published, so the QR page and
/// the printed cards always match what belongs on the wall.
fn head_tokens(raw: &RawConfig) -> Vec<(String, String)> {
    raw.passes
        .iter()
        .filter_map(|p| {
            p.tokens.iter().find_map(|t| match t {
                guestpass::config::RawToken::Current(v) => Some((p.id.clone(), v.clone())),
                guestpass::config::RawToken::Retiring { .. } => None,
            })
        })
        .collect()
}

/// The complete denotation of a config, printed where the owner already looks.
fn explain(registry: &Registry) {
    let base = registry.base_url();
    for pass in registry.passes() {
        tracing::info!(
            pass = %pass.id,
            trigger = ?pass.trigger,
            per_minute = pass.quota.per_minute,
            "pass"
        );
        for (suffix, device, verb) in reachable(registry, pass) {
            let call = guestpass::policy::authorize(device, verb);
            tracing::info!(
                url = %format!("{base}/t/<token-{}>{suffix}", pass.id),
                service = call.service(),
                entity = %call.entity(),
                "  reaches"
            );
        }
    }
}

fn serve(config: &Path) -> Result<(), String> {
    let (registry, raw) = load(config)?;
    let token = raw.tunnel.token.clone();
    explain(&registry);

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| e.to_string())?;

    runtime.block_on(async move {
        let registry = Arc::new(ArcSwap::from_pointee(registry));
        let link = Arc::new(HaLink::detect().map_err(|e| e.to_string())?);
        let readings = Arc::new(Readings::default());

        let state = Arc::new(AppState {
            registry: Arc::clone(&registry),
            readings: Arc::clone(&readings),
            link: Arc::clone(&link),
            buckets: Mutex::new(HashMap::new()),
        });

        // A UNIX socket, never a network address (AGENTS.md I-5, gate G9).
        let listener = bind_socket().map_err(|e| e.to_string())?;
        tracing::info!(
            "guest surface listening; set the tunnel's public hostname service to unix:{}",
            guestpass::http::SOCKET_PATH
        );

        tokio::spawn(run_poller(
            Arc::clone(&link),
            Arc::clone(&readings),
            Arc::clone(&registry),
            Duration::from_secs(15),
        ));

        let supervisor = tokio::spawn(tunnel::supervise(token));

        let server = axum::serve(listener, router(state)).with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
            tracing::info!("shutting down");
        });

        let outcome = server.await.map_err(|e| e.to_string());
        supervisor.abort();
        outcome
    })
}

const _: () = assert!(MIN_TOKEN_CHARS == 26);
