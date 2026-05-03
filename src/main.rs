mod audit;
mod audit_tui;
mod config;
mod faker;
mod patterns;
mod providers;
mod proxy;
mod redactor;

mod session;
mod stats;
mod update;
mod vault;
mod vault_tui;

use clap::{Parser, Subcommand};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use reqwest::Client;
use std::collections::HashSet;

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use tokio::net::TcpListener;
use tracing::error;

use audit::AuditLog;
use config::Config;
use proxy::{handle_request, ProxyState};
use session::SessionManager;
use stats::Stats;
use vault::Vault;


#[derive(Subcommand, Debug)]
enum Commands {
    /// Run the proxy server (default)
    Run {
        /// Port to listen on
        #[arg(short, long)]
        port: Option<u16>,

        /// Bind address
        #[arg(short, long)]
        bind: Option<String>,

        /// Config file path
        #[arg(short, long)]
        config: Option<String>,

        /// Log level (trace, debug, info, warn, error)
        #[arg(long, default_value = "info")]
        log_level: String,

        /// Dry run: log what would be redacted without modifying traffic
        #[arg(long)]
        dry_run: bool,

        /// Sensitivity level (low, medium, high, paranoid)
        #[arg(long)]
        sensitivity: Option<String>,

        /// Vault encryption key (passphrase). Can also use MIRAGE_VAULT_KEY env var.
        #[arg(long)]
        vault_key: Option<String>,

        /// Vault file path
        #[arg(long)]
        vault_path: Option<String>,

        /// Flush vault after N new mappings (0 = manual only)
        #[arg(long, default_value = "50")]
        vault_flush_threshold: usize,

        /// List all built-in provider routes
        #[arg(long)]
        list_providers: bool,

        /// Disable automatic version update check
        #[arg(long)]
        no_update_check: bool,
    },
    /// View audit log in interactive TUI
    Audit {
        /// Audit log file path
        #[arg(short, long)]
        path: Option<String>,
        
        /// Config file path (to load default audit path)
        #[arg(short, long)]
        config: Option<String>,

        /// Audit/vault encryption key passphrase (or MIRAGE_VAULT_KEY env var)
        #[arg(long)]
        vault_key: Option<String>,
    },
    /// View vault mappings in interactive TUI
    Vault {
        /// Vault encryption key (passphrase). Can also use MIRAGE_VAULT_KEY env var.
        #[arg(long)]
        vault_key: Option<String>,
        
        /// Vault file path
        #[arg(long)]
        vault_path: Option<String>,
        
        /// Config file path (to load default vault path)
        #[arg(short, long)]
        config: Option<String>,
    },
}

#[derive(Parser, Debug)]
#[command(
    name = "mirage-proxy",
    version,
    about = "Invisible sensitive data filter for LLM APIs",
    long_about = "Mirage sits between your LLM client and provider, silently replacing \
    secrets, credentials, and sensitive data with plausible fakes. The LLM never knows. \
    Sub-millisecond overhead."
)]
struct Args {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let args = Args::parse();

    // Get the command or default to Run with no options
    let command = args.command.unwrap_or(Commands::Run {
        port: None,
        bind: None,
        config: None,
        log_level: "info".to_string(),
        dry_run: false,
        sensitivity: None,
        vault_key: None,
        vault_path: None,
        vault_flush_threshold: 50,
        list_providers: false,
        no_update_check: false,
    });

    match command {
        Commands::Audit { path, config, vault_key } => {
            // Fallback chain: CLI arg → config file → current directory default
            let audit_path = if let Some(p) = path {
                std::path::PathBuf::from(p)
            } else {
                let cfg = Config::load(config.as_deref());
                
                // If config file exists and has a path, use it
                // Otherwise use current directory default
                if cfg.audit.path.exists() || cfg.audit.path != std::path::PathBuf::from("./mirage-audit.jsonl") {
                    cfg.audit.path
                } else {
                    // Check current directory for default file
                    let current_dir_default = std::path::PathBuf::from("./mirage-audit.jsonl");
                    if current_dir_default.exists() {
                        current_dir_default
                    } else {
                        // Use config default anyway (will create or show empty)
                        cfg.audit.path
                    }
                }
            };
            
            if !audit_path.exists() {
                eprintln!("⚠️  Audit log not found at: {}", audit_path.display());
                eprintln!("   The file will be created when the proxy runs.");
                eprintln!();
            }
            
            let cfg_for_audit = Config::load(config.as_deref());
            let audit_key = if cfg_for_audit.audit.encrypted {
                let passphrase = vault_key
                    .or_else(|| std::env::var("MIRAGE_VAULT_KEY").ok())
                    .ok_or("Audit is encrypted. Provide --vault-key or MIRAGE_VAULT_KEY.")?;
                Some(Vault::key_from_passphrase(&passphrase))
            } else {
                None
            };

            let mut viewer = audit_tui::AuditViewer::new(audit_path, audit_key)?;
            viewer.run()?;
            return Ok(());
        }
        Commands::Vault { vault_key, vault_path, config } => {
            // Vault key: CLI arg → env var
            let passphrase = vault_key
                .or_else(|| std::env::var("MIRAGE_VAULT_KEY").ok())
                .ok_or("Vault key required. Use --vault-key or MIRAGE_VAULT_KEY env var")?;
            
            let key = Vault::key_from_passphrase(&passphrase);
            
            // Fallback chain: CLI arg → config file → current directory default
            let vault_path_buf = if let Some(p) = vault_path {
                std::path::PathBuf::from(p)
            } else {
                let cfg = Config::load(config.as_deref());
                
                // If config file exists and has a path, use it
                // Otherwise use current directory default
                if cfg.vault.path.exists() || cfg.vault.path != std::path::PathBuf::from("./mirage-vault.enc") {
                    cfg.vault.path
                } else {
                    // Check current directory for default file
                    let current_dir_default = std::path::PathBuf::from("./mirage-vault.enc");
                    if current_dir_default.exists() {
                        current_dir_default
                    } else {
                        // Use config default anyway (will create or show empty)
                        cfg.vault.path
                    }
                }
            };
            
            if !vault_path_buf.exists() {
                eprintln!("⚠️  Vault file not found at: {}", vault_path_buf.display());
                eprintln!("   The vault will be created when the proxy runs with --vault-key.");
                eprintln!();
            }
            
            let mut viewer = vault_tui::VaultViewer::new(vault_path_buf, &key)?;
            viewer.run()?;
            return Ok(());
        }
        Commands::Run {
            port,
            bind,
            config,
            log_level,
            dry_run,
            sensitivity,
            vault_key,
            vault_path,
            vault_flush_threshold,
            list_providers,
            no_update_check,
        } => {
            run_proxy(
                port,
                bind,
                config,
                log_level,
                dry_run,
                sensitivity,
                vault_key,
                vault_path,
                vault_flush_threshold,
                list_providers,
                no_update_check,
            ).await
        }
    }
}

async fn run_proxy(
    port: Option<u16>,
    bind: Option<String>,
    config: Option<String>,
    log_level: String,
    dry_run: bool,
    sensitivity: Option<String>,
    vault_key: Option<String>,
    vault_path: Option<String>,
    vault_flush_threshold: usize,
    list_providers: bool,
    no_update_check: bool,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {

    let default_level = if log_level == "info" {
        "warn"
    } else {
        &log_level
    };
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(default_level)),
        )
        .init();

    if list_providers {
        eprintln!();
        eprintln!(
            "  Built-in provider routes ({} providers)",
            providers::PROVIDERS.len()
        );
        eprintln!("  ─────────────────────────────────────────────────");
        for p in providers::PROVIDERS {
            eprintln!("  {:16} {:14} → {}", p.name, p.prefix, p.upstream);
        }
        eprintln!();
        return Ok(());
    }



    // Load config, override with CLI args
    let mut cfg = Config::load(config.as_deref());

    if let Some(p) = port {
        cfg.port = p;
    }
    if let Some(b) = bind {
        cfg.bind = b;
    }
    if dry_run {
        cfg.dry_run = true;
    }
    if no_update_check {
        cfg.update_check.enabled = false;
    }
    if let Some(ref s) = sensitivity {
        cfg.sensitivity = match s.as_str() {
            "low" => config::Sensitivity::Low,
            "high" => config::Sensitivity::High,
            "paranoid" => config::Sensitivity::Paranoid,
            _ => config::Sensitivity::Medium,
        };
    }

    let vault_key_resolved = vault_key
        .or_else(|| std::env::var("MIRAGE_VAULT_KEY").ok());

    let audit_log = if cfg.audit.enabled {
        let audit_key = if cfg.audit.encrypted {
            Some(
                vault_key_resolved
                    .as_ref()
                    .map(|p| Vault::key_from_passphrase(p))
                    .ok_or("Audit encryption enabled but no vault key provided (--vault-key or MIRAGE_VAULT_KEY)")?,
            )
        } else {
            None
        };

        Some(Arc::new(AuditLog::new(
            cfg.audit.path.clone(),
            cfg.audit.log_values,
            cfg.audit.encrypted,
            audit_key,
            cfg.audit.max_size_mb,
            cfg.audit.rotate_keep,
            cfg.audit.max_age_days,
        )?))
    } else {
        None
    };

    let vault_path_resolved = vault_path
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| cfg.vault.path.clone());
    let vault = vault_key_resolved.as_ref().map(|passphrase| {
        let key = Vault::key_from_passphrase(passphrase);
        let legacy_key = Vault::key_from_passphrase_legacy(passphrase);
        let v = Vault::new_with_legacy(
            vault_path_resolved.clone(),
            &key,
            Some(&legacy_key),
            vault_flush_threshold,
        );
        Arc::new(v)
    });

    let stats = Stats::new();

    let state = Arc::new(ProxyState {
        client: {
            let mut builder = Client::builder()
                .connect_timeout(std::time::Duration::from_secs(30));
            // Overall timeout only for non-streaming; streaming handled via per-request.
            // Use a generous timeout for streaming LLM responses (5 minutes).
            builder = builder.timeout(std::time::Duration::from_secs(300));
            builder.build().expect("failed to build reqwest client")
        },
        sessions: SessionManager::new(vault.clone()),
        config: cfg.clone(),
        audit_log,
        stats: stats.clone(),
        seen_pii: Mutex::new(HashSet::new()),
    });

    let addr: SocketAddr = format!("{}:{}", cfg.bind, cfg.port).parse()?;
    let listener = TcpListener::bind(addr).await?;

    eprintln!();
    eprintln!(
        "  \x1b[1mmirage-proxy\x1b[0m v{}",
        env!("CARGO_PKG_VERSION")
    );
    eprintln!("  ─────────────────────────────────────");
    eprintln!("  listen:  http://{}", addr);
    eprintln!("  target:  \x1b[36mmulti-provider\x1b[0m (auto-route)");
    eprintln!("           /anthropic → api.anthropic.com");
    eprintln!("           /openai    → api.openai.com");
    eprintln!("           /google    → generativelanguage.googleapis.com");
    eprintln!("           /deepseek  → api.deepseek.com");
    eprintln!(
        "           ... and {} more (--list-providers)",
        providers::PROVIDERS.len() - 4
    );
    eprintln!(
        "  mode:    {}{}",
        if cfg.dry_run { "dry-run " } else { "" },
        format!("{:?}", cfg.sensitivity).to_lowercase()
    );
    if cfg.audit.enabled {
        eprintln!("  audit:   {}", cfg.audit.path.display());
    }
    if vault.is_some() {
        eprintln!("  vault:   {} (encrypted)", vault_path_resolved.display());
    }
    eprintln!("  ─────────────────────────────────────");
    eprintln!();

    if cfg.update_check.enabled && !disable_update_check_from_env() {
        let timeout_ms = cfg.update_check.timeout_ms;
        tokio::spawn(async move {
            if let Some(update) = update::check_for_update(timeout_ms).await {
                eprintln!(
                    "  update:  v{} available (current v{})",
                    update.latest, update.current
                );
                eprintln!("           brew update && brew upgrade mirage-proxy");
                eprintln!("           {}", update.release_url);
            }
        });
    }

    let stats_handle = stats.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(5));
        loop {
            interval.tick().await;
            let reqs = stats_handle
                .requests
                .load(std::sync::atomic::Ordering::Relaxed);
            if reqs > 0 {
                eprint!("\r\x1b[2K  📊 {}", stats_handle.display());
            }
        }
    });

    loop {
        let (stream, remote) = listener.accept().await?;
        let io = TokioIo::new(stream);
        let state = state.clone();

        tokio::task::spawn(async move {
            let service = service_fn(move |req| {
                let state = state.clone();
                async move { handle_request(req, state).await }
            });

            if let Err(err) = http1::Builder::new()
                .serve_connection(io, service)
                .with_upgrades()
                .await
            {
                if !err.to_string().contains("connection closed") {
                    error!("Connection error from {}: {}", remote, err);
                }
            }
        });
    }
}

fn disable_update_check_from_env() -> bool {
    match std::env::var("MIRAGE_NO_UPDATE_CHECK") {
        Ok(v) => {
            let s = v.trim().to_ascii_lowercase();
            s == "1" || s == "true" || s == "yes" || s == "on"
        }
        Err(_) => false,
    }
}

