//! The agent-vault daemon: control socket, gateway, MCP, web UI server and
//! connectors. Ports `src/daemon/*`, `src/ui/server.js`, `src/ui/webauthn.js`,
//! `src/ui/list-paging.js` and `src/connectors/*`.
//!
//! `unsafe` is denied crate-wide. The one exception is [`peercred`], which
//! wraps the socket peer-credential calls; nothing else may opt out.
#![deny(unsafe_code)]

pub mod connectors;
pub mod decode;
pub mod err;
pub mod http;
pub mod listen;
pub mod mcp;
pub mod notify;
#[allow(unsafe_code)]
pub mod peercred;
pub mod pipeline;
pub mod preview;
pub mod server;
pub mod session_requests;
pub mod sse;
pub mod state;
pub mod tls;
pub mod tripwire;
pub mod ui;
pub mod upstream;
pub mod util;

#[cfg(test)]
mod tests;

use std::path::PathBuf;

use av_core::errors::Exit;
pub use state::{Shared, VaultRef};

/// The service entry point: read `AV_VAULT_DIR`, `AV_RUN_DIR`, `AV_PORT`,
/// `AV_ENROLLED_UID` and `AV_CLIENT_GROUP`, refuse to run as root, open (or
/// create, factor `none`) the vault in its recorded lock state, start the
/// [`server::Daemon`] and run until SIGINT/SIGTERM. Ports the whole of
/// `bin/agent-vault-daemon.js`.
pub fn run_from_env() -> Exit {
    run_from_env_unlocking(None)
}

/// [`run_from_env`] with the passphrase `agent-vault daemon --passphrase`
/// read from the terminal. It is passed to
/// [`av_store::vault::Vault::start_in_recorded_state`] and is not stored in
/// the environment. `None` leaves a passphrase vault that cannot be opened
/// locked, which is what a boot without the flag does.
pub fn run_from_env_unlocking(passphrase: Option<av_core::secret::SecretString>) -> Exit {
    if let Err(e) = peercred::disable_core_dumps() {
        eprintln!("agent-vault-daemon: could not turn off core dumps: {e}");
    }
    let env = |k: &str| std::env::var(k).ok().filter(|v| !v.is_empty());
    let (Some(vault_dir), Some(run_dir)) = (env("AV_VAULT_DIR"), env("AV_RUN_DIR")) else {
        eprintln!("agent-vault-daemon: AV_VAULT_DIR and AV_RUN_DIR must be set; this runs under launchd or systemd");
        return Exit::Usage;
    };
    if peercred::effective_uid() == 0 {
        eprintln!("agent-vault-daemon: refusing to run as root; the service unit must set the service user");
        return Exit::Usage;
    }
    let port: u16 = match env("AV_PORT") {
        None => server::DEFAULT_GATEWAY_PORT,
        Some(p) => match p.trim().parse() {
            Ok(n) => n,
            Err(_) => {
                eprintln!("agent-vault-daemon: AV_PORT is not a port: {p}");
                return Exit::Usage;
            }
        },
    };
    let enrolled = env("AV_ENROLLED_UID").and_then(|u| u.parse().ok());
    let group = env("AV_CLIENT_GROUP");
    let rt = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("agent-vault-daemon: {e}");
            return Exit::Internal;
        }
    };
    rt.block_on(run(
        PathBuf::from(vault_dir),
        PathBuf::from(run_dir),
        port,
        enrolled,
        group,
        passphrase,
    ))
}

async fn run(
    vault_dir: PathBuf,
    run_dir: PathBuf,
    port: u16,
    enrolled: Option<u32>,
    group: Option<String>,
    passphrase: Option<av_core::secret::SecretString>,
) -> Exit {
    use av_store::vault::{CreateOptions, Vault};
    let db = vault_dir.join(av_store::vault::VAULT_DB_FILE);
    let (vault, unlocked) = if db.exists() {
        let mut v = match Vault::open(&vault_dir) {
            Ok(v) => v,
            Err(e) => {
                eprintln!(
                    "agent-vault-daemon: cannot open the vault in {}: {e}",
                    vault_dir.display()
                );
                return Exit::Failure;
            }
        };
        let unlocked = v
            .start_in_recorded_state(passphrase.as_ref())
            .unwrap_or(false);
        (v, unlocked)
    } else if vault_dir.join(av_store::vault::LEGACY_VAULT_FILE).exists() {
        eprintln!(
            "agent-vault-daemon: {} holds a vault.json from the JavaScript daemon and no vault.db; convert it first with: agent-vault migrate",
            vault_dir.display()
        );
        return Exit::Failure;
    } else {
        if let Err(e) = std::fs::create_dir_all(&vault_dir) {
            eprintln!(
                "agent-vault-daemon: cannot create {}: {e}",
                vault_dir.display()
            );
            return Exit::Failure;
        }
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&vault_dir, std::fs::Permissions::from_mode(0o700));
        }
        match Vault::create(&vault_dir, CreateOptions::default()) {
            Ok(v) => (v, true),
            Err(e) => {
                eprintln!(
                    "agent-vault-daemon: cannot create the vault in {}: {e}",
                    vault_dir.display()
                );
                return Exit::Failure;
            }
        }
    };
    let shared = Shared::new(vault);
    let socket = run_dir.join("control.sock");
    let daemon = match server::Daemon::new(
        shared,
        server::DaemonOptions {
            port,
            socket_path: Some(socket.clone()),
            socket_group: group,
            enrolled_uid: enrolled,
            ..Default::default()
        },
    ) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("agent-vault-daemon: {e}");
            return Exit::Usage;
        }
    };
    if let Err(e) = daemon.start().await {
        eprintln!("agent-vault-daemon: {e}");
        return Exit::Failure;
    }
    println!(
        "agent-vault daemon ready as uid {}",
        peercred::effective_uid()
    );
    println!("  vault    {}", vault_dir.display());
    println!(
        "  gateway  http://127.0.0.1:{}",
        daemon.gateway_port().unwrap_or(port)
    );
    println!("  control  {}", socket.display());
    if !unlocked {
        println!("  vault is LOCKED; run: agent-vault unlock");
    }
    use std::io::Write;
    let _ = std::io::stdout().flush();
    let mut term = match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
        Ok(s) => s,
        Err(_) => return Exit::Internal,
    };
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {}
        _ = term.recv() => {}
    }
    daemon.stop().await;
    Exit::Ok
}
