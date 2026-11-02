mod anonymous_clients;
#[allow(dead_code)]
mod app_protection;
mod app_state;
mod calls;
mod config;
mod data;
mod identity;
mod omega;
mod provisioning;
mod rho;
mod services;
mod util;

use std::{fmt::Write, path::PathBuf};

use dotenv::dotenv;
use once_cell::sync::Lazy;

pub static WORKING_DIR: Lazy<PathBuf> =
    Lazy::new(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")));
use rustls::crypto::aws_lc_rs::default_provider;
use tokio::sync::watch;

use mtp::crypto::Keyring;

use crate::{
    app_state::AppState,
    calls::{call_manager::CallManager, call_util::LiveKitService},
    config::Config,
    identity::{KEYRING_PATH, PUBLIC_KEY_PATH, load_or_create_keyring},
    omega::omega_connection::{OmegaConnection, start_task_cleanup_loop},
    rho::rho_manager::RhoManager,
    rho::server::start,
    util::logger::{PrintType, startup},
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    if default_provider().install_default().is_err() {
        return Err("Error loading Provider".into());
    }
    dotenv().ok();

    let config = match Config::from_environment() {
        Ok(config) => config,
        Err(error) => {
            return Err(format!("Invalid configuration: {error}").into());
        }
    };
    let _logger_guard = startup(config.logger_queue_capacity)
        .map_err(|error| format!("Unable to initialize logger: {error}"))?;

    let keyring = match load_or_create_keyring(KEYRING_PATH, PUBLIC_KEY_PATH) {
        Ok(keyring) => keyring,
        Err(error) => {
            return Err(format!("Unable to load Omikron keyring: {error}").into());
        }
    };
    let public_key = match omega_database_public_key(&keyring) {
        Ok(public_key) => public_key,
        Err(error) => {
            return Err(format!("Unable to serialize public key for Omega: {error}").into());
        }
    };
    log!(
        0,
        PrintType::Omikron,
        "Omikron public_key for Omega enrollment: {public_key}"
    );

    let omega_keyring = match keyring_for_omega(&keyring) {
        Ok(keyring) => keyring,
        Err(error) => {
            return Err(format!("Unable to copy keyring for Omega: {error}").into());
        }
    };
    let rho = std::sync::Arc::new(RhoManager::new());
    let omega = std::sync::Arc::new(OmegaConnection::from_config(
        &config,
        omega_keyring,
        rho.clone(),
    ));
    omega.clone().start().await;
    start_task_cleanup_loop(omega.clone());
    let livekit = std::sync::Arc::new(LiveKitService::new(config.livekit.clone()));
    livekit.set_call_host_id(config.omikron_id);
    // Use exactly the key pinned by Omega's authenticated transport. A hostname
    // is a route, never the authority that owns account IDs.
    let omega_public_key = mtp::files::load_public_key_bundle("./omega.mpkb")
        .map_err(|error| format!("Unable to load pinned Omega call authority: {error}"))?;
    let principal_authority = call_authority("omega-key", &omega_public_key)?;
    let owner_authority = call_authority("omikron-key", &keyring.public_key_bundle())?;
    let call_db_path = std::env::var("CALL_DB_PATH").unwrap_or_else(|_| "calls.sqlite3".into());
    let repository = std::sync::Arc::new(crate::calls::repository::SqliteCallRepository::open(
        std::path::Path::new(&call_db_path),
    )?);
    let runtime = std::sync::Arc::new(crate::calls::runtime::CallRuntime {
        repository: repository.clone(),
        rho: rho.clone(),
        principal_authority: principal_authority.clone(),
    });
    let engine = std::sync::Arc::new(tau::calls::CallEngine::new(
        repository.clone(),
        livekit.clone(),
        runtime.clone(),
        runtime.clone(),
        std::sync::Arc::new(tau::calls::SystemCallClock),
    ));
    let call_manager = std::sync::Arc::new(
        CallManager::new_with_limits(
            livekit.clone(),
            config.omikron_id,
            config.call_limits.clone(),
        )
        .with_runtime(
            repository,
            engine.clone(),
            owner_authority,
            principal_authority,
        )
        .with_persistence(std::sync::Arc::new(
            crate::calls::persistence::CallPersistence::open(std::path::Path::new(&call_db_path))?,
        )),
    );
    call_manager.restore().await?;
    let (shutdown, _) = watch::channel(false);
    let webhook_task = if let Some(livekit) = &config.livekit {
        crate::calls::webhooks::start(call_manager.clone(), livekit.clone(), shutdown.subscribe())
            .await?
    } else {
        if std::env::var_os("LIVEKIT_WEBHOOK_BIND").is_some() {
            return Err("LIVEKIT_WEBHOOK_BIND requires LiveKit configuration".into());
        }
        None
    };
    let call_effect_worker =
        crate::calls::runtime::start_effect_worker(engine, runtime, shutdown.subscribe());
    livekit
        .clone()
        .garbage_collect_calls(call_manager.clone(), rho.clone(), shutdown.subscribe());
    let state = AppState::new(config.clone(), keyring, omega.clone(), rho, call_manager);
    let server = start(state, shutdown.subscribe());
    tokio::pin!(server);
    let stopped = tokio::select! {
        result = &mut server => Some(result),
        result = tokio::signal::ctrl_c() => {
            result.map_err(|error| format!("Unable to wait for shutdown signal: {error}"))?;
            None
        }
    };
    omega.begin_shutdown();
    let _ = shutdown.send(true);
    call_effect_worker.abort();
    let _ = call_effect_worker.await;
    let deadline = tokio::time::Instant::now() + config.message_drain + config.cleanup_timeout;
    let webhook_stopped = if let Some(mut task) = webhook_task {
        match tokio::time::timeout_at(deadline, &mut task).await {
            Ok(Ok(Ok(()))) => true,
            Ok(_) => false,
            Err(_) => {
                task.abort();
                let _ = task.await;
                false
            }
        }
    } else {
        true
    };
    let unexpected_stop = stopped.is_some();
    let listener = match stopped {
        Some(result) => Ok(result),
        None => tokio::time::timeout_at(deadline, &mut server).await,
    };
    let report = rho::tasks::drain_process_operations(
        deadline.saturating_duration_since(tokio::time::Instant::now()),
    )
    .await;
    log!(0, PrintType::General, "Shutdown operations: {report:?}");
    let incomplete = !webhook_stopped || listener.is_err() || !report.is_complete();
    if incomplete {
        log_err!(
            0,
            PrintType::General,
            "Incomplete shutdown: {report:?}; wait_on_incomplete_shutdown={}",
            config.wait_on_incomplete_shutdown
        );
        if !config.wait_on_incomplete_shutdown {
            return Err(format!(
                "Incomplete shutdown: {report:?}; remote intents require reconciliation; precommit preparation and postcommit delivery may stop"
            )
            .into());
        }
    }
    // An operator can opt into waiting beyond the report deadline.
    let listener = match listener {
        Ok(result) => result,
        Err(_) => (&mut server).await,
    };
    let final_report = rho::tasks::finish_process_operations().await;
    listener.map_err(|error| format!("Rho listener shutdown failed: {error}"))?;
    if incomplete || !final_report.is_complete() {
        return Err(format!(
            "Incomplete shutdown: initial={report:?}; final={final_report:?}; unresolved durable operations require reconciliation"
        )
        .into());
    }
    if unexpected_stop {
        return Err("Rho listener stopped unexpectedly".into());
    }
    Ok(())
}

fn keyring_for_omega(keyring: &Keyring) -> Result<Keyring, String> {
    let bytes = keyring.try_to_bytes().map_err(|error| error.to_string())?;
    Keyring::from_bytes(&bytes).map_err(|error| error.to_string())
}

fn call_authority(
    kind: &str,
    keys: &mtp::crypto::PublicKeyBundle,
) -> Result<tau::calls::CallAuthority, Box<dyn std::error::Error>> {
    let bytes = keys.try_as_bytes()?;
    let fingerprint = mtp::crypto::sha256(&bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    Ok(tau::calls::CallAuthority::new(format!(
        "{kind}:{fingerprint}"
    ))?)
}

fn omega_database_public_key(keyring: &Keyring) -> Result<String, String> {
    let public_key = keyring
        .public_key_bundle()
        .try_as_bytes()
        .map_err(|error| error.to_string())?;
    omega_database_blob_literal(&public_key)
}

fn omega_database_blob_literal(public_key: &[u8]) -> Result<String, String> {
    let mut literal = String::with_capacity(3 + public_key.len() * 2);
    literal.push_str("X'");
    for byte in public_key {
        write!(&mut literal, "{byte:02X}").map_err(|error| error.to_string())?;
    }
    literal.push('\'');
    Ok(literal)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_key_blob_literal_is_valid_mysql_hex_syntax() {
        assert_eq!(
            omega_database_blob_literal(&[0x00, 0x1A, 0xFF]),
            Ok("X'001AFF'".to_string())
        );
    }
}
