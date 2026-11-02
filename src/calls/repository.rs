//! SQLite implementation of Tau's transactional single-writer contract.
use std::{
    path::Path,
    sync::{Arc, Mutex},
    time::Duration,
};

use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use tau::calls::*;
use uuid::Uuid;
mod epochs;
pub use epochs::PendingEpochEnvelope;
#[cfg(test)]
pub(crate) mod tests;

#[derive(Clone)]
pub struct SqliteCallRepository {
    db: Arc<Mutex<Connection>>,
    workers: Arc<tokio::sync::Semaphore>,
    max_commands_per_minute: usize,
    max_pending_key_epochs: usize,
    max_calls_per_principal: usize,
}

#[derive(Debug, serde::Serialize)]
pub struct CallOutboxHealth {
    pub pending_effects: u64,
    pub expired_leases: u64,
    pub retries: u64,
    pub max_attempts: u32,
    pub pending_key_envelopes: u64,
}

const MIGRATION: &str = "
CREATE TABLE IF NOT EXISTS call_schema_migrations (version INTEGER PRIMARY KEY);
CREATE TABLE IF NOT EXISTS managed_calls (
 authority TEXT NOT NULL, call_id TEXT NOT NULL, revision INTEGER NOT NULL CHECK(revision >= 0),
 state_json TEXT NOT NULL, PRIMARY KEY(authority, call_id));
CREATE TABLE IF NOT EXISTS managed_call_operations (
 authority TEXT NOT NULL, call_id TEXT NOT NULL, actor TEXT NOT NULL,
 operation_id TEXT NOT NULL, request BLOB NOT NULL, result_json TEXT NOT NULL,
 PRIMARY KEY(authority, call_id, actor, operation_id));
CREATE TABLE IF NOT EXISTS managed_call_audit (
 authority TEXT NOT NULL, call_id TEXT NOT NULL, actor TEXT NOT NULL,
 operation_id TEXT NOT NULL, revision INTEGER NOT NULL, created_at_ms INTEGER NOT NULL,
 command_json TEXT NOT NULL, PRIMARY KEY(authority, call_id, actor, operation_id));
CREATE TABLE IF NOT EXISTS managed_call_events (
 authority TEXT NOT NULL, call_id TEXT NOT NULL, revision INTEGER NOT NULL,
 event_index INTEGER NOT NULL, event_json TEXT NOT NULL,
 PRIMARY KEY(authority, call_id, revision, event_index));
CREATE TABLE IF NOT EXISTS managed_call_effects (
 id TEXT PRIMARY KEY, authority TEXT NOT NULL, call_id TEXT NOT NULL,
 revision INTEGER NOT NULL, effect_json TEXT NOT NULL,
 state TEXT NOT NULL CHECK(state IN ('pending','claimed','complete')),
 attempts INTEGER NOT NULL DEFAULT 0, next_attempt_ms INTEGER NOT NULL,
 claim_generation INTEGER NOT NULL DEFAULT 0, claim_until_ms INTEGER,
 last_error TEXT);
CREATE INDEX IF NOT EXISTS managed_call_effects_due ON managed_call_effects(state, next_attempt_ms, claim_until_ms);
INSERT OR IGNORE INTO call_schema_migrations(version) VALUES(1);
CREATE TABLE IF NOT EXISTS managed_call_host (
 authority TEXT NOT NULL, call_id TEXT NOT NULL, created_at_ms INTEGER NOT NULL,
 reservation_expires_at_ms INTEGER, legacy_principal_authority TEXT,
 PRIMARY KEY(authority,call_id),
 FOREIGN KEY(authority,call_id) REFERENCES managed_calls(authority,call_id));
INSERT OR IGNORE INTO call_schema_migrations(version) VALUES(2);
CREATE TABLE IF NOT EXISTS managed_call_legacy_envelopes (
 authority TEXT NOT NULL,call_id TEXT NOT NULL,recipient TEXT NOT NULL,
 epoch INTEGER NOT NULL,inviter TEXT NOT NULL,payload BLOB NOT NULL,
 revoked INTEGER NOT NULL DEFAULT 0 CHECK(revoked IN(0,1)),
 PRIMARY KEY(authority,call_id,recipient,epoch),
 FOREIGN KEY(authority,call_id) REFERENCES managed_calls(authority,call_id));
INSERT OR IGNORE INTO call_schema_migrations(version) VALUES(3);
CREATE TABLE IF NOT EXISTS managed_call_guest_capabilities (
 id TEXT PRIMARY KEY, authority TEXT NOT NULL,call_id TEXT NOT NULL,
 token_hash BLOB NOT NULL,expires_at_ms INTEGER NOT NULL,max_uses INTEGER NOT NULL,
 uses INTEGER NOT NULL DEFAULT 0,revoked INTEGER NOT NULL DEFAULT 0,
 FOREIGN KEY(authority,call_id) REFERENCES managed_calls(authority,call_id));
INSERT OR IGNORE INTO call_schema_migrations(version) VALUES(4);
CREATE TABLE IF NOT EXISTS managed_call_credentials (
 authority TEXT NOT NULL,call_id TEXT NOT NULL,principal TEXT NOT NULL,
 valid_until_ms INTEGER NOT NULL, PRIMARY KEY(authority,call_id,principal));
INSERT OR IGNORE INTO call_schema_migrations(version) VALUES(5);
CREATE TABLE IF NOT EXISTS managed_call_key_plans (
 authority TEXT NOT NULL,call_id TEXT NOT NULL,epoch INTEGER NOT NULL,
 generation INTEGER NOT NULL,proposer TEXT NOT NULL,recipients_json TEXT NOT NULL,
 available INTEGER NOT NULL DEFAULT 0,PRIMARY KEY(authority,call_id,epoch));
CREATE TABLE IF NOT EXISTS managed_call_key_envelopes (
 authority TEXT NOT NULL,call_id TEXT NOT NULL,epoch INTEGER NOT NULL,recipient TEXT NOT NULL,
 generation INTEGER NOT NULL,payload BLOB NOT NULL,staged INTEGER NOT NULL DEFAULT 0,
 activated INTEGER NOT NULL DEFAULT 0,PRIMARY KEY(authority,call_id,epoch,recipient));
CREATE TABLE IF NOT EXISTS managed_call_key_operations (
 authority TEXT NOT NULL,call_id TEXT NOT NULL,actor TEXT NOT NULL,operation_id TEXT NOT NULL,
 payload BLOB NOT NULL,PRIMARY KEY(authority,call_id,actor,operation_id));
CREATE TABLE IF NOT EXISTS managed_call_host_audit (
 authority TEXT NOT NULL,call_id TEXT NOT NULL,revision INTEGER NOT NULL,
 operation_id TEXT NOT NULL,event_kind TEXT NOT NULL,created_at_ms INTEGER NOT NULL,
 PRIMARY KEY(authority,call_id,revision));
INSERT OR IGNORE INTO call_schema_migrations(version) VALUES(6);
CREATE TABLE IF NOT EXISTS managed_call_presence (
 authority TEXT NOT NULL,call_id TEXT NOT NULL,empty_since_ms INTEGER,
 observed_at_ms INTEGER NOT NULL,PRIMARY KEY(authority,call_id));
INSERT OR IGNORE INTO call_schema_migrations(version) VALUES(7);
CREATE TABLE IF NOT EXISTS managed_call_webhook_receipts (
 authority TEXT NOT NULL,call_id TEXT NOT NULL,event_id TEXT NOT NULL,
 created_at_ms INTEGER NOT NULL,PRIMARY KEY(authority,call_id,event_id));
INSERT OR IGNORE INTO call_schema_migrations(version) VALUES(8);
CREATE TABLE IF NOT EXISTS managed_call_write_budgets (
 authority TEXT NOT NULL,actor TEXT NOT NULL,window_start_ms INTEGER NOT NULL,
 operations INTEGER NOT NULL,PRIMARY KEY(authority,actor));
CREATE INDEX IF NOT EXISTS managed_calls_lifecycle ON managed_calls(authority,json_extract(state_json,'$.lifecycle'));
";

fn storage(_: impl std::fmt::Display) -> CallError {
    CallError::StorageUnavailable
}
fn json<T: serde::Serialize>(value: &T) -> Result<String, CallError> {
    serde_json::to_string(value).map_err(storage)
}

impl SqliteCallRepository {
    pub fn open(path: &Path) -> Result<Self, CallError> {
        let setting = |name, default| -> Result<usize, CallError> {
            match std::env::var(name) {
                Ok(value) => value
                    .parse::<usize>()
                    .ok()
                    .filter(|value| *value > 0 && *value <= i64::MAX as usize)
                    .ok_or(CallError::InvalidRequest),
                Err(std::env::VarError::NotPresent) => Ok(default),
                Err(_) => Err(CallError::InvalidRequest),
            }
        };
        let max_commands_per_minute = setting("CALL_COMMANDS_PER_MINUTE", 120)?;
        let max_pending_key_epochs = setting("CALL_MAX_PENDING_KEY_EPOCHS", 4)?;
        let max_calls_per_principal = setting("CALL_MAX_CALLS_PER_USER", 16)?;
        let mut db = Connection::open(path).map_err(storage)?;
        db.busy_timeout(Duration::from_secs(5)).map_err(storage)?;
        db.execute_batch(
            "PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA foreign_keys=ON;",
        )
        .map_err(storage)?;
        let tx = db
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage)?;
        tx.execute_batch(MIGRATION).map_err(storage)?;
        if !tx.prepare("SELECT 1 FROM pragma_table_info('managed_call_key_envelopes') WHERE name='next_attempt_ms'").map_err(storage)?.exists([]).map_err(storage)? {
            tx.execute_batch("ALTER TABLE managed_call_key_envelopes ADD COLUMN next_attempt_ms INTEGER NOT NULL DEFAULT 0").map_err(storage)?;
        }
        tx.execute(
            "INSERT OR IGNORE INTO call_schema_migrations(version) VALUES(9)",
            [],
        )
        .map_err(storage)?;
        tx.execute(
            "INSERT OR IGNORE INTO call_schema_migrations(version) VALUES(10)",
            [],
        )
        .map_err(storage)?;
        tx.execute(
            "INSERT OR IGNORE INTO call_schema_migrations(version) VALUES(11)",
            [],
        )
        .map_err(storage)?;
        let schema: i64 = tx
            .query_row(
                "SELECT MAX(version) FROM call_schema_migrations",
                [],
                |row| row.get(0),
            )
            .map_err(storage)?;
        if schema > 11 {
            return Err(CallError::StorageUnavailable);
        }
        tx.commit().map_err(storage)?;
        Ok(Self {
            db: Arc::new(Mutex::new(db)),
            workers: Arc::new(tokio::sync::Semaphore::new(4)),
            max_commands_per_minute,
            max_pending_key_epochs,
            max_calls_per_principal,
        })
    }

    async fn blocking<T: Send + 'static>(
        &self,
        work: impl FnOnce(&mut Connection) -> Result<T, CallError> + Send + 'static,
    ) -> Result<T, CallError> {
        let permit = self
            .workers
            .clone()
            .acquire_owned()
            .await
            .map_err(storage)?;
        let db = self.db.clone();
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            let mut db = db.lock().map_err(storage)?;
            work(&mut db)
        })
        .await
        .map_err(storage)?
    }

    /// Creation/import is host-only. A conflicting aggregate is never overwritten.
    #[cfg(test)]
    pub async fn insert(&self, call: Call) -> Result<(), CallError> {
        call.validate()?;
        self.blocking(move |db| {
            let tx = db.transaction_with_behavior(TransactionBehavior::Immediate).map_err(storage)?;
            let existing = Self::read_from(&tx, &call.id);
            match existing {
                Ok(existing) if existing == call => return Ok(()),
                Ok(_) => return Err(CallError::Conflict { current_revision: call.revision }),
                Err(CallError::NotFound) => {},
                Err(error) => return Err(error),
            }
            tx.execute("INSERT INTO managed_calls(authority,call_id,revision,state_json) VALUES(?1,?2,?3,?4)",
                params![call.id.owner_authority.as_str(), call.id.id.to_string(), i64::try_from(call.revision).map_err(storage)?, json(&call)?]).map_err(storage)?;
            tx.commit().map_err(storage)
        }).await
    }

    pub async fn list(&self) -> Result<Vec<Call>, CallError> {
        self.blocking(|db| {
            let mut stmt = db
                .prepare("SELECT state_json FROM managed_calls ORDER BY authority,call_id")
                .map_err(storage)?;
            let rows = stmt
                .query_map([], |row| row.get::<_, String>(0))
                .map_err(storage)?;
            let mut calls = Vec::new();
            for row in rows {
                let call: Call = serde_json::from_str(&row.map_err(storage)?).map_err(storage)?;
                call.validate()?;
                calls.push(call);
            }
            Ok(calls)
        })
        .await
    }

    pub async fn outbox_health(&self, now_ms: i64) -> Result<CallOutboxHealth, CallError> {
        self.blocking(move |db| {
            let (pending_effects,expired_leases,retries,max_attempts)=db.query_row("SELECT COALESCE(SUM(state!='complete'),0),COALESCE(SUM(state='claimed' AND claim_until_ms<=?1),0),COALESCE(SUM(MAX(attempts-1,0)),0),COALESCE(MAX(attempts),0) FROM managed_call_effects",
                [now_ms],|row|Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?))).map_err(storage)?;
            let pending_key_envelopes=db.query_row("SELECT COUNT(*) FROM managed_call_key_envelopes e JOIN managed_calls c ON c.authority=e.authority AND c.call_id=e.call_id WHERE e.activated=0 AND e.generation=json_extract(c.state_json,'$.rotation_generation') AND e.epoch>json_extract(c.state_json,'$.key_epoch') AND json_extract(c.state_json,'$.lifecycle')='active' AND json_extract(CAST(e.payload AS TEXT),'$.expires_at_ms')>?1",
                [now_ms],|row|row.get(0)).map_err(storage)?;
            Ok(CallOutboxHealth {pending_effects,expired_leases,retries,max_attempts,pending_key_envelopes})
        }).await
    }

    pub async fn replay(
        &self,
        actor: AuthenticatedCallActor,
        request: CallCommandRequest,
    ) -> Result<Option<CallCommandResult>, CallError> {
        request.validate()?;
        self.blocking(move |db| {
            let stored:Option<(Vec<u8>,String)>=db.query_row("SELECT request,result_json FROM managed_call_operations WHERE authority=?1 AND call_id=?2 AND actor=?3 AND operation_id=?4",
                params![request.call.owner_authority.as_str(),request.call.id.to_string(),json(actor.principal())?,request.operation_id.to_string()],|row|Ok((row.get(0)?,row.get(1)?))).optional().map_err(storage)?;
            match stored {
                None=>Ok(None),
                Some((bytes,result))=>{
                    if bytes!=encode_call_command(&request)? { return Err(CallError::OperationConflict); }
                    Ok(Some(serde_json::from_str(&result).map_err(storage)?))
                }
            }
        }).await
    }

    pub async fn queue_media_inspection(
        &self,
        id: CallId,
        event_id: String,
        created_at_ms: i64,
        now_ms: i64,
        max_age_ms: i64,
    ) -> Result<bool, CallError> {
        if event_id.is_empty()
            || event_id.len() > 128
            || created_at_ms < 0
            || now_ms < 0
            || max_age_ms <= 0
            || created_at_ms < now_ms.saturating_sub(max_age_ms)
            || created_at_ms > now_ms.saturating_add(max_age_ms)
        {
            return Err(CallError::InvalidRequest);
        }
        self.blocking(move |db| {
            let tx=db.transaction_with_behavior(TransactionBehavior::Immediate).map_err(storage)?;
            let call=Self::read_from(&tx,&id)?;
            tx.execute("DELETE FROM managed_call_webhook_receipts WHERE created_at_ms<?1",[now_ms.saturating_sub(max_age_ms)]).map_err(storage)?;
            let added=tx.execute("INSERT OR IGNORE INTO managed_call_webhook_receipts(authority,call_id,event_id,created_at_ms) VALUES(?1,?2,?3,?4)",
                params![id.owner_authority.as_str(),id.id.to_string(),event_id,created_at_ms]).map_err(storage)?;
            if added==1 { Self::queue_inspection(&tx,&call,now_ms)?; }
            tx.commit().map_err(storage)?;
            Ok(added==1)
        }).await
    }

    fn queue_inspection(tx: &Connection, call: &Call, now_ms: i64) -> Result<(), CallError> {
        let pending:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM managed_call_effects WHERE authority=?1 AND call_id=?2 AND state!='complete' AND json_extract(effect_json,'$.effect')='inspect_room')",
            params![call.id.owner_authority.as_str(),call.id.id.to_string()],|row|row.get(0)).map_err(storage)?;
        if !pending {
            tx.execute("INSERT INTO managed_call_effects(id,authority,call_id,revision,effect_json,state,next_attempt_ms) VALUES(?1,?2,?3,?4,?5,'pending',?6)",
                params![Uuid::new_v4().to_string(),call.id.owner_authority.as_str(),call.id.id.to_string(),i64::try_from(call.revision).map_err(storage)?,json(&CallEffect::InspectRoom)?,now_ms]).map_err(storage)?;
        }
        Ok(())
    }

    /// Import only absent aggregates. Restarts must not overwrite restrictions,
    /// revocations, or ownership changes with the old compatibility projection.
    pub async fn insert_legacy(&self, call: Call, created_at_ms: i64) -> Result<(), CallError> {
        call.validate()?;
        if created_at_ms < 0 {
            return Err(CallError::InvalidRequest);
        }
        self.blocking(move |db| {
            let tx = db.transaction_with_behavior(TransactionBehavior::Immediate).map_err(storage)?;
            let rows = tx.execute("INSERT OR IGNORE INTO managed_calls(authority,call_id,revision,state_json) VALUES(?1,?2,?3,?4)",
                params![call.id.owner_authority.as_str(),call.id.id.to_string(), i64::try_from(call.revision).map_err(storage)?,json(&call)?]).map_err(storage)?;
            if rows == 1 {
                tx.execute("INSERT INTO managed_call_host(authority,call_id,created_at_ms,legacy_principal_authority) VALUES(?1,?2,?3,?4)",
                    params![call.id.owner_authority.as_str(),call.id.id.to_string(),created_at_ms,call.owner.authority.as_str()]).map_err(storage)?;
                // Existing legacy JWTs used LiveKit's default six-hour TTL.
                // Retain reconciliation through their worst-case admission window.
                let window = SystemCallClock.now_ms()?.saturating_add(i64::try_from(livekit_api::access_token::DEFAULT_TTL.as_millis()).map_err(storage)?);
                tx.execute("INSERT INTO managed_call_credentials(authority,call_id,principal,valid_until_ms) VALUES(?1,?2,'*',?3)",
                    params![call.id.owner_authority.as_str(),call.id.id.to_string(),window]).map_err(storage)?;
                tx.execute("INSERT INTO managed_call_host_audit(authority,call_id,revision,operation_id,event_kind,created_at_ms) VALUES(?1,?2,?3,?4,?5,?6)",
                    params![call.id.owner_authority.as_str(),call.id.id.to_string(),i64::try_from(call.revision).map_err(storage)?,Uuid::new_v4().to_string(),
                        json(&serde_json::json!({"action":"legacy_import","owner":call.owner}))?,SystemCallClock.now_ms()?]).map_err(storage)?;
            }
            tx.commit().map_err(storage)
        }).await
    }

    pub async fn media_binding(&self, id: CallId) -> Result<Option<CallAuthority>, CallError> {
        self.blocking(move |db| {
            let value: Option<String> = db.query_row("SELECT legacy_principal_authority FROM managed_call_host WHERE authority=?1 AND call_id=?2",
                params![id.owner_authority.as_str(), id.id.to_string()], |row| row.get(0)).optional().map_err(storage)?.flatten();
            value.map(CallAuthority::new).transpose()
        }).await
    }

    /// Existing legacy creation uses numeric media identities within one
    /// explicitly bound principal authority. Other authorities fail closed.
    pub async fn reserve(
        &self,
        call: Call,
        created_at_ms: i64,
        expires_at_ms: i64,
        max_calls_per_user: usize,
        legacy_media: bool,
    ) -> Result<(), CallError> {
        call.validate()?;
        if call.lifecycle != CallLifecycle::Reserved
            || created_at_ms < 0
            || expires_at_ms <= created_at_ms
            || max_calls_per_user == 0
        {
            return Err(CallError::InvalidRequest);
        }
        self.blocking(move |db| {
            let tx = db.transaction_with_behavior(TransactionBehavior::Immediate).map_err(storage)?;
            let mut count = 0;
            {
                let mut stmt = tx.prepare("SELECT c.state_json,h.reservation_expires_at_ms FROM managed_calls c LEFT JOIN managed_call_host h USING(authority,call_id)").map_err(storage)?;
                let rows = stmt.query_map([], |row| Ok((row.get::<_, String>(0)?,row.get::<_,Option<i64>>(1)?))).map_err(storage)?;
                for row in rows {
                    let (state, expiry) = row.map_err(storage)?;
                    let existing: Call = serde_json::from_str(&state).map_err(storage)?;
                    if existing.terminal() || (existing.lifecycle == CallLifecycle::Reserved && expiry.is_none_or(|t| t <= created_at_ms)) { continue; }
                    if existing.member(&call.owner).is_some_and(|m| m.authorized)
                        || existing.invitations.iter().any(|i| i.recipient == call.owner && i.expires_at_ms > created_at_ms) { count += 1; }
                }
            }
            if count >= max_calls_per_user { return Err(CallError::RateLimited); }
            tx.execute("INSERT INTO managed_calls(authority,call_id,revision,state_json) VALUES(?1,?2,?3,?4)",
                params![call.id.owner_authority.as_str(),call.id.id.to_string(),i64::try_from(call.revision).map_err(storage)?,json(&call)?]).map_err(storage)?;
            tx.execute("INSERT INTO managed_call_host(authority,call_id,created_at_ms,reservation_expires_at_ms,legacy_principal_authority) VALUES(?1,?2,?3,?4,?5)",
                params![call.id.owner_authority.as_str(),call.id.id.to_string(),created_at_ms,expires_at_ms,legacy_media.then(||call.owner.authority.as_str())]).map_err(storage)?;
            tx.commit().map_err(storage)
        }).await
    }

    pub async fn reservation_created_at(
        &self,
        id: CallId,
        owner: CallPrincipal,
        now_ms: i64,
    ) -> Result<i64, CallError> {
        self.blocking(move |db| {
            let call = Self::read_from(db,&id)?;
            if call.owner != owner || !matches!(call.lifecycle, CallLifecycle::Reserved | CallLifecycle::Provisioning) { return Err(CallError::NotFound); }
            let (created,expiry): (i64,Option<i64>) = db.query_row("SELECT created_at_ms,reservation_expires_at_ms FROM managed_call_host WHERE authority=?1 AND call_id=?2",
                params![id.owner_authority.as_str(),id.id.to_string()],|row| Ok((row.get(0)?,row.get(1)?))).map_err(storage)?;
            if call.lifecycle == CallLifecycle::Reserved && expiry.is_none_or(|t| t <= now_ms) { return Err(CallError::NotFound); }
            Ok(created)
        }).await
    }

    pub async fn created_at(&self, id: CallId) -> Result<i64, CallError> {
        self.blocking(move |db| {
            db.query_row(
                "SELECT created_at_ms FROM managed_call_host WHERE authority=?1 AND call_id=?2",
                params![id.owner_authority.as_str(), id.id.to_string()],
                |row| row.get(0),
            )
            .optional()
            .map_err(storage)?
            .ok_or(CallError::NotFound)
        })
        .await
    }

    pub async fn begin_activation(
        &self,
        id: CallId,
        owner: CallPrincipal,
        now_ms: i64,
    ) -> Result<(), CallError> {
        self.blocking(move |db| {
            let tx = db.transaction_with_behavior(TransactionBehavior::Immediate).map_err(storage)?;
            let mut call = Self::read_from(&tx,&id)?;
            if call.owner != owner { return Err(CallError::NotFound); }
            if matches!(call.lifecycle,CallLifecycle::Provisioning | CallLifecycle::Active) { return Ok(()); }
            let expiry: Option<i64> = tx.query_row("SELECT reservation_expires_at_ms FROM managed_call_host WHERE authority=?1 AND call_id=?2",
                params![id.owner_authority.as_str(),id.id.to_string()],|row| row.get(0)).map_err(storage)?;
            if call.lifecycle != CallLifecycle::Reserved || expiry.is_none_or(|t| t <= now_ms) { return Err(CallError::NotFound); }
            call.lifecycle = CallLifecycle::Provisioning;
            Self::host_transition(&tx,&mut call,Some(CallEffect::ProvisionRoom),CallEventKind::StateChanged,now_ms)?;
            tx.commit().map_err(storage)
        }).await
    }

    pub async fn complete_activation(
        &self,
        id: CallId,
        owner: CallPrincipal,
    ) -> Result<(), CallError> {
        self.blocking(move |db| {
            let tx = db.transaction_with_behavior(TransactionBehavior::Immediate).map_err(storage)?;
            let mut call = Self::read_from(&tx,&id)?;
            if call.owner != owner { return Err(CallError::NotFound); }
            if call.lifecycle == CallLifecycle::Active { return Ok(()); }
            if call.lifecycle != CallLifecycle::Provisioning { return Err(CallError::NotAuthorized); }
            call.lifecycle = CallLifecycle::Active;
            let now_ms = SystemCallClock.now_ms()?;
            Self::host_transition(&tx,&mut call,Some(CallEffect::ReconcileMember { principal: owner }),CallEventKind::StateChanged,now_ms)?;
            tx.execute("UPDATE managed_call_host SET reservation_expires_at_ms=NULL WHERE authority=?1 AND call_id=?2",
                params![id.owner_authority.as_str(),id.id.to_string()]).map_err(storage)?;
            tx.commit().map_err(storage)
        }).await
    }

    fn host_transition(
        tx: &Connection,
        call: &mut Call,
        effect: Option<CallEffect>,
        kind: CallEventKind,
        now_ms: i64,
    ) -> Result<(), CallError> {
        call.revision = call
            .revision
            .checked_add(1)
            .ok_or(CallError::StorageUnavailable)?;
        call.validate()?;
        let operation_id = Uuid::new_v4();
        let event = CallEvent {
            version: CALL_PROTOCOL_VERSION,
            call: call.id.clone(),
            revision: call.revision,
            operation_id,
            audience: call
                .members
                .iter()
                .filter(|m| m.authorized)
                .map(|m| m.principal.clone())
                .collect(),
            kind: kind.clone(),
        };
        let revision = i64::try_from(call.revision).map_err(storage)?;
        tx.execute(
            "UPDATE managed_calls SET revision=?3,state_json=?4 WHERE authority=?1 AND call_id=?2",
            params![
                call.id.owner_authority.as_str(),
                call.id.id.to_string(),
                revision,
                json(call)?
            ],
        )
        .map_err(storage)?;
        tx.execute("INSERT INTO managed_call_events(authority,call_id,revision,event_index,event_json) VALUES(?1,?2,?3,0,?4)",
            params![call.id.owner_authority.as_str(),call.id.id.to_string(),revision,json(&event)?]).map_err(storage)?;
        tx.execute("INSERT INTO managed_call_host_audit(authority,call_id,revision,operation_id,event_kind,created_at_ms) VALUES(?1,?2,?3,?4,?5,?6)",
            params![call.id.owner_authority.as_str(),call.id.id.to_string(),revision,operation_id.to_string(),json(&kind)?,now_ms]).map_err(storage)?;
        for effect in effect
            .into_iter()
            .chain([CallEffect::ProjectMetadata, CallEffect::Publish { event }])
        {
            tx.execute("INSERT INTO managed_call_effects(id,authority,call_id,revision,effect_json,state,next_attempt_ms) VALUES(?1,?2,?3,?4,?5,'pending',?6)",
                params![Uuid::new_v4().to_string(),call.id.owner_authority.as_str(),call.id.id.to_string(),revision,json(&effect)?,now_ms]).map_err(storage)?;
        }
        Ok(())
    }

    /// Durable preparation for the invitation saga. Only ciphertext envelopes
    /// belong in payload. The invitation itself is created by Tau afterwards.
    pub async fn stage_legacy_envelope(
        &self,
        id: CallId,
        recipient: CallPrincipal,
        inviter: CallPrincipal,
        payload: Vec<u8>,
    ) -> Result<(), CallError> {
        if payload.is_empty() || payload.len() > 16 * 1024 || recipient.user_id == 0 {
            return Err(CallError::InvalidRequest);
        }
        self.blocking(move |db| {
            let tx = db.transaction_with_behavior(TransactionBehavior::Immediate).map_err(storage)?;
            let call = Self::read_from(&tx,&id)?;
            let now_ms = SystemCallClock.now_ms()?;
            if call.banned(&recipient) { return Err(CallError::Banned); }
            let activation_self = matches!(call.lifecycle,CallLifecycle::Reserved | CallLifecycle::Provisioning)
                && inviter==call.owner && recipient==call.owner && call.member(&inviter).is_some_and(|m|m.authorized);
            if !permissions(&call,&inviter,now_ms).invite && !activation_self { return Err(CallError::NotAuthorized); }
            if call.key_epoch!=0 || call.key_available_generation!=call.rotation_generation { return Err(CallError::KeyEpochPending); }
            if call.terminal() { return Err(CallError::AlreadyEnded); }
            let existing: Option<(Vec<u8>,String,bool)> = tx.query_row("SELECT payload,inviter,revoked FROM managed_call_legacy_envelopes WHERE authority=?1 AND call_id=?2 AND recipient=?3 AND epoch=?4",
                params![id.owner_authority.as_str(),id.id.to_string(),json(&recipient)?,i64::try_from(call.key_epoch).map_err(storage)?],
                |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?))).optional().map_err(storage)?;
            if let Some((stored,source,revoked)) = existing {
                if revoked { return Err(CallError::KeyEpochPending); }
                return if stored == payload && source == json(&inviter)? { Ok(()) } else { Err(CallError::EnvelopeConflict) };
            }
            let count: i64 = tx.query_row("SELECT COUNT(*) FROM managed_call_legacy_envelopes WHERE authority=?1 AND call_id=?2 AND revoked=0",
                params![id.owner_authority.as_str(),id.id.to_string()],|row|row.get(0)).map_err(storage)?;
            if count >= (call.policy.max_invites + call.policy.max_members) as i64 { return Err(CallError::RateLimited); }
            tx.execute("INSERT INTO managed_call_legacy_envelopes(authority,call_id,recipient,epoch,inviter,payload) VALUES(?1,?2,?3,?4,?5,?6)",
                params![id.owner_authority.as_str(),id.id.to_string(),json(&recipient)?,i64::try_from(call.key_epoch).map_err(storage)?,json(&inviter)?,payload]).map_err(storage)?;
            tx.commit().map_err(storage)
        }).await
    }

    pub async fn legacy_envelope(
        &self,
        id: CallId,
        recipient: CallPrincipal,
    ) -> Result<Option<Vec<u8>>, CallError> {
        self.blocking(move |db| {
            let call = Self::read_from(db,&id)?;
            if call.terminal() || call.banned(&recipient) { return Ok(None); }
            db.query_row("SELECT payload FROM managed_call_legacy_envelopes WHERE authority=?1 AND call_id=?2 AND recipient=?3 AND epoch=?4 AND revoked=0",
                params![id.owner_authority.as_str(),id.id.to_string(),json(&recipient)?,i64::try_from(call.key_epoch).map_err(storage)?],|row|row.get(0)).optional().map_err(storage)
        }).await
    }

    pub async fn invitation_ready(
        &self,
        id: CallId,
        recipient: CallPrincipal,
        epoch: u64,
    ) -> Result<(), CallError> {
        self.blocking(move |db| {
            let tx = db
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(storage)?;
            let mut call = Self::read_from(&tx, &id)?;
            if call.terminal() || call.banned(&recipient) {
                return Err(CallError::NotAuthorized);
            }
            if call.key_epoch != epoch || call.key_available_generation != call.rotation_generation
            {
                return Err(CallError::KeyEpochPending);
            }
            let now_ms = SystemCallClock.now_ms()?;
            let invitation = call
                .invitations
                .iter_mut()
                .find(|i| i.recipient == recipient && i.expires_at_ms > now_ms)
                .ok_or(CallError::InviteExpired)?;
            if invitation.delivery_ready {
                return Ok(());
            }
            invitation.delivery_ready = true;
            Self::host_transition(&tx, &mut call, None, CallEventKind::StateChanged, now_ms)?;
            tx.commit().map_err(storage)
        })
        .await
    }

    pub async fn clear_legacy_envelopes_through(
        &self,
        id: CallId,
        recipient: CallPrincipal,
        max_epoch: u64,
    ) -> Result<(), CallError> {
        self.blocking(move |db| {
            db.execute("UPDATE managed_call_legacy_envelopes SET revoked=1 WHERE authority=?1 AND call_id=?2 AND recipient=?3 AND epoch<=?4",
                params![id.owner_authority.as_str(),id.id.to_string(),json(&recipient)?,i64::try_from(max_epoch).map_err(storage)?]).map_err(storage)?;
            Ok(())
        }).await
    }

    pub async fn create_guest_capability(
        &self,
        id: CallId,
        actor: AuthenticatedCallActor,
        expires_at_ms: i64,
        max_uses: usize,
    ) -> Result<String, CallError> {
        let budget = self.max_commands_per_minute;
        self.blocking(move |db| {
            let tx = db.transaction_with_behavior(TransactionBehavior::Immediate).map_err(storage)?;
            let call = Self::read_from(&tx,&id)?;
            let now_ms = SystemCallClock.now_ms()?;
            if actor.principal() != &call.owner || !permissions(&call,actor.principal(),now_ms).moderate
                || call.policy.join_policy != JoinPolicy::Guests || call.policy.locked {
                return Err(CallError::NotAuthorized);
            }
            if expires_at_ms <= now_ms || expires_at_ms > now_ms.saturating_add(call.policy.invite_ttl_ms)
                || max_uses == 0 || max_uses > call.policy.max_members { return Err(CallError::InvalidRequest); }
            Self::consume_write_budget(&tx,&id,actor.principal(),now_ms,budget)?;
            let capability_id = Uuid::new_v4();
            let token = format!("{capability_id}.{}.{}",Uuid::new_v4(),Uuid::new_v4());
            // Regeneration revokes the underlying old capability, not just its redirect.
            tx.execute("UPDATE managed_call_guest_capabilities SET revoked=1 WHERE authority=?1 AND call_id=?2",
                params![id.owner_authority.as_str(),id.id.to_string()]).map_err(storage)?;
            tx.execute("INSERT INTO managed_call_guest_capabilities(id,authority,call_id,token_hash,expires_at_ms,max_uses) VALUES(?1,?2,?3,?4,?5,?6)",
                params![capability_id.to_string(),id.owner_authority.as_str(),id.id.to_string(),mtp::crypto::sha256(token.as_bytes()).to_vec(),expires_at_ms,max_uses as i64]).map_err(storage)?;
            tx.commit().map_err(storage)?;
            Ok(token)
        }).await
    }

    pub async fn revoke_guest_capabilities(
        &self,
        id: CallId,
        actor: AuthenticatedCallActor,
    ) -> Result<(), CallError> {
        self.blocking(move |db| {
            let tx = db.transaction_with_behavior(TransactionBehavior::Immediate).map_err(storage)?;
            let call = Self::read_from(&tx,&id)?;
            if actor.principal() != &call.owner || !permissions(&call,actor.principal(),SystemCallClock.now_ms()?).moderate { return Err(CallError::NotAuthorized); }
            tx.execute("UPDATE managed_call_guest_capabilities SET revoked=1 WHERE authority=?1 AND call_id=?2",
                params![id.owner_authority.as_str(),id.id.to_string()]).map_err(storage)?;
            tx.commit().map_err(storage)
        }).await
    }

    pub async fn verify_guest_capability(
        &self,
        id: CallId,
        principal: CallPrincipal,
        token: String,
        now_ms: i64,
    ) -> Result<AuthenticatedCallActor, CallError> {
        if token.len() > 128 || now_ms < 0 {
            return Err(CallError::NotAuthorized);
        }
        let parts: Vec<_> = token.split('.').collect();
        if parts.len() != 3 || parts.iter().any(|p| Uuid::parse_str(p).is_err()) {
            return Err(CallError::NotAuthorized);
        }
        let capability_id = Uuid::parse_str(parts[0]).map_err(|_| CallError::NotAuthorized)?;
        self.blocking(move |db| {
            let valid: bool = db.query_row("SELECT EXISTS(SELECT 1 FROM managed_call_guest_capabilities WHERE id=?1 AND authority=?2 AND call_id=?3 AND token_hash=?4 AND revoked=0 AND uses<max_uses AND expires_at_ms>?5)",
                params![capability_id.to_string(),id.owner_authority.as_str(),id.id.to_string(),mtp::crypto::sha256(token.as_bytes()).to_vec(),now_ms],|row|row.get(0)).map_err(storage)?;
            if !valid { return Err(CallError::NotAuthorized); }
            AuthenticatedCallActor::from_verified_guest_admission(principal,id,capability_id)
        }).await
    }

    pub async fn observe_presence(
        &self,
        id: CallId,
        occupied: bool,
        now_ms: i64,
        max_age_ms: i64,
    ) -> Result<(), CallError> {
        if now_ms < 0 || max_age_ms <= 0 {
            return Err(CallError::InvalidRequest);
        }
        self.blocking(move |db| {
            let tx=db.transaction_with_behavior(TransactionBehavior::Immediate).map_err(storage)?;
            let mut call=Self::read_from(&tx,&id)?;
            if call.lifecycle!=CallLifecycle::Active { return Ok(()); }
            let previous:Option<(Option<i64>,i64)>=tx.query_row("SELECT empty_since_ms,observed_at_ms FROM managed_call_presence WHERE authority=?1 AND call_id=?2",
                params![id.owner_authority.as_str(),id.id.to_string()],|row|Ok((row.get(0)?,row.get(1)?))).optional().map_err(storage)?;
            if previous.is_some_and(|(_,observed)|observed>now_ms) { return Ok(()); }
            let empty_since=if occupied { None } else { previous.and_then(|(since,_)|since).or(Some(now_ms)) };
            tx.execute("INSERT INTO managed_call_presence(authority,call_id,empty_since_ms,observed_at_ms) VALUES(?1,?2,?3,?4) ON CONFLICT(authority,call_id) DO UPDATE SET empty_since_ms=excluded.empty_since_ms,observed_at_ms=excluded.observed_at_ms",
                params![id.owner_authority.as_str(),id.id.to_string(),empty_since,now_ms]).map_err(storage)?;
            let created:i64=tx.query_row("SELECT created_at_ms FROM managed_call_host WHERE authority=?1 AND call_id=?2",
                params![id.owner_authority.as_str(),id.id.to_string()],|row|row.get(0)).map_err(storage)?;
            let expired=created.saturating_add(max_age_ms)<=now_ms;
            let idle=empty_since.is_some_and(|since|since.saturating_add(call.policy.empty_grace_ms)<=now_ms)
                && !call.invitations.iter().any(|i|i.expires_at_ms>now_ms);
            if expired || idle {
                let recipients:std::collections::BTreeSet<_>=call.members.iter().map(|m|m.principal.clone()).chain(call.invitations.iter().map(|i|i.recipient.clone())).collect();
                call.lifecycle=CallLifecycle::Ending;
                call.invitations.clear();
                let until:Option<i64>=tx.query_row("SELECT MAX(valid_until_ms) FROM managed_call_credentials WHERE authority=?1 AND call_id=?2",
                    params![id.owner_authority.as_str(),id.id.to_string()],|row|row.get(0)).map_err(storage)?;
                Self::host_transition(&tx,&mut call,Some(CallEffect::EnsureEnded { credentials_valid_until_ms:until.unwrap_or(now_ms) }),CallEventKind::Ending,now_ms)?;
                for effect in recipients.into_iter().map(|principal|CallEffect::RevokeEnvelopes { principal }).chain(std::iter::once(CallEffect::RevokeLinks)) {
                    let effect=Self::persistable_effect(&tx,&call,&effect,now_ms)?;
                    tx.execute("INSERT INTO managed_call_effects(id,authority,call_id,revision,effect_json,state,next_attempt_ms) VALUES(?1,?2,?3,?4,?5,'pending',?6)",
                        params![Uuid::new_v4().to_string(),id.owner_authority.as_str(),id.id.to_string(),i64::try_from(call.revision).map_err(storage)?,json(&effect)?,now_ms]).map_err(storage)?;
                }
                tx.execute("UPDATE managed_call_guest_capabilities SET revoked=1 WHERE authority=?1 AND call_id=?2",params![id.owner_authority.as_str(),id.id.to_string()]).map_err(storage)?;
            } else {
                Self::queue_inspection(&tx,&call,now_ms)?;
            }
            tx.commit().map_err(storage)
        }).await
    }

    fn read_from(db: &Connection, id: &CallId) -> Result<Call, CallError> {
        let state: String = db
            .query_row(
                "SELECT state_json FROM managed_calls WHERE authority=?1 AND call_id=?2",
                params![id.owner_authority.as_str(), id.id.to_string()],
                |row| row.get(0),
            )
            .optional()
            .map_err(storage)?
            .ok_or(CallError::NotFound)?;
        let call: Call = serde_json::from_str(&state).map_err(storage)?;
        call.validate()?;
        if &call.id != id {
            return Err(CallError::StorageUnavailable);
        }
        Ok(call)
    }

    fn persistable_effect(
        tx: &Connection,
        call: &Call,
        effect: &CallEffect,
        now_ms: i64,
    ) -> Result<CallEffect, CallError> {
        let authority = call.id.owner_authority.as_str();
        let call_id = call.id.id.to_string();
        Ok(match effect {
            CallEffect::RemoveMember { principal } => {
                let until:Option<i64>=tx.query_row("SELECT MAX(valid_until_ms) FROM managed_call_credentials WHERE authority=?1 AND call_id=?2 AND principal IN('*',?3)",params![authority,call_id,json(principal)?],|row|row.get(0)).map_err(storage)?;
                CallEffect::EnsureRevoked {
                    principal: principal.clone(),
                    credentials_valid_until_ms: until.unwrap_or(now_ms),
                }
            }
            CallEffect::EndRoom => {
                let until:Option<i64>=tx.query_row("SELECT MAX(valid_until_ms) FROM managed_call_credentials WHERE authority=?1 AND call_id=?2",params![authority,call_id],|row|row.get(0)).map_err(storage)?;
                CallEffect::EnsureEnded {
                    credentials_valid_until_ms: until.unwrap_or(now_ms),
                }
            }
            CallEffect::RevokeEnvelopes { principal } => {
                let proposed:Option<u64>=tx.query_row("SELECT MAX(epoch) FROM managed_call_key_plans WHERE authority=?1 AND call_id=?2",params![authority,call_id],|row|row.get(0)).map_err(storage)?;
                CallEffect::RevokeEnvelopesThrough {
                    principal: principal.clone(),
                    max_epoch: proposed.unwrap_or(call.key_epoch).max(call.key_epoch),
                }
            }
            other => other.clone(),
        })
    }

    fn consume_write_budget(
        tx: &Connection,
        id: &CallId,
        actor: &CallPrincipal,
        now_ms: i64,
        limit: usize,
    ) -> Result<(), CallError> {
        let principal = json(actor)?;
        let current:Option<(i64,i64)>=tx.query_row("SELECT window_start_ms,operations FROM managed_call_write_budgets WHERE authority=?1 AND actor=?2",
            params![id.owner_authority.as_str(),principal],|row|Ok((row.get(0)?,row.get(1)?))).optional().map_err(storage)?;
        let (start, count) = current
            .filter(|(start, _)| now_ms < start.saturating_add(60_000))
            .unwrap_or((now_ms, 0));
        if count >= limit as i64 {
            return Err(CallError::RateLimited);
        }
        tx.execute("INSERT INTO managed_call_write_budgets(authority,actor,window_start_ms,operations) VALUES(?1,?2,?3,?4) ON CONFLICT(authority,actor) DO UPDATE SET window_start_ms=excluded.window_start_ms,operations=excluded.operations",
            params![id.owner_authority.as_str(),principal,start,count+1]).map_err(storage)?;
        Ok(())
    }

    fn related_call_count(
        tx: &Connection,
        authority: &CallAuthority,
        principal: &CallPrincipal,
        now_ms: i64,
    ) -> Result<usize, CallError> {
        tx.query_row("SELECT COUNT(*) FROM managed_calls c LEFT JOIN managed_call_host h ON c.authority=h.authority AND c.call_id=h.call_id WHERE c.authority=?1 AND (json_extract(c.state_json,'$.lifecycle') IN('active','provisioning') OR (json_extract(c.state_json,'$.lifecycle')='reserved' AND h.reservation_expires_at_ms>?3)) AND (EXISTS(SELECT 1 FROM json_each(c.state_json,'$.members') m WHERE json_extract(m.value,'$.principal')=?2 AND json_extract(m.value,'$.authorized')=1) OR EXISTS(SELECT 1 FROM json_each(c.state_json,'$.invitations') i WHERE json_extract(i.value,'$.recipient')=?2 AND json_extract(i.value,'$.expires_at_ms')>?3))",
            params![authority.as_str(),json(principal)?,now_ms],|row|row.get(0)).map_err(storage)
    }

    pub async fn check_invite_capacity(
        &self,
        id: CallId,
        target: CallPrincipal,
        now_ms: i64,
    ) -> Result<(), CallError> {
        let limit = self.max_calls_per_principal;
        self.blocking(move |db| {
            let call = Self::read_from(db, &id)?;
            let related = call.member(&target).is_some_and(|m| m.authorized)
                || call
                    .invitations
                    .iter()
                    .any(|i| i.recipient == target && i.expires_at_ms > now_ms);
            if !related
                && Self::related_call_count(db, &id.owner_authority, &target, now_ms)? >= limit
            {
                return Err(CallError::RateLimited);
            }
            Ok(())
        })
        .await
    }
}

impl CallRepository for SqliteCallRepository {
    fn next_key_epoch(&self, id: CallId) -> CallFuture<'_, u64> {
        Box::pin(self.blocking(move |db| {
            let call=Self::read_from(db,&id)?;
            let largest:Option<u64>=db.query_row("SELECT MAX(epoch) FROM managed_call_key_plans WHERE authority=?1 AND call_id=?2",
                params![id.owner_authority.as_str(),id.id.to_string()],|row|row.get(0)).map_err(storage)?;
            largest.unwrap_or(call.key_epoch).max(call.key_epoch).checked_add(1).filter(|epoch|*epoch<=i64::MAX as u64).ok_or(CallError::KeyEpochPending)
        }))
    }
    fn record_join_credential(
        &self,
        id: CallId,
        principal: CallPrincipal,
        revision: u64,
        expires_at_ms: i64,
        now_ms: i64,
    ) -> CallFuture<'_, ()> {
        let budget = self.max_commands_per_minute;
        Box::pin(self.blocking(move |db| {
            let tx = db.transaction_with_behavior(TransactionBehavior::Immediate).map_err(storage)?;
            let call = Self::read_from(&tx,&id)?;
            if call.revision!=revision { return Err(CallError::Conflict { current_revision:call.revision }); }
            if !permissions(&call,&principal,now_ms).join || expires_at_ms<=now_ms { return Err(CallError::NotAuthorized); }
            Self::consume_write_budget(&tx,&id,&principal,now_ms,budget)?;
            tx.execute("INSERT INTO managed_call_credentials(authority,call_id,principal,valid_until_ms) VALUES(?1,?2,?3,?4) ON CONFLICT(authority,call_id,principal) DO UPDATE SET valid_until_ms=MAX(valid_until_ms,excluded.valid_until_ms)",
                params![id.owner_authority.as_str(),id.id.to_string(),json(&principal)?,expires_at_ms]).map_err(storage)?;
            tx.commit().map_err(storage)
        }))
    }
    fn enforcement_status(&self, id: CallId) -> CallFuture<'_, EnforcementStatus> {
        Box::pin(self.blocking(move |db| {
            Self::read_from(db,&id)?;
            let pending: bool = db.query_row("SELECT EXISTS(SELECT 1 FROM managed_call_effects WHERE authority=?1 AND call_id=?2 AND state!='complete')",
                params![id.owner_authority.as_str(),id.id.to_string()],|row|row.get(0)).map_err(storage)?;
            Ok(if pending { EnforcementStatus::PendingEnforcement } else { EnforcementStatus::Applied })
        }))
    }
    fn read(&self, call: CallId) -> CallFuture<'_, Call> {
        Box::pin(self.blocking(move |db| Self::read_from(db, &call)))
    }

    fn transact(
        &self,
        actor: AuthenticatedCallActor,
        request: CallCommandRequest,
        now_ms: i64,
    ) -> CallFuture<'_, CallCommandResult> {
        let budget = self.max_commands_per_minute;
        let call_limit = self.max_calls_per_principal;
        Box::pin(self.blocking(move |db| {
            request.validate()?;
            let bytes = encode_call_command(&request)?;
            let actor_json = json(actor.principal())?;
            let authority = request.call.owner_authority.as_str();
            let call_id = request.call.id.to_string();
            let operation = request.operation_id.to_string();
            let tx = db.transaction_with_behavior(TransactionBehavior::Immediate).map_err(storage)?;
            let existing: Option<(Vec<u8>, String)> = tx.query_row(
                "SELECT request,result_json FROM managed_call_operations WHERE authority=?1 AND call_id=?2 AND actor=?3 AND operation_id=?4",
                params![authority, call_id, actor_json, operation], |row| Ok((row.get(0)?, row.get(1)?))).optional().map_err(storage)?;
            if let Some((stored, result)) = existing {
                if stored != bytes { return Err(CallError::OperationConflict); }
                return serde_json::from_str(&result).map_err(storage);
            }
            if let CallCommand::AcceptGuestAdmission = request.command {
                let proof = actor.guest_admission().filter(|proof|proof.call==request.call).ok_or(CallError::NotAuthorized)?;
                let used = tx.execute("UPDATE managed_call_guest_capabilities SET uses=uses+1 WHERE id=?1 AND authority=?2 AND call_id=?3 AND revoked=0 AND uses<max_uses AND expires_at_ms>?4",
                    params![proof.capability_id.to_string(),authority,call_id,now_ms]).map_err(storage)?;
                if used!=1 { return Err(CallError::NotAuthorized); }
            }
            let current = Self::read_from(&tx, &request.call)?;
            let decided = transition(&current, &actor, &request, now_ms)?;
            let admitted=match &request.command {
                CallCommand::Invite {target}=>Some(target),
                CallCommand::AcceptGuestAdmission=>Some(actor.principal()),
                _=>None,
            };
            if let Some(target)=admitted {
                let related=current.member(target).is_some_and(|m|m.authorized) || current.invitations.iter().any(|i|&i.recipient==target && i.expires_at_ms>now_ms);
                if !related && Self::related_call_count(&tx,&request.call.owner_authority,target,now_ms)? >= call_limit {return Err(CallError::RateLimited);}
            }
            Self::consume_write_budget(&tx,&request.call,actor.principal(),now_ms,budget)?;
            let result = CallCommandResult {
                revision: decided.call.revision,
                status: if decided.effects.is_empty() { EnforcementStatus::Applied } else { EnforcementStatus::PendingEnforcement },
                rotation_required: decided.call.rotation_required,
            };
            let revision = i64::try_from(decided.call.revision).map_err(storage)?;
            let changed = tx.execute("UPDATE managed_calls SET revision=?3,state_json=?4 WHERE authority=?1 AND call_id=?2 AND revision=?5",
                params![authority, call_id, revision, json(&decided.call)?, i64::try_from(current.revision).map_err(storage)?]).map_err(storage)?;
            if changed != 1 { return Err(CallError::Conflict { current_revision: current.revision }); }
            if decided.call.terminal() || decided.call.policy.join_policy != JoinPolicy::Guests {
                tx.execute("UPDATE managed_call_guest_capabilities SET revoked=1 WHERE authority=?1 AND call_id=?2",
                    params![authority,call_id]).map_err(storage)?;
            }
            tx.execute("INSERT INTO managed_call_operations(authority,call_id,actor,operation_id,request,result_json) VALUES(?1,?2,?3,?4,?5,?6)",
                params![authority, call_id, actor_json, operation, bytes, json(&result)?]).map_err(storage)?;
            tx.execute("INSERT INTO managed_call_audit(authority,call_id,actor,operation_id,revision,created_at_ms,command_json) VALUES(?1,?2,?3,?4,?5,?6,?7)",
                params![authority, call_id, actor_json, operation, revision, now_ms, json(&decided.audit_command)?]).map_err(storage)?;
            for (index, effect) in decided.effects.iter().enumerate() {
                if let CallEffect::Publish { event } = effect {
                    tx.execute("INSERT INTO managed_call_events(authority,call_id,revision,event_index,event_json) VALUES(?1,?2,?3,?4,?5)",
                        params![authority, call_id, revision, index as i64, json(event)?]).map_err(storage)?;
                }
                let effect=Self::persistable_effect(&tx,&decided.call,effect,now_ms)?;
                tx.execute("INSERT INTO managed_call_effects(id,authority,call_id,revision,effect_json,state,next_attempt_ms) VALUES(?1,?2,?3,?4,?5,'pending',?6)",
                    params![Uuid::new_v4().to_string(), authority, call_id, revision, json(&effect)?, now_ms]).map_err(storage)?;
            }
            tx.commit().map_err(storage)?;
            Ok(result)
        }))
    }

    fn claim_effects(&self, now_ms: i64, limit: usize) -> CallFuture<'_, Vec<PendingCallEffect>> {
        Box::pin(self.blocking(move |db| {
            if now_ms < 0 || limit == 0 || limit > 1024 { return Err(CallError::InvalidRequest); }
            let tx = db.transaction_with_behavior(TransactionBehavior::Immediate).map_err(storage)?;
            let mut claims = Vec::new();
            {
                let mut stmt = tx.prepare("SELECT id,authority,call_id,revision,effect_json,claim_generation,attempts FROM managed_call_effects WHERE (state='pending' AND next_attempt_ms<=?1) OR (state='claimed' AND claim_until_ms<=?1) ORDER BY next_attempt_ms,id LIMIT ?2").map_err(storage)?;
                let rows = stmt.query_map(params![now_ms, limit as i64], |row| Ok((
                    row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, String>(2)?, row.get::<_, u64>(3)?,
                    row.get::<_, String>(4)?, row.get::<_, u64>(5)?, row.get::<_, u32>(6)?))).map_err(storage)?;
                for row in rows {
                    let (id, authority, call_id, revision, effect, generation, attempts) = row.map_err(storage)?;
                    claims.push(PendingCallEffect { id: Uuid::parse_str(&id).map_err(storage)?,
                        call: CallId { owner_authority: CallAuthority::new(authority)?, id: Uuid::parse_str(&call_id).map_err(storage)? },
                        revision, effect: serde_json::from_str(&effect).map_err(storage)?,
                        claim_generation: generation.checked_add(1).ok_or(CallError::StorageUnavailable)?, attempts: attempts.saturating_add(1),
                    });
                }
            }
            for claim in &claims {
                tx.execute("UPDATE managed_call_effects SET state='claimed',claim_generation=?2,claim_until_ms=?3,attempts=?4 WHERE id=?1",
                    params![claim.id.to_string(), i64::try_from(claim.claim_generation).map_err(storage)?, now_ms.saturating_add(60_000), claim.attempts]).map_err(storage)?;
            }
            tx.commit().map_err(storage)?;
            Ok(claims)
        }))
    }

    fn prepare_claim(
        &self,
        mut claim: PendingCallEffect,
        effect: CallEffect,
        now_ms: i64,
    ) -> CallFuture<'_, PendingCallEffect> {
        Box::pin(self.blocking(move |db| {
            let tx=db.transaction_with_behavior(TransactionBehavior::Immediate).map_err(storage)?;
            let stored:Option<String>=tx.query_row("SELECT effect_json FROM managed_call_effects WHERE id=?1 AND state='claimed' AND claim_generation=?2 AND claim_until_ms>?3",
                params![claim.id.to_string(),i64::try_from(claim.claim_generation).map_err(storage)?,now_ms],|row|row.get(0)).optional().map_err(storage)?;
            let stored:CallEffect=serde_json::from_str(&stored.ok_or(CallError::Conflict { current_revision:claim.revision })?).map_err(storage)?;
            if stored!=effect {
                match (&stored,&effect) {
                    (CallEffect::MuteMicrophoneNow { principal },CallEffect::BoundMicrophoneMute { principal:target,participant_sid,track_sids })
                        if principal==target && participant_sid.len()<=256 && track_sids.len()<=128
                            && track_sids.iter().all(|sid|!sid.is_empty() && sid.len()<=256)=>{},
                    _=>return Err(CallError::InvalidRequest),
                }
            }
            let changed = tx.execute("UPDATE managed_call_effects SET effect_json=?3,claim_until_ms=?4 WHERE id=?1 AND state='claimed' AND claim_generation=?2 AND claim_until_ms>?5",
                params![claim.id.to_string(),i64::try_from(claim.claim_generation).map_err(storage)?,json(&effect)?,now_ms.saturating_add(60_000),now_ms]).map_err(storage)?;
            if changed!=1 { return Err(CallError::Conflict { current_revision:claim.revision }); }
            claim.effect=effect;
            tx.commit().map_err(storage)?;
            Ok(claim)
        }))
    }

    fn finish_effect(
        &self,
        claim: PendingCallEffect,
        outcome: Result<(), CallError>,
        now_ms: i64,
    ) -> CallFuture<'_, ()> {
        Box::pin(self.blocking(move |db| {
            let tx=db.transaction_with_behavior(TransactionBehavior::Immediate).map_err(storage)?;
            let error = outcome.as_ref().err().map(ToString::to_string);
            let delay = if matches!(claim.effect,CallEffect::EnsureRevoked { .. } | CallEffect::EnsureEnded { .. } | CallEffect::ReconcileMember { .. }) { 2000 }
                else { 1000_i64.saturating_mul(1_i64 << claim.attempts.min(8)) };
            let next = now_ms.saturating_add(delay);
            let changed = tx.execute("UPDATE managed_call_effects SET state=?3,claim_until_ms=NULL,next_attempt_ms=?4,last_error=?5 WHERE id=?1 AND state='claimed' AND claim_generation=?2 AND claim_until_ms>?6",
                params![claim.id.to_string(), i64::try_from(claim.claim_generation).map_err(storage)?, if outcome.is_ok() { "complete" } else { "pending" }, next, error, now_ms]).map_err(storage)?;
            if changed != 1 { return Err(CallError::Conflict { current_revision: claim.revision }); }
            if outcome.is_ok() {
                let mut call=Self::read_from(&tx,&claim.call)?;
                if call.lifecycle==CallLifecycle::Ending {
                    let pending:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM managed_call_effects WHERE authority=?1 AND call_id=?2 AND state!='complete')",
                        params![call.id.owner_authority.as_str(),call.id.id.to_string()],|row|row.get(0)).map_err(storage)?;
                    if !pending && call.finish_ending()? {
                        Self::host_transition(&tx,&mut call,None,CallEventKind::Ended,now_ms)?;
                    }
                }
            }
            tx.commit().map_err(storage)?;
            Ok(())
        }))
    }
}
