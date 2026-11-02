use super::*;

fn principal(user_id: u64) -> CallPrincipal {
    CallPrincipal {
        authority: CallAuthority::new(format!("omega-key:{}", "a".repeat(64))).unwrap(),
        user_id,
    }
}

fn actor(user_id: u64) -> AuthenticatedCallActor {
    AuthenticatedCallActor::from_verified_session(principal(user_id)).unwrap()
}

pub(crate) fn call() -> Call {
    Call {
        id: CallId {
            owner_authority: principal(1).authority,
            id: Uuid::new_v4(),
        },
        owner: principal(1),
        lifecycle: CallLifecycle::Active,
        revision: 0,
        policy: CallPolicy {
            locked: false,
            allow_locked_rejoin: true,
            join_policy: JoinPolicy::Invited,
            invite: RolePolicy::All,
            speak: RolePolicy::All,
            camera: RolePolicy::All,
            screen_share: RolePolicy::All,
            publish_data: RolePolicy::All,
            new_members_muted: false,
            guest_microphone: false,
            guest_screen_share: false,
            moderators_may_end: false,
            moderators_may_change_policy: false,
            moderators: ModeratorPermissions::default(),
            max_members: 10,
            max_invites: 10,
            invite_ttl_ms: 60_000,
            empty_grace_ms: 30_000,
        },
        members: (1..=4)
            .map(|id| CallMember {
                principal: principal(id),
                role: match id {
                    1 => CallRole::Owner,
                    2 | 3 => CallRole::Moderator,
                    _ => CallRole::Member,
                },
                authorized: true,
                approved: true,
                guest: false,
                restrictions: Restrictions::default(),
                timeout_until_ms: None,
                overrides: PermissionOverrides::default(),
            })
            .collect(),
        invitations: vec![],
        bans: vec![],
        key_epoch: 0,
        rotation_required: false,
        rotation_generation: 0,
        key_available_generation: 0,
        key_installations: vec![],
    }
}

fn request(call: &Call, command: CallCommand) -> CallCommandRequest {
    CallCommandRequest {
        call: call.id.clone(),
        operation_id: Uuid::new_v4(),
        expected_revision: None,
        command,
    }
}

fn restriction(call: &Call, restriction: MemberRestriction) -> CallCommandRequest {
    request(
        call,
        CallCommand::SetMemberRestriction {
            target: principal(4),
            restriction,
            enabled: true,
        },
    )
}

fn memory() -> SqliteCallRepository {
    SqliteCallRepository::open(Path::new(":memory:")).unwrap()
}

struct Database(std::path::PathBuf);

impl Database {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!("omikron-call-tests-{}", Uuid::new_v4()));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }

    fn open(&self) -> SqliteCallRepository {
        SqliteCallRepository::open(&self.0.join("calls.sqlite")).unwrap()
    }
}

impl Drop for Database {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).unwrap();
    }
}

// Include every transactional output, so a rejection cannot hide a partial write.
fn counts(repo: &SqliteCallRepository) -> Vec<i64> {
    let db = repo.db.lock().unwrap();
    [
        "managed_call_operations",
        "managed_call_audit",
        "managed_call_events",
        "managed_call_effects",
        "managed_call_host_audit",
    ]
    .into_iter()
    .map(|table| {
        db.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
            row.get(0)
        })
        .unwrap()
    })
    .collect()
}

#[tokio::test]
async fn exact_replay_survives_restart_and_actor_removal_without_duplicate_outputs() {
    let file = Database::new();
    let repo = file.open();
    let call = call();
    repo.insert(call.clone()).await.unwrap();
    let mut command = request(&call, CallCommand::Leave);
    command.expected_revision = Some(0);
    let first = repo
        .transact(actor(4), command.clone(), 1000)
        .await
        .unwrap();
    let outputs = counts(&repo);
    let state = repo.read(call.id.clone()).await.unwrap();
    drop(repo);
    let repo = file.open();
    assert_eq!(
        repo.transact(actor(4), command.clone(), 2000)
            .await
            .unwrap(),
        first
    );
    assert_eq!(repo.read(call.id.clone()).await.unwrap(), state);
    assert_eq!(counts(&repo), outputs);
    command.command = CallCommand::End;
    assert_eq!(
        repo.transact(actor(4), command, 2000).await,
        Err(CallError::OperationConflict)
    );
    assert_eq!(counts(&repo), outputs);
}

#[tokio::test]
async fn rejected_commands_leave_state_audit_events_and_effects_unchanged() {
    let repo = memory();
    let call = call();
    repo.insert(call.clone()).await.unwrap();
    let before = counts(&repo);
    assert_eq!(
        repo.transact(actor(4), request(&call, CallCommand::End), 1000)
            .await,
        Err(CallError::NotAuthorized)
    );
    let mut stale = restriction(&call, MemberRestriction::Camera);
    stale.expected_revision = Some(1);
    assert_eq!(
        repo.transact(actor(1), stale, 1000).await,
        Err(CallError::Conflict {
            current_revision: 0
        })
    );
    assert_eq!(repo.read(call.id.clone()).await.unwrap(), call);
    assert_eq!(counts(&repo), before);
}

#[tokio::test]
async fn independent_connections_preserve_concurrent_independent_restrictions() {
    let file = Database::new();
    let left = file.open();
    let right = file.open();
    let call = call();
    left.insert(call.clone()).await.unwrap();
    let (a, b) = tokio::join!(
        left.transact(
            actor(2),
            restriction(&call, MemberRestriction::Microphone),
            1000
        ),
        right.transact(
            actor(3),
            restriction(&call, MemberRestriction::Camera),
            1000
        ),
    );
    let mut revisions = vec![a.unwrap().revision, b.unwrap().revision];
    revisions.sort();
    assert_eq!(revisions, vec![1, 2]);
    let state = left.read(call.id).await.unwrap();
    let restrictions = &state.member(&principal(4)).unwrap().restrictions;
    assert!(restrictions.microphone && restrictions.camera);
    assert_eq!(counts(&left)[..2], [2, 2]);
}

#[tokio::test]
async fn demotion_and_moderator_mutation_have_a_single_serial_order() {
    let file = Database::new();
    let owner = file.open();
    let moderator = file.open();
    let call = call();
    owner.insert(call.clone()).await.unwrap();
    let (demotion, mutation) = tokio::join!(
        owner.transact(
            actor(1),
            request(
                &call,
                CallCommand::SetRole {
                    target: principal(2),
                    role: CallRole::Member
                }
            ),
            1000
        ),
        moderator.transact(
            actor(2),
            restriction(&call, MemberRestriction::Microphone),
            1000
        ),
    );
    let demotion = demotion.unwrap();
    let state = owner.read(call.id).await.unwrap();
    assert_eq!(state.member(&principal(2)).unwrap().role, CallRole::Member);
    match mutation {
        Ok(result) => {
            assert_eq!(
                (result.revision, demotion.revision, state.revision),
                (1, 2, 2)
            );
            assert!(state.member(&principal(4)).unwrap().restrictions.microphone);
        }
        Err(error) => {
            assert_eq!(error, CallError::NotAuthorized);
            assert_eq!((demotion.revision, state.revision), (1, 1));
            assert!(!state.member(&principal(4)).unwrap().restrictions.microphone);
        }
    }
    assert_eq!(counts(&owner)[0], state.revision as i64);
}

#[tokio::test]
async fn expired_and_reclaimed_leases_fence_prepare_and_acknowledgement() {
    let repo = memory();
    let call = call();
    repo.insert(call.clone()).await.unwrap();
    repo.transact(
        actor(1),
        restriction(&call, MemberRestriction::Microphone),
        1000,
    )
    .await
    .unwrap();
    let old = repo.claim_effects(1000, 1).await.unwrap().pop().unwrap();
    assert_eq!(
        repo.prepare_claim(old.clone(), old.effect.clone(), 61_000)
            .await
            .unwrap_err(),
        CallError::Conflict {
            current_revision: old.revision
        }
    );
    assert_eq!(
        repo.finish_effect(old.clone(), Ok(()), 61_000).await,
        Err(CallError::Conflict {
            current_revision: old.revision
        })
    );
    let reclaimed = repo
        .claim_effects(61_000, 1024)
        .await
        .unwrap()
        .into_iter()
        .find(|claim| claim.id == old.id)
        .unwrap();
    assert_eq!(reclaimed.claim_generation, old.claim_generation + 1);
    assert_eq!(reclaimed.attempts, old.attempts + 1);
    assert!(
        repo.prepare_claim(old.clone(), old.effect.clone(), 61_001)
            .await
            .is_err()
    );
    assert!(repo.finish_effect(old, Ok(()), 61_001).await.is_err());
    repo.finish_effect(reclaimed.clone(), Ok(()), 61_001)
        .await
        .unwrap();
    assert!(
        !repo
            .claim_effects(121_001, 1024)
            .await
            .unwrap()
            .iter()
            .any(|claim| claim.id == reclaimed.id)
    );
}

#[tokio::test]
async fn prepared_microphone_binding_survives_restart_and_reclaim() {
    let file = Database::new();
    let repo = file.open();
    let call = call();
    repo.insert(call.clone()).await.unwrap();
    repo.transact(
        actor(1),
        request(
            &call,
            CallCommand::MuteMicrophoneNow {
                target: principal(4),
            },
        ),
        1000,
    )
    .await
    .unwrap();
    let claim = repo
        .claim_effects(1000, 1024)
        .await
        .unwrap()
        .into_iter()
        .find(|claim| matches!(claim.effect, CallEffect::MuteMicrophoneNow { .. }))
        .unwrap();
    let binding = CallEffect::BoundMicrophoneMute {
        principal: principal(4),
        participant_sid: "PA_original".into(),
        track_sids: vec!["TR_original".into()],
    };
    let prepared = repo
        .prepare_claim(claim, binding.clone(), 1001)
        .await
        .unwrap();
    drop(repo);
    let repo = file.open();
    let reclaimed = repo
        .claim_effects(61_001, 1024)
        .await
        .unwrap()
        .into_iter()
        .find(|claim| claim.id == prepared.id)
        .unwrap();
    assert_eq!(reclaimed.effect, binding);
    assert_eq!(reclaimed.claim_generation, prepared.claim_generation + 1);
    assert_eq!(repo.read(call.id).await.unwrap().members, call.members);
    assert!(
        repo.prepare_claim(
            prepared,
            CallEffect::MuteMicrophoneNow {
                principal: principal(4)
            },
            61_002
        )
        .await
        .is_err()
    );
    let rebound = CallEffect::BoundMicrophoneMute {
        principal: principal(4),
        participant_sid: "PA_reconnected".into(),
        track_sids: vec!["TR_new".into()],
    };
    assert!(
        repo.prepare_claim(reclaimed.clone(), rebound, 61_002)
            .await
            .is_err(),
        "a retry must never retarget a reconnected participant or newly published track"
    );
    repo.finish_effect(reclaimed, Ok(()), 61_002).await.unwrap();
}

#[tokio::test]
async fn reservation_quota_is_atomic_and_provisioning_survives_expiry_and_restart() {
    let file = Database::new();
    let left = file.open();
    let right = file.open();
    let mut a = call();
    a.lifecycle = CallLifecycle::Reserved;
    let mut b = a.clone();
    b.id.id = Uuid::new_v4();
    let (first, second) = tokio::join!(
        left.reserve(a.clone(), 1000, 2000, 1, false),
        right.reserve(b.clone(), 1000, 2000, 1, false)
    );
    let winner = match (first, second) {
        (Ok(()), Err(CallError::RateLimited)) => a,
        (Err(CallError::RateLimited), Ok(())) => b,
        other => panic!("quota race returned {other:?}"),
    };
    left.begin_activation(winner.id.clone(), principal(1), 1999)
        .await
        .unwrap();
    let outputs = counts(&left);
    drop(left);
    drop(right);
    let repo = file.open();
    assert_eq!(
        repo.reservation_created_at(winner.id.clone(), principal(1), 3000)
            .await
            .unwrap(),
        1000
    );
    repo.begin_activation(winner.id.clone(), principal(1), 3000)
        .await
        .unwrap();
    assert_eq!(counts(&repo), outputs);
    let mut next = call();
    next.lifecycle = CallLifecycle::Reserved;
    assert_eq!(
        repo.reserve(next, 3000, 4000, 1, false).await,
        Err(CallError::RateLimited)
    );
    repo.complete_activation(winner.id.clone(), principal(1))
        .await
        .unwrap();
    let outputs = counts(&repo);
    repo.complete_activation(winner.id.clone(), principal(1))
        .await
        .unwrap();
    assert_eq!(counts(&repo), outputs);
    assert_eq!(
        repo.read(winner.id).await.unwrap().lifecycle,
        CallLifecycle::Active
    );
}

#[tokio::test]
async fn expired_reservations_release_quota_but_cannot_activate() {
    let repo = memory();
    let mut old = call();
    old.lifecycle = CallLifecycle::Reserved;
    repo.reserve(old.clone(), 1000, 2000, 1, false)
        .await
        .unwrap();
    assert_eq!(
        repo.begin_activation(old.id.clone(), principal(1), 2000)
            .await,
        Err(CallError::NotFound)
    );
    assert_eq!(
        repo.reservation_created_at(old.id, principal(1), 2000)
            .await,
        Err(CallError::NotFound)
    );
    let mut next = call();
    next.lifecycle = CallLifecycle::Reserved;
    repo.reserve(next, 2000, 3000, 1, false).await.unwrap();
}

#[tokio::test]
async fn legacy_import_never_overwrites_authoritative_state_or_media_binding() {
    let repo = memory();
    let legacy = call();
    repo.insert_legacy(legacy.clone(), 1000).await.unwrap();
    repo.transact(
        actor(1),
        restriction(&legacy, MemberRestriction::Microphone),
        2000,
    )
    .await
    .unwrap();
    let state = repo.read(legacy.id.clone()).await.unwrap();
    let mut stale = legacy.clone();
    stale.owner.authority = CallAuthority::new(format!("omega-key:{}", "b".repeat(64))).unwrap();
    stale.members[0].principal = stale.owner.clone();
    repo.insert_legacy(stale, 500).await.unwrap();
    assert_eq!(repo.read(legacy.id.clone()).await.unwrap(), state);
    assert_eq!(
        repo.media_binding(legacy.id.clone()).await.unwrap(),
        Some(principal(1).authority)
    );
    assert_eq!(repo.created_at(legacy.id).await.unwrap(), 1000);
    let new = call();
    repo.insert(new.clone()).await.unwrap();
    repo.insert_legacy(new.clone(), 1000).await.unwrap();
    assert_eq!(repo.media_binding(new.id).await.unwrap(), None);
}

#[tokio::test]
async fn guest_capabilities_store_hashes_and_recheck_expiry_revocation_and_max_uses() {
    let repo = memory();
    let mut call = call();
    call.policy.join_policy = JoinPolicy::Guests;
    repo.insert(call.clone()).await.unwrap();
    let now = SystemCallClock.now_ms().unwrap();
    let expiry = now + 30_000;
    let token = repo
        .create_guest_capability(call.id.clone(), actor(1), expiry, 1)
        .await
        .unwrap();
    {
        let db = repo.db.lock().unwrap();
        let hash: Vec<u8> = db
            .query_row(
                "SELECT token_hash FROM managed_call_guest_capabilities",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(hash, mtp::crypto::sha256(token.as_bytes()).to_vec());
        assert_ne!(hash, token.as_bytes());
    }
    let forged = format!(
        "{}.{}.{}",
        token.split('.').next().unwrap(),
        Uuid::new_v4(),
        Uuid::new_v4()
    );
    assert!(
        repo.verify_guest_capability(call.id.clone(), principal(5), forged, now)
            .await
            .is_err()
    );
    let guest5 = repo
        .verify_guest_capability(call.id.clone(), principal(5), token.clone(), now)
        .await
        .unwrap();
    let guest6 = repo
        .verify_guest_capability(call.id.clone(), principal(6), token.clone(), now)
        .await
        .unwrap();
    let before = counts(&repo);
    assert_eq!(
        repo.transact(
            guest5.clone(),
            request(&call, CallCommand::AcceptGuestAdmission),
            expiry
        )
        .await,
        Err(CallError::NotAuthorized)
    );
    assert_eq!(counts(&repo), before);
    let accept5 = request(&call, CallCommand::AcceptGuestAdmission);
    let (a, b) = tokio::join!(
        repo.transact(guest5.clone(), accept5.clone(), now),
        repo.transact(
            guest6,
            request(&call, CallCommand::AcceptGuestAdmission),
            now
        )
    );
    assert_eq!(usize::from(a.is_ok()) + usize::from(b.is_ok()), 1);
    assert!(matches!(
        (&a, &b),
        (Ok(_), Err(CallError::NotAuthorized)) | (Err(CallError::NotAuthorized), Ok(_))
    ));
    if let Ok(result) = a {
        assert_eq!(
            repo.transact(guest5, accept5, expiry).await.unwrap(),
            result
        );
    }
    let token = repo
        .create_guest_capability(call.id.clone(), actor(1), expiry, 1)
        .await
        .unwrap();
    let verified = repo
        .verify_guest_capability(call.id.clone(), principal(7), token, now)
        .await
        .unwrap();
    repo.revoke_guest_capabilities(call.id.clone(), actor(1))
        .await
        .unwrap();
    let before = counts(&repo);
    assert_eq!(
        repo.transact(
            verified,
            request(&call, CallCommand::AcceptGuestAdmission),
            now
        )
        .await,
        Err(CallError::NotAuthorized)
    );
    assert_eq!(counts(&repo), before);
}

#[tokio::test]
async fn rejected_guest_transition_rolls_back_capability_consumption() {
    let repo = memory();
    let mut call = call();
    call.policy.join_policy = JoinPolicy::Guests;
    repo.insert(call.clone()).await.unwrap();
    let now = SystemCallClock.now_ms().unwrap();
    let token = repo
        .create_guest_capability(call.id.clone(), actor(1), now + 30_000, 1)
        .await
        .unwrap();
    let guest = repo
        .verify_guest_capability(call.id.clone(), principal(5), token, now)
        .await
        .unwrap();
    repo.transact(
        actor(1),
        request(
            &call,
            CallCommand::SetPolicy {
                change: CallPolicyChange::Locked(true),
            },
        ),
        now,
    )
    .await
    .unwrap();
    let before = counts(&repo);
    assert_eq!(
        repo.transact(
            guest.clone(),
            request(&call, CallCommand::AcceptGuestAdmission),
            now
        )
        .await,
        Err(CallError::CallLocked)
    );
    assert_eq!(counts(&repo), before);
    repo.transact(
        actor(1),
        request(
            &call,
            CallCommand::SetPolicy {
                change: CallPolicyChange::Locked(false),
            },
        ),
        now,
    )
    .await
    .unwrap();
    repo.transact(
        guest,
        request(&call, CallCommand::AcceptGuestAdmission),
        now,
    )
    .await
    .unwrap();
    assert!(
        repo.read(call.id)
            .await
            .unwrap()
            .member(&principal(5))
            .unwrap()
            .guest
    );
}

fn envelope(call: &Call, recipient: u64, epoch: u64, now: i64) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "operation_id": Uuid::new_v4(), "call_id": call.id, "recipient": principal(recipient),
        "epoch": epoch, "created_at_ms": now, "expires_at_ms": now + 30_000,
        "secret_id": "shared-secret", "wrapping_scheme": "mtp-call-secret-kem-chacha20poly1305-hkdf-sha256-v1",
        "encrypted_secret": [1,2,3], "kem_ciphertext": [4,5,6]
    })).unwrap()
}

#[tokio::test]
async fn epoch_staging_rejects_reused_operations_and_changed_ciphertext() {
    let repo = memory();
    let call = call();
    repo.insert(call.clone()).await.unwrap();
    let payload = envelope(&call, 1, 1, SystemCallClock.now_ms().unwrap());
    repo.stage_epoch_envelope(call.id.clone(), actor(1), payload.clone())
        .await
        .unwrap();
    repo.stage_epoch_envelope(call.id.clone(), actor(1), payload.clone())
        .await
        .unwrap();
    let mut changed: serde_json::Value = serde_json::from_slice(&payload).unwrap();
    changed["encrypted_secret"] = serde_json::json!([9]);
    assert_eq!(
        repo.stage_epoch_envelope(
            call.id.clone(),
            actor(1),
            serde_json::to_vec(&changed).unwrap()
        )
        .await,
        Err(CallError::OperationConflict)
    );
    changed["operation_id"] = serde_json::json!(Uuid::new_v4());
    assert_eq!(
        repo.stage_epoch_envelope(
            call.id.clone(),
            actor(1),
            serde_json::to_vec(&changed).unwrap()
        )
        .await,
        Err(CallError::EnvelopeConflict)
    );
    let pending = repo.pending_epoch_envelopes().await.unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].payload, payload);
    assert_eq!(repo.read(call.id.clone()).await.unwrap(), call);
    assert_eq!(counts(&repo), vec![0; 5]);
}

#[tokio::test]
async fn epoch_commit_requires_all_delivery_receipts_and_separate_member_installation_acks() {
    let repo = memory();
    let mut call = call();
    call.rotation_required = true;
    call.rotation_generation = 1;
    repo.insert(call.clone()).await.unwrap();
    let now = SystemCallClock.now_ms().unwrap();
    for user in 1..=4 {
        repo.stage_epoch_envelope(call.id.clone(), actor(1), envelope(&call, user, 1, now))
            .await
            .unwrap();
    }
    assert_eq!(
        repo.commit_epoch(call.id.clone(), actor(1), 1, 0).await,
        Err(CallError::KeyEpochPending)
    );
    assert_eq!(
        repo.commit_epoch(call.id.clone(), actor(3), 1, 1).await,
        Err(CallError::NotAuthorized)
    );
    assert_eq!(
        repo.epoch_envelope_activated(call.id.clone(), principal(1), 1, 1)
            .await,
        Err(CallError::KeyEpochPending)
    );
    for user in 1..=4 {
        repo.epoch_envelope_staged(call.id.clone(), principal(user), 1, 1)
            .await
            .unwrap();
        if user < 4 {
            repo.epoch_envelope_activated(call.id.clone(), principal(user), 1, 1)
                .await
                .unwrap();
        }
    }
    let before = counts(&repo);
    assert_eq!(
        repo.commit_epoch(call.id.clone(), actor(1), 1, 1).await,
        Err(CallError::KeyEpochPending)
    );
    assert_eq!(counts(&repo), before);
    repo.epoch_envelope_activated(call.id.clone(), principal(4), 1, 1)
        .await
        .unwrap();
    repo.commit_epoch(call.id.clone(), actor(1), 1, 1)
        .await
        .unwrap();
    let available = repo.read(call.id.clone()).await.unwrap();
    assert_eq!(
        (available.key_epoch, available.key_available_generation),
        (1, 1)
    );
    assert!(available.rotation_required);
    assert!(available.key_installations.is_empty());
    let before = counts(&repo);
    repo.commit_epoch(call.id.clone(), actor(1), 1, 1)
        .await
        .unwrap();
    assert_eq!(counts(&repo), before);
    for user in 1..=4 {
        repo.transact(
            actor(user),
            request(
                &call,
                CallCommand::AcknowledgeKeyEpoch {
                    epoch: 1,
                    generation: 1,
                },
            ),
            now,
        )
        .await
        .unwrap();
        let state = repo.read(call.id.clone()).await.unwrap();
        assert_eq!(state.rotation_required, user < 4);
        assert_eq!(state.key_installations.len(), user as usize);
    }
}

#[tokio::test]
async fn epoch_proposer_recipient_set_and_removal_generation_are_fenced() {
    let repo = memory();
    let mut call = call();
    call.rotation_required = true;
    call.rotation_generation = 1;
    repo.insert(call.clone()).await.unwrap();
    let now = SystemCallClock.now_ms().unwrap();
    repo.stage_epoch_envelope(call.id.clone(), actor(2), envelope(&call, 1, 1, now))
        .await
        .unwrap();
    assert_eq!(
        repo.stage_epoch_envelope(call.id.clone(), actor(3), envelope(&call, 2, 1, now))
            .await,
        Err(CallError::KeyEpochPending)
    );
    repo.transact(
        actor(1),
        request(
            &call,
            CallCommand::Invite {
                target: principal(5),
            },
        ),
        now,
    )
    .await
    .unwrap();
    assert_eq!(
        repo.stage_epoch_envelope(call.id.clone(), actor(2), envelope(&call, 2, 1, now))
            .await,
        Err(CallError::KeyEpochPending)
    );
    assert_eq!(
        repo.commit_epoch(call.id.clone(), actor(2), 1, 1).await,
        Err(CallError::KeyEpochPending)
    );
    repo.transact(
        actor(1),
        request(
            &call,
            CallCommand::Kick {
                target: principal(4),
                reason: None,
            },
        ),
        now,
    )
    .await
    .unwrap();
    let state = repo.read(call.id.clone()).await.unwrap();
    assert!(state.rotation_generation > 1);
    assert_eq!(
        repo.epoch_envelope_staged(call.id.clone(), principal(1), 1, 1)
            .await,
        Err(CallError::KeyEpochPending)
    );
    assert_eq!(
        repo.commit_epoch(call.id.clone(), actor(2), 1, 1).await,
        Err(CallError::KeyEpochPending)
    );
    assert!(repo.pending_epoch_envelopes().await.unwrap().is_empty());
    assert_eq!(repo.read(call.id).await.unwrap().key_epoch, 0);
}

#[tokio::test]
async fn presence_grace_preserves_live_invites_and_ignores_out_of_order_observations() {
    let repo = memory();
    let call = call();
    let now = SystemCallClock.now_ms().unwrap();
    repo.insert_legacy(call.clone(), now).await.unwrap();
    repo.transact(
        actor(1),
        request(
            &call,
            CallCommand::Invite {
                target: principal(5),
            },
        ),
        now,
    )
    .await
    .unwrap();
    repo.observe_presence(call.id.clone(), false, now, 120_000)
        .await
        .unwrap();
    repo.observe_presence(call.id.clone(), false, now + 30_000, 120_000)
        .await
        .unwrap();
    let state = repo.read(call.id.clone()).await.unwrap();
    assert_eq!(state.lifecycle, CallLifecycle::Active);
    assert_eq!(state.invitations.len(), 1);
    repo.observe_presence(call.id.clone(), true, now + 40_000, 120_000)
        .await
        .unwrap();
    repo.observe_presence(call.id.clone(), false, now + 35_000, 120_000)
        .await
        .unwrap();
    repo.observe_presence(call.id.clone(), false, now + 60_000, 120_000)
        .await
        .unwrap();
    assert_eq!(
        repo.read(call.id.clone()).await.unwrap().lifecycle,
        CallLifecycle::Active
    );
    repo.observe_presence(call.id.clone(), false, now + 90_000, 120_000)
        .await
        .unwrap();
    assert_eq!(
        repo.read(call.id).await.unwrap().lifecycle,
        CallLifecycle::Ending
    );
}

#[tokio::test]
async fn expired_epoch_ciphertext_cannot_be_receipted_committed_or_read() {
    let repo = memory();
    let call = call();
    repo.insert(call.clone()).await.unwrap();
    let now = SystemCallClock.now_ms().unwrap();
    for user in 1..=4 {
        repo.stage_epoch_envelope(call.id.clone(), actor(1), envelope(&call, user, 1, now))
            .await
            .unwrap();
        repo.epoch_envelope_staged(call.id.clone(), principal(user), 1, 0)
            .await
            .unwrap();
        repo.epoch_envelope_activated(call.id.clone(), principal(user), 1, 0)
            .await
            .unwrap();
    }
    // Age persisted retention metadata without a wall-clock sleep.
    repo.db.lock().unwrap().execute("UPDATE managed_call_key_envelopes SET payload=json_set(CAST(payload AS TEXT),'$.expires_at_ms',?1)",[now-1]).unwrap();
    assert_eq!(
        repo.epoch_envelope_staged(call.id.clone(), principal(1), 1, 0)
            .await,
        Err(CallError::KeyEpochPending)
    );
    assert_eq!(
        repo.epoch_envelope_activated(call.id.clone(), principal(1), 1, 0)
            .await,
        Err(CallError::KeyEpochPending)
    );
    assert_eq!(
        repo.commit_epoch(call.id.clone(), actor(1), 1, 0).await,
        Err(CallError::KeyEpochPending)
    );
    assert_eq!(repo.read(call.id).await.unwrap().key_epoch, 0);
}

#[tokio::test]
async fn unavailable_epoch_recipients_do_not_starve_later_pages() {
    let mut repo = memory();
    repo.max_commands_per_minute = 1024;
    let mut call = call();
    call.policy.max_members = 140;
    for user in 5..=130 {
        call.members.push(CallMember {
            principal: principal(user),
            role: CallRole::Member,
            authorized: true,
            approved: true,
            guest: false,
            restrictions: Restrictions::default(),
            overrides: PermissionOverrides::default(),
            timeout_until_ms: None,
        });
    }
    repo.insert(call.clone()).await.unwrap();
    let now = SystemCallClock.now_ms().unwrap();
    for user in 1..=130 {
        repo.stage_epoch_envelope(call.id.clone(), actor(1), envelope(&call, user, 1, now))
            .await
            .unwrap();
    }
    let mut seen = std::collections::BTreeSet::new();
    for _ in 0..33 {
        let batch = repo.pending_epoch_envelopes().await.unwrap();
        assert!(batch.len() <= 4);
        for item in batch {
            assert!(seen.insert(item.recipient));
        }
    }
    assert_eq!(seen.len(), 130);
    assert!(repo.pending_epoch_envelopes().await.unwrap().is_empty());
}

#[tokio::test]
async fn credentials_are_revision_fenced_and_their_admission_window_is_durable() {
    let repo = memory();
    let call = call();
    repo.insert(call.clone()).await.unwrap();
    assert_eq!(
        repo.record_join_credential(call.id.clone(), principal(4), 1, 3000, 1000)
            .await,
        Err(CallError::Conflict {
            current_revision: 0
        })
    );
    repo.record_join_credential(call.id.clone(), principal(4), 0, 3000, 1000)
        .await
        .unwrap();
    repo.transact(
        actor(1),
        request(
            &call,
            CallCommand::Kick {
                target: principal(4),
                reason: None,
            },
        ),
        1001,
    )
    .await
    .unwrap();
    let claims = repo.claim_effects(1001, 1024).await.unwrap();
    assert!(claims.iter().any(|claim|matches!(&claim.effect,CallEffect::EnsureRevoked { principal:target,credentials_valid_until_ms:3000 } if target==&principal(4))));
    assert_eq!(
        repo.record_join_credential(call.id.clone(), principal(4), 1, 4000, 1002)
            .await,
        Err(CallError::NotAuthorized)
    );
}

#[tokio::test]
async fn delayed_envelope_revocation_is_bounded_before_reinvitation() {
    let repo = memory();
    let call = call();
    repo.insert(call.clone()).await.unwrap();
    let now = SystemCallClock.now_ms().unwrap();
    repo.stage_epoch_envelope(call.id.clone(), actor(1), envelope(&call, 4, 1, now))
        .await
        .unwrap();
    repo.transact(
        actor(1),
        request(
            &call,
            CallCommand::Kick {
                target: principal(4),
                reason: None,
            },
        ),
        now,
    )
    .await
    .unwrap();
    repo.transact(
        actor(1),
        request(
            &call,
            CallCommand::Invite {
                target: principal(4),
            },
        ),
        now,
    )
    .await
    .unwrap();
    repo.stage_epoch_envelope(call.id.clone(), actor(1), envelope(&call, 4, 2, now))
        .await
        .unwrap();
    let claims = repo.claim_effects(now, 1024).await.unwrap();
    assert!(claims.iter().any(|claim|matches!(&claim.effect,CallEffect::RevokeEnvelopesThrough { principal:target,max_epoch:1 } if target==&principal(4))));
    assert!(
        repo.epoch_numbers(call.id, principal(4))
            .await
            .unwrap()
            .contains(&2)
    );
}

#[tokio::test]
async fn withdrawn_approval_is_not_an_impossible_epoch_installation_requirement() {
    let repo = memory();
    let mut call = call();
    call.policy.join_policy = JoinPolicy::Approved;
    repo.insert(call.clone()).await.unwrap();
    let now = SystemCallClock.now_ms().unwrap();
    repo.transact(
        actor(1),
        request(
            &call,
            CallCommand::SetMemberApproval {
                target: principal(4),
                approved: false,
            },
        ),
        now,
    )
    .await
    .unwrap();
    let generation = repo
        .read(call.id.clone())
        .await
        .unwrap()
        .rotation_generation;
    for user in 1..=3 {
        repo.stage_epoch_envelope(call.id.clone(), actor(1), envelope(&call, user, 1, now))
            .await
            .unwrap();
        repo.epoch_envelope_staged(call.id.clone(), principal(user), 1, generation)
            .await
            .unwrap();
        repo.epoch_envelope_activated(call.id.clone(), principal(user), 1, generation)
            .await
            .unwrap();
    }
    repo.commit_epoch(call.id.clone(), actor(1), 1, generation)
        .await
        .unwrap();
    for user in 1..=3 {
        repo.transact(
            actor(user),
            request(
                &call,
                CallCommand::AcknowledgeKeyEpoch {
                    epoch: 1,
                    generation,
                },
            ),
            now,
        )
        .await
        .unwrap();
    }
    assert!(!repo.read(call.id).await.unwrap().rotation_required);
}

#[tokio::test]
async fn rate_limits_preserve_deduplication_and_rollback() {
    let mut repo = memory();
    repo.max_commands_per_minute = 1;
    let call = call();
    repo.insert(call.clone()).await.unwrap();
    let command = restriction(&call, MemberRestriction::Microphone);
    let first = repo
        .transact(actor(1), command.clone(), 1000)
        .await
        .unwrap();
    assert_eq!(repo.transact(actor(1), command, 1001).await.unwrap(), first);
    let before = counts(&repo);
    assert_eq!(
        repo.transact(
            actor(1),
            restriction(&call, MemberRestriction::Camera),
            1001
        )
        .await,
        Err(CallError::RateLimited)
    );
    assert_eq!(counts(&repo), before);
    repo.transact(
        actor(1),
        restriction(&call, MemberRestriction::Camera),
        61_000,
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn expired_proposals_release_capacity_without_reusing_epoch_numbers() {
    let repo = memory();
    let call = call();
    repo.insert(call.clone()).await.unwrap();
    let now = SystemCallClock.now_ms().unwrap();
    for epoch in 1..=4 {
        repo.stage_epoch_envelope(call.id.clone(), actor(1), envelope(&call, 1, epoch, now))
            .await
            .unwrap();
    }
    assert_eq!(
        repo.stage_epoch_envelope(call.id.clone(), actor(1), envelope(&call, 1, 5, now))
            .await,
        Err(CallError::RateLimited)
    );
    repo.db.lock().unwrap().execute("UPDATE managed_call_key_envelopes SET payload=json_set(CAST(payload AS TEXT),'$.expires_at_ms',?1)",[now-1]).unwrap();
    repo.stage_epoch_envelope(call.id.clone(), actor(1), envelope(&call, 1, 5, now))
        .await
        .unwrap();
    assert_eq!(repo.next_key_epoch(call.id.clone()).await.unwrap(), 6);
    assert_eq!(
        repo.epoch_envelope_staged(call.id, principal(1), 1, 0)
            .await,
        Err(CallError::KeyEpochPending)
    );
}

#[tokio::test]
async fn ending_finalizes_only_after_required_cleanup_is_confirmed() {
    let repo = memory();
    let call = call();
    repo.insert(call.clone()).await.unwrap();
    repo.transact(actor(1), request(&call, CallCommand::End), 1000)
        .await
        .unwrap();
    for claim in repo.claim_effects(1000, 1024).await.unwrap() {
        let outcome = if matches!(claim.effect, CallEffect::EnsureEnded { .. }) {
            Err(CallError::MediaEnforcementPending)
        } else {
            Ok(())
        };
        repo.finish_effect(claim, outcome, 1001).await.unwrap();
    }
    assert_eq!(
        repo.read(call.id.clone()).await.unwrap().lifecycle,
        CallLifecycle::Ending
    );
    let deletion = repo
        .claim_effects(3001, 1024)
        .await
        .unwrap()
        .into_iter()
        .find(|c| matches!(c.effect, CallEffect::EnsureEnded { .. }))
        .unwrap();
    repo.finish_effect(deletion, Ok(()), 3002).await.unwrap();
    let ended = repo.read(call.id).await.unwrap();
    assert_eq!(ended.lifecycle, CallLifecycle::Ended);
    assert_eq!(ended.revision, 2);
}

#[tokio::test]
async fn concurrent_invitations_share_the_recipients_call_quota_and_decline_releases_it() {
    let file = Database::new();
    let mut left = file.open();
    let mut right = file.open();
    left.max_calls_per_principal = 1;
    right.max_calls_per_principal = 1;
    let first = call();
    let mut second = first.clone();
    second.id.id = Uuid::new_v4();
    left.insert(first.clone()).await.unwrap();
    left.insert(second.clone()).await.unwrap();
    let (a, b) = tokio::join!(
        left.transact(
            actor(1),
            request(
                &first,
                CallCommand::Invite {
                    target: principal(5)
                }
            ),
            1000
        ),
        right.transact(
            actor(1),
            request(
                &second,
                CallCommand::Invite {
                    target: principal(5)
                }
            ),
            1000
        )
    );
    let (invited, other) = match (a, b) {
        (Ok(_), Err(CallError::RateLimited)) => (first, second),
        (Err(CallError::RateLimited), Ok(_)) => (second, first),
        other => panic!("quota race returned {other:?}"),
    };
    assert_eq!(
        left.check_invite_capacity(other.id.clone(), principal(5), 1000)
            .await,
        Err(CallError::RateLimited)
    );
    left.transact(actor(5), request(&invited, CallCommand::Leave), 1001)
        .await
        .unwrap();
    right
        .transact(
            actor(1),
            request(
                &other,
                CallCommand::Invite {
                    target: principal(5),
                },
            ),
            1002,
        )
        .await
        .unwrap();
}

pub(crate) struct ContractAdapters;

impl MediaController for ContractAdapters {
    fn capabilities(&self) -> MediaCapabilities {
        MediaCapabilities {
            source_permissions: true,
            deny_receive_media: true,
            mute_microphone_track: true,
            immediate_credential_revocation: false,
        }
    }

    fn apply(&self, _call: Call, _effect: CallEffect, _now_ms: i64) -> CallFuture<'_, ()> {
        Box::pin(async { Ok(()) })
    }

    fn issue_join_credential(
        &self,
        call: &Call,
        _principal: &CallPrincipal,
        permissions: EffectivePermissions,
        now_ms: i64,
    ) -> Result<JoinGrant, CallError> {
        Ok(JoinGrant {
            call: call.id.clone(),
            revision: call.revision,
            media_endpoint: "fake://media".into(),
            credential: "scoped-test-credential".into(),
            expires_at_ms: now_ms + 30_000,
            permissions,
        })
    }
}

impl CallEventPublisher for ContractAdapters {
    fn publish(&self, _current: Call, _event: CallEvent) -> CallFuture<'_, ()> {
        Box::pin(async { Ok(()) })
    }
}

impl CallEnvelopeDirectory for ContractAdapters {
    fn apply(&self, _current: Call, _effect: CallEffect) -> CallFuture<'_, ()> {
        Box::pin(async { Ok(()) })
    }
}

#[tokio::test]
async fn sqlite_owner_passes_the_shared_management_contract() {
    tau::calls::conformance::call_management_conformance(|| async {
        let repository = Arc::new(memory());
        let call = call();
        repository.insert(call.clone()).await?;
        let adapters = Arc::new(ContractAdapters);
        Ok(tau::calls::conformance::CallManagementFixture {
            management: Arc::new(CallEngine::new(
                repository,
                adapters.clone(),
                adapters.clone(),
                adapters,
                Arc::new(SystemCallClock),
            )),
            call: call.id,
            owner: actor(1),
            moderator: actor(2),
            other_moderator: actor(3),
            member: actor(4),
            outsider: actor(5),
        })
    })
    .await;
}
