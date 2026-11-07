use crate::calls::{
    call_group::{CallGroup, CallMember, CallRole, PendingCallInvite},
    call_util::LiveKitService,
    error::CallError,
    repository::SqliteCallRepository,
};
use crate::config::CallLimits;
use dashmap::DashMap;
use std::{
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
use tau::calls::{self as domain, CallManagement, CallRepository};
use uuid::Uuid;

#[derive(Debug, thiserror::Error)]
pub enum CallServiceError {
    #[error("call not found")]
    NotFound,
    #[error("not authorized")]
    NotAuthorized,
    #[error("timed out until {until_ms}")]
    TimedOut { until_ms: i64 },
    #[error("invalid user")]
    InvalidUser,
    #[error("invalid request")]
    InvalidRequest,
    #[error("call {call_id} authority mapping changed; an explicit migration is required")]
    AuthorityMappingChanged { call_id: Uuid },
    #[error("resource limit reached")]
    ResourceLimit,
    #[error("delivery failed")]
    DeliveryFailed,
    #[error(transparent)]
    LiveKit(#[from] CallError),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn changed_authority_cannot_reimport_stale_legacy_permissions() {
        let (manager, id) = manager_with_call().await;
        let repository = manager.repository().unwrap();
        let mut other = repository.read(manager.call_id(id).unwrap()).await.unwrap();
        other.id.id = Uuid::new_v4();
        other.id.owner_authority =
            domain::CallAuthority::new(format!("omikron-key:{}", "f".repeat(64))).unwrap();
        let conflicting = other.id.id;
        repository.insert(other).await.unwrap();
        assert!(
            matches!(manager.restore().await,Err(CallServiceError::AuthorityMappingChanged {call_id}) if call_id==conflicting)
        );
    }

    async fn manager_with_call() -> (CallManager, Uuid) {
        let repository =
            Arc::new(SqliteCallRepository::open(std::path::Path::new(":memory:")).unwrap());
        let authority =
            domain::CallAuthority::new(format!("omega-key:{}", "1".repeat(64))).unwrap();
        let owner_authority =
            domain::CallAuthority::new(format!("omikron-key:{}", "2".repeat(64))).unwrap();
        let livekit = Arc::new(LiveKitService::new(None));
        let runtime = Arc::new(crate::calls::runtime::CallRuntime {
            repository: repository.clone(),
            rho: Arc::new(crate::rho::rho_manager::RhoManager::new()),
            principal_authority: authority.clone(),
        });
        let engine = Arc::new(domain::CallEngine::new(
            repository.clone(),
            livekit.clone(),
            runtime.clone(),
            runtime,
            Arc::new(domain::SystemCallClock),
        ));
        let manager = CallManager::new_with_owner(livekit, 1).with_runtime(
            repository.clone(),
            engine,
            owner_authority,
            authority,
        );
        let id = Uuid::new_v4();
        let mut call = manager
            .initial_call(id, 1, domain::CallLifecycle::Active)
            .unwrap();
        call.members.push(domain::CallMember {
            principal: manager.principal(2).unwrap(),
            role: domain::CallRole::Member,
            authorized: true,
            approved: true,
            guest: false,
            restrictions: domain::Restrictions::default(),
            overrides: domain::PermissionOverrides::default(),
            timeout_until_ms: None,
        });
        repository
            .insert_legacy(call, CallManager::timestamp())
            .await
            .unwrap();
        (manager, id)
    }

    #[tokio::test]
    async fn call_listing_does_not_turn_a_repository_failure_into_an_empty_snapshot() {
        let (mut manager, _) = manager_with_call().await;
        let directory = std::env::temp_dir().join(format!("tensamin-call-list-{}", Uuid::new_v4()));
        std::fs::create_dir(&directory).unwrap();
        let path = directory.join("calls.sqlite");
        manager.repository = Some(Arc::new(SqliteCallRepository::open(&path).unwrap()));
        {
            let connection = rusqlite::Connection::open(&path).unwrap();
            connection.execute("DROP TABLE managed_calls", []).unwrap();
        }
        assert!(manager.get_call_groups(1).await.is_err());
        drop(manager);
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[tokio::test]
    async fn stale_admin_projection_cannot_authorize_a_moderation_write() {
        let (manager, id) = manager_with_call().await;
        let projection = manager.get_call(id).await.unwrap();
        projection
            .state
            .write()
            .await
            .members
            .get_mut(&2)
            .unwrap()
            .role = CallRole::Admin;
        let result = manager
            .timeout_user(id, 2, 1, CallManager::timestamp() + 60_000)
            .await;
        assert!(matches!(result, Err(CallServiceError::NotAuthorized)));
        let call = manager
            .repository()
            .unwrap()
            .read(manager.call_id(id).unwrap())
            .await
            .unwrap();
        assert_eq!(
            call.member(&manager.principal(1).unwrap())
                .unwrap()
                .timeout_until_ms,
            None
        );
    }

    #[tokio::test]
    async fn legacy_kick_revokes_in_sqlite_before_the_media_worker_runs() {
        let (manager, id) = manager_with_call().await;
        manager.disconnect_user(id, 1, 2).await.unwrap();
        let call = manager
            .repository()
            .unwrap()
            .read(manager.call_id(id).unwrap())
            .await
            .unwrap();
        assert!(
            !call
                .member(&manager.principal(2).unwrap())
                .unwrap()
                .authorized
        );
        assert!(
            manager
                .get_call(id)
                .await
                .unwrap()
                .member(2)
                .await
                .is_none()
        );
        assert!(
            manager
                .snapshot(2, manager.call_id(id).unwrap())
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn legacy_owner_leave_does_not_elect_an_arbitrary_successor() {
        let (manager, id) = manager_with_call().await;
        manager.disconnect_user(id, 1, 1).await.unwrap();
        let call = manager
            .repository()
            .unwrap()
            .read(manager.call_id(id).unwrap())
            .await
            .unwrap();
        assert_eq!(call.owner, manager.principal(1).unwrap());
        assert!(!call.member(&call.owner).unwrap().authorized);
        assert_eq!(
            call.member(&manager.principal(2).unwrap()).unwrap().role,
            domain::CallRole::Member
        );
    }
}
impl From<domain::CallError> for CallServiceError {
    fn from(error: domain::CallError) -> Self {
        match error {
            domain::CallError::NotFound | domain::CallError::AlreadyEnded => Self::NotFound,
            domain::CallError::TimedOut { until_ms } => Self::TimedOut { until_ms },
            domain::CallError::NotAuthorized
            | domain::CallError::NotMember
            | domain::CallError::Banned
            | domain::CallError::CallLocked => Self::NotAuthorized,
            domain::CallError::CallFull | domain::CallError::RateLimited => Self::ResourceLimit,
            domain::CallError::InvalidTarget => Self::InvalidUser,
            domain::CallError::StorageUnavailable
            | domain::CallError::MediaEnforcementPending
            | domain::CallError::KeyEpochPending => Self::DeliveryFailed,
            _ => Self::InvalidRequest,
        }
    }
}
#[derive(Clone, Copy, Eq, PartialEq)]
pub enum InviteRelation {
    Member,
    Pending,
    New,
}

/// Legacy wire projections. SQLite and Tau own authorization and mutations.
pub struct CallManager {
    pub(crate) groups: DashMap<Uuid, Arc<CallGroup>>,
    pub livekit: Arc<LiveKitService>,
    pub owner_omikron_id: u64,
    limits: CallLimits,
    pub(crate) repository: Option<Arc<SqliteCallRepository>>,
    pub(crate) engine: Option<Arc<domain::CallEngine>>,
    owner_authority: Option<domain::CallAuthority>,
    principal_authority: Option<domain::CallAuthority>,
}
impl Default for CallManager {
    fn default() -> Self {
        Self::new_with_owner(Arc::new(LiveKitService::new(None)), 0)
    }
}
impl CallManager {
    pub fn new_with_owner(livekit: Arc<LiveKitService>, owner: u64) -> Self {
        Self::new_with_limits(livekit, owner, CallLimits::default())
    }
    pub fn new_with_limits(livekit: Arc<LiveKitService>, owner: u64, limits: CallLimits) -> Self {
        Self {
            groups: DashMap::new(),
            livekit,
            owner_omikron_id: owner,
            limits,
            repository: None,
            engine: None,
            owner_authority: None,
            principal_authority: None,
        }
    }
    pub fn with_runtime(
        mut self,
        repository: Arc<SqliteCallRepository>,
        engine: Arc<domain::CallEngine>,
        owner_authority: domain::CallAuthority,
        principal_authority: domain::CallAuthority,
    ) -> Self {
        self.repository = Some(repository);
        self.engine = Some(engine);
        self.owner_authority = Some(owner_authority);
        self.principal_authority = Some(principal_authority);
        self
    }
    fn repository(&self) -> Result<&Arc<SqliteCallRepository>, CallServiceError> {
        self.repository
            .as_ref()
            .ok_or(CallServiceError::DeliveryFailed)
    }
    pub fn principal(&self, user_id: u64) -> Result<domain::CallPrincipal, domain::CallError> {
        if user_id == 0 {
            return Err(domain::CallError::NotAuthorized);
        }
        Ok(domain::CallPrincipal {
            authority: self
                .principal_authority
                .clone()
                .ok_or(domain::CallError::NotAuthorized)?,
            user_id,
        })
    }
    pub fn actor(&self, user_id: u64) -> Result<domain::AuthenticatedCallActor, domain::CallError> {
        domain::AuthenticatedCallActor::from_verified_session(self.principal(user_id)?)
    }
    pub fn call_id(&self, id: Uuid) -> Result<domain::CallId, domain::CallError> {
        Ok(domain::CallId {
            owner_authority: self
                .owner_authority
                .clone()
                .ok_or(domain::CallError::NotAuthorized)?,
            id,
        })
    }
    /// This host authenticates only its pinned Omega namespace.
    fn check_namespace(
        &self,
        request: &domain::CallCommandRequest,
    ) -> Result<(), domain::CallError> {
        if request.call.owner_authority
            != *self
                .owner_authority
                .as_ref()
                .ok_or(domain::CallError::NotAuthorized)?
        {
            return Err(domain::CallError::NotFound);
        }
        let target = match &request.command {
            domain::CallCommand::Invite { target }
            | domain::CallCommand::RevokeInvite { target }
            | domain::CallCommand::Kick { target, .. }
            | domain::CallCommand::Ban { target, .. }
            | domain::CallCommand::Unban { target }
            | domain::CallCommand::Timeout { target, .. }
            | domain::CallCommand::ClearTimeout { target }
            | domain::CallCommand::MuteMicrophoneNow { target }
            | domain::CallCommand::SetMemberRestriction { target, .. }
            | domain::CallCommand::SetRole { target, .. }
            | domain::CallCommand::SetMemberApproval { target, .. }
            | domain::CallCommand::SetMemberOverride { target, .. }
            | domain::CallCommand::TransferOwnership { target } => Some(target),
            _ => None,
        };
        if target.is_some_and(|target| {
            Some(&target.authority) != self.principal_authority.as_ref()
                && (Some(&target.authority) != self.owner_authority.as_ref()
                    || matches!(request.command, domain::CallCommand::Invite { .. }))
        }) {
            return Err(domain::CallError::NotAuthorized);
        }
        Ok(())
    }
    pub async fn execute(
        &self,
        user: u64,
        request: domain::CallCommandRequest,
    ) -> Result<domain::CallCommandResult, domain::CallError> {
        self.check_namespace(&request)?;
        let id = request.call.id;
        let result = self
            .engine
            .as_ref()
            .ok_or(domain::CallError::StorageUnavailable)?
            .execute(self.actor(user)?, request)
            .await?;
        let _ = self.refresh(id).await;
        Ok(result)
    }
    pub async fn snapshot(
        &self,
        user: u64,
        id: domain::CallId,
    ) -> Result<domain::CallSnapshot, domain::CallError> {
        if id != self.call_id(id.id)? {
            return Err(domain::CallError::NotFound);
        }
        self.engine
            .as_ref()
            .ok_or(domain::CallError::StorageUnavailable)?
            .snapshot(self.actor(user)?, id)
            .await
    }
    pub async fn authorize_join(
        &self,
        user: u64,
        request: domain::JoinRequest,
    ) -> Result<domain::JoinGrant, domain::CallError> {
        if request.call != self.call_id(request.call.id)? {
            return Err(domain::CallError::NotFound);
        }
        self.engine
            .as_ref()
            .ok_or(domain::CallError::StorageUnavailable)?
            .authorize_join(self.actor(user)?, request)
            .await
    }
    async fn legacy_command(
        &self,
        user: u64,
        id: Uuid,
        command: domain::CallCommand,
    ) -> Result<domain::CallCommandResult, CallServiceError> {
        Ok(self
            .execute(
                user,
                domain::CallCommandRequest {
                    call: self.call_id(id)?,
                    operation_id: Uuid::new_v4(),
                    expected_revision: None,
                    command,
                },
            )
            .await?)
    }
    fn policy(&self) -> domain::CallPolicy {
        domain::CallPolicy {
            locked: false,
            allow_locked_rejoin: true,
            join_policy: domain::JoinPolicy::Invited,
            invite: domain::RolePolicy::All,
            speak: domain::RolePolicy::All,
            camera: domain::RolePolicy::All,
            screen_share: domain::RolePolicy::All,
            publish_data: domain::RolePolicy::All,
            new_members_muted: false,
            guest_microphone: false,
            guest_screen_share: false,
            moderators_may_end: true,
            moderators_may_change_policy: true,
            moderators: domain::ModeratorPermissions::default(),
            max_members: self.limits.max_members_per_call,
            max_invites: self.limits.max_pending_invites_per_call,
            invite_ttl_ms: self
                .limits
                .invite_ttl
                .as_millis()
                .try_into()
                .unwrap_or(i64::MAX),
            empty_grace_ms: self
                .limits
                .empty_grace
                .as_millis()
                .try_into()
                .unwrap_or(i64::MAX),
        }
    }
    fn initial_call(
        &self,
        id: Uuid,
        user: u64,
        lifecycle: domain::CallLifecycle,
    ) -> Result<domain::Call, CallServiceError> {
        let owner = self.principal(user)?;
        Ok(domain::Call {
            id: self.call_id(id)?,
            owner: owner.clone(),
            lifecycle,
            revision: 0,
            policy: self.policy(),
            members: vec![domain::CallMember {
                principal: owner,
                role: domain::CallRole::Owner,
                authorized: true,
                approved: true,
                guest: false,
                restrictions: domain::Restrictions::default(),
                overrides: domain::PermissionOverrides::default(),
                timeout_until_ms: None,
            }],
            invitations: Vec::new(),
            bans: Vec::new(),
            key_epoch: 0,
            rotation_required: false,
            rotation_generation: 0,
            key_available_generation: 0,
            key_installations: Vec::new(),
        })
    }
    pub async fn restore(&self) -> Result<(), CallServiceError> {
        let repository = self.repository()?;
        for call in repository.list().await? {
            if call.id != self.call_id(call.id.id)?
                || call.owner.authority != self.principal(call.owner.user_id)?.authority
            {
                return Err(CallServiceError::AuthorityMappingChanged {
                    call_id: call.id.id,
                });
            }
        }
        for call in repository.list().await? {
            if let Some(authority) = repository.media_binding(call.id.clone()).await? {
                self.livekit
                    .register_legacy_call(call.id.clone(), authority);
            }
            if call.lifecycle == domain::CallLifecycle::Provisioning {
                self.livekit.create_room(call.id.id).await?;
                repository
                    .complete_activation(call.id.clone(), call.owner.clone())
                    .await?;
            }
            self.refresh(call.id.id).await?;
        }
        Ok(())
    }
    pub async fn reserve(&self, user: u64) -> Result<Uuid, CallServiceError> {
        let id = Uuid::new_v4();
        let now = Self::now_ms()?;
        self.repository()?
            .reserve(
                self.initial_call(id, user, domain::CallLifecycle::Reserved)?,
                now,
                now.saturating_add(
                    self.limits
                        .reservation_ttl
                        .as_millis()
                        .try_into()
                        .unwrap_or(i64::MAX),
                ),
                self.limits.max_calls_per_user,
                true,
            )
            .await?;
        Ok(id)
    }
    pub async fn reservation_created_at(
        &self,
        user: u64,
        id: Uuid,
    ) -> Result<i64, CallServiceError> {
        Ok(self
            .repository()?
            .reservation_created_at(self.call_id(id)?, self.principal(user)?, Self::now_ms()?)
            .await?)
    }
    pub async fn activate(
        &self,
        user: u64,
        id: Uuid,
        _created_at: i64,
    ) -> Result<String, CallServiceError> {
        let call = self.call_id(id)?;
        let owner = self.principal(user)?;
        self.repository()?
            .begin_activation(call.clone(), owner.clone(), Self::now_ms()?)
            .await?;
        self.livekit
            .register_legacy_call(call.clone(), owner.authority.clone());
        self.livekit.create_room(id).await?;
        self.repository()?.complete_activation(call, owner).await?;
        self.refresh(id).await?;
        self.get_call_token(user, id).await
    }
    async fn refresh(&self, id: Uuid) -> Result<Option<Arc<CallGroup>>, CallServiceError> {
        let now_ms = Self::now_ms()?;
        let call = self.repository()?.read(self.call_id(id)?).await?;
        if call.lifecycle != domain::CallLifecycle::Active {
            self.groups.remove(&id);
            return Ok(None);
        }
        let mut group = CallGroup::new_with_service(
            id,
            self.owner_omikron_id,
            call.owner.user_id,
            self.livekit.clone(),
            self.limits.clone(),
        );
        group.created_at_ms = self.repository()?.created_at(call.id.clone()).await?;
        {
            let mut state = group.state.write().await;
            state.members = call
                .members
                .into_iter()
                .filter(|m| {
                    m.authorized
                        && Some(&m.principal.authority) == self.principal_authority.as_ref()
                })
                .map(|m| {
                    (
                        m.principal.user_id,
                        CallMember {
                            user_id: m.principal.user_id,
                            role: if m.role == domain::CallRole::Member {
                                CallRole::Member
                            } else {
                                CallRole::Admin
                            },
                            timeout_until_ms: m.timeout_until_ms,
                            participating: false,
                        },
                    )
                })
                .collect();
            state.pending_invites = call
                .invitations
                .into_iter()
                .filter(|i| {
                    i.delivery_ready
                        && i.expires_at_ms > now_ms
                        && Some(&i.recipient.authority) == self.principal_authority.as_ref()
                })
                .map(|i| {
                    (
                        i.recipient.user_id,
                        PendingCallInvite {
                            inviter_id: i.inviter.user_id,
                            created_at_ms: i
                                .expires_at_ms
                                .saturating_sub(call.policy.invite_ttl_ms),
                        },
                    )
                })
                .collect();
        }
        let group = Arc::new(group);
        self.groups.insert(id, group.clone());
        Ok(Some(group))
    }
    pub async fn get_call(&self, id: Uuid) -> Option<Arc<CallGroup>> {
        if self.repository.is_some() {
            return self.refresh(id).await.ok().flatten();
        }
        #[cfg(test)]
        return self.groups.get(&id).map(|g| g.clone());
        #[cfg(not(test))]
        None
    }
    pub async fn get_call_groups(
        &self,
        user: u64,
    ) -> Result<Vec<Arc<CallGroup>>, CallServiceError> {
        let ids = if let Some(repository) = &self.repository {
            repository
                .list()
                .await?
                .into_iter()
                .map(|c| c.id.id)
                .collect::<Vec<_>>()
        } else {
            self.groups.iter().map(|g| *g.key()).collect()
        };
        let mut groups = Vec::new();
        for id in ids {
            let group = if self.repository.is_some() {
                self.refresh(id).await?
            } else {
                self.get_call(id).await
            };
            if let Some(group) = group
                && group.is_related(user).await
            {
                groups.push(group);
            }
        }
        Ok(groups)
    }
    pub fn should_forward_invite(&self, from: u64, to: u64) -> bool {
        from != to
    }
    fn now_ms() -> Result<i64, CallServiceError> {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .ok()
            .and_then(|d| i64::try_from(d.as_millis()).ok())
            .ok_or(CallServiceError::InvalidRequest)
    }
    pub fn timestamp() -> i64 {
        Self::now_ms().unwrap_or_default()
    }
    pub async fn get_call_token(&self, user: u64, id: Uuid) -> Result<String, CallServiceError> {
        let snapshot = self.snapshot(user, self.call_id(id)?).await?;
        if snapshot.key_epoch != 0 {
            return Err(CallServiceError::InvalidRequest);
        }
        if snapshot.member.is_none() {
            self.legacy_command(user, id, domain::CallCommand::AcceptInvite)
                .await?;
        }
        Ok(self
            .authorize_join(
                user,
                domain::JoinRequest {
                    call: self.call_id(id)?,
                },
            )
            .await?
            .credential)
    }
    pub async fn add_invite(&self, id: Uuid, from: u64, to: u64) -> Result<(), CallServiceError> {
        self.legacy_command(
            from,
            id,
            domain::CallCommand::Invite {
                target: self.principal(to)?,
            },
        )
        .await?;
        Ok(())
    }
    pub async fn check_invite(
        &self,
        id: Uuid,
        from: u64,
        to: u64,
    ) -> Result<(Arc<CallGroup>, InviteRelation), CallServiceError> {
        let snapshot = self.snapshot(from, self.call_id(id)?).await?;
        if snapshot.key_epoch != 0 {
            return Err(CallServiceError::InvalidRequest);
        }
        if from == to || !snapshot.permissions.invite {
            return Err(CallServiceError::NotAuthorized);
        }
        let call = self.repository()?.read(self.call_id(id)?).await?;
        let target = self.principal(to)?;
        self.repository()?
            .check_invite_capacity(call.id.clone(), target.clone(), Self::now_ms()?)
            .await?;
        let relation = if call.member(&target).is_some_and(|m| m.authorized) {
            InviteRelation::Member
        } else if call
            .invitations
            .iter()
            .any(|i| i.recipient == target && i.expires_at_ms > Self::timestamp())
        {
            InviteRelation::Pending
        } else {
            InviteRelation::New
        };
        Ok((
            self.get_call(id).await.ok_or(CallServiceError::NotFound)?,
            relation,
        ))
    }
    pub async fn call_data(
        &self,
        id: Uuid,
        user: u64,
    ) -> Result<(Vec<u64>, i64), CallServiceError> {
        if self.snapshot(user, self.call_id(id)?).await?.key_epoch != 0 {
            return Err(CallServiceError::InvalidRequest);
        }
        let group = self.get_call(id).await.ok_or(CallServiceError::NotFound)?;
        Ok((group.member_ids().await, group.created_at_ms))
    }
    pub async fn timeout_user(
        &self,
        id: Uuid,
        requester: u64,
        target: u64,
        until_ms: i64,
    ) -> Result<domain::CallCommandResult, CallServiceError> {
        self.legacy_command(
            requester,
            id,
            domain::CallCommand::Timeout {
                target: self.principal(target)?,
                until_ms,
            },
        )
        .await
    }
    pub async fn set_anonymous_joining(
        &self,
        id: Uuid,
        requester: u64,
        enabled: bool,
        _omega: &crate::omega::omega_connection::OmegaConnection,
    ) -> Result<Option<String>, CallServiceError> {
        let call = self.call_id(id)?;
        if !enabled {
            self.repository()?
                .revoke_guest_capabilities(call.clone(), self.actor(requester)?)
                .await?;
        }
        self.legacy_command(
            requester,
            id,
            domain::CallCommand::SetPolicy {
                change: domain::CallPolicyChange::Join(if enabled {
                    domain::JoinPolicy::Guests
                } else {
                    domain::JoinPolicy::Invited
                }),
            },
        )
        .await?;
        if !enabled {
            return Ok(None);
        }
        let expires_at = Self::now_ms()?.saturating_add(
            self.limits
                .invite_ttl
                .as_millis()
                .try_into()
                .unwrap_or(i64::MAX),
        );
        let capability = self
            .repository()?
            .create_guest_capability(
                call,
                self.actor(requester)?,
                expires_at,
                self.limits.max_members_per_call,
            )
            .await?;
        Ok(Some(format!(
            "https://app.tensamin.net/call/anonymous?call_id={id}&omikron_id={}&capability={capability}",
            self.owner_omikron_id
        )))
    }

    pub async fn authorize_guest(
        &self,
        session_user: u64,
        call: domain::CallId,
        capability: String,
        operation_id: Uuid,
    ) -> Result<domain::JoinGrant, domain::CallError> {
        if call != self.call_id(call.id)? {
            return Err(domain::CallError::NotFound);
        }
        let principal = domain::CallPrincipal {
            authority: call.owner_authority.clone(),
            user_id: session_user,
        };
        let repository = self
            .repository
            .as_ref()
            .ok_or(domain::CallError::StorageUnavailable)?;
        let current = repository.read(call.clone()).await?;
        let actor = if current
            .member(&principal)
            .is_some_and(|m| m.authorized && m.guest)
        {
            domain::AuthenticatedCallActor::from_verified_session(principal)?
        } else {
            let actor = repository
                .verify_guest_capability(call.clone(), principal, capability, Self::timestamp())
                .await?;
            let request = domain::CallCommandRequest {
                call: call.clone(),
                operation_id,
                expected_revision: None,
                command: domain::CallCommand::AcceptGuestAdmission,
            };
            self.engine
                .as_ref()
                .ok_or(domain::CallError::StorageUnavailable)?
                .execute(actor.clone(), request)
                .await?;
            actor
        };
        self.engine
            .as_ref()
            .ok_or(domain::CallError::StorageUnavailable)?
            .authorize_join(actor, domain::JoinRequest { call })
            .await
    }
    pub async fn guest_actor(
        &self,
        session_user: u64,
        call: domain::CallId,
    ) -> Result<domain::AuthenticatedCallActor, domain::CallError> {
        if call != self.call_id(call.id)? {
            return Err(domain::CallError::NotFound);
        }
        let principal = domain::CallPrincipal {
            authority: call.owner_authority.clone(),
            user_id: session_user,
        };
        let current = self
            .repository
            .as_ref()
            .ok_or(domain::CallError::StorageUnavailable)?
            .read(call)
            .await?;
        if !current.member(&principal).is_some_and(|m| m.guest) {
            return Err(domain::CallError::NotAuthorized);
        }
        domain::AuthenticatedCallActor::from_verified_session(principal)
    }
    pub async fn disconnect_user(
        &self,
        id: Uuid,
        requester: u64,
        target: u64,
    ) -> Result<domain::CallCommandResult, CallServiceError> {
        let command = if requester == target {
            domain::CallCommand::Leave
        } else {
            domain::CallCommand::Kick {
                target: self.principal(target)?,
                reason: None,
            }
        };
        self.legacy_command(requester, id, command).await
    }
    pub async fn reconcile_participants(
        &self,
        id: Uuid,
        participants: &[u64],
    ) -> Result<(), CallServiceError> {
        if let Some(group) = self.get_call(id).await {
            for member in group.state.write().await.members.values_mut() {
                member.participating = participants.contains(&member.user_id);
            }
        }
        Ok(())
    }
    pub async fn end_call(
        &self,
        id: Uuid,
        requester: u64,
    ) -> Result<domain::CallCommandResult, CallServiceError> {
        self.legacy_command(requester, id, domain::CallCommand::End)
            .await
    }
    pub async fn cleanup_observed(
        &self,
        id: Uuid,
        occupied: bool,
        now_ms: i64,
    ) -> Result<(), CallServiceError> {
        self.repository()?
            .observe_presence(
                self.call_id(id)?,
                occupied,
                now_ms,
                self.limits
                    .max_call_age
                    .as_millis()
                    .try_into()
                    .unwrap_or(i64::MAX),
            )
            .await?;
        self.refresh(id).await?;
        Ok(())
    }
}
