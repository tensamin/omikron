use super::*;
use std::collections::{BTreeMap, HashSet};

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct ContactPresence {
    handles: BTreeMap<i64, i64>,
    unavailable: Vec<i64>,
    epoch: Option<Uuid>,
    observations: BTreeMap<i64, (u64, Option<String>)>,
    pending: BTreeMap<i64, (Uuid, u64, String)>,
}

fn invalid() -> InitialPresenceError {
    InitialPresenceError::InvalidSnapshot("invalid canonical presence projection".into())
}

fn positive(value: Option<&DataValue>) -> Result<i64, InitialPresenceError> {
    value
        .and_then(DataValue::as_number)
        .and_then(|id| i64::try_from(id).ok())
        .filter(|id| *id > 0)
        .ok_or_else(invalid)
}

fn sequence(value: Option<&DataValue>) -> Result<u64, InitialPresenceError> {
    positive(value).map(|value| value as u64)
}

fn public_status(value: Option<&DataValue>) -> Result<String, InitialPresenceError> {
    match value.and_then(DataValue::as_str) {
        Some(
            status @ ("user_online" | "user_idle" | "user_dnd" | "user_wc" | "user_offline"
            | "iota_offline" | "user_borked" | "iota_online" | "iota_borked"),
        ) => Ok(status.to_string()),
        _ => Err(invalid()),
    }
}

impl ContactPresence {
    pub(super) fn from_contacts(
        frame: &CommunicationValue,
        authority: &str,
    ) -> Result<Self, InitialPresenceError> {
        tau::relay_protocol::Principal::validate_authority(authority).map_err(|_| invalid())?;
        let Some(DataValue::Array(contacts)) = frame.get_data(DataType::UserIds) else {
            return Err(invalid());
        };
        let map = frame.type_map().ok_or_else(invalid)?;
        let user_id = data_type_id(DataType::UserId, map);
        let principal = data_type_id(DataType::Principal, map);
        let mut handles = BTreeMap::new();
        let mut unavailable = Vec::new();
        let mut aliases = HashSet::new();
        let mut principals = HashSet::new();
        for contact in contacts {
            let alias = positive(contact.get_field(user_id))?;
            let canonical: tau::relay_protocol::Principal = serde_json::from_str(
                contact
                    .get_field(principal)
                    .and_then(DataValue::as_str)
                    .ok_or_else(invalid)?,
            )
            .map_err(|_| invalid())?;
            if !aliases.insert(alias) || !principals.insert(canonical.clone()) {
                return Err(invalid());
            }
            if canonical.authority == authority {
                handles.insert(canonical.user_id as i64, alias);
            } else {
                unavailable.push(alias);
            }
        }
        Ok(Self {
            handles,
            unavailable,
            epoch: None,
            observations: BTreeMap::new(),
            pending: BTreeMap::new(),
        })
    }

    pub(super) fn user_ids(&self) -> Vec<i64> {
        self.handles.keys().copied().collect()
    }

    pub(super) fn suspend(&mut self) -> Vec<DataValue> {
        self.epoch = None;
        self.observations.clear();
        self.pending.clear();
        self.handles
            .values()
            .chain(self.unavailable.iter())
            .map(|alias| DataValue::SignedNumber((*alias).into()))
            .collect()
    }

    pub(super) fn event(
        &mut self,
        frame: &CommunicationValue,
        pending_snapshot: bool,
    ) -> Result<Option<CommunicationValue>, InitialPresenceError> {
        let user = positive(frame.get_data(DataType::UserId))?;
        let Some(alias) = self.handles.get(&user).copied() else {
            return Ok(None);
        };
        let epoch = frame
            .get_data(DataType::Uuid)
            .as_str()
            .and_then(|value| Uuid::parse_str(value).ok())
            .ok_or_else(invalid)?;
        let version = sequence(frame.get_data(DataType::VersionNumber))?;
        let status = public_status(frame.get_data(DataType::UserState))?;
        if self.epoch != Some(epoch) {
            if pending_snapshot
                && self
                    .pending
                    .get(&user)
                    .is_none_or(|(previous, sequence, _)| *previous != epoch || *sequence < version)
            {
                self.pending.insert(user, (epoch, version, status));
            }
            return Ok(None);
        }
        if self
            .observations
            .get(&user)
            .is_some_and(|(previous, _)| *previous >= version)
        {
            return Ok(None);
        }
        self.observations.insert(user, (version, Some(status)));
        Ok(Some(frame.clone().add_typed_default(
            DataType::UserId,
            DataValue::SignedNumber(alias.into()),
        )))
    }

    pub(super) fn snapshot(
        &mut self,
        frame: &CommunicationValue,
    ) -> Result<CommunicationValue, InitialPresenceError> {
        let epoch = frame
            .get_data(DataType::Uuid)
            .as_str()
            .and_then(|value| Uuid::parse_str(value).ok())
            .ok_or_else(invalid)?;
        let boundary = sequence(frame.get_data(DataType::VersionNumber))?;
        let Some(DataValue::Array(states)) = frame.get_data(DataType::UserStates) else {
            return Err(invalid());
        };
        let Some(DataValue::Array(missing)) = frame.get_data(DataType::MissingUserIds) else {
            return Err(invalid());
        };
        let map = frame.type_map().ok_or_else(invalid)?;
        let user_id = data_type_id(DataType::UserId, map);
        let user_state = data_type_id(DataType::UserState, map);
        let version = data_type_id(DataType::VersionNumber, map);
        let mut observations = BTreeMap::new();
        for state in states {
            let user = positive(state.get_field(user_id))?;
            let sequence = sequence(state.get_field(version))?;
            let status = public_status(state.get_field(user_state))?;
            if sequence < boundary
                || !self.handles.contains_key(&user)
                || observations
                    .insert(user, (sequence, Some(status)))
                    .is_some()
            {
                return Err(invalid());
            }
        }
        for user in missing {
            let user = positive(Some(user))?;
            if !self.handles.contains_key(&user)
                || observations.insert(user, (boundary, None)).is_some()
            {
                return Err(invalid());
            }
        }
        if observations.len() != self.handles.len() {
            return Err(invalid());
        }
        if self.epoch != Some(epoch) {
            self.observations.clear();
            self.epoch = Some(epoch);
        }
        for (user, observation) in observations {
            if self
                .observations
                .get(&user)
                .is_none_or(|(previous, _)| *previous < observation.0)
            {
                self.observations.insert(user, observation);
            }
        }
        for (user, (pending_epoch, sequence, status)) in std::mem::take(&mut self.pending) {
            if pending_epoch == epoch
                && self
                    .observations
                    .get(&user)
                    .is_none_or(|(previous, _)| *previous < sequence)
            {
                self.observations.insert(user, (sequence, Some(status)));
            }
        }
        let mut projected = Vec::new();
        let mut missing = self
            .unavailable
            .iter()
            .map(|alias| DataValue::SignedNumber((*alias).into()))
            .collect::<Vec<_>>();
        for (user, (sequence, status)) in &self.observations {
            let alias = self.handles.get(user).ok_or_else(invalid)?;
            if let Some(status) = status {
                projected.push(DataValue::Container(vec![
                    (user_id, DataValue::SignedNumber((*alias).into())),
                    (user_state, DataValue::Str(status.clone())),
                    (version, DataValue::UnsignedNumber((*sequence).into())),
                ]));
            } else {
                missing.push(DataValue::SignedNumber((*alias).into()));
            }
        }
        Ok(frame
            .clone()
            .add_typed_default(DataType::UserStates, DataValue::Array(projected))
            .add_typed_default(DataType::MissingUserIds, DataValue::Array(missing)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn contacts() -> ContactPresence {
        let map = mtp::codec::TypeMap::latest();
        let contacts = [(7, "1"), (42, "2")]
            .into_iter()
            .map(|(alias, authority)| {
                DataValue::Container(vec![
                    (
                        data_type_id(DataType::UserId, &map),
                        DataValue::SignedNumber(alias),
                    ),
                    (
                        data_type_id(DataType::Principal, &map),
                        DataValue::Str(
                            serde_json::to_string(
                                &tau::relay_protocol::Principal::new(
                                    format!("omega-key:{}", authority.repeat(64)),
                                    42,
                                )
                                .unwrap(),
                            )
                            .unwrap(),
                        ),
                    ),
                ])
            })
            .collect();
        let frame = CommunicationValue::new(CommunicationType::GetChats)
            .add_typed_default(DataType::UserIds, DataValue::Array(contacts));
        ContactPresence::from_contacts(&frame, &format!("omega-key:{}", "1".repeat(64))).unwrap()
    }

    fn event(epoch: Uuid, version: u64, user: i64, status: &str) -> CommunicationValue {
        CommunicationValue::new(CommunicationType::ClientChanged)
            .add_typed_default(DataType::Uuid, DataValue::Str(epoch.to_string()))
            .add_typed_default(
                DataType::VersionNumber,
                DataValue::UnsignedNumber(version.into()),
            )
            .add_typed_default(DataType::UserId, DataValue::SignedNumber(user.into()))
            .add_typed_default(DataType::UserState, DataValue::Str(status.into()))
    }

    fn snapshot(epoch: Uuid, boundary: u64, version: u64, status: &str) -> CommunicationValue {
        let map = mtp::codec::TypeMap::latest();
        CommunicationValue::new(CommunicationType::GetStates)
            .add_typed_default(DataType::Uuid, DataValue::Str(epoch.to_string()))
            .add_typed_default(
                DataType::VersionNumber,
                DataValue::UnsignedNumber(boundary.into()),
            )
            .add_typed_default(DataType::MissingUserIds, DataValue::Array(vec![]))
            .add_typed_default(
                DataType::UserStates,
                DataValue::Array(vec![DataValue::Container(vec![
                    (
                        data_type_id(DataType::UserId, &map),
                        DataValue::SignedNumber(42),
                    ),
                    (
                        data_type_id(DataType::UserState, &map),
                        DataValue::Str(status.into()),
                    ),
                    (
                        data_type_id(DataType::VersionNumber, &map),
                        DataValue::UnsignedNumber(version.into()),
                    ),
                ])]),
            )
    }

    #[test]
    fn authority_and_canonical_user_select_the_alias_not_a_numeric_collision() {
        let mut projection = contacts();
        assert_eq!(projection.user_ids(), vec![42]);
        let epoch = Uuid::new_v4();
        let frame = projection
            .snapshot(&snapshot(epoch, 1, 2, "user_online"))
            .unwrap();
        let map = mtp::codec::TypeMap::latest();
        let Some(DataValue::Array(states)) = frame.get_data(DataType::UserStates) else {
            panic!("states")
        };
        assert_eq!(
            states[0].get_field(data_type_id(DataType::UserId, &map)),
            Some(&DataValue::SignedNumber(7))
        );
        assert_eq!(
            frame.get_data(DataType::MissingUserIds),
            Some(&DataValue::Array(vec![DataValue::SignedNumber(42)]))
        );
        assert!(
            projection
                .event(&event(epoch, 3, 7, "user_dnd"), false)
                .unwrap()
                .is_none()
        );
        let update = projection
            .event(&event(epoch, 3, 42, "user_dnd"), false)
            .unwrap()
            .unwrap();
        assert_eq!(
            update.get_data(DataType::UserId),
            Some(&DataValue::SignedNumber(7))
        );
    }

    #[test]
    fn pending_and_delayed_updates_never_roll_a_newer_observation_back() {
        let mut projection = contacts();
        let epoch = Uuid::new_v4();
        assert!(
            projection
                .event(&event(epoch, 4, 42, "user_dnd"), true)
                .unwrap()
                .is_none()
        );
        projection
            .snapshot(&snapshot(epoch, 1, 3, "user_online"))
            .unwrap();
        assert_eq!(projection.observations[&42], (4, Some("user_dnd".into())));
        assert!(
            projection
                .event(&event(epoch, 2, 42, "user_online"), false)
                .unwrap()
                .is_none()
        );
        projection
            .snapshot(&snapshot(epoch, 1, 3, "user_online"))
            .unwrap();
        assert_eq!(projection.observations[&42], (4, Some("user_dnd".into())));
    }

    #[test]
    fn only_a_snapshot_can_install_a_restarted_omega_epoch() {
        let mut projection = contacts();
        let old = Uuid::new_v4();
        let new = Uuid::new_v4();
        projection
            .snapshot(&snapshot(old, 10, 11, "user_online"))
            .unwrap();
        assert!(
            projection
                .event(&event(new, 3, 42, "user_dnd"), true)
                .unwrap()
                .is_none()
        );
        assert_eq!(projection.epoch, Some(old));
        projection
            .snapshot(&snapshot(new, 1, 2, "user_online"))
            .unwrap();
        assert_eq!(projection.observations[&42], (3, Some("user_dnd".into())));
        assert!(
            projection
                .event(&event(old, 99, 42, "user_online"), false)
                .unwrap()
                .is_none()
        );
        assert_eq!(projection.epoch, Some(new));
    }

    #[test]
    fn disconnect_clears_observed_states_and_retains_the_canonical_subscription() {
        let mut projection = contacts();
        let epoch = Uuid::new_v4();
        projection
            .snapshot(&snapshot(epoch, 1, 2, "user_online"))
            .unwrap();
        assert_eq!(
            projection.suspend(),
            vec![DataValue::SignedNumber(7), DataValue::SignedNumber(42)]
        );
        assert_eq!(projection.user_ids(), vec![42]);
        assert!(projection.observations.is_empty());
        assert!(projection.epoch.is_none());
        assert!(
            projection
                .event(&event(epoch, 4, 42, "user_dnd"), true)
                .unwrap()
                .is_none()
        );
        projection
            .snapshot(&snapshot(epoch, 2, 3, "user_online"))
            .unwrap();
        assert_eq!(projection.observations[&42], (4, Some("user_dnd".into())));
    }

    #[test]
    fn incomplete_snapshots_and_numeric_only_contacts_are_rejected() {
        let mut projection = contacts();
        let before = projection.clone();
        let incomplete = snapshot(Uuid::new_v4(), 1, 2, "user_online")
            .add_typed_default(DataType::UserStates, DataValue::Array(vec![]));
        assert!(projection.snapshot(&incomplete).is_err());
        assert_eq!(projection, before);
        assert!(
            projection
                .snapshot(&snapshot(Uuid::new_v4(), 3, 2, "user_online"))
                .is_err()
        );
        assert!(
            projection
                .snapshot(&snapshot(Uuid::new_v4(), 1, 2, "user_invisible"))
                .is_err()
        );
        assert_eq!(projection, before);
        let numeric = CommunicationValue::new(CommunicationType::GetChats).add_typed_default(
            DataType::UserIds,
            DataValue::Array(vec![DataValue::SignedNumber(42)]),
        );
        assert!(
            ContactPresence::from_contacts(&numeric, &format!("omega-key:{}", "1".repeat(64)))
                .is_err()
        );
    }
}
