# Call management backend

Omikron is the authoritative writer for hosted calls. Tau owns the policy and
state machine; SQLite stores the aggregate and transactional operation, audit,
event, and outbox records. LiveKit and Iota requests run after commit. Legacy
`CallGroup` values are read projections, not permission authorities.

## Identity and storage

Account principals use `omega-key:<SHA-256 of serialized Omega public-key bundle>`.
Startup reads the authenticated transport's pinned `./omega.mpkb`. The hosting
call authority uses the equivalent `omikron-key:` fingerprint of Omikron's enrolled
public-key bundle. Numeric Omikron IDs remain legacy routing and metadata fields.
Changing either pinned authority while retaining a managed call database stops
startup. Stored calls are never remapped to a different authority.

Use a fresh database at `CALL_DB_PATH` for initial deployment, then retain and
reuse that file across restarts to restore calls and pending effects. Startup
creates the current schema and format marker atomically. Unsupported existing
files fail before schema or journal writes. There are no numbered migrations or
imports from older call tables.
An owner leaving does not choose a successor.
Guest admission capabilities do not grant administrative sessions, so guest
identities cannot receive owner or moderator roles.

Legacy rooms keep their UUID room name and explicitly registered Omega numeric
participant identities. Guest principals use the hosting authority and opaque
media identities, so an anonymous numeric ID cannot impersonate an account.

## Protocol and keys

The single version 1.0 type map includes the call-management allocations. The call
operations carry bounded, typed JSON bytes in `CallPayload`. Actors come from
authenticated sessions, never payload user IDs. New call events are sent to
sessions that opted into the managed-call operations. Legacy call operations
continue through adapters to Tau.
Legacy kick, timeout, leave, and end replies acknowledge policy commit with
`Success`, carry the committed revision in `VersionNumber`, and state
`pending_enforcement` or `applied` in `Description`. They do not assert that
revocation is complete merely because policy committed.

See `../mtp-type-maps/call-management.md` for operation IDs and payloads, and
`../iota/call-key-envelopes.md` for the Iota directory protocol.

The owner stages immutable recipient ciphertext, records Iota delivery receipts,
and commits an epoch only when its current recipient set is ready. Staging,
availability, and client installation are different states. Installation ACKs use
`AcknowledgeKeyEpoch`. Snapshots expose `next_key_epoch` so superseded or expired
proposals do not require guessing an unused epoch number.

Any admitted account participant can propose an epoch. The owner transaction
binds the first proposer for that epoch and its complete current recipient set.
Snapshots expose that set to eligible account participants without exposing
moderation reasons or other users' ciphertext. Key maintenance does not require
the owner's device to remain online. Installation ACKs are recipient assertions;
the later client integration must install keys on each active media connection
before cryptographic removal can be claimed.

Removal, bans, approval withdrawal, and invitation revocation advance the key
generation. Old revocation effects retain their epoch boundary and cannot erase
material issued for a subsequent admission. State sync and explicit key reads
recheck active admission and the current epoch before and after remote reads.

Media keys remain client-generated. The backend never creates a replacement
plaintext key. Legacy clients cannot complete a required rekey; new invitation
delivery then remains pending until upgraded clients provide a new epoch. A
previously delivered key cannot be revoked retroactively.

## Enforcement

Client JWTs have no room-admin or metadata-update grant. New scoped credentials
last 60 seconds, and the owner persists their admission window before returning
them. Effective publication sources and subscription/data rights come from Tau.
One-time mute effects bind the original participant SID and microphone track SIDs
before mutation, including across lost responses and worker restarts.

The current adapter does not claim immediate credential revocation on self-hosted
LiveKit. Old join or server-refreshed credentials can evade a later permission
change. Revocation, room termination, and restrictive permission reconciliation
therefore remain `PendingEnforcement` and continue inspection/retries. Short JWT
lifetimes do not solve that problem. Strict rollout needs a separately verified
admission gate or another provider adapter with proven revocation behavior.

Soundboard-specific restriction is unsupported because its traffic has no
independently enforceable source in this adapter. Server deafen blocks all incoming
media and microphone publication. Undeafen recomputes the complete policy and does
not clear an independent microphone restriction.

## Guest links

Enabling anonymous joining creates an opaque, call-scoped capability with expiry
and a usage limit. Regeneration revokes the underlying previous capability.
Disabling joining revokes capabilities at Omikron. A URL or Omega redirect alone
does not authorize admission. Old anonymous links without proof are rejected.

Guest join requests bind the capability to the actual anonymous connection's
principal. Existing admitted sessions may reconnect under their session binding;
new sessions need a valid capability. A guest ban applies to that principal, not
an IP address, and cannot prevent a person acquiring a different anonymous identity.
Guest ciphertext is stored at the owner and obeys the same epoch/read checks.

## Configuration and operations

| Setting | Default |
| --- | --- |
| `CALL_DB_PATH` | `calls.sqlite3` |
| `CALL_MAX_MEMBERS` | 64 |
| `CALL_MAX_PENDING_INVITES` | 64 |
| `CALL_MAX_CALLS_PER_USER` | 16 |
| `CALL_INVITE_TTL_SECONDS` | 259200 |
| `CALL_RESERVATION_TTL_SECONDS` | 30 |
| `CALL_EMPTY_GRACE_SECONDS` | 300 |
| `CALL_MAX_AGE_SECONDS` | 259200 |
| `CALL_COMMANDS_PER_MINUTE` | 120 per canonical actor and hosting authority |
| `CALL_MAX_PENDING_KEY_EPOCHS` | 4 per current recipient set and generation |
| `LIVEKIT_WEBHOOK_BIND` | Disabled unless set to a socket address |

Unexpired invitations preserve an empty call through the grace period. Maximum
call age still applies. Tombstones and journals remain for replay protection and
recovery; do not delete them while effects are pending.

When enabled, `POST /livekit/webhook` verifies LiveKit's JWT and complete raw-body
hash. It bounds connections, headers, body size, and request time. Durable replay
checks enqueue inspection hints only. The endpoint never changes roles or restores
membership. Put this listener behind the deployment's HTTPS reverse proxy.

Outbox claims have generation-fenced leases. External work has timeouts and retries;
one unavailable Iota does not monopolize later epoch-delivery pages. Every minute,
the `call.outbox_health` event reports pending effects, expired leases, retries,
maximum attempts, and pending key envelopes. Retrying effects or expired leases
raise the event to warning level. Payloads, credentials, and guest capability URLs
are not logged.

## Local validation and publication

The components are separate repositories. Tau is pinned to an exact Git revision
in Cargo; the Nix flake and submodule pin the published type-map revision. Validate
the release package from the Omikron checkout:

```sh
nix build --no-link
```

To check local Omikron or type-map changes, including untracked source files, use
the package helper from the workspace:

```sh
bash omikron/build-local.sh --no-link -L
```

For Cargo, set the updated map inside the devshell command:

```sh
nix develop --command env MTP_TYPE_MAPS=/absolute/path/to/mtp-type-maps/type-maps.yaml cargo test --all-features --locked
```

The helper snapshots Omikron and the canonical type maps, and excludes build
outputs and runtime data. Tau still resolves from its published Cargo pin. The
helper does not publish repositories or rewrite release pins.
The in-memory and SQLite conformance tests use fake external services. They do not
verify a deployed LiveKit server's admission or cryptographic removal guarantees.

Rho uses persistent ordered streams. The pinned MTP handshake sends version
selection and final acceptance consecutively; separate receive-stream tasks can
reverse those responses and lose the assigned-client-ID handshake stage.
