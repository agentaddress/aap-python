# Changelog

## v0.10.0 — 2026-06-25 — trust-root issuer domain

### Changed

- **Trust-root issuer is now `aap-trust-root^agentaddress.org`** (previously
  `…^agentaddressprotocol.org`, which is not a real domain).
  `TRUSTED_VERIFIERS_ISSUER` changed: the relay that signs the
  trusted-verifiers list and the SDK clients that verify it must run this
  version together. The Ed25519 signing key / pinned public key is unchanged —
  only the identifier string. A client rejects a list signed under the old
  issuer until both sides upgrade and the 24h trust-list cache expires.

## v0.9.1 — 2026-06-25 — PyPI publish + encrypted envelopes

### Packaging

- Published to PyPI as `agentaddress` (the `aap-python` name was already taken).
  Install with `pip install agentaddress`; the import package remains `aap`.

### Added

- **End-to-end encrypted AAP envelopes.** `aap.encryption` implements RFC 9180
  HPKE base mode with X25519, HKDF-SHA256, and ChaCha20-Poly1305. Existing
  Ed25519-signed `aap.envelope/v1` JSON is encrypted inside
  `aap.encrypted-envelope/v1`, keeping payloads opaque to relays.
- **Separate X25519 identity keys.** `IdentityFile` persists an encryption
  keypair alongside the Ed25519 signing keypair and migrates existing identity
  files on load. AgentCards advertise the public key as `encryption_key`.
- `AAPClient.send_envelope()` and `send_envelope_raw()` encrypt by default.
  `AAPClient.decrypt_inbound()` decrypts relay-delivered encrypted envelopes.
- Encrypted outbound sends now sign the outer `aap.routing-envelope/v1`
  wrapper with the sender key, binding `from`, `to`, `iat`, `nonce`, and the
  encrypted inner envelope so relays can authenticate and meter the sender
  without decrypting message contents.
- **Authenticated AgentCard resolution.** `AAPClient` requires the AgentCard
  envelope issuer to equal the requested AAP address, verifies the envelope
  signature with the card's `public_key`, and binds the card's `did:web` domain
  to the requested address domain.
- **TOFU key-change detection.** AgentCard signing keys are pinned by address in
  memory or in an optional mode-0600 JSON file. Unexpected rotation raises
  `AgentCardKeyChanged` until the caller explicitly clears the pin after
  independently verifying the change.
- **Envelope freshness/replay policy helpers.** `aap.envelope_policy` adds
  timestamp freshness validation, optional TTL replay caching, and a combined
  signature/freshness verifier for high-risk inbound flows.
- **Strict inbound receive policy.** `aap.inbound.validate_inbound_envelope()`
  centralizes decrypt-before-verify handling, signature verification,
  freshness checks, and optional replay detection before host dispatch.
  `validate_inbound_chat()` adds chat payload parsing plus active relationship
  authorization.
- **Service request/response ledger.** `ServiceResponse` now carries its own
  nonce, and `ServiceRequestStore` persists signed outbound requests plus
  verified response proofs for durable request correlation and replay defense.
- **Signed discovery query responses.** Verifiers now answer discovery queries
  with `aap.discovery-query-response/v1` envelopes bound to the original query
  nonce.
- **Signed trusted-verifier lists.** Trust-list responses are now
  `aap.trusted-verifiers/v1` envelopes signed by the configured trust root, and
  verifier entries carry the verifier Ed25519 public key.
- **Signed verifier OTP responses.** Verification start and confirm endpoints
  now return nonce-bound signed envelopes, and confirm responses wrap a verified
  attestation envelope.
- **Private SDK state writes.** SDK-managed JSON state now writes atomically
  with file mode `0600`.

### Security

- Configurable relay, verifier, and trust-list endpoints now require HTTPS.
  Plain HTTP is accepted only for loopback development hosts such as
  `localhost`, `127.0.0.1`, and `::1`.
- AgentCard resolution rejects stale or far-future signed AgentCard envelopes.
  New attestation storage requires a verifier public key, verifies the
  attestation signature, and rejects duplicate verifier nonces.
- Discovery identity-badge extraction now requires trusted verifier metadata
  and verifier public keys, and returns badges only for signed, trusted,
  unexpired attestations.
- `TrustListCache` rejects unsigned or wrongly signed trusted-verifier lists
  and persists only the signed envelope. `VerifierPubkeyCache` resolves verifier
  keys from the signed trust list instead of trusting mutable verifier-hosted
  key JSON.
- `start_sms_verification()` / `start_email_verification()` reject unsigned,
  wrongly signed, wrong-issuer, stale, or nonce-mismatched verifier responses.
  `confirm_sms_verification()` / `confirm_email_verification()` now send signed
  confirm envelopes, verify the signed confirm response, and verify the returned
  `VerificationAttestation` before returning it.
- Relationship, conversation, verifier, service, replay, attestation, consent,
  pending-verification, and other SDK state files no longer rely on process
  umask for privacy; writes go through a shared private atomic JSON writer.
- Follow-up grant storage now requires the counterparty public key, verifies
  grant signatures, enforces `env.iss == counterparty`, rejects stale/future
  grants, and rejects duplicate grant nonces.
- Relationship revocation now requires a signed `aap.relationship-revoke/v1`
  envelope with a nonce. Verified revocations are persisted as proof before the
  active relationship row is removed, and duplicate revoke nonces are rejected.
- Hosts no longer need to hand-roll inbound chat validation: the SDK exposes a
  receive gate that rejects plaintext by default, verifies the inner signed
  envelope after decryption, and checks active relationship state for chat.
- `AAPClient.send_envelope_raw()` now validates pre-built protocol envelopes
  before encryption/submission: issuer must equal the client address, signature
  must verify against the client public key, and `iat` must be fresh.
- Service catalogs are now signed `aap.service-catalog/v1` envelopes. The cache
  verifies the catalog agent, domain binding, signature, and timestamp before
  accepting or persisting a catalog.
- Discovery query results are accepted only from signed verifier envelopes:
  `query_discovery()` now requires a verifier public-key resolver, verifies the
  expected verifier relay issuer, rejects stale responses, and checks the
  response nonce against the outbound query nonce.
- Service responses must now match a recorded request, come from the expected
  business, verify against that business key, match the original service id,
  and use a response nonce that has not already been stored.
- The legacy synchronous `aap.resolve()` helper was removed from the public API.
  AgentCard resolution now goes through `AAPClient.resolve_agent_card()` /
  `resolve_peer()`, which authenticate the card through self-signatures,
  domain binding, and address key pins.
- The recipient address and delivery metadata remain visible to the relay.
- HPKE base mode does not provide forward secrecy after compromise of the
  recipient's long-term X25519 private key.
- Unsigned encrypted routing wrappers should be rejected by relays; encrypted
  delivery requires the authenticated outer routing wrapper above.

## v0.9.0 — 2026-06-12 — api subdomain migration + address syntax break

Two changes ship together: the api-subdomain relay URL migration and a
breaking change to the AAP address syntax.

### Changed (breaking — address format)

- **AAP addresses are now `<localpart>^<domain>` (e.g. `chris^chrisevans.id`).**
  The legacy `agent:<localpart>@<domain>` form is no longer accepted by
  `Address.parse()`. Rationale: the old form was visually
  indistinguishable from email and invited email mental models (DNS MX,
  bounces, etc.); the new form is self-identifying without a strippable
  scheme prefix. **Migration:** replace any literal `agent:X@Y` with `X^Y`. Stored
  addresses must be rewritten out-of-band before upgrading.

### Changed

- **`DEFAULT_TRUSTED_VERIFIERS_URL`** → `https://api.agentaddress.org/.well-known/aap-trusted-verifiers`
  (`src/aap/verifiers.py`). Callers that don't override
  `AAP_TRUSTED_VERIFIERS_URL` will pick this up automatically on
  upgrade.
- Test fixtures and example AgentCard endpoints in `README.md` and
  `demo.py` updated to reference `https://api.agentaddress.org`.

## v0.8.0 — 2026-06-09 — host-state cleanup

Cosmetic and structural cleanup of host-specific naming and one
behavior change. The F-numbered notes below refer to the internal
release-readiness review that drove this cleanup.

### Removed (breaking for pre-rebrand installs only)

- **F1**: deleted the one-time `aap.json → aap.json` rename in
  `aap.identity.load_or_generate`. Users still on a pre-rebrand
  identity file must rename it manually before upgrading; see
  `aap-hermes/INSTALL.md` for the documented step. Resolves the
  env-override ordering side effect (F10) as well.

### Changed

- **F2, F11**: `aap.identity` module + `IdentityFile` docstrings
  rewritten to host-agnostic phrasing.
- **F3**: `HERMES_HOME`-by-name disclaimers in `aap.verifiers`,
  `aap.conversations`, and `aap.stores.verification_flow`
  rephrased to generic "no environment lookups" / "host's
  commands layer".
- **F4**: legacy provider-name parenthetical references in
  `verifier_client.py` and `discovery.py` removed; replaced with
  `TODO(F4)` markers pointing at the spec-promotion roadmap item.
  The legacy `attestation` response-key alias is retained for now
  and will be dropped once the AAP verifier protocol is formalized.
- **F5**: sibling-repo pointer in `discovery.py` generalized from
  `aap-hermes/discovery.py` to "the host adapter".
- **F7**: `tests/test_client.py` module docstring corrected to
  describe the AAP relay HTTP client.
- **F8**: example hostnames updated. README/demo use the reference
  deployment (`relay.agentaddress.org`); tests use RFC 2606
  `.example` hosts (`relay.example`, `verify.example`,
  `bob.example`).
- **F12**: signed envelope conformance vectors in
  `tests/vectors/envelopes.json` regenerated with the new
  hostnames. Added `tests/vectors/regenerate.py` and
  `tests/vectors/README.md` documenting the regen procedure.

### Tests

- **F6**: renamed the `tmp_hermes_dir` fixture in
  `tests/test_identity.py` to `tmp_identity_dir`; inner directory
  `hermes_home` → `identity_home`.

### Roadmap (no code change)

- **F4 (open)**: the verifier wire shapes encoded in
  `verifier_client.py` and `discovery.py` are de-facto a single
  implementation's contract. The agreed direction is to promote
  them to a normative AAP verifier protocol (schemas, conformance
  tests, publication). Scoped as its own initiative.

## v0.7.1 — 2026-06-03

Domain migration.

### Changed

- **`DEFAULT_TRUSTED_VERIFIERS_URL`** now points at
  `https://agentaddress.org/.well-known/aap-trusted-verifiers` (was
  `agentcallsign.com`). The reference relay deployment is moving from
  `agentcallsign.com` to `agentaddress.org`; this default tracks it. The
  `AAP_TRUSTED_VERIFIERS_URL` env var still overrides for self-hosted
  trust lists.
- Test fixtures previously using `agentcallsign.com` as a generic
  address-domain string updated to `agentaddress.org` for consistency.

## v0.7.0 — 2026-06-02

Promotion from reference codec to full agent SDK. Absorbs protocol + state-store
layers previously living in `aap-hermes`, so any host (OpenClaw, Hermes, etc.)
inherits the same machinery.

### Added

- **`aap.client`** — `AAPClient`, `AAPClientError`, `KeyChangeRejected`. Async HTTP
  client for AAP relays (register, send envelope, poll inbox, resolve peer).
- **`aap.messages`** — `aap.message/v1` chat payload, `aap.routing-envelope/v1`,
  `build_chat_envelope`, `unwrap_chat_envelope`, `wrap_routing_envelope`.
- **`aap.host_policy`** — `token_lifetime_days`, `should_auto_renew`, and
  related capability-token policy constants.
- **`aap.group_flow`** — envelope builders for group-conversation primitives
  (`build_group_invitation_envelope`, `build_group_membership_update_envelope`,
  `build_group_leave_envelope`, `build_group_complete_envelope`). Membership
  update builders now separate the signed issuer from the resulting convener so
  the old convener can sign a handoff to the new convener.
- **`aap.verifier_client`** — verifier OTP helpers (`start_sms_verification`,
  `confirm_sms_verification`, `start_email_verification`,
  `confirm_email_verification`).
- **`aap.identity`** — `IdentityFile`, `load_or_generate` for Ed25519 identity
  lifecycle (env / file / generate priority).
- **`aap.verifiers`** — `TrustListCache`, `VerifierPubkeyCache`,
  `trusted_verifiers_supporting`, `verifier_relay_address`. Path-injected
  fetch + cache layer that complements `aap.trusted_verifiers`'s parser.
- **`aap.services`** — `ServiceCatalogCache`, `ServiceCatalogPayload`,
  `ServiceDefinition`, `ServiceCatalog`, `ValidationFailure`,
  `validate_service_payload`, `build_service_catalog_envelope`,
  `build_service_request_envelope`, `build_service_response_envelope`.
  Customer↔business protocol surface with signed catalogs and JSON-schema
  validation.
- **`aap.relationships`** — `RelationshipStore`, `RelationshipRecord`,
  `RelationshipRevocationRecord`, `VALID_RELATIONSHIP_TYPES`, four envelope builders for the
  friend/admin/team handshake. `RelationshipStore.establish()` is the write
  path for records: it verifies proposal/accept signatures, freshness, nonce
  linkage, issuer binding, replay, and embedded AgentCard key/address binding
  before persisting. `RelationshipStore.revoke()` verifies and persists a
  signed revoke envelope before removing an active row.
- **`aap.service_followups`** — `FollowupGrantStore`, `StoredFollowupGrant`,
  `build_followup_grant_envelope`, `build_followup_envelope`,
  `parse_iso_duration`.
- **`aap.conversations`** — `Conversation`, `ConversationEventRecord`,
  `ConversationPolicyError`, `ConversationStore`, `broadcast_to_conversation`.
  Group-state receivers should use `accept_invitation()`,
  `apply_membership_update()`, `apply_leave()`, and `apply_complete()`, which
  verify signed envelopes, enforce current-convener authority, validate
  membership diffs/handoffs, and persist event proofs/nonces to reject replay.
- **`aap.discovery`** — `query_discovery`, `extract_searcher_identities`,
  `build_introduction_response_envelope`.
- **`aap.pending_responses`** — `PendingResponses` (in-process service-response
  correlation table).
- **`aap.stores`** subpackage — persistent JSON state stores with `base_dir`
  injection: `AttestationStore`, `PendingProposalStore`, `IdentityBindingStore`,
  `PendingConsent`, `OutboundContactStore`, `PendingVerifications`,
  `PendingIntroductions`, `ServiceRequestGroupIndex`.
- New runtime dep: `jsonschema>=4.20` (used by `aap.services`).

### Changed

- Public surface roughly doubled. The v0.6 surface remains fully exported and is
  guarded against regression by `tests/test_smoke.py`.

## v0.5.1 — 2026-05-21

Small additive release.

### Added

- **`aap.keys.seed_to_keypair(seed)`**: derive `(seed, public_key)` from a 32-byte Ed25519 seed without dropping down to the `cryptography` library. `generate_keypair()` now delegates to it.
- **`CatalogEntry.verification_required`** (`dict | None`): capability publishers' `verification_required` metadata is now exposed on `CatalogEntry`, so consumers no longer need to duplicate the parsing in local wrappers.

## v0.5.0 — 2026-05-22

This release adds the wire-level primitives for verification and discovery. All additive — v0.4 envelopes and AgentCards round-trip identically.

### Added

- **`VerificationAttestation`** payload (`aap.verification-attestation/v1`): a verifier-signed claim that the verifier challenged the subject and confirmed control of an identity (phone, email, ...). Carries `subject_address`, `identity` (`{"type", "value"}`), `challenge_method`, `verified_at`, `expires_at`, `verifier`, `nonce`.
- **`DiscoveryIntroductionRequest`** payload (`aap.discovery-introduction-request/v1`): sent by a verifier on a searcher's behalf to ask a recipient whether they want to receive contact. Carries `searcher`, optional `searcher_label_for_recipient`, optional `searcher_attestations`, `verifier_nonce`, `expires_at`.
- **`DiscoveryIntroductionResponse`** payload (`aap.discovery-introduction-response/v1`): recipient's approve/deny reply, correlated by `verifier_nonce`.
- **`Envelope.verification_attestations`** (optional `list[str]`): carries one or more serialized attestation envelopes alongside any payload, so recipients can render verified-identity badges without a separate fetch. Included in the JCS-signed form — tampering invalidates the signature. Backward-compatible: omitted from canonical bytes when None/empty.
- **`trusted_verifiers` module**: parser for the `/.well-known/aap-trusted-verifiers` JSON document, returning `VerifierTrustListEntry` records. Strict on HTTPS: rejects any entry whose `discovery_endpoint`, `verification_endpoint`, or `pubkey_endpoint` is not an `https://` URL. Fetching and caching are left to host implementations.

### Changed

- **`VerifiedIdentity.value`** is now nullable (`str | None`). AgentCards can carry presence-only indicators (e.g. "this agent has a verified phone") without disclosing the identifier. The previous v0.2 behaviour — `value` carrying the actual phone or email — is preserved when callers populate it.

### Spec

- See `docs/specs/2026-05-22-aap-verification-and-discovery-design.md` (Rev 1) for the full design.

## v0.4.0 — 2026-05-22

This release adds group-conversation primitives on top of the v0.3 trust/capability model. Tokens stay strictly 1:1 — groups are a thread-linkage layer above.

### Added

- **`Envelope.conversation_id`** (optional): opaque string identifier (≤128 chars) that threads messages into a multi-party conversation.
- **`Envelope.conversation_members`** (optional): list of AAP addresses, length 2–10 inclusive. The sender's declared view of who's in the conversation. Hard-capped at 10 members at the protocol level — `from_dict` rejects envelopes with >10 members.
- **`GroupInvitation`** payload (`aap.group-invitation/v1`): convener sends this to each prospective member; carries the proposed `members` list, `purpose`, `nonce`. `convener` must be in `members`.
- **`GroupMembershipUpdate`** payload (`aap.group-membership-update/v1`): convener broadcasts mid-conversation changes (add/remove member, transfer convener role). Carries the full post-update `members` list plus `added`/`removed` deltas.
- **`GroupLeave`** payload (`aap.group-leave/v1`): any member sends to declare they're exiting. Carries required `nonce` plus optional human-readable `reason`.

### Changed

- Envelope JCS canonicalization now includes `conversation_id` and `conversation_members` when present. Backward-compatible: envelopes without these fields canonicalize identically to v0.3.

### Spec

- See `docs/specs/2026-05-22-aap-group-conversations-design.md` (Rev 1) for the full design.

### Limits

- 10-member cap on groups, enforced at the protocol level. Larger groups need a separate mechanism (group-agent pattern); deferred.

## v0.3.0 — 2026-05-22

This release replaces the v0.2 verb-registry model with publisher-defined permission identifiers. **Wire format breaks**: v0.2 scope strings of the form `<verb>:<domain>/<noun>` are no longer accepted; scopes must now be `<publisher-domain>/<permission-name>` (or the wildcard `*`).

### Removed

- `aap.scopes` module (`VERBS`, `WILDCARD`, `parse_scope`, `is_valid_scope`). Replaced by inline scope-string shape validation in `payloads.py`.

### Added

- **`AccessDenied`** payload (`aap.access-denied/v1`): auto-sent by recipients when a chat or action envelope arrives without a valid `capability_token`. Includes `rejected_payload_type`, `reason` (`no_capability` / `scope_mismatch` / `expired_token` / `invalid_token`), `required_scopes` hint, and `rejected_at` timestamp.
- **`Envelope.capability_token`** optional field: carries a serialized inner `RelationshipToken` envelope. Recipients deserialize and verify to authorize the carrying envelope. Backward-compatible — omitted when not present. Included in the JCS-signed form so tampering invalidates the signature.
- **`CapabilityCatalog`** helper: fetches publisher capability metadata from `https://<publisher>/.well-known/aap-capabilities/<name>` with in-process caching. Used by host implementations to render rich consent UI.

### Changed

- Scope strings throughout (`RelationshipToken.scopes`, `CapabilityRequestScope.scope`, `CapabilityOfferedGrant.scope`, `CapabilityRefresh.requested_scopes`) now validate as `<domain>/<name>` or `*`. No verb prefix.

### Spec

- See `docs/specs/2026-05-22-aap-trust-capabilities-design.md` (Rev 2) for the full design.

## v0.2.0 — 2026-05-22

### Added

- **Scope vocabulary** (`aap.scopes`): seven standardized verbs (`read`, `write`, `book`, `cancel`, `pay`, `subscribe`, `delegate`) plus the wildcard `*`. Scope strings have the form `<verb>:<noun>` with `<noun>` free-form (typically a domain or URI). Verbs are not extensible by vendors — the registry is fixed so recipients always know the intent class.
- **`VerifiedIdentity`** payload-component: typed verified identifier (phone, email, etc.) with timestamp and verifier attribution (`"self"` or third-party domain). Embedded in `AgentCard.verified_identities`.
- **`AgentCard.verified_identities`** optional field — list of `VerifiedIdentity`. Backward-compatible: empty by default, omitted from serialization when empty, parses v0.1 AgentCards without the field.
- **`CapabilityRequest`** (`aap.capability-request/v1`): structured ask for capability tokens. Carries `scopes` (what the requester wants) and optional `offered_grants` (capabilities the requester reciprocally offers), enabling single-prompt bidirectional relationship setup.
- **`CapabilityGrant`** (`aap.capability-grant/v1`): wraps a `RelationshipToken` plus the originating request's nonce.
- **`CapabilityDenial`** (`aap.capability-denial/v1`): explicit "no" with structured reason (`user_denied`, `scope_not_supported`, `rate_limited`, `unknown`).
- **`CapabilityRefresh`** (`aap.capability-refresh/v1`): request to renew an existing token before expiry.

### Changed

- **`RelationshipToken.from_dict`** now validates scopes: each scope must parse as a valid `<verb>:<noun>` (or the wildcard `*`); the wildcard `*` is mutually exclusive with other scopes in the same token.

### Spec

- See `https://github.com/zazig-team/agentToAgentCommunication/blob/main/docs/specs/2026-05-22-aap-trust-capabilities-design.md` for the full trust-primitives design.

## v0.1.1 — 2026-05-19

Hardening release. Wire format unchanged — v0.1.0 conformance vectors still pass.

### Added
- `Envelope.from_dict` rejects unknown top-level fields.
- `Envelope.from_dict` enforces `type == "aap.envelope/v1"`.
- `Address.parse` lowercases the domain.
- `Address.parse` validates domain characters (ASCII alphanumeric, `.`, `-`).
- `Address.parse` enforces length caps (localpart 64, domain 253).
- `AgentCard.from_dict` validates each endpoint entry (dict with string `type` and `uri`).
- The legacy AgentCard resolver enforced `card.address`, issuer domain,
  redirect, and response-size checks. It was later removed from the public API
  in favor of authenticated, agent-signed AgentCard resolution.

### Documented
- `Envelope` docstring records the temporal-validation gap: v0.1.x does no timestamp, expiry, or replay validation. Callers responsible for temporal policy must implement it themselves.

## v0.1.0 — 2026-05-19

Initial release. Wire format frozen by conformance vectors.

### Added
- `aap.Envelope` — signed envelope codec (JCS + Ed25519).
- `aap.Address` — `agent:<localpart>@<domain>` parser.
- `aap.AgentCard` and `aap.RelationshipToken` payload types.
- Agent Card resolution client for `POST .well-known/aap-resolve` with a
  caller-supplied verification key. This legacy API was later removed from the
  public surface in favor of authenticated, agent-signed AgentCard resolution.
- `aap.keys` — Ed25519 keygen / sign / verify and base64url codec.

### Not yet implemented
- DIDComm v2 encrypted envelopes.
- `did:web` resolver (caller must obtain verification keys out-of-band).
- OPRF discovery client.
- Status List 2021 revocation.
- SD-JWT selective disclosure.
- ECDH-PSI mutual contact proof.
