# Active backend trust store (contract version 2)

Activate once, then verify any number of documents without resending roots.
Enable mutations only on an isolated evaluation instance with
`SPRING_PROFILES_ACTIVE=evaluation` or `REQUEST_TRUST_ENABLED=true`.
The evaluation profile also disables invalid-signature notifications.

GET `/api/v1/trust/active` returns metadata for the effective trust snapshot:
mode (SERVER/CUSTOM), activeTrustId (process UUID + revision), activatedAt,
certificateCount, anchors (DER SHA-256, subject, issuer, serialNumber),
snapshotSha256, onlineValidationEnabled. It does not return certificate DER/PEM.
`/api/v1/info` announces contractVersion=2 and activeTrustSupported=true.

POST `/api/v1/trust/active` accepts multipart fields:
- `mode=CUSTOM|SERVER`
- required `expectedTrustId` from the most recent GET
- repeatable `retainSha256`: retain exactly these certificates from the current
  effective source (including the configured source when first entering CUSTOM)
- repeatable `trustedCertificates`: new X.509 DER/PEM certificates to add

CUSTOM replaces the full effective set with retained certificates plus uploads.
Both lists empty intentionally activates an empty set: no fallback to standard
roots. Up to 100 certificates / 1 MiB per upload and final custom set. PEM bundles
are supported. Invalid input/unknown retained roots/limits/disabled mutations
return 400 without changing current state. Parse and validate before atomically
replacing the snapshot. Stale expectedTrustId (including from another process or
a restarted backend) returns 409 TRUST_CHANGED. No automatic overwrite.

SERVER accepts neither certificates nor retained hashes and restores the current
configured resolver source. Background resolver refreshes cannot affect a CUSTOM
override. The override lasts for the Java process lifetime, until another
activation or explicit SERVER reset. Browser refresh/close does not reset it.
Restart initializes a new process identity and uses the configured standard source.
No persistence across backend restart, no shared multi-replica state, no root-file
modification. Run evaluation on one instance or add explicit shared-state coordination.

Normal `/verify/signature`, `/timestamp`, `/xades`, `/pades`, `/cades` requests
(no extra fields, or trustMode=SERVER) now use the backend's effective snapshot.
Optional `expectedTrustId` rejects a changed activation before invoking the engine;
an already-started verification keeps its immutable original snapshot. The UI pins
this ID within a batch and stops on TRUST_CHANGED. Results preserve the actual
trustContext and activeTrustId for each report.

Legacy explicit trustMode=CUSTOM + certificates still overrides only that request,
without changing the backend active store. It cannot combine with expectedTrustId.
The normal UI document flow no longer uses this request-only mode.

Custom trust requires validateCertificate=true for standalone timestamps. A TSA
chain that cannot reach the selected custom roots produces INVALID; standard mode
retains existing warning semantics, so also inspect tsaCertificate.trusted.
Embedded timestamps remain governed by the configured DSS policy. Online
revocation/AIA configuration is independent from root-source selection.
Expired or bad self-signature certificates may be loaded as deliberate test anchors;
never infer trust merely from certificates embedded in a signed document.

Snapshot hash: sorted unique lowercase DER SHA-256 hex strings, joined by LF with
no trailing LF, UTF-8 encoded then SHA-256. Empty set hashes the empty byte string.
The UI checks metadata consistency and the pinned activation ID.

Access to the evaluation instance must be restricted to operators permitted to
change its trust: activation affects all subsequent default requests to that process.
This feature is not durable audit storage or proof that all compliance cases pass.


## Active policy metadata

GET `/api/v1/info` also returns `verificationPolicy` with `profile`
(`signer-strict`, `strict`, or `custom`), `source` (`BUILT_IN` or `CUSTOM_XML`),
and `fallbackApplied`. The values come from the same active policy store that
signature validation reads (`ActivePolicyStore`). Without an API activation an
explicit policy path takes precedence; an unknown built-in profile falls back to
signer-strict. After `POST /api/v1/policy/active` they describe the activated
policy. `runtimeProfiles` reports active Spring profiles, or default profiles if
none are explicitly active.

These fields describe the policy for subsequent signature validations, not
policy availability or evidence for previous reports (each report carries its own
`policyContext`). This read does not load custom resources or expose resource
paths/credentials. The UI keeps its local policy draft until it is activated and
reads trust anchors from `/api/v1/trust/active`. Runtime activation, its feature flag
(`POLICY_ACTIVATION_ENABLED`, off by default and independent of `REQUEST_TRUST_ENABLED`;
never enable it in production, it is for TÜBİTAK Uyum Değerlendirme deployments only) and
`policyCapabilities` are described in [policy-activation.md](policy-activation.md).
