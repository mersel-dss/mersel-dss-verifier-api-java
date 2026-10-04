# Active validation policy

The DSS validation policy used by signature verification can be switched at runtime,
like the active trust store. Activation is global (every later signature verification
on that process), in-memory (a restart returns to `dss.policy.path` / `dss.policy.profile`)
and process-local (no shared multi-replica state).

> **WARNING — never use in production.** Runtime policy activation was built only for
> TÜBİTAK Uyum Değerlendirme (conformity assessment) deployments. Production instances
> must keep it disabled.

## Enabling

Activation is a feature flag. It is off by default and only the
`POLICY_ACTIVATION_ENABLED=true` environment variable turns it on; neither the
`evaluation` profile nor `REQUEST_TRUST_ENABLED` enables it. When enabled, the service
logs a WARN at startup.

| Property | Env | Default |
| --- | --- | --- |
| `dss.policy.activation-enabled` | `POLICY_ACTIVATION_ENABLED` | `false` (feature flag; TÜBİTAK Uyum Değerlendirme deployments only) |
| `dss.policy.max-bytes` | `POLICY_MAX_BYTES` | `1048576` (1 MiB, CUSTOM_XML upload limit) |

Reads (GET, including the policy XML itself) are always available, whatever
`activation-enabled` says: the policy is configuration, not a secret. Policy endpoint
responses (`/api/v1/policy/active*`, `/api/v1/info`) never contain the configured
`dss.policy.path` or any other server path. Restrict access to
instances where activation is enabled: anyone who can POST changes the policy for all
subsequent verifications.

## GET `/api/v1/policy/active`

```json
{
  "policyId": "30a90a62-580e-4cfd-9e7e-82349b5b9056:0",
  "profile": "signer-strict",
  "source": "BUILT_IN",
  "origin": "CONFIGURATION",
  "name": "KamuSM Signer Strict",
  "sha256": "ab59f8eaafcad5cb5bdfadd0dc4dec5cf223eb8ade1cbb2cbff87b2608270138",
  "activatedAt": "2026-10-03T21:38:35.415Z",
  "fallbackApplied": false,
  "activationEnabled": true
}
```

- `policyId`: opaque revision id (`<process UUID>:<revision>`); new on every activation,
  on every restart, and when a configured policy that had failed to load loads later
  (see below).
- `profile`: `signer-strict` | `strict` | `custom`; `source`: `BUILT_IN` | `CUSTOM_XML`
  (`custom` iff `CUSTOM_XML`).
- `origin`: `CONFIGURATION` (startup configuration) or `API` (activated through POST).
- `name`: `KamuSM Signer Strict`, `KamuSM Strict`, the uploaded `policyName`, or
  `Özel politika` (custom XML without a name, including `dss.policy.path`).
- `sha256`: lowercase hex SHA-256 of the exact policy XML bytes given to DSS.
- `fallbackApplied`: an unknown `dss.policy.profile` fell back to `signer-strict`.

The configured resource is loaded on first use, not at startup and not by `/info`.

## GET `/api/v1/policy/active/xml`

Returns the exact policy XML that the next signature verifications give to DSS:
the bundled profile file (`BUILT_IN`), the bytes uploaded with `CUSTOM_XML`, or the
`dss.policy.path` file. The bytes are served as stored, never re-encoded, so their
SHA-256 is the `sha256` reported by `GET /api/v1/policy/active`.

```http
HTTP/1.1 200
Content-Type: application/xml;charset=UTF-8
X-Policy-Id: 746bfa1d-cfa6-4141-a051-0d10f87c3030:1
X-Policy-Sha256: c4d63c7da00f721fa77482afd0c73050bf340a254d4be302f5ff12eb59831336
ETag: "c4d63c7da00f721fa77482afd0c73050bf340a254d4be302f5ff12eb59831336"
Cache-Control: no-store
Content-Disposition: inline; filename="Mersel-KamuSM-Signer-Strict-Policy.xml"
Content-Security-Policy: default-src 'none'; sandbox

<?xml version="1.0" encoding="UTF-8"?>
<!-- ... -->
<ConstraintsParameters ...>
```

| Header | Value |
| --- | --- |
| `Content-Type` | `application/xml;charset=UTF-8` for built-in and UI-uploaded policies. The charset is the document's own encoding: a UTF-8 BOM, a UTF-16 BOM (`UTF-16`), otherwise the XML declaration's `encoding`, otherwise UTF-8. |
| `X-Policy-Id` | `policyId` of the revision the body belongs to |
| `X-Policy-Sha256` | lowercase hex SHA-256 of the body |
| `ETag` | `"<sha256>"` (identifies the content; the same XML under another revision has the same ETag) |
| `Cache-Control` | `no-store` |
| `Content-Disposition` | `inline; filename="…"`: `kamusm-signer-strict-constraint.xml` / `kamusm-strict-constraint.xml` for built-in profiles; for `CUSTOM_XML` the `policyName` reduced to ASCII (`ı→i`, accents dropped, every other run of characters outside `A-Z a-z 0-9 _ -` becomes `-`, at most 80 characters, `.xml` appended); `active-policy.xml` when no name was given and for `dss.policy.path`. Never a server path. |
| `Content-Security-Policy` | `default-src 'none'; sandbox` (nothing in a user XML runs if the URL is opened in a browser; `X-Content-Type-Options: nosniff` comes from the global header filter) |

The body and every header come from one immutable snapshot of the active policy: a
concurrent activation can never pair one revision's id with another revision's XML.
The `Accept` header is not negotiated; the response is always the XML.

In the failed state (see below) the endpoint answers the same
`503 POLICY_UNAVAILABLE` JSON body as `GET /api/v1/policy/active` (same `policyId`
and `activationEnabled`; `path` is `/api/v1/policy/active/xml`), also when the client
sends `Accept: application/xml`.

### Editing the active policy

1. `GET /api/v1/policy/active/xml` and keep `X-Policy-Id`.
2. Edit the text. Hash the bytes you will upload if you want to detect "no change"
   against `X-Policy-Sha256`.
3. `POST /api/v1/policy/active` with `mode=CUSTOM_XML`, the edited file as `policyXml`
   and `expectedPolicyId=<X-Policy-Id>`. If someone activated another policy in the
   meantime the save is rejected with `409 CONFLICT` instead of overwriting it.

Browser clients: `fetch(...).text()` always decodes as UTF-8 and drops a UTF-8 BOM,
so for a non-UTF-8 charset decode `arrayBuffer()` with `TextDecoder(charset)`; compare
hashes over raw bytes, not decoded text. CORS exposes `X-Policy-Id`, `X-Policy-Sha256`,
`ETag` and `Content-Disposition` (`Access-Control-Expose-Headers`), so a UI on another
origin can read them.

```bash
curl -s -D headers.txt -o active-policy.xml localhost:8086/api/v1/policy/active/xml
shasum -a 256 active-policy.xml          # equals X-Policy-Sha256
ID=$(grep -i '^X-Policy-Id:' headers.txt | cut -d' ' -f2 | tr -d '\r')
curl -F mode=CUSTOM_XML -F policyXml=@active-policy.xml -F "policyName=Kurum politikası" \
     -F expectedPolicyId=$ID localhost:8086/api/v1/policy/active
```

## Failed configuration and recovery

If an explicit `dss.policy.path` cannot be loaded and no policy has been activated yet
(the *failed state*), GET returns `503 POLICY_UNAVAILABLE`. The body is the common
error shape plus the current revision and whether activation is enabled; the
configured path is never echoed:

```json
{
  "error": "POLICY_UNAVAILABLE",
  "message": "Sunucu yapılandırmasındaki doğrulama politikası (dss.policy.path) yüklenemedi; yapılandırma düzeltilene veya başka bir politika etkinleştirilene kadar imza doğrulamaları başarısız olur.",
  "details": "Ayrıntı sunucu loglarında",
  "policyId": "77988277-fba9-424e-bc96-3a394d4513a2:0",
  "activationEnabled": true,
  "timestamp": "2026-10-03T22:06:30.897+00:00",
  "path": "/api/v1/policy/active"
}
```

With `activationEnabled: false` the message ends with
`yapılandırma düzeltilene kadar imza doğrulamaları başarısız olur.` and POST answers
`403 POLICY_ACTIVATION_DISABLED`.

While the failed state lasts, every signature verification keeps failing fast with the
existing `VerificationException` (`400 VERIFICATION_ERROR`); there is no silent fallback.
To recover, POST with `expectedPolicyId` set to the 503 body's `policyId`:

| `mode` | Result in the failed state |
| --- | --- |
| `BUILT_IN` | `200`, the profile becomes active (`origin=API`); verifications use it |
| `CUSTOM_XML` | `200` if the XML passes the checks below (`origin=API`) |
| `CONFIGURED` | `200` (`origin=CONFIGURATION`) if `dss.policy.path` now loads; otherwise `503 POLICY_UNAVAILABLE` with the same `policyId`, state unchanged |

The usual rules still apply: a wrong `expectedPolicyId` is `409 CONFLICT`, an invalid
request is `400 INVALID_POLICY`.

If the file is fixed on the server instead, the next GET or verification loads it under
a **new** `policyId` (`origin=CONFIGURATION`). A client that saw the failed state and
then POSTs with the old `policyId` gets `409 CONFLICT`, refreshes, and sees the
recovered configuration before replacing it.

`CONFIGURED` after a policy has been activated also answers `503 POLICY_UNAVAILABLE`
(with the current `policyId`) when the file still cannot be loaded, but then the active
policy stays in force and the message is
`Sunucu yapılandırmasındaki doğrulama politikası (dss.policy.path) yüklenemedi; etkin politika değişmedi.`

## POST `/api/v1/policy/active` (multipart/form-data)

| Field | Rule |
| --- | --- |
| `mode` | `BUILT_IN` \| `CUSTOM_XML` \| `CONFIGURED` |
| `profile` | `signer-strict` \| `strict`; required for and only allowed with `BUILT_IN` |
| `policyXml` | file; required for and only allowed with `CUSTOM_XML`; at most `maxBytes` |
| `policyName` | optional display name for `CUSTOM_XML`, at most 120 characters, no control characters; default `Özel politika` |
| `expectedPolicyId` | required; must equal the current `policyId` |

`CONFIGURED` reloads the startup configuration (`dss.policy.path` is re-read) and
reports `origin=CONFIGURATION` with a new `policyId`. The response is the new
`ActivePolicy`. Every activation is logged at INFO with policyId, profile, source,
origin, name and sha256 only (never XML content).

`CUSTOM_XML` is accepted only if it:
1. is not larger than `dss.policy.max-bytes`;
2. parses with an XXE-safe SAX parser (no DOCTYPE, hence no ENTITY; external entities
   and DTD loading disabled) and is well formed;
3. loads through the same DSS API that signature validation uses
   (`ValidationPolicyLoader.fromValidationPolicy(...)`), which unmarshals
   `ConstraintsParameters` with DSS XSD validation.

The stored bytes are exactly the uploaded bytes, so `sha256` can be compared with a
client-side hash of the editor buffer.

## Errors

Errors use the common `ErrorResponse` shape (`error`, `message`, `details`, `timestamp`, `path`);
`503 POLICY_UNAVAILABLE` also carries `policyId` and `activationEnabled`.
State never changes on an error.

| HTTP | `error` | When |
| --- | --- | --- |
| 400 | `INVALID_POLICY` | bad/missing `mode`, `profile` or `expectedPolicyId`; field not allowed for the mode; empty/too large file; DOCTYPE/ENTITY; not well formed; not a DSS `ConstraintsParameters` or fails its XSD |
| 403 | `POLICY_ACTIVATION_DISABLED` | `dss.policy.activation-enabled=false` (checked first) |
| 409 | `CONFLICT` | `expectedPolicyId` is stale (another activation or a restart) |
| 503 | `POLICY_UNAVAILABLE` | the configured `dss.policy.path` cannot be loaded (GET `/policy/active` or `/policy/active/xml` in the failed state, `CONFIGURED`); body includes the current `policyId` for recovery |

Example: `{"error":"INVALID_POLICY","message":"Politika XML'i DOCTYPE/ENTITY bildirimi içeremez (DTD ve harici varlıklar güvenlik nedeniyle kabul edilmez).","details":"Politika etkinleştirilmedi; sunucudaki etkin politika değişmedi",...}`

## `/api/v1/info`

`verificationPolicy` keeps its shape `{profile, source, fallbackApplied}` and now
describes the ACTIVE policy. New:

```json
"policyCapabilities": { "activationSupported": true, "activationEnabled": true, "maxBytes": 1048576, "contentAvailable": true }
```

`contentAvailable: true` means `GET /api/v1/policy/active/xml` exists on this server
(older servers omit the field).

## Verification responses

Signature verification responses (`/verify/signature`, `/xades`, `/pades`, `/cades`)
carry the policy used for that request:

```json
"policyContext": {
  "policyId": "30a90a62-580e-4cfd-9e7e-82349b5b9056:2",
  "profile": "custom",
  "source": "CUSTOM_XML",
  "name": "Kurum politikası",
  "sha256": "8c7bf4912097a7e13fab01906e2b719cdd43a4c32f4301ae0f6390066e859309"
}
```

The policy is read once at the start of the verification (an immutable snapshot);
the XML given to DSS and `policyContext` come from that snapshot, so a concurrent
activation never mixes policies within one request. Standalone timestamp verification
does not use the DSS validation policy and has no `policyContext`.

```bash
ID=$(curl -s localhost:8086/api/v1/policy/active | jq -r .policyId)
curl -F mode=BUILT_IN -F profile=strict -F expectedPolicyId=$ID localhost:8086/api/v1/policy/active
curl -F mode=CUSTOM_XML -F policyXml=@my-policy.xml -F "policyName=Kurum politikası" \
     -F expectedPolicyId=<policyId> localhost:8086/api/v1/policy/active
curl -F mode=CONFIGURED -F expectedPolicyId=<policyId> localhost:8086/api/v1/policy/active
```
