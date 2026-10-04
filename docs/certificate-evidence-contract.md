# Certificate and signature evidence contract

The existing verification endpoints now expose inspection evidence in addition to their existing validation decision. No certificate is recovered by client-side XML parsing. XAdES, CAdES and PAdES certificate bytes come from the DSS validation diagnostic report; standalone timestamp certificates come from the RFC 3161 token and configured trust store.

## CertificateInfo additions

| Field | Meaning |
| --- | --- |
| `certificateId` | DSS certificate identifier; can be used to deduplicate certificates. |
| `issuerCertificateId` | Identified issuer certificate ID where available. |
| `certificateBase64` | Base64 of the actual X.509 DER certificate. Decode for `.der`/`.crt`, or wrap the same data in `BEGIN CERTIFICATE` / `END CERTIFICATE` for PEM. |
| `sha256Fingerprint`, `sha1Fingerprint` | Uppercase hexadecimal fingerprints of the DER bytes. SHA-1 is an identification aid, not an algorithm recommendation. |
| `certificatePolicyOids` | OIDs in the X.509 certificate-policies extension. |
| `keyUsages`, `extendedKeyUsages` | Enabled key-usage names and extended-key-usage OIDs. The legacy `keyUsage` string remains. |
| `criticalExtensionOids`, `nonCriticalExtensionOids` | Extension inventory. |
| `subjectAlternativeNames` | GeneralName type number and value. Binary values are base64. |
| `certificateAuthority`, `basicConstraints` | CA status and X.509 basic constraints (`-1` means end entity). |

Existing `publicKeyAlgorithm`, `publicKeySize` and `signatureAlgorithm` are populated from the certificate. RSA, EC and DSA key sizes are supported. Existing diagnostic trust/revocation fields are preserved. Missing or unreadable binary evidence does not erase certificate details and is not advertised as an available download.

## SignatureInfo additions

- `parentSignatureId`, `counterSignature`, `counterSignatureIds`: the DSS diagnostic relationship and its inverse. These IDs refer to validation-result IDs. XML nesting and common names are not used to infer parentage.
- `timestamps`: every timestamp reported for the signature. The existing `timestampInfo` remains an alias of the first element; `timestampCount` matches the complete list, including zero.
- `signedReferences`: DSS digest matchers with `id`, `uri`, `documentName`, `type`, `digestAlgorithm`, base64 `digestValue`, `dataFound`, `dataIntact` and `duplicated`. A successful reference digest alone is not a successful signature verdict.
- `recommendations`: `{code,title,description,severity}` preservation guidance. Recommendations never modify `valid`, `indication`, `subIndication`, configured validation policy, or suppression rules.

Signature chains continue to be returned in `COMPREHENSIVE` mode. Each timestamp now exposes its TSA certificate and certificate chain.

## TimestampInfo additions

`timestampId`, `indication`, `subIndication`, `certificateChain`, `messageImprintDataFound` and `messageImprintDataIntact` are added. Digest, message imprint and serial number are filled when available. `valid` is true only for an actual DSS `PASSED` or `TOTAL_PASSED` conclusion; a matching imprint with no full conclusion is not treated as a validated timestamp. A failed TSA chain therefore cannot be hidden behind an intact message imprint.

Standalone timestamp responses add `certificateChain`. The TSA signer is selected using the CMS SignerIdentifier, independently of certificate order. Chain edges require both matching issuer names and verification of the child's certificate signature. Missing issuers remain missing; unrelated certificates are not appended to the chain.

## Recommendation codes

| Code | Condition |
| --- | --- |
| `ARCHIVE_TIMESTAMP_MISSING` | No archive timestamp was reported. Informational, not an urgent warning. |
| `TRUST_CHAIN_INCOMPLETE` | DSS did not report a trusted chain. |
| `REVOCATION_EVIDENCE_MISSING` | Chain revocation status is unknown/not checked. |
| `TIMESTAMP_VALIDATION_INCOMPLETE` | A timestamp conclusion is missing or unsuccessful. |
| `SIGNED_REFERENCE_INCOMPLETE` | A signed reference is missing, not intact, or duplicated. |
| `ARCHIVE_REQUIRED_DIGEST_POLICY` | A valid signature has an explicit DSS digest-policy warning. |
| `ARCHIVE_REQUIRED_REVOCATION_EVIDENCE` | A valid signature has an explicit DSS revocation-evidence warning (including timestamp evidence). |
| `VALIDATION_EVIDENCE_INCOMPLETE` | An unsuccessful result explicitly lacks required certificate, revocation or signed-content evidence. |

Preservation guidance is based on DSS evidence. It does not silently apply MA3 policies or claim that adding an archive timestamp repairs an invalid signature.

## Local verification

The test suite generates RSA/EC certificates, XML countersignatures, an RFC 3161 timestamp, and a signed PDF locally. No external certificate service is needed. Generated files under `target/generated-test-fixtures` are temporary test output; the timestamp and PDF certificates are test identities and are not production trust anchors.
