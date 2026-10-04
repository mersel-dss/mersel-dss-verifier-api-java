# UI report evidence and invoice preview

The comprehensive signature report now exports public X.509 certificate DER as `certificateBase64`, DSS certificate/issuer identifiers, SHA-256 and SHA-1 fingerprints, policies, key usage, extended key usage and extension OIDs. Trust/revocation decisions remain DSS evidence; exporting a certificate does not establish trust. The frontend generates CRT/DER/PEM downloads from these bytes rather than parsing certificate elements from signed XML.

`SignatureInfo` adds `parentSignatureId`, `counterSignature`, `counterSignatureIds`, `signedReferences`, `timestamps` and `recommendations`. Parent relationships and digest matcher evidence are copied from DSS diagnostic data. Every timestamp carries a detailed-report verdict, imprint evidence and its TSA certificate chain; `timestampInfo` remains the first-token compatibility alias. Matching a timestamp imprint without a DSS verdict is no longer treated as a fully valid timestamp. Recommendations never override a signature decision.

Standalone RFC3161 reports expose the actual SID-matching TSA signer and available chain. When no signing certificate or chain material is available, the report must retain that absence.

## Preview service

Invoice preview is delegated to Mersel's existing `MERSEL.Service.XsltService`; signature and timestamp verification remain in this Java API. The compliance UI configures the verification and preview services independently. The temporary `/api/v1/documents/preview` endpoint, child JVM worker and preview-only Saxon dependency have been removed. See [the preview service boundary](document-preview.md) for migration details.

Returned HTML is untrusted. Consumers must sanitize it and display it in an iframe without script, same-origin, forms or navigation privileges, with a CSP blocking external resources. The Mersel UI applies DOMPurify, CSP and an empty sandbox. This preview does not establish which displayed values were signed. Inspect DSS references separately.

## Local validation

`mvn clean test` covers certificate material, report relationships, timestamps and generated signatures. Preview transformation tests belong to `MERSEL.Service.XsltService`. Browser downloads and UI compatibility are tested in `mersel-dss-compliance-ui`. The real sample smoke test is documented there in `docs/live-smoke.md`. These checks verify API/UI behavior; an approved expectation manifest, deployment policy and trust-store context are still required for formal compliance testing.
