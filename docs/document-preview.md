# Invoice preview service boundary

Invoice XML/XSLT presentation is handled by Mersel's existing `MERSEL.Service.XsltService` project. `mersel-dss-verifier-api-java` handles signature and timestamp verification, certificate chains, revocation evidence and validation policy evaluation.

The temporary `POST /api/v1/documents/preview` endpoint and its isolated Java/Saxon preview worker have been removed from this verifier. Consumers must use the XSLT service's API for previews and this verifier's existing `/api/v1/verify/*` APIs for verification. The compliance UI configures these as separate services; preview failure does not alter the verification result.

The XSLT service contract and deployment settings live in `MERSEL.Service.XsltService`. The compliance UI's `docs/backend-contract.md` documents how the two services are connected. The verifier no longer bundles a preview engine or needs permission to launch child JVMs for this feature. Use a clean Maven build when updating an existing checkout so removed classes and resources do not remain in the packaged application.

## HTML consumption

Preview HTML remains untrusted presentation content. The compliance UI sanitizes it and renders it in an iframe with an empty `sandbox` attribute and a restrictive CSP. Previewing an invoice does not establish signature validity or which displayed values are covered by the signature; those facts come from DSS verification and its signed-reference evidence.
