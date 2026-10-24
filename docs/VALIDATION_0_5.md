# Validation of 0.5.0

Checked 23-24 October 2026 using synthetic data. No production credentials or public
customer deployment was used. Summary: [qa/results-0.5.json](qa/results-0.5.json).

| Check | Actual result |
|---|---|
| Windows Python 3.10.11, PostgreSQL enabled | **347 passed, 2 POSIX-only skips; 259 subtests passed** |
| Linux Python 3.12, PostgreSQL enabled | **349 passed; 259 subtests passed; no skips**, read-only resource-limited final image |
| PostgreSQL 17.11 | Non-superuser forced RLS on 14 scoped tables, pooled context, cross-tenant boundaries, concurrency and additive migrations |
| Historical compatibility | Golden 0.2 report regeneration; independently installed 0.4 image created schema-3 encrypted approved text/run, then 0.5 migrated to schema 4 without altering ciphertext or snapshots |
| ClamAV 1.5.4 | Real definitions 28162; clean PDF/OOXML/text scanned, standard in-memory EICAR and a decompression-limit fixture rejected; patched scanner passed real PDF HTTP workflow |
| Final HTTP workflow | Rootless/read-only image, DML-only database role: real PDF scan, self-approval 403, independent approval, byte-identical auditor attachment and offline-verified document-inclusive package |
| Real browser identity | Keycloak 26.8.1 code/PKCE/nonce sign-ins for synthetic admin/reviewer/auditor, workspace switching, app/provider logout, fresh sign-in after restore/session invalidation |
| Browser QA | Desktop 1280x900 and mobile 390x844; upload/review/download, PDF+DOCX+snapshot package download/verification, auditor boundaries, escaped XSS-like title. Fixed Unicode and CSP chart. Controls/evidence/integrations/monitoring/reports inspected; no console errors on final checked pages. |
| Recovery | Quiesced logical backup, killed worker/child, separate restore, key/file/audit/RLS verification, wrong-key rejection, session invalidation. 81.38-second local outage; no quiesced committed fixture data loss. Interrupted job failed without success snapshot after accelerated fixture lease expiry. |
| Local read load | 100 requests, 8 clients, two tenants with 100 documents each: all 200; 26.73 requests/s; p95 811.71 ms. Local synthetic HTTP reads, not production capacity/soak evidence. |
| Dependencies/images | pip-audit: no known vulnerabilities in 36-distribution runtime lock. Trivy 0.76.1: zero known matches at all severities in both final application and patched scanner images. |
| Source | Ruff F, Python compilation and JavaScript syntax passed; four Ruff S alerts contextually reviewed in SECURITY_REVIEW.md |
| Installed release wheel | Fresh schema 4, encrypted upload, independent approval, auditor bytes and audit chain passed; trusted browser package and independent 0.4 snapshot verified with isolated standard library only |
| Compose | Complete scanning and maintenance profiles validated without deployment |
| Google compatibility | Official discovery supports S256/RS256/client authentication. Bounded Google callback metadata allowed; signed identity/membership, duplicate/unknown/control/oversized metadata rejection tested. Actual Google sign-in needs the selected client/hostname. |
| Live cloud providers | Private fail-closed validation preflight returned blocked/incomplete with missing integrations. Actual GitHub/Workspace/AWS checks not run; accounts/authorization not supplied. |

Final image IDs and inventories are in [SECURITY_REVIEW.md](SECURITY_REVIEW.md).
The image has no pip/ensurepip; Linux test dependencies were separately mounted.
The browser's zero-record snapshot does not claim live provider validation.
Four warnings: two upstream HTTPX deprecations and two intentional duplicate-ZIP
attack fixtures. Remote GitHub CI was not dispatched.

Local HTTP Keycloak does not validate customer MFA or HTTPS ingress. Logical
restore does not establish off-host WAL/PITR, geographic loss, IdP recovery or a
production SLA. No independent human security/auditor review occurred. Read
[RELEASE_GATES.md](RELEASE_GATES.md) before customer launch.

Synthetic screenshots: [desktop](qa/approved-evidence-0.5.jpg),
[mobile](qa/mobile-evidence-0.5.jpg). Private environment files, credentials, dumps,
raw exports and image archives are excluded from releases. Only explicitly
allowlisted sanitized QA/scan reports are included. Prior validation records:
[0.4](VALIDATION_0_4.md), [0.3](VALIDATION_0_3.md), [0.2](VALIDATION_0_2.md).
