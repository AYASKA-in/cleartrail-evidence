# Release readiness: 0.5.0

Assessed 24 October 2026 (Asia/Kolkata). **Controlled staging release.** Local
implementation and validation are complete; customer launch requires actual
deployment/account evidence and an independent review.

| Requested work | Completed and exercised | Deployment gate |
|---|---|---|
| PDF/Office scanning | Bounded PDF/DOCX/XLSX/PPTX validation, fresh ClamAV scans, fail-closed errors/limits, encrypted scan provenance and safe attachments. Real clean files, EICAR detection and size-limit rejection tested. | Operate signature updates/health monitoring; antivirus is not content disarm or a safety guarantee. |
| Document-inclusive packages | Exact approved versions, reviews, expiry, scan records, period/source inventory, optional snapshot and bounded offline verification with trusted manifest digest. | Auditor review of relevance/effectiveness; signing/external immutable anchors remain future work. |
| Browser QA | Real Keycloak admin/reviewer/auditor sign-ins, uploads, independent review, downloads, package verification, workspace/role boundaries, desktop/mobile layouts and restore reauthentication. Fixed CSP chart and Unicode defects. | Production Google sign-in, MFA/account recovery and HTTPS ingress acceptance. |
| Identity/providers | Local real OIDC flow; private `validate-providers` command with isolated read-only collectors and explicit blocked/incomplete outcomes. | Selected Google OIDC client is not configured yet. Actual GitHub test scope is unspecified; Workspace and AWS test accounts are unavailable. Live cloud checks remain **not run**. |
| Recovery | Real PostgreSQL logical backup, killed worker, separate restore, audit/key/file/RLS checks, session invalidation and failed interrupted-job recovery. 81.38-second local outage. | Off-host WAL/PITR, hosting/IdP loss and approved RPO/RTO rehearsal. Only the disposable fixture lease expiry was accelerated. |
| Security review | Internal boundary review, regressions, dependency audit, SAST triage, least-privilege runtime smoke, rate-budget fix; both final images have zero known vulnerability matches at scan time. | Independent review, operated shared limits/alerts, managed keys, retention/offboarding and incident response. |

The Google OIDC guide uses `https://compliance.example.com` as a placeholder.
No public DNS/TLS-validated service is included with the release. See
[GOOGLE_STAGING.md](GOOGLE_STAGING.md) for setup and required deployment inputs.

Before customer data: provision HTTPS/private database/secrets/shared limits;
validate the chosen identity and each enabled provider; run CI against the release
revision; rehearse off-host recovery; obtain independent security/auditor review.
Missing providers must stay unknown and must not be advertised as validated.
No paid Workspace/AWS account is required just to authenticate or exercise manual
evidence workflows. Do not create subscriptions merely to turn a gate green.

See [VALIDATION.md](VALIDATION.md), [SECURITY_REVIEW.md](SECURITY_REVIEW.md),
[LIVE_VALIDATION.md](LIVE_VALIDATION.md) and [RECOVERY.md](RECOVERY.md).
