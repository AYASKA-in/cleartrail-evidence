# Validation of 0.6.0

Checked 24 October 2026 with synthetic fixtures. No public AWS deployment,
customer credentials or real Google sign-in was used.

| Check | Actual result |
|---|---|
| Windows Python 3.10.11, PostgreSQL enabled | **382 passed, 2 POSIX-only skips; 259 subtests passed** |
| Linux Python 3.12, PostgreSQL enabled | **384 passed; no skips; 259 subtests passed**, non-root/read-only image with separate test dependencies |
| PostgreSQL 17.11 | Seven tests: forced RLS, tenant context, pooled reset, concurrent jobs/schedulers/reviews, governance revision serialization and additive migration |
| Governance | Five record schemas; strict dates/enums/risk bands; independent/stale reviews; foreign workspace IDs; quotas/withdrawal slot; ciphertext tampering; key rotation; linked evidence withdrawal; dependency closure; forged-register rejection |
| Compatibility | Frozen catalogs unchanged; older supported snapshot/document packages retained; independently installed 0.5 image seeded schema 4; 0.6 migration preserved ciphertext, original snapshot, approval and file download |
| Browser OIDC | Real Keycloak 26.8.1 code/PKCE sign-ins as synthetic admin, operator/reviewer and auditor; DML-only PostgreSQL application role |
| Browser workflow | Created risk and implemented applicability decision; exact approved text evidence and risk links; independent approvals; escaped XSS-like title; auditor cannot create/review; remaining three forms inspected |
| Browser export | Downloaded two approved records; CLI verified whole-file trusted SHA-256 `8cb9526c9ea5fb3334f681c8fd9c721a32d18186ea61f084afd33407ac7e417c` |
| Responsive QA | 1280×900 desktop, 375×812 mobile and 812×375 landscape; mobile header wrapping corrected; no page-level horizontal overflow at checked mobile/landscape dimensions; no console errors/warnings on final pages |
| Static checks | Ruff F and JavaScript syntax passed; explicit asset MIME types regression added after Windows registry default blocked JavaScript with nosniff |
| AWS template | cfn-lint passed locally for Mumbai resource schemas/dependencies; account/AMI/quota/credit/price checks and CloudFormation execution **not performed** |
| Application image | `sha256:be4a4dd4e011fbb479b6e91378ace5932a29a0275fc7611c4889e519a344a694`; Trivy 0.76.1, zero known vulnerability matches at all severities, scan 24 October 2026 UTC |

The Linux test harness initially mounted tests outside the package tree, breaking
isolated verifier subprocess imports. Mounting under `/app/tests` corrected the
harness; the final complete Linux run passed. The mobile CSS correction was
browser-checked and the final image rebuilt/rescanned afterward. Runtime Python
dependencies and scanner image are unchanged from 0.5.

Four warnings are two upstream HTTPX deprecations and two intentional duplicate
ZIP attack fixtures. Scanner acceptance, document-inclusive package browser QA,
installed 0.5 wheel and the 81.38-second logical recovery rehearsal are recorded
in [VALIDATION_0_5.md](VALIDATION_0_5.md); they are not new 0.6 operational recovery
measurements. Current regressions retain those behaviors. The current wheel/source distribution built successfully. An isolated installation of the wheel verified the browser register without hosted dependencies.

Screenshots: [desktop](qa/governance-desktop-0.6.png),
[mobile](qa/governance-mobile-0.6.png). Image inventory:
[application-image-0.6.json](security/application-image-0.6.json).
Private QA configurations, realm credentials, database dumps, raw exports and
original reference PDFs are excluded from source releases.

The register is unsigned and does not embed supporting file bytes. A trusted
digest does not establish provider truth or operating effectiveness. Local
Keycloak does not validate real Google MFA/HTTPS. AWS credit runway and 8 GiB
host capacity are unmeasured candidates. Off-host recovery, sustained capacity,
customer provider authorization and independent human security/auditor review
remain launch gates. See [RELEASE_GATES.md](RELEASE_GATES.md).

Earlier records: [0.5](VALIDATION_0_5.md), [0.4](VALIDATION_0_4.md),
[0.3](VALIDATION_0_3.md), [0.2](VALIDATION_0_2.md).
