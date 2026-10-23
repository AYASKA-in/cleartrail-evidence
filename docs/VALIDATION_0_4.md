# Validation of 0.4.0

Checked on 23 October 2026. Synthetic data only; no real customer IdP or provider credentials were used.

| Check | Actual result |
|---|---|
| Windows Python 3.10.11, PostgreSQL enabled | **305 passed, 2 POSIX-only skips; 259 subtests passed** |
| Linux Python 3.12, PostgreSQL enabled | **307 passed; 259 subtests passed**, inside a resource-limited read-only container |
| PostgreSQL 17.11 | Real non-superuser role; forced RLS on all 14 scoped tables, pooled-context isolation, concurrent worker/scheduler claims, concurrent uploads/reviews and additive migration passed |
| Historical compatibility | A golden 0.2.0 bundle regenerated its HTML/CSV exactly; frozen historical catalog validation and byte-preserving migration passed |
| Linux image build | Built successfully from pinned Python base and hash-pinned runtime dependencies |
| Container workflow | Actual HTTP upload larger than 128 KiB, independent approval, auditor download of identical bytes, foreign-tenant denial, readiness and download headers passed with synthetic identities in a non-root/read-only container |
| Least-privilege runtime | The HTTP evidence workflow passed with a separate DML-only, non-superuser/non-BYPASSRLS role lacking CREATE on the application schema. Schema migration used a distinct owner role. |
| Installed wheel | Packaged schema 3, encrypted upload/review/download, new demo export and compatibility with a synthetic export generated independently by the 0.3 wheel passed |
| Source checks | Ruff F checks, Python compilation and JavaScript syntax checks passed |
| Compose | Configuration validated with the example environment |
| Runtime dependencies | No new runtime dependencies; the unchanged 36-distribution lock retains the same-date 0.2 pip-audit result with no known vulnerabilities reported |

New evidence tests exercise cross-tenant IDs and RLS, auditor read/write restrictions, reviewer independence, replacement-version approval reset, assignment and stale forms, concurrent uploads/reviews, withdrawal and expiry, historical approval withdrawal after reviewer offboarding or file corruption, final-review-slot reservation, upload formats/limits, workspace/CSRF checks before the larger upload allocation, workspace/version quotas, ciphertext/immutable-metadata tampering, transactional key rotation, permission revocation and v2-to-v3 migration. Existing scheduler, monitoring, collector, report and historical compatibility regressions remain in the suite.

The PostgreSQL test containers are disposable and expose their database only on host loopback. Container API smoke traffic stayed within the private test network. No public customer service was deployed. The Linux suite used read-only mounts of application/tests/project metadata and a separate disposable database from the Windows suite.

The golden fixtures are synthetic exports/schema generated from the independently installed 0.2.0 wheel. They are deliberately included in source distribution; real evidence exports, credentials, runtime environment files, databases and raw vendor captures remain excluded.

Three benign warnings remain: two upstream HTTPX deprecation warnings and the intentional duplicate-ZIP-member attack-test warning. Remote GitHub CI was not dispatched. Visual browser QA remains pending because browser access to the existing error tab was blocked earlier in this session. API and source verification do not establish visual correctness.

Live customer OIDC/provider permissions, operational PITR/restore, shared ingress/external alerting, capacity/soak testing, image vulnerability scanning and independent security review remain required. Unsigned reports and audit chains require trusted external anchors; they do not authenticate provider assertions or establish audit-period operating effectiveness.

See [TEAM_EVIDENCE.md](TEAM_EVIDENCE.md) and [MONITORING.md](MONITORING.md) for operation/upgrade semantics and [HARDENING.md](HARDENING.md) for remaining launch gates. Previous validation records are preserved for [0.3](VALIDATION_0_3.md) and [0.2](VALIDATION_0_2.md).
