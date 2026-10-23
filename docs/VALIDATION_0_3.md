# Validation of 0.3.0

Checked on 23 October 2026. Synthetic data only; no real customer IdP or provider credentials were used.

| Check | Actual result |
|---|---|
| Windows Python 3.10.11, PostgreSQL enabled | **266 passed, 2 POSIX-only skips; 259 subtests passed** |
| Linux Python 3.12, PostgreSQL enabled | **268 passed; 259 subtests passed**, inside a resource-limited read-only container |
| PostgreSQL 17.11 | Real non-superuser role; forced RLS, pooled-context isolation, concurrent worker claims, concurrent scheduler dispatch and v1-to-v2 migration passed |
| Historical compatibility | A golden 0.2.0 bundle regenerated its HTML/CSV exactly; frozen historical catalog validation and byte-preserving migration passed |
| Linux image build | Built successfully from pinned Python base and hash-pinned runtime dependencies |
| Container workflow | Non-root/read-only migrate, schedule-once, worker-once with a real subprocess, authenticated API, policy update, compact polling and notice acknowledgment passed against a separate disposable database |
| Least-privilege runtime | A separate DML-only, non-superuser/non-BYPASSRLS role could run scheduler/worker/API and policy writes, while lacking CREATE on the application schema. A credential-less provider remained incomplete with zero passing checks. |
| Installed wheel | Packaged catalog/scheduler/schema v2, new demo export verification and 0.2 golden-export compatibility passed independently of the source import path |
| Source checks | Ruff F checks, Python compilation and JavaScript syntax checks passed |
| Compose | Configuration validated with the example environment |
| Runtime dependencies | No new runtime dependencies; the unchanged 36-distribution lock retains the same-date 0.2 pip-audit result with no known vulnerabilities reported |

The new tests exercise duplicated schedulers, restart persistence, immediate due times, active-job deferral, missed-period coalescing, quotas and recovery, idempotent policy updates, disabled defaults, tenant isolation and acknowledgment roles. They also cover stale/missing/incomplete/scope-changed/catalog-changed evidence, failed-job history, polling races, corrupted-cache fail-closed behavior and verified cache rebuild.

The PostgreSQL test containers are disposable and expose their database only on host loopback. Container API smoke traffic stayed within the private test network. No public customer service was deployed. The Linux suite used read-only mounts of application/tests/project metadata and a separate disposable database from the Windows suite.

The golden fixtures are synthetic exports/schema generated from the independently installed 0.2.0 wheel. They are deliberately included in source distribution; real evidence exports, credentials, runtime environment files, databases and raw vendor captures remain excluded.

Three benign warnings remain: two upstream HTTPX deprecation warnings and the intentional duplicate-ZIP-member attack-test warning. Remote GitHub CI was not dispatched. Visual browser QA remains pending because browser access to the existing error tab was blocked earlier in this session. API and source verification do not establish visual correctness.

Live customer OIDC/provider permissions, operational PITR/restore, shared ingress/external alerting, capacity/soak testing, image vulnerability scanning and independent security review remain required. Unsigned reports and audit chains require trusted external anchors; they do not authenticate provider assertions or establish audit-period operating effectiveness.

See [MONITORING.md](MONITORING.md) for operation/upgrade semantics and [HARDENING.md](HARDENING.md) for remaining launch gates. [The previous validation record](VALIDATION_0_2.md) is preserved separately.
