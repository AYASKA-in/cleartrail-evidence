# Validation of 0.2.0

Checked on 23 October 2026 using Python 3.10.11 on Windows. Results apply to
the local source and locked hosted runtime, not an externally deployed service.

| Check | Actual result |
|---|---|
| Full Python regression suite | **233 passed, 5 skipped; 259 subtests passed** |
| Skips | Three PostgreSQL tests lack a running disposable database; two filesystem tests require POSIX |
| Warnings | Two upstream HTTPX deprecation notices and one intentional duplicate-ZIP-member test warning |
| Exact runtime dependency audit | 36 locked distributions; no known vulnerabilities reported by pip-audit at check time |
| Dependency consistency | `pip check`: no broken requirements |
| Reproducible runtime install | `pip install --require-hashes -r requirements-hosted.lock` passed |
| Linux Python 3.12 artifacts | All 36 locked runtime distributions downloaded with compatible wheels and verified hashes |
| Python / JavaScript syntax | `compileall` and `node --check` passed |
| Static correctness | Ruff F checks passed across application, scripts and tests |
| Python release build | Wheel and source distribution built successfully with setuptools 84.2.1 |
| Compose schema | `docker compose config --quiet` passed using the example environment file |
| CLI workflow | Synthetic collect, export, structural/hash/render verification and SQLite health check passed |
| Hosted worker workflow | Real isolated subprocess atomically persisted an unconfigured live-mode snapshot with zero automated passes |
| Installed wheel smoke test | Collect, export, pinned-manifest CLI verification and backup restore passed independently of the source import path |
| Source archive privacy | 56 allowlisted files; no runtime databases, actual environment/config files, exports, raw captures or recognized credential/private-key patterns |

Security regressions cover customer data and export isolation, guessed foreign
snapshot IDs, workspace switching/stale tabs, roles, membership revocation,
last-admin protection, session expiry/hash storage, CSRF and malformed requests.
Real RSA token verification rejects invalid signatures, issuer, audience, nonce,
expiration and issued-at claims. Credential tests cover context substitution,
rotation, no-secret browser state and workspace-bound AWS external IDs.

Job tests cover single flight, persisted scope/notes, lease expiry, failed jobs,
subprocess environment isolation and timeout. Provider tests cover malformed and
partial populations, scope, pagination, retries and secret redaction. Evidence
tests cover semantic forgery, manual-evidence rehashing, database/audit tampering,
backup restore, ZIP/decompression attacks, CSV/HTML injection and atomic exports.

The additional Ruff security-rule review reported three patterns requiring human
triage: URL opening, subprocess execution and suppression of a child-process
failure while writing its generic error record. The URL helper enforces an exact
HTTPS origin allowlist before constructing authorization headers and denies
redirects. The subprocess uses a fixed absolute interpreter/entrypoint argument
list, isolated environment and no shell. Child failure output deliberately omits
exception details to prevent credentials entering logs. These were reviewed,
not treated as evidence that static analysis found no security risks.

The local demonstration server was restarted with capability authentication.
Browser security blocked attaching to the existing error tab, so version 0.2's
new sign-in, member and integration UI has **not** received fresh visual QA.
Version 0.1 had been checked on desktop and a 375 × 812 phone viewport; that does
not establish visual correctness of the new hosted flows.

No customer provider credentials or live IdP were available. Connectors use mocked
responses; signed-token tests use locally generated keys. Docker's Linux engine
was not running, so the container image and PostgreSQL runtime tests were not
executed here. Wheel compatibility is not a substitute for those tests. CI jobs
are provided for Windows/Linux, PostgreSQL RLS/concurrency and container builds,
but were not dispatched or observed in this session.

The allowlisted source ZIP excludes evidence databases, credentials, real runtime
environment files, exports, virtual environments and raw reference captures.
Complete the [customer launch gates](HARDENING.md#required-launch-evidence)
before production onboarding. The assessment also lists remaining product work,
trust assumptions, operations, recovery and independent-review requirements.
