# Internal security review: 0.5.0

Reviewed 23–24 October 2026 using synthetic fixtures, source inspection, tests
and local containers. This is an internal assessment, not an independent
penetration test or compliance certificate.

## Remediation and boundaries

- Session rate budgets use canonical capabilities/IPs; unrelated cookies cannot
  reset the budget. A separate IP budget bounds token churn. Shared limits across
  API replicas remain an ingress responsibility.
- Office ZIP/XML parsing bounds members/decompression and rejects unsafe paths,
  DTD/entities, external relationships, macro/embedded-object indicators and bad
  deflate streams. Scanning finishes before publication; stale/unavailable/limited
  scanner responses fail closed. Authenticated envelopes bind scan provenance.
- Audit verification validates review/document/control graphs, regenerates HTML,
  checks trusted digests, and never extracts/executes customer files. Packages are
  unsigned; scans/approval are recorded as of export and cannot recall downloads.
- Real browser QA found and fixed CSP-blocked chart styles and broken Unicode.
  An XSS-like synthetic document title remained escaped text.
- Final runtime uses pinned Alpine Python and unchanged hash-locked dependencies,
  with unused pip/ensurepip removed. The scanner applies an exact available libc
  patch rather than suppressing its advisory match.

## Static analysis triage

Ruff F passes. Ruff S returned four contextual alerts, retained for review:

| Rule / source | Disposition |
|---|---|
| S110 `collector_process.py` | Redaction fallback deliberately avoids logging potentially secret-bearing exception text or corrupting the child protocol; parent receives a generic failure. |
| S310 `connectors.py` | URL calls are behind exact HTTPS scheme/origin checks, no redirects and response/request budgets; arbitrary file/custom-scheme destinations are rejected. |
| S314 `documents.py` | Bounded UTF-8 XML rejects NUL, DTD and ENTITY declarations before ElementTree; no XInclude resolution; external relationships denied. Keep Python/Expat patched and expand corpus/fuzz testing. |
| S603 `isolated.py` | Absolute trusted interpreter, isolated mode, fixed script/argv, no shell, restricted environment, deadlines and output bounds. Credential-context separation is not an untrusted-code sandbox. |

These are internal review decisions, not proof that the primitives have no bugs.
No unreviewed blanket suppression was introduced.

## Supply chain

Trivy 0.76.1 scanned saved image archives without the Docker socket, against the
fresh database obtained on 23 October 2026 UTC. Both final images reported
**zero known vulnerability matches across all severities**:

- Application `sha256:83ff48d8c948dbd1104ecaf0bad37de35ec9827b337b7350e68c9cd583f6469a`.
- Scanner `sha256:425e3a320c6054bef7a52d51dda9e5b1241f1c28a26b76541342fb8b4a34c455`.

Reports under `docs/security/` preserve inventories/timestamps. Earlier Debian
base advisory matches were not claims of confirmed application exploits. Final
images were rescanned after remediation. `pip-audit` reported no known
vulnerabilities in the 36-distribution runtime lock. Results are time-specific,
exclude operator IdP/PostgreSQL/ingress and do not detect source logic flaws or
zero-days. Rescan regularly; CI gates known High/Critical image findings.

Operators, database administrators, IdP and worker host remain trusted. Fourteen
evidence tables use forced RLS; control-plane membership/session tables are scoped
by application queries. Stolen operator keys/arbitrary SQL need infrastructure
defenses. AV does not make files safe to execute. A small local read-load test
does not establish production capacity. Independent security/auditor review,
off-host recovery, managed keys, external anchors, retention and incident handling
remain explicit [release gates](RELEASE_GATES.md).
