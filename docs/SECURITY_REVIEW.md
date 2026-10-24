# Internal security review: 0.6.0

Reviewed 24 October 2026 through source inspection, synthetic regressions,
real PostgreSQL and local browser OIDC. This is an internal assessment, not an
independent penetration test or certification. Prior reviewed file/scanner,
session and export boundaries remain in [the 0.5 review](SECURITY_REVIEW_0_5.md).

## Governance boundaries

- Every operation validates membership and tenant scope. Mutation routes require
  CSRF, exact origin and active workspace. Three new tables have composite tenant
  foreign keys and forced RLS, bringing the scoped population to 17 tables.
- Canonical payloads have bounded fields, links, versions and quotas. MultiFernet
  envelopes bind identity, title/owner, type/reference, author/time and digest.
  Governance payloads participate in transactional vault rotation. Search/review
  metadata remains visible to trusted database operators.
- Edits create pending versions. Optimistic record/review identifiers and tenant
  locks serialize competing mutations. Authors/owners cannot approve themselves;
  auditors cannot write. Withdrawal remains possible for older/damaged versions.
- Review/export rechecks exact linked evidence and governance approvals, expiry
  and envelope integrity. Missing/revoked dependencies fail closed. The app's
  approved badge represents a historical decision, not continuous revalidation.
- The separate bounded JSON export includes approved dependency closure. Its
  standard-library verifier rejects malformed schemas, duplicate identities,
  invalid review histories, inconsistent scores/digests and invalid/cyclic links.
  It does not execute content or extract files. Exports are unsigned; trusted
  external digests are necessary against full rewrites. File bytes are separate.
- Browser values remain escaped text. Real QA tested an XSS-like title, separate
  reviewer identity, auditor controls and desktop/mobile layouts. Explicit MIME
  types fix OS-dependent asset inference while retaining nosniff and the CSP.

## Supply chain and deployment

The runtime lock, pinned Python base and scanner are unchanged. Trivy 0.76.1
scanned the final 0.6 application archive on 24 October 2026 UTC and found zero
known vulnerability matches at all severities:
`sha256:be4a4dd4e011fbb479b6e91378ace5932a29a0275fc7611c4889e519a344a694`.
See [inventory](security/application-image-0.6.json). This is a dated database
match, not proof against unknown vulnerabilities or source logic flaws. The
unchanged scanner's last scan is recorded separately in the 0.5 review.

The Mumbai CloudFormation candidate requires an explicit HTTP/HTTPS tester CIDR,
encrypted EBS, IMDSv2 and an SSM-only host role. It opens no SSH/database/scanner
or application API port. No secrets or application installer run through user
data. Data EBS retention protects against stack deletion but continues consuming
credits and does not substitute for backup. Public IPv4, broad outbound internet,
a single host, temporary funding and a floating AMI parameter remain operator
tradeoffs requiring review. A change set must be checked before execution.

## Remaining work before customer launch

No AWS resources, actual Google client, public TLS/DNS, provider customer accounts,
off-host restore or sustained 8 GiB capacity test were exercised. Do not mark
these gates passed based on local fixtures. Customer ownership, risk acceptance,
assessor independence/competence and audit scope require human judgment.

Retention/deletion automation, fine-grained auditor engagements, signed unified
packages, custom scoring, external immutable audit anchors and wider governance
automation remain future work. Trusted operators, database administrators, IdP
and worker host can affect the system; RLS is not protection from those parties.
