# Security policy

ClearTrail 0.5 has a separately supported local collector and hosted deployment artifacts.
It has not completed an independent penetration test or a live multi-customer
production rollout. Local OIDC/browser, scanner and restore checks are documented
in [readiness evidence](docs/RELEASE_GATES.md). See [the hardening assessment](docs/HARDENING.md) before onboarding
customers. Compliance frameworks and audit decisions require independent review.

Report a suspected vulnerability privately to the repository maintainer through
GitHub's **Report a vulnerability** feature when enabled. If unavailable, open an
issue requesting a private contact without disclosing the vulnerability, tokens,
evidence, personal information, or customer account details. This project does
not yet have a dedicated security-response mailbox or response-time commitment.

Include the affected version, deployment mode, minimal reproduction with synthetic
data, expected boundary, and impact. Rotate exposed provider credentials and
invalidate affected sessions immediately. Preserve relevant audit anchors and
database backups for investigation. Do not test another customer's accounts.

Only the latest release receives fixes. Hashes and audit chains detect changes
relative to a trusted external anchor; they are not source signatures and do not
protect against an administrator who can rewrite both records and anchors.
