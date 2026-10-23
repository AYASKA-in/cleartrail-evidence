# Team evidence in 0.5

The hosted **Team documents** page supports uploaded evidence, assigned
owners, immutable file versions and independent review. It works without a paid
storage or scanning service. Optional self-hosted ClamAV enables PDF and modern
Office uploads; Python runtime dependencies are unchanged.

## Workflow

1. An administrator or operator uploads supported text, PDF or modern Office
   evidence, selects existing controls and a responsible workspace member.
   Optionally set an expiry, interpreted in the browser's local timezone.
2. A different administrator or operator downloads the exact version and records
   approval or rejection with a rationale. The uploader, owner at upload, and
   current owner cannot approve or reject it. A second eligible person is required
   for approval; there is no single-administrator approval bypass.
3. Replacement uploads retain old bytes and reviews and begin **pending**. Stale
   upload, assignment and review forms return 409 instead of changing newer work.
4. Reviews append to history. A subsequent rejection or withdrawal supersedes
   the previous decision for that version. Expiry independently prevents current
   approval and auditor downloads, while retaining the historical decision. Any
   administrator or operator can withdraw sharing of a current or older approved
   version, including its owner/uploader after a reviewer leaves. Withdrawal
   remains available when a stored file is corrupt; it does not approve bytes.

Auditors cannot upload, assign or review. The list shows documents whose latest
version is approved and unexpired. When an auditor opens a known document, its
older approved, unexpired versions remain available even if its newest version
is pending. Pending/rejected/withdrawn/expired versions return 404 to auditors.
Administrators and operators retain access to the complete history.

Approval records a customer review of specific bytes. It does not establish
that a control passed, that every account was reviewed, or that the evidence
covers an audit period. Uploaded files never change automated check results or
convert manual self-attestations into independently verified provider evidence.

## Storage and limits

File contents use authenticated Fernet encryption with the existing vault key
ring. Envelopes bind the tenant, document, version, sequence, filename, byte
count, SHA-256, uploader, owner at upload, creation time, expiry and the new scan
record. Existing 0.4 text envelopes remain byte-for-byte unchanged. Downloads
and review decisions verify both ciphertext and the bound metadata. Corruption
or a swapped envelope fails closed with HTTP 503. Titles, ownership, control
links and review metadata are database fields protected by tenant authorization
and RLS; they are not encrypted application metadata.

Files and metadata commit in one PostgreSQL transaction. There is no writable
container volume or separate object-store backup to coordinate. Back up the
database **and** protect the vault keys separately. Losing every applicable key
loses access to uploaded contents. `rotate-vault` also rotates document
envelopes; keep old keys until all tenants and backup recovery have been checked.
A damaged document rolls back that tenant's entire rotation.

Limits are 512 KiB per file, 25 MiB of original file bytes per workspace, 100
documents, 20 versions per document and 20 review decisions per version. The
final review slot cannot approve, preserving a rejection/withdrawal slot. The
database and backups use additional space for encryption, indexes and history.
Tenant locks serialize quota accounting, uploads, reviews and assignment.
Library requests batch metadata queries and never load encrypted file contents.

Uploads are authenticated, CSRF checked and workspace bound before allocating
the larger upload body buffer. The endpoint accepts bounded JSON with base64
contents; other endpoints retain their 128 KiB limit. Filenames use a restricted
ASCII grammar. Text requires UTF-8 without NUL/hidden formatting characters.
Binary files require fresh scanning and bounded structural validation before
publication; see [SCANNING.md](SCANNING.md). Downloads are attachments with
`nosniff`, no-store and restrictive CSP. Text uses `text/plain`; binary uses
`application/octet-stream`. Contents are never previewed, executed or parsed for
compliance claims. Customer files and scans do not establish content trust.

Uploads, ownership changes, version-bound decisions and successful downloads
append tenant audit events without file contents. Version/review history is
immutable through the application; database administrators remain privileged.
Use independently retained audit heads for tamper evidence. There are no delete,
overwrite or public-sharing endpoints in this release.

## Upgrade

Stop API, worker and scheduler, back up PostgreSQL and retain the key ring. Run
`python -m cleartrail.hosted_admin migrate` using the schema-owner migration
role. Schema **4** additively upgrades versions 1–3; it preserves existing
snapshots, catalogs, schedules and jobs. Grant the restricted runtime role DML
on the document tables if upgrading from before 0.4, then start
the services and check `/readyz`. All three tables require forced RLS. The API
never silently migrates the database. Do not run a previous binary against the
new schema; use the pre-upgrade backup for rollback.

## Remaining development

PDF/modern Office scanning and document-inclusive period packages are implemented;
see [SCANNING.md](SCANNING.md) and [AUDIT_PACKAGES.md](AUDIT_PACKAGES.md). Use
**Reports → Create audit package** for selected approved versions and their review
history. The existing snapshot-only export remains compatible.

Object-storage adapters, effective-date workflows, engagement-scoped auditor
permissions, continuous file re-scanning, image evidence, retention/legal holds,
deletion/offboarding and independently signed archives remain separate product
development. They are not claimed by the period-selection feature.

Real local Keycloak/browser testing, a PostgreSQL logical restore drill and a
bounded load exercise passed. Actual customer identity/provider setup,
hosting/ingress, production recovery objectives and independent human review
still require deployment-specific evidence. See [RELEASE_GATES.md](RELEASE_GATES.md).
