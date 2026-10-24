# Governance registers

ClearTrail 0.6 adds hosted customer records for risk assessment, applicability,
internal audit, management review and corrective action. They complement the
14 starter configuration checks; they never change an automated result or
establish certification. Local CLI/dashboard mode does not expose these records.

## What a record contains

| Type | Customer-authored fields |
|---|---|
| Risk | Scope/assets, scenario, inherent and residual likelihood/impact, treatment, plan/acceptance rationale, next review date |
| Applicability | Annex A reference, applicable/not applicable, inclusion/exclusion basis, implementation state, customer description, next review date |
| Internal audit | Scope, criteria, assessor identity, period, findings, conclusion, next review date |
| Management review | Meeting date, participants, inputs considered, decisions/resources, actions, next review date |
| Corrective action | Finding/source, root cause, action, due date, status, effectiveness verification or plan, next review date |

Every type has a title, owner, immutable numbered versions, exact supporting
document-version references and related governance-version references. Fields
are required; write a reasoned “none identified” where appropriate. Use management
review inputs to document context changes, relevant interested parties and
whether climate change is relevant to the organization's context. This supports
recordkeeping for the 2024 amendment; it is not a complete context-assessment
workflow or a claim of conformance.

The applicability register offers the **93 factual reference identifiers** in
Annex A, with one record per reference per workspace. Control descriptions and
inclusion/exclusion rationales must come from the customer. An exclusion requires
a rationale and `not_applicable` implementation state. An applicable item uses
`planned`, `in_progress` or `implemented`. Linked governance records for an
applicability decision must be risk versions. Blank references are not silently
classified; counts show entries, not a compliance percentage. A full Statement
of Applicability needs a competent person's completeness/scope review and a
properly licensed current standard.

Risk scores multiply integer likelihood (1–5) by impact (1–5), separately for
inherent and residual risk. The fixed bands are low 1–4, medium 5–9, high 10–15
and critical 16–25. **This is ClearTrail's starter convention, not an ISO-mandated
method.** Document how your organization interprets each score and accepts risk.
Custom scoring matrices, automated acceptance routing and asset inventories are
future work.

## Identity, versions and approval

Administrators and operators create/edit records, assigning an existing admin or
operator as owner. Each edit—including owner/title changes—creates a new pending
version with an optimistic revision check. Record kind and applicability reference
are immutable. The internal audit assessor must be an existing workspace member
different from the responsible owner; this identity check does not establish
organizational independence or competence.

Only an admin/operator different from the version's author, version owner and
current owner may approve or reject the latest version. Approvals and reviews
are append-only; stale forms fail instead of overwriting a decision. An authorized
writer can withdraw an older approval, including a damaged version. The final
review slot cannot approve, preserving a withdrawal slot. Withdrawal cannot
recall an already downloaded export.

Auditors see approved current records and approved historical versions through
record details. A new pending head hides the record from their current register;
its previously approved history remains available by record ID. This is workspace
membership, not engagement-scoped or expiring auditor sharing.

Dates are calendar dates in UTC; a review becomes overdue after its due date.
Management reviews use the next review date for this indicator. An overdue
indicator does not revoke approval. A corrective action's separate due date is
retained but is not currently part of an automatic reminder/escalation system.

Approval of an implemented applicability entry or completed action requires at
least one approved, unexpired supporting document version. Other records may
also link evidence. Every linked file and governance version is checked in the
same tenant at review time; file envelopes are authenticated. Later withdrawals,
expiry or integrity failures block a new register export until resolved. A saved
approval remains a historical decision and should not be interpreted as continuous
revalidation of its links. Records cannot refer to their own revisions.

## Storage, isolation and limits

Schema **5** adds `ct_governance_records`, `ct_governance_versions` and
`ct_governance_reviews`; PostgreSQL now requires forced RLS on **17** scoped
tables. Migrate with the schema owner, then grant the runtime role DML on the
three new tables. Production readiness rejects an old schema or missing forced
RLS. Migration is additive and preserves document/snapshot bytes.

Payloads use the existing authenticated MultiFernet vault key ring. Their envelope
binds tenant, record/version identity, number, kind, title, owner, reference,
author, creation time, size and digest. Titles, owners, review comments, reference
IDs and review metadata are stored as database metadata, not encrypted private
search fields. Protect database access and backups accordingly. Rotation validates
and re-encrypts governance/file/provider envelopes transactionally; retain old keys
until all tenants and required backups have a tested recovery path.

Per workspace: 250 records, 20 versions per record, 20 reviews per version,
16 KiB per canonical payload and 20 MiB cumulative plaintext payload budget.
Text fields are bounded to 3,000 characters (identity subjects 255, titles 160,
review comments 2,000). Each version permits up to 10 distinct evidence and 10
distinct governance references. The register is limited to 500 exported versions
including dependencies and 12 MiB. Existing request/session/export concurrency
budgets apply. These are staging safety budgets, not measured production capacity.

## Export and offline verification

**Export register** downloads `cleartrail-governance-register.json`: approved
current heads plus the transitive closure of exact, still-approved governance
versions they reference. Historical dependencies may therefore appear alongside
current heads. Pending/rejected/withdrawn records are not exported. Dependencies
are rechecked under the tenant lock, and the export event/digest enter the tenant
audit chain. A broken dependency blocks the export instead of silently dropping
it. Hashes bind contents; the file is unsigned.

Retain the displayed whole-file SHA-256 separately through a trusted channel:

```bash
python -m cleartrail verify-governance cleartrail-governance-register.json --expected-sha256 TRUSTED_DIGEST
```

The verifier needs only Python's standard library. It checks strict schemas,
version/review identity and sequence, independent approval, payload digests,
risk calculations, dependency completeness and cycles. Without a trusted digest,
an attacker can rewrite an unsigned file and recompute its hashes. The verifier
cannot validate provider truth, historical identity membership, auditor competence,
full-period effectiveness or withdrawals made after export.

**Supporting file bytes are not embedded in this register.** Use the existing
[document audit package](AUDIT_PACKAGES.md) for exact approved files, scan records
and reviews. The register lists their version IDs but does not authenticate their
bytes by itself. A unified signed engagement package, cross-package reference
verification and a printable SoA are future work. Snapshot and document package
formats remain unchanged and continue accepting their older supported generators.

## Reference provenance

This design was informed by privately supplied ISO/IEC 27001:2022 and a historical
2012 ISACA SOC 2 user guide. Neither PDF nor its extracted normative text is
distributed. The 2012 guide is background, not the current SOC 2 criterion source.
Record schemas, UI labels and validation rules are original implementation work.

Use [AICPA's published Trust Services Criteria resource](https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria-with-revised-points-of-focus-2022)
for current SOC 2 mapping review, and consider
[ISO/IEC 27001:2022/Amd 1:2024](https://www.iso.org/standard/88435.html).
Existing catalog `2026.10.1` remains frozen; its 14 checks and indicative mappings
are not expanded into full-framework coverage by these governance records.
