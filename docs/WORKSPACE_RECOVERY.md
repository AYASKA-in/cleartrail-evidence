# Private recovery, identity labels and list navigation

These hosted workspace features require **schema 6**. They use the existing OIDC identity, active-workspace checks, CSRF protection, encrypted vault and PostgreSQL row-level security. Local/demo use still requires no hosted dependencies; it does not persist hosted private drafts.

## Recover unfinished work

Governance forms (all five record types), team-document metadata, monitoring policy and manual team notes keep private server recovery copies while you edit. **My drafts** lists your available copies and provides Resume and Discard actions. Resume opens the relevant form; choose **Restore draft**, review the recovered fields, then publish through the usual save/approval workflow.

- Recovery copies expire seven days after their last save. At most 20 copies per person/workspace, each up to 32 KiB, are retained. Expired copies are unavailable immediately; expired database rows are purged on the next draft write in that workspace. Backups follow the operator's separate retention policy.
- No localStorage, sessionStorage, IndexedDB or service worker stores draft text. Recovery survives a page reload and application sign-out, but requires signing back in as the same issuer/subject in the same workspace.
- Provider credentials, member administration, review decisions and upload files are excluded. Re-select an upload file after restoring document metadata. Exact supporting evidence links may be recovered; the server rechecks them before approving/publishing records.
- Governance drafts are separate for each record and type. Switching types saves the previous supported fields first. My drafts can reopen the appropriate type directly. Restoring after typing requires confirmation before replacing the current edits.
- **Save draft now** requests immediate recovery. **Close and keep draft** retains it; **Discard changes** removes the current recovery copy. The private-draft panel can discard a saved copy while leaving current form text in place.
- Successful publication clears that form's recovery copy. A stale or unavailable cleanup is reported rather than silently deleting a newer copy from another tab.
- Writes compare a random revision token under the workspace transaction lock. A concurrent tab cannot silently overwrite another tab's draft. Automatic/manual saves serialize in the browser. A conflict preserves the server's newer copy; reopen the correct workspace/form to recover it.
- Changing/removing a person's role discards their private recovery copies in that workspace. A newly granted role cannot recover work retained under a previous role. Expired/revoked sessions and auditor access cannot read private recovery.

Drafts are not approved evidence, audit-chain events, independent review decisions or export inputs. Their field envelope authenticates the tenant, issuer, subject, form key, role, revision and timestamps. Metadata needed to locate/expire a copy is stored separately. Vault rotation includes draft envelopes. An operator with database/key access is inside the same trusted service boundary as other encrypted workspace evidence.

Unsupported forms keep the existing unsaved-change guard; integration credentials are intentionally never recoverable. Recovery requires a successful connection/save: edits made during an outage are not guaranteed durable until the UI confirms a save. The page-unload warning remains for unprotected work. Role/workspace changes always take precedence over retaining an editing screen.

## Govern friendly names

An administrator uses **Members → Friendly identity labels** to label an existing workspace member. Labels are presentation metadata, bounded to 80 plain characters and audited when changed. Leave the field blank to remove a label. This action cannot add membership or change a role.

Owners and reviewers show their friendly label with the exact identity subject; owner selections retain exact subjects. Duplicate labels do not combine accounts, waive independent-review rules or grant access. Labels are scoped to the workspace/configured issuer. Auditors receive labels only for identities in records they are authorized to see; they cannot browse the administrative member directory.

## Navigate bounded libraries

The document and governance libraries request pages of 10, 25 or 50 records. Search and type/review filters apply to the entire authorized list before slicing, including friendly owner labels. Sort by newest/oldest, title, owner or review/expiry date. Stable IDs break ties. Changing filters/order/size starts at page one; a no-longer-existing page clamps to the final available page.

Counts and summary values describe only the current role's visible population. A query cannot select a tenant/person, duplicate parameters, unbounded page size or arbitrary ordering. Server projection remains bounded by existing quotas (100 documents / 250 governance records); this is response pagination over that bounded projection, not an unbounded database search service. Concurrent inserts may change offset-page membership; refresh when reconciling a changing register.

Pagination is keyboard accessible and labeled. Changing pages focuses the resulting table region. On narrow screens, labeled cards preserve document/governance metadata; intermediate-width tables retain a named, focusable scroll region.

## Operator upgrade

Stop/quiesce writers, back up the database and vault keys, and run the explicit schema-owner migration. Version 6 additively creates `ct_drafts` and `ct_member_profiles`, preserving earlier evidence/ciphertext and schema versions 1–5. Grant the runtime role DML on the two new tables, keep `ct_schema` SELECT-only, then check readiness with the runtime identity. All **19** tenant-scoped tables require forced RLS. Never give the web process schema ownership or BYPASSRLS.

See [HOSTED_DEPLOYMENT.md](HOSTED_DEPLOYMENT.md), [RECOVERY.md](RECOVERY.md) and the [UI closeout measurements](WORKSPACE_UX_CLOSEOUT.md).
