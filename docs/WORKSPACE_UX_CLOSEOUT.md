# Workspace UX follow-up closeout

24 October 2026. This revision completes the requested development for private recovery, friendly owner labels and server list navigation, and broadens the automated accessibility/reflow review. It does not replace deployment-specific security acceptance or human assistive-technology review.

| Area | Implemented and checked |
|---|---|
| Persistent drafts | Encrypted server copies, seven-day expiry, per-person/workspace/type keys, My drafts discovery/resume/discard, autosave serialization, revision conflicts, role-change cleanup, key rotation and publish cleanup |
| Friendly owners | Administrator-managed audited labels; exact subject remains visible and authoritative; no change to roles or approval identity |
| Pagination | Server search/filter/sort before slicing; 10/25/50 page sizes; deterministic ties, page clamping, authorized counts and keyboard focus after paging |
| Accessibility | axe-core 4.14.0 across eight page views and five governance forms, upload/member/draft dialogs and narrow reflow; contrast fixes; explicit manual limitations |

## Actual validation

- Windows Python 3.10.11, real PostgreSQL 17.11 enabled: **412 passed, two POSIX-only skips, 259 subtests passed**. Eight PostgreSQL cases include forced RLS for both new tables and concurrent draft compare-and-swap. An independently reset schema-5 fixture additively migrated twice while preserving its governance record.
- **11 Node presentation regressions passed**, including password/upload exclusion, supported checkbox/toggle recovery, record-type transition binding and serialized autosave/manual tasks with failure recovery. JavaScript syntax and Ruff F passed.
- Local Keycloak code/PKCE sign-in and a PostgreSQL DML runtime identity; schema metadata is SELECT-only. The browser recovered title/scope after application sign-out/reauthentication, retained separate record-type work, published a recovered risk and verified its recovery copy was cleared.
- Monitoring recovered the edited value 48 after navigating away and saved it successfully. Document metadata recovered its title and control selection with an empty upload field. My drafts listed only the current person's copies and resumed the correct document form. Membership label editing retained the exact subject/role. A manual team-note draft resumed from My drafts and remained a self-attestation requiring human review.
- Multi-page synthetic data: 35 governance records and 26 documents. Page two, stable title ordering and search outside the current page worked; owner-label search found the expected record. Existing tenant/auth/approval/export regressions remain in the complete suite.
- Populated overview/control/evidence views were additionally scanned using a zero-pass empty-source snapshot (11 unknown checks, three human-review controls). This found metric/count contrast issues that first-run pages did not expose; all were corrected. Auditor document/governance views had zero automated violations and no private-draft action.
- Final scanned page/form states had zero automated accessibility violations. Incomplete/manual findings are preserved rather than converted into passes. No page-level register overflow at the checked widths; a 768-pixel table retains its own named scroll region.

See [private recovery and paging](WORKSPACE_RECOVERY.md), [accessibility methods and limitations](ACCESSIBILITY.md), [sanitized machine results](qa/accessibility-workspace.json), and synthetic [desktop](qa/workspace-recovery-desktop.png)/[mobile](qa/workspace-recovery-mobile.png) screenshots.

Schema 6 requires an explicit schema-owner migration and runtime grants for `ct_drafts` and `ct_member_profiles`; 19 tenant-scoped tables force RLS. New image/distribution artifacts are rebuilt from the current revision; older hashes in VALIDATION.md remain historical. Real Google/AWS/provider validation, measured cloud capacity, off-host recovery and independent security/auditor acceptance remain release gates.
