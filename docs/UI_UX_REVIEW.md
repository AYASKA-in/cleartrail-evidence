# Workspace UI and usability review

Checked 24 October 2026 with synthetic data. This is an implementation and focused browser review, not an independent accessibility assessment or production acceptance.

## Changes delivered

| Gap | Result |
|---|---|
| Small labels and controls | Larger body/table/helper text, stronger muted/status colors, consistent focus rings and 44-pixel primary controls |
| Mobile navigation hid destinations | Explicit Menu disclosure exposes all eight hosted sections; Escape returns focus to its toggle; selecting the current page also closes it |
| Long document/governance lists | Labeled search, review/type/overdue filters, live visible counts, clear/reset actions and actionable empty states |
| Dense registers on narrow screens | Document/governance rows become labeled cards while retaining every metadata field; other wide tables are keyboard-focusable scroll regions |
| Unclear first step | First-collection guidance links to sources, team files and governance, with role-specific instructions |
| Lost editing context | Modal close/Escape asks before discarding changed input, restores field/opener focus; background refresh preserves open dialogs and dirty monitoring forms |
| Lost connection | Persistent connection message, automatic retry and a manual Retry action retain the last loaded view and inputs |
| Confusing exports | Reports separates configuration snapshots, exact-file audit packages and JSON governance registers, with scope and verification guidance |
| Weak action feedback | Save/export buttons indicate progress, recover after failure and clear stale validation errors on retry; selection legends report chosen versions |
| Workspace/role transitions | Clear workspace-specific caches/filters and abort/discard old refresh responses; auditor actions and status choices match visible permissions |
| Skip link changed the application route | Skip now focuses main content without replacing the current view hash |

Search operates on the records already returned by the authorized server. It is not an access-control boundary. No customer search/filter state is persisted to browser storage; role/workspace changes force a fresh render even during editing. The existing server authorization, approval, CSRF, encryption and evidence limits remain authoritative.

## Verification performed

- Windows Python 3.10.11: complete suite **376 passed, 9 skipped, 259 subtests passed** without a PostgreSQL test URL. The seven PostgreSQL-specific tests then passed against a separate disposable PostgreSQL 17.11 database. The remaining two skips are POSIX-only cases. Combined coverage: **383 test cases passed** across these invocations.
- Node.js 24: seven pure presentation regressions passed, covering combined search, exact review/type filters, overdue records, no source mutation, context changes and bounded error messages. CI runs Node tests explicitly; Node is not required by the deployed application.
- JavaScript syntax, Ruff F and distribution builds checked separately. Static-asset MIME/routing tests include the new helper script.
- Real local Keycloak code/PKCE sign-in with a synthetic identity, a DML-only PostgreSQL application role, an admin workspace and a second auditor-only workspace.
- Browser: combined document search/status filtering; governance text/type/overdue filters; a complete risk form saved as pending; supporting-version selection counts; Close/Keep editing/Discard and Escape; preserved title and restored field focus.
- Browser: Reports governance export and selected document ZIP both produced download confirmation and a trusted-digest display. An empty selection failed safely; selecting a file and retrying cleared the old error and restored the button. Offline verification security remains covered by backend regression tests; the download bytes were not separately reverified in this UI review.
- Controlled local API outage: the warning appeared, the unsaved freshness value remained 48, automatic reconnection cleared the warning, and the same edited value saved successfully. The manual Retry control was observed; automatic polling recovered before its click could be exercised.
- Local synthetic demo: existing 14-control overview rendered, evidence search retained `AWS-S3` through a completed collection, and Reports linked the exact new snapshot. No browser errors/warnings were recorded in that local demo tab.
- Narrow widths **320 and 375**, plus **1280×900** desktop: all hosted navigation links reachable; no page-level horizontal overflow on the checked register views. Menu Escape returned focus to its toggle. Skip retained `#documents` and focused `main`.

Screenshots contain only synthetic records: [desktop](qa/workspace-desktop-ui.png), [mobile](qa/workspace-mobile-ui.png).

## Follow-up completed

Private encrypted recovery (including a My drafts list), administrator-governed friendly labels and server search/filter/sort/page navigation are implemented. The broader automated scan covers eight page views and five governance forms, with keyboard/reflow checks and contrast remediation. See [WORKSPACE_UX_CLOSEOUT.md](WORKSPACE_UX_CLOSEOUT.md) for current measurements, [WORKSPACE_RECOVERY.md](WORKSPACE_RECOVERY.md) for behavior/limits and [ACCESSIBILITY.md](ACCESSIBILITY.md) for actual test scope. This original review's counts describe the preceding UI baseline.

Actual NVDA/VoiceOver and representative-user sessions, additional browser engines and native OS accessibility-mode acceptance remain separate manual validation. Engagement-specific auditor onboarding, guided provider authorization, bulk evidence actions and broader remediation are product-roadmap work, outside this UI follow-up.

Cloud deployment, live provider acceptance and independent operational/security release gates remain in [RELEASE_GATES.md](RELEASE_GATES.md).
