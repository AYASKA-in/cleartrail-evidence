# Accessibility engineering and validation

ClearTrail uses semantic HTML, visible labels, native dialogs/selects/checkboxes, keyboard navigation, explicit focus recovery, status text alongside colors, a skip link, named scroll regions and reduced-motion styling. This is an engineering baseline, not a claim of WCAG conformance or an independent accessibility certification.

## Checked in this revision

24 October 2026, synthetic local OIDC/PostgreSQL workspace, Chromium 156 on Windows. **axe-core 4.14.0** checked WCAG 2 A/AA, 2.1 A/AA, 2.2 AA and best-practice rule tags. The final eight hosted page views and five governance forms had **zero automated violations**. Document-upload metadata, membership/identity labels, private draft management, team-note recovery, auditor libraries and 320-pixel reflow were also inspected. Populated overview/control/evidence views were checked using an honest empty-source snapshot: 11 automated results remained unknown and three controls required human review. Raw sanitized results are in [accessibility-workspace.json](qa/accessibility-workspace.json).

The scan found insufficient contrast in eyebrow/version text, the control-count label, and populated-dashboard metric/idle-provider text; these colors were darkened. The avatar was given its appropriate accessible role. The Google provider mark was darkened after a manual contrast check. Some logo, overlapping/scrolling text dashboard-ring and dialog text checks remain `incomplete` in the raw scanner output: these are not counted as automated passes. The brand/workspace foreground on the sidebar background measures 11.45:1; inspect the checked screenshots and these specific nodes when repeating manual review.

Keyboard checks covered menu Enter/Escape with focus return, navigation and skip-to-main without changing the view, next-page focus, native dialog dismissal, draft Keep/Discard/Restore, immediate saving and post-save recovery. Reflow widths 320, 375, 640, 768, 1024 and 1280 CSS pixels were checked. No page-level horizontal overflow was observed on the checked register view; the intermediate-width data table uses its own keyboard-focusable scroll region. A 320-pixel layout checks the available CSS width associated with 400% zoom of a 1280-pixel layout; native browser zoom was not separately exercised.

Source includes `prefers-reduced-motion` and `forced-colors` adaptations, with visible system-color borders/focus and distinguishable disabled controls. Native OS forced-color/reduced-motion settings were not toggled during this run.

## Reproduce an automated local review

Use only an isolated, disposable hosted deployment and synthetic identities. Install the optional test engine outside application/runtime packaging:

```powershell
npm install --prefix .cleartrail/a11y --ignore-scripts --no-audit --no-fund --save-exact axe-core@4.14.0
python scripts/serve_ui_qa.py --settings .cleartrail/qa-settings.json --axe .cleartrail/a11y/node_modules/axe-core/axe.min.js
```

The settings file uses the ordinary `HostedSettings` keys, a non-production environment and `http://127.0.0.1:PORT` as its public URL. Provision/migrate the disposable database and configure the local identity provider normally. The harness refuses production/external URLs, adds no login bypass and is absent from the normal application factory. Keep settings/secrets under ignored `.cleartrail/`.

Sign in normally, then open `/qa/page#overview` on that loopback origin. Use **Run accessibility audit** on each page; **F8** audits an open dialog. Inspect the actual result, every violation and every incomplete/manual item. The harness excludes its own reporting panel from scans. It does not send results to Deque or any remote service. The deployed application does not require Node, axe or these QA endpoints.

## Manual acceptance that still requires people/devices

An actual NVDA/Chrome and VoiceOver/Safari session, Firefox behavior, native 200%/400% browser zoom, real OS high-contrast/reduced-motion preferences, and usability sessions with representative users were **not performed** here. Automated scans cannot establish reading-order quality, announcement timing, cognitive usability or all focus behavior. Before making a public accessibility-conformance claim, record these sessions, settings, outcomes and any remediation with an independent reviewer.

Use the keyboard to complete sign-in, a document review, all record types and an audit export; listen to names, required/error messages, selection counts, page updates and dialog restoration. Check menu links and pagination at high zoom, long names, empty/error states, and after session/role/workspace changes. Confirm that native shortcuts remain available and that an inaccessible or failed action gives a useful recovery path.
