# ClearTrail reference investigation

Investigation date: 23 October 2026. User-selected reference: the shared Vanta / Drata evidence collection workflow. This is a clean-room product study for an independently implemented, local compliance evidence collector. ClearTrail is not a fork of either product and does not establish feature parity, SOC 2 attestation, ISO 27001 certification, or auditor acceptance.

## Method and boundary

Applied the explicitly requested reverse-engineer-anything research workflow and its runtime-observation reference. REA launched the already installed Microsoft Edge executable with a temporary, empty profile, navigated to two official public help articles, waited for the article title, and captured selected rendered artifacts. REA performed these declared navigation/wait actions. Both successful runs report that the owned browser process was terminated during cleanup.

This observed the public documentation pages, not authenticated product workflows or vendor internals. No vendor account, private source code, paid application access, credentials, source maps, network bodies, or storage values were requested. No vendor code, visual assets, standard text, or proprietary test catalogue is used as application implementation.

## Finding ledger

The following are observations of published documentation. Statements about the vendors' applications remain vendor-described behavior rather than independently exercised application behavior.

| ID | Observation and source | Implication for this MVP |
| --- | --- | --- |
| REF-01 | Vanta documents a GitHub App with read-only monitoring by default. Its guide describes repository configuration, merged pull requests, organization membership, and vulnerability alerts as evidence inputs. [Official GitHub integration guide](https://help.vanta.com/en/articles/14845240-github-integration-guide) | Prefer minimal read permissions and explicit collection scope. ClearTrail's independently chosen token-based MVP connector is different from Vanta's connection method. |
| REF-02 | The same guide describes branch protection and code-review checks, a production/default branch boundary, repository selection, and partial support for GitHub Rulesets. [Official GitHub integration guide](https://help.vanta.com/en/articles/14845240-github-integration-guide) | Report precisely which settings and repositories were inspected. Classic branch protection alone cannot justify claims about every effective ruleset or actual review history. |
| REF-03 | Drata describes evidence linked to controls, reusable across frameworks, with owners, current artifacts, renewal states, prior versions, and automatically generated test artifacts. [Official Evidence Overview](https://help.drata.com/en/articles/13404035-evidence-overview) | Keep the evidence artifact and its control references together. Record collection time and provenance; make missing/manual evidence visible. |
| REF-04 | Drata distinguishes missing artifacts, renewal needs, and test errors; an evidence item being available is distinct from its test passing. [Official Evidence Overview](https://help.drata.com/en/articles/13404035-evidence-overview) | Keep evidence availability separate from check outcomes. An API error must not become a passing result or proof of a failed security setting. |
| REF-05 | Drata describes third-party connections plus manual evidence, periodic reviews, and attestations where automation does not apply. [Official Understanding Connections](https://help.drata.com/en/articles/13273728-understanding-connections-in-drata) | Automated settings checks cover a subset of a compliance programme; people and process controls still require review. |
| REF-06 | Drata documents individual evidence downloads and an audit/date-scoped package, and cautions that the latter may not contain all evidence types. [Official manual export guide](https://help.drata.com/en/articles/13464187-manually-export-evidence-data-from-drata) | Export an explicit manifest with scope, included files, results and limitations, so a reviewer can identify what is present and absent. |

## REA evidence retained locally

`docs/research/rea-public-reference-evidence.json` is a local provenance bundle. It includes captured vendor documentation and is excluded from public source distribution; use the concise finding ledger and manifest when sharing the project. Evidence identities refer to the bundle's original records.

| Evidence ID | Target and selected artifacts | Coverage |
| --- | --- | --- |
| `ev_c0dac3290ec8c549ae3171f17fe2f9b35499c8507dc1eca37a15d41458c40645` | Vanta GitHub integration guide; DOM, accessibility tree and final URL | Completed navigation and title wait. Requested sections complete. DOM SHA-256: `2473d43cecfd537f49d8ebc502d3c67e711c28469da638d3840f08c13398627b`. |
| `ev_34276d97c4ab132372c987c70c6c048a874228faa6d3ff40f7d4188489ab9cf1` | Drata Evidence Overview; accessibility tree and final URL | Completed navigation and exact article-title wait. Requested sections complete. Accessibility SHA-256: `e86ed34fb87b37e695971656ac9df30e9c8c7f4266ab3d9e8faa0049f5d0dbc9`. |
| `ev_0cb9b4ccce8d57a6142aeee6d8d0858f3a3fb025ed370eced1c2dd511683a462` | Initial Drata article attempt | The generic `h1` wait failed because the page has multiple matching headings. The final accessibility capture succeeded, but this scenario is incomplete and is not used to claim a successful wait. The subsequent exact-title selector corrected the input. |

The first attempted Vanta request used an empty action array and was rejected by input validation before browser launch. The corrected request supplied the required wait action. No installation, client reconfiguration, authenticated access, or native binary session was needed.

All captures used the installed executable `C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe`; the provider reported Chromium `155.0.4283.62`, a 1280 × 720 viewport, and process isolation. Host platform/architecture and immutable application-artifact identity were not observed by REA. Events, screenshots, history, storage and network content were not requested. Completeness applies only to selected artifacts at capture time, not to all product behavior or all background activity. Public pages and provider behavior may change.

## Independent design decisions

These decisions are analyst inferences and product choices, not recovered vendor algorithms:

1. Use a local Python dashboard and explicit collection runs for an accessible first version. Keep credentials outside exports and the browser-facing UI; make demo data unmistakable.
2. Offer read-only GitHub, Google Workspace, and AWS collection with transparent prerequisites. Keep an unconfigured integration distinguishable from a connected integration with no resources.
3. Evaluate a small, inspectable control catalogue. Store source identity, timestamps, observed settings, resource scope, result, remediation and limitations. Return unknown/error when permissions, APIs, unsupported features or incomplete data prevent a defensible decision.
4. Associate selected checks with illustrative SOC 2 / ISO 27001 control references using original descriptions. A mapping is a review aid; it does not demonstrate that an entire framework requirement has been satisfied.
5. Export an evidence pack with machine-readable observations and a readable report. A checksum can detect changes relative to the manifest; it does not prove the source was truthful, the collector was trustworthy, or the organization operated a control throughout an audit period.
6. Describe the offering as free, open-source software. Third-party accounts, infrastructure, professional support and independent audits can have their own costs. No investment-return or vendor-pricing claim is established by this investigation.

## Questions and residual unknowns

| Question | Status | Boundary or next evidence needed |
| --- | --- | --- |
| What is the common collection → checks → linked evidence → export pattern? | Answered at public-documentation level | Finding ledger REF-01–06; two public page runtime captures. |
| Which GitHub settings and access boundaries are material? | Partially answered | Vanta's guide describes the reference behavior. ClearTrail must validate its own connector against current GitHub API responses and scope. |
| Does ClearTrail match either vendor's implementation? | Unresolved and outside MVP scope | No private application behavior, source code, algorithms or parity suite was available. |
| Do live GitHub, Workspace and AWS checks work for a real organization? | Unresolved by this research | Requires user-authorized accounts, permissions and live run verification. Fixtures or demo runs do not establish this. |
| Will an auditor accept an exported pack? | Unresolved | Requires the auditor's scope, period, population and evidence requirements, plus human review. A generated report is preparation material. |
| Does the tool provide ongoing monitoring, full policy workflows, access reviews or a complete ISMS? | Outside this research / initial MVP | Public reference coverage is broader than the small local evidence collector. Do not imply these capabilities without implementation and validation. |

No equivalence claim or reconstruction verification is made. The REA observations support the public-page findings and their provenance only.
