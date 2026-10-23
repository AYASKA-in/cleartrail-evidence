# Contributing to ClearTrail

Help make evidence collection inspectable, secure and useful to small teams.
The current release is a staging foundation. Be precise about what a change
observes, proves and leaves unknown; a setting check is not a compliance opinion.

## Choose the right channel

- Use GitHub Issues for non-sensitive bugs and scoped proposals. Include version,
  deployment mode, steps, expected/actual behavior and a synthetic reproduction.
- Follow [SECURITY.md](SECURITY.md) for vulnerabilities. Do not post credentials,
  customer evidence, account inventories or personal information publicly.
- Discuss new providers, migrations and substantial workflows before building
  them. Define permissions, populations, bounds and missing-data semantics.

## Set up a development environment

Fork/clone the repository, create a focused branch, and use Python 3.10+ in a
virtual environment:

```bash
python -m pip install --require-hashes -r requirements-hosted.lock
python -m pip install -e ".[dev]"
python -m pytest -q
python -m ruff check cleartrail scripts tests --select F
```

Node.js is optional for `node --check cleartrail/static/app.js`; no frontend build
is needed. Preserve standard-library local/core and offline-verifier execution.

PostgreSQL tests use `CLEARTRAIL_TEST_POSTGRES_URL` for an empty disposable database
owned by a non-superuser/non-BYPASSRLS role. They create data. Never use customer
databases. Without the variable, those tests skip; CI supplies an ephemeral
database. Windows skips the POSIX-only filesystem cases.

## Engineering expectations

- Keep changes focused and explain the resulting behavior for users/reviewers.
- Add meaningful regression coverage for bugs and security boundaries. Exercise
  tenant isolation, permission changes, malformed data and unknown coverage when
  relevant; do not only duplicate the implementation in tests.
- Provider APIs must remain read-only, explicitly scoped and bounded. Hidden or
  inaccessible resources cannot become passes. Do not persist raw SDK errors or
  silently broaden required permissions.
- Preserve role, CSRF, origin and active-workspace boundaries. Recheck permissions
  in the transaction that commits sensitive writes or exports.
- Preserve immutable encrypted evidence, independent approval and historical
  verification. Schema changes need explicit migrations, compatibility/recovery
  analysis and tests; never migrate automatically at API startup.
- Historical catalogs and compatibility fixtures preserve fixed bytes. Respect
  `.gitattributes`; do not reformat a released catalog or regenerate a golden
  fixture simply to make a failing test pass.
- Do not add default users, first-user bypasses, real credentials, telemetry
  destinations or external service requirements without design discussion.
- Use synthetic fixtures. Keep framework mappings and limitations accurate;
  wording that creates false confidence is a product defect.

## Dependencies and deployment changes

Update `requirements-hosted.in` and regenerate the hash-pinned lock using
[HOSTED_DEPLOYMENT.md](docs/HOSTED_DEPLOYMENT.md). Explain new dependencies and
their effect on local/offline use. Run dependency audits, builds and relevant
regressions. Rebuild pinned images rather than installing fixes in live containers.

Parser/scanner changes must preserve fail-closed decisions, bounds and passive
downloads. Deployment changes should describe permissions, secret delivery,
trust boundaries and recovery impact. Do not test another organization's live
resources without authorization.

## Before opening a pull request

1. Run relevant checks and report commands/outcomes, skips, mocks and checks not
   run. Do not imply local fixtures validate a real account or production SLA.
2. Update affected setup, limitation, migration and operation documents.
3. Inspect the diff for secrets, evidence, personal paths and generated files.
   `.cleartrail/`, environment secrets, exports, databases, virtual environments
   and build output must stay uncommitted. Only the placeholder environment
   example and explicitly synthetic compatibility fixtures belong in source.
4. Describe the problem, resulting behavior, validation and material limitations.
   Maintainers may request smaller scope or additional evidence.

Contributions use the [MIT License](LICENSE). No separate contributor agreement
or response-time commitment is currently defined. Be respectful and keep review
feedback specific, constructive and focused on the work.
