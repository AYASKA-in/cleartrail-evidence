# Document-inclusive audit packages

In hosted **Reports**, choose **Create audit package**, declare a start/end
period, optionally select a live automated snapshot and choose up to 100 approved,
unexpired file versions. Older approved versions can be selected explicitly.
The snapshot must have been collected within the declared interval (end exclusive).
At least one snapshot or file is required. Draft, rejected, withdrawn, expired or
foreign-tenant selections fail; they are not silently omitted.

The ZIP contains:

- `report.html`: printable, escaped summary and control coverage inventory;
- `index.json`: exact versions, source/upload/scan times, control links, expiry,
  reviewer identities/rationale/history, declared period and prior audit head;
- `documents/<version-UUID>.<extension>`: original, integrity-checked bytes;
- optional `snapshot.zip`: the existing independently verifiable automated report;
- `manifest.json`: SHA-256 for every included file, plus format/generator metadata;
- `README.txt`: handling and verification instructions.

The displayed manifest digest is also returned in `X-ClearTrail-Manifest-SHA256`.
Retain that digest through a separately trusted channel. Verify offline:

```sh
python -m cleartrail verify-audit cleartrail-audit-package.zip --manifest-sha256 TRUSTED_DIGEST
```

Verification bounds ZIP directory/member counts, paths, sizes and expansion;
rejects duplicates/special files; checks original file hashes, version/approval
links, scan records and control inventory; regenerates the HTML; and invokes the
existing verifier on the bounded nested snapshot. It does not extract user archive
paths, execute content or render Office/PDF files. Packages are capped at the
existing 64 MiB content limit and retain the workspace's 25 MiB original-file cap.

The API uses the current tenant, role, CSRF and active-workspace boundary. Selection,
current approval checks, decryption and the export audit event share a tenant-locked
transaction. A revoked approval cannot race into a package generated afterward.
The export event records the selected IDs, period and manifest digest without file
contents. Auditors can export approved selections but cannot approve evidence.

The manifest is unsigned. A matching independently trusted digest establishes
integrity against that manifest; it does not authenticate provider assertions,
reviewer identity to an outside recipient, scan completeness or full-period control
effectiveness. A policy uploaded outside the interval may still be relevant, so
the file's actual upload timestamp is retained rather than treated as proof of
effective dates. An already downloaded package cannot be recalled by a later
withdrawal. Share the sensitive archive through an approved secure channel.

The older **Download package** action deliberately keeps its snapshot-only format
and CLI `verify` compatibility. Historical 0.2/0.3/0.4 reports remain verifiable.
The new format uses the separate `verify-audit` command.
