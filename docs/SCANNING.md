# File scanning in 0.5

ClearTrail accepts UTF-8 text (`.txt`, `.md`, `.csv`), PDF and modern Office
(`.docx`, `.xlsx`, `.pptx`). The 512 KiB upload limit is unchanged. Legacy
`.doc`/`.xls`/`.ppt`, macro-enabled formats, arbitrary archives and executables
are not accepted. Filenames remain restricted ASCII names.

Binary uploads require a fresh ClamAV verdict before publication. The authenticated,
bounded upload is held in memory while scanning; it is never exposed as a draft
download or written into the evidence store first. A detection returns 422.
Unavailable/stale scanners, unknown responses, timeouts and errors return 503.
No document/version is published on either path. Permissions and quotas are
rechecked in the commit transaction after scanning. Two upload scans and one
audit export per API process bound the heavier work; shared ingress limits are
still needed across replicas.

The client uses the private ClamD INSTREAM protocol, not filesystem paths or
shell commands. It requires an exact clean response, checks definition age
(72 hours by default), and verifies the engine/database version did not change
during the scan. The scan record binds the original SHA-256, engine, definition
version/date and scan time into the authenticated encrypted version envelope.
Changing that record or exchanging ciphertext between versions fails integrity
checks. Scans are observations at upload time, not malware-free guarantees or
continuous re-scanning of retained files.

PDF magic/trailer checks and bounded OOXML inspection precede scanning. OOXML
rejects unsafe paths, duplicate/encrypted members, oversized expansion, DTDs,
entities, known VBA/embedded-object constructs and external relationships.
The prescribed daemon policy alerts on encrypted content, macros and scan limits
instead of silently skipping them. This is not content disarm/reconstruction.
Files remain untrusted customer content. They download as attachments with
`nosniff`; binary files use `application/octet-stream` and are never previewed or
executed in ClearTrail.

## Self-hosted setup

1. Set `CLEARTRAIL_SCANNER_HOST=clamav` in your private hosted environment file.
2. Initialize/update definitions once:

   ```sh
   docker compose --profile scanning run --rm signature-updater --config-file=/etc/clamav/freshclam.conf
   ```

3. Start services:

   ```sh
   docker compose --profile scanning up -d api worker scheduler clamav signature-updater
   ```

The scanner build pins the tested ClamAV 1.5.4 base digest and upgrades the
vendor-fixed musl packages to `1.2.6-r3`; see `deploy/clamav.Dockerfile`. The daemon runs
as UID 100, with a read-only root, no Linux capabilities, bounded CPU/RAM, private
temporary storage and read-only signature files. Its Docker network is internal
and its port is not published. A separate unprivileged FreshClam process has
outbound access and write access to the signature volume. Keep `TZ=UTC` for
consistent definition timestamps. Health checks test daemon availability; the
client independently enforces freshness. Monitor updater failures and 503 rates.

ClamAV's full signature engine needs substantial RAM; the Compose scanner has a
4 GiB limit and the updater 3 GiB. Those are limits, not reserved memory. Measure
your host during initial load and definition updates. This requires no paid
scanner license; infrastructure and maintenance still have costs.

An empty scanner host permits text-only uploads, explicitly labeled
`not_scanned`; it never enables binary uploads. A configured but unavailable
scanner blocks new text uploads too. Schema 4 preserves 0.4 text evidence with
a null scan record; those files remain labeled legacy/unscanned. Existing file
contents and reviews are not rewritten by migration.

Actual local validation used freshly updated official definitions 28162 and
verified clean PDF/DOCX/text, the benign EICAR test signature rejection, and a
scan-limit failure. Unit tests additionally cover stale signatures, malformed
responses, tampered scan metadata, active OOXML and publication rollback. These
checks do not establish detection of every malicious document.

Protocol/configuration references: [ClamD protocol](https://docs.clamav.net/manual/Usage/ClamdProtocol.html),
[official container and RAM guidance](https://docs.clamav.net/manual/Installing/Docker.html),
[upstream daemon policy options](https://github.com/Cisco-Talos/clamav/blob/main/etc/clamd.conf.sample).
