"""Portable evidence bundles with bounded, structural integrity verification.

Verification deliberately makes no claim of provider or collector authenticity.
An independently retained manifest hash can establish that the received package
matches the package whose manifest was trusted through that separate channel.
"""
from __future__ import annotations

import csv
import errno
import hashlib
import html
import io
import json
import os
import re
import stat
import struct
import tempfile
import unicodedata
import zipfile
import zlib
from pathlib import Path

from . import __version__
from .core import canonical
from .validation import strict_json_loads, validate_run


_EXPECTED_NAMES = frozenset({"manifest.json", "report.html", "controls.csv", "run.json", "evidence.json", "README.txt"})
_MAX_MEMBER_BYTES = 32 * 1024 * 1024
_MAX_TOTAL_BYTES = 64 * 1024 * 1024
_MAX_ARCHIVE_BYTES = _MAX_TOTAL_BYTES + 1024 * 1024
_MAX_MANIFEST_BYTES = 256 * 1024
_MAX_DIRECTORY_BYTES = 64 * 1024
_MAX_COMPRESSION_RATIO = 2000
_READ_CHUNK = 64 * 1024
_RENDER_SCHEMA_VERSION = 1
_SUPPORTED_GENERATORS = {"0.2.0", "0.3.0", "0.4.0", "0.5.0", "0.6.0"}
_BUNDLE_FORMAT = "cleartrail-review-bundle"
_INTEGRITY = "SHA-256; unsigned manifest; does not establish authenticity"
_README = (
    "ClearTrail evidence review package\n\n"
    "Open report.html for a printable review report. controls.csv maps results to indicative "
    "framework references. run.json is the full snapshot; evidence.json contains individual records.\n\n"
    "Verify structure and file integrity: python -m cleartrail verify <bundle.zip>\n"
    "Verify against a manifest hash retained through a separately trusted channel:\n"
    "python -m cleartrail verify <bundle.zip> --manifest-sha256 <trusted-sha256>\n\n"
    "The manifest is unsigned. A matching trusted hash binds this package to that manifest; "
    "it does not authenticate the collector or provider. Verification does not execute or extract files.\n"
    "Files can contain sensitive account identifiers and team notes. Review recipients and share "
    "through an approved secure channel. Keep credentials outside evidence and configuration exports.\n"
    "This is point-in-time evidence, not an audit opinion or certification. Automated results cover "
    "only the observed settings; human controls still require independent review.\n"
).encode("utf-8")


def csv_cell(value):
    text = str(value)
    # Spreadsheet applications may discard whitespace and invisible controls
    # before interpreting a formula. Quoting CSV alone does not stop execution.
    offset = 0
    while offset < len(text) and (text[offset].isspace() or unicodedata.category(text[offset]) in {"Cc", "Cf"}):
        offset += 1
    unsafe = text[offset:].startswith(("=", "+", "-", "@"))
    leading_control = bool(text) and unicodedata.category(text[0]) in {"Cc", "Cf"}
    return "'" + text if unsafe or leading_control else text


def controls_csv(run: dict) -> bytes:
    output = io.StringIO(newline="")
    writer = csv.writer(output)
    writer.writerow(["Control", "Title", "Provider", "Status", "SOC 2 (indicative)", "ISO 27001:2022 (indicative)", "Resources", "Coverage gap", "Evidence IDs", "Remediation"])
    for c in run["checks"]:
        writer.writerow(map(csv_cell, [c["id"], c["title"], c["provider"], c["status"], c["frameworks"]["SOC 2"], c["frameworks"]["ISO 27001:2022"], c["resource_count"], c["has_unknown"], "; ".join(c["evidence_ids"]), c["remediation"]]))
    return output.getvalue().encode("utf-8-sig")


def report_html(run: dict, *, generator_version=None) -> bytes:
    generator_version = generator_version or __version__
    if generator_version not in _SUPPORTED_GENERATORS:
        raise ValueError("Unsupported report generator version.")
    esc = lambda value: html.escape(str(value), quote=True)
    s = {key: esc(value) for key, value in run["summary"].items()}
    demo = '<div class="demo">SYNTHETIC DEMONSTRATION — not evidence from a live organization.</div>' if run["demo"] else ""
    rows = "".join(f'<tr><td><b>{esc(c["title"])}</b><br><small>{esc(c["id"])}</small></td><td>{esc(c["provider"])}</td><td>{esc(c["status"].upper())}{" · incomplete coverage" if c["has_unknown"] else ""}</td><td>{esc(c["frameworks"]["SOC 2"])} / {esc(c["frameworks"]["ISO 27001:2022"])}</td><td>{esc(c["remediation"])}<br><small>{esc(", ".join(c["evidence_ids"]) or "No evidence collected")}</small></td></tr>' for c in run["checks"])
    evidence = "".join(f'<article><h3>{esc(e["control_id"])} · {esc(e["resource"])}</h3><p>{esc(e["status"])} · {esc(e["summary"])}</p><p>Source: {esc(e["source"])}<br>Collected: {esc(e["collected_at"])}<br>ID: {esc(e["id"])}<br>SHA-256: {esc(e["sha256"])}</p><pre>{esc(json.dumps(e["data"], indent=2, ensure_ascii=False))}</pre></article>' for e in run["evidence"])
    metadata = {key: run[key] for key in ("schema_version", "catalog_version", "config_fingerprint", "collection_started_at", "collected_at", "provenance") if key in run}
    provenance = esc(json.dumps(metadata, indent=2, ensure_ascii=False))
    doc = f'''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'"><meta name="referrer" content="no-referrer"><meta name="viewport" content="width=device-width,initial-scale=1"><title>ClearTrail evidence report</title><style>
body{{font:15px/1.6 system-ui,sans-serif;color:#172c2a;max-width:1150px;margin:40px auto;padding:0 24px}}h1{{font-size:36px}}small{{color:#50645f;overflow-wrap:anywhere}}.demo{{background:#fff0d5;padding:16px;font-weight:bold}}.metrics{{background:#edf6f2;padding:18px;border-radius:8px}}table{{border-collapse:collapse;width:100%;font-size:13px}}th,td{{text-align:left;vertical-align:top;border-bottom:1px solid #ccd9d4;padding:12px 8px}}td:last-child{{width:40%}}article{{border-top:1px solid #ccd9d4;padding:12px 0;break-inside:avoid}}pre{{background:#f2f5f4;padding:16px;white-space:pre-wrap;overflow-wrap:anywhere}}@media print{{body{{margin:0;padding:0}}h2{{break-before:page}}thead{{display:table-header-group}}tr{{break-inside:avoid}}}}
</style></head><body>{demo}<p>CLEARTRAIL / EVIDENCE COLLECTION</p><h1>{esc(run["organization"])}</h1><p>Point-in-time review package · {esc(run["collected_at"])}<br>Snapshot {esc(run["id"])}</p><div class="metrics">{s["passed"]} passed · {s["failed"]} needs attention · {s["unknown"]} unknown · {s["manual"]} human review · {s["evidence_count"]} evidence records</div><p>{esc(run["scope"])}</p><p>Coverage: GitHub default branches where classic branch protection can be observed; active Google Workspace users; the selected AWS account and configured region. Check source records, configuration and individual evidence for collection gaps and unsupported rules. A pass covers only the observed setting. Missing permissions, API failures and unsupported settings are unknown. S3 bucket blocks do not prove public exposure. Human controls remain subject to review.</p><p>Framework references are indicative mappings authored for this tool, not official control text or an assertion of completeness. ISO 27001-lite is not a certification. This package cannot establish operation throughout an audit period, auditor acceptance, or the origin and authenticity of the evidence. File hashes detect changes only against a trusted manifest; they are not digital signatures.</p><h2>Control index</h2><table><thead><tr><th>Control</th><th>Source</th><th>Result</th><th>Reference</th><th>Review / evidence</th></tr></thead><tbody>{rows}</tbody></table><h2>Collection provenance</h2><p>Collector metadata is recorded for traceability and has not been independently authenticated. The configuration fingerprint identifies the collected scope without exporting credentials. Legacy snapshots may omit this metadata.</p><pre>{provenance}</pre><h2>Collected evidence</h2>{evidence or "<p>No evidence has been collected.</p>"}<p>Generated by ClearTrail {esc(generator_version)}. Open report.html locally or print to PDF in your browser.</p></body></html>'''
    return doc.encode("utf-8")


def bundle_bytes(run: dict) -> bytes:
    # Freeze one JSON snapshot before generating multiple representations. This
    # also refuses non-JSON values instead of silently coercing source data.
    run = strict_json_loads(canonical(run).decode("utf-8"))
    validate_run(run)
    files = {
        "report.html": report_html(run),
        "controls.csv": controls_csv(run),
        "run.json": json.dumps(run, indent=2, ensure_ascii=False).encode("utf-8"),
        "evidence.json": json.dumps(run["evidence"], indent=2, ensure_ascii=False).encode("utf-8"),
        "README.txt": _README,
    }
    manifest = dict(schema_version=2, bundle_format=_BUNDLE_FORMAT,
                    generator=dict(name="cleartrail", version=__version__, render_schema_version=_RENDER_SCHEMA_VERSION),
                    run_schema_version=run["schema_version"], catalog_version=run.get("catalog_version", "legacy-v1"),
                    run_id=run["id"], collected_at=run["collected_at"], demo=run["demo"], integrity=_INTEGRITY,
                    files={name: hashlib.sha256(content).hexdigest() for name, content in files.items()})
    files["manifest.json"] = canonical(manifest)
    _validate_content_sizes(files)
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, content in files.items():
            # A frozen timestamp gives reproducible bundles for a saved run;
            # collection time is in the authenticated-by-hash JSON content.
            member = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            member.create_system = 3
            member.external_attr = (stat.S_IFREG | 0o600) << 16
            member.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(member, content)
    return output.getvalue()


def export_bundle(run: dict, path: str | Path):
    path = Path(path)
    if os.path.lexists(path):
        raise FileExistsError(errno.EEXIST, "An evidence package already exists at the destination.", path)
    payload = bundle_bytes(run)
    path.parent.mkdir(parents=True, exist_ok=True)
    # Write and fsync a private sibling before publishing. Windows rename and
    # POSIX hard-link creation both publish atomically without replacement:
    # no reader observes a partial bundle or loses an existing package.
    descriptor, temporary = tempfile.mkstemp(prefix=".cleartrail-export-", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        _publish_exclusive(temporary, path)
    finally:
        Path(temporary).unlink(missing_ok=True)


def _publish_exclusive(temporary: str, destination: Path):
    if os.name == "nt":
        # Unlike POSIX rename, Windows rename refuses an existing target.
        os.rename(temporary, destination)
    else:
        os.link(temporary, destination)


def _validate_content_sizes(files: dict[str, bytes]):
    if any(len(content) > (_MAX_MANIFEST_BYTES if name == "manifest.json" else _MAX_MEMBER_BYTES) for name, content in files.items()):
        raise ValueError("A package member exceeds the verification size limit.")
    if sum(map(len, files.values())) > _MAX_TOTAL_BYTES:
        raise ValueError("The package exceeds the 64 MiB verification limit.")


def _preflight_archive(stream, *, maximum_members=None):
    """Bound central-directory parsing before zipfile allocates member objects."""
    file_stat = os.fstat(stream.fileno())
    size = file_stat.st_size
    if not stat.S_ISREG(file_stat.st_mode) or size > _MAX_ARCHIVE_BYTES or size < 22:
        raise ValueError("Invalid package file or archive size.")
    stream.seek(max(0, size - 65557))
    tail = stream.read(65557)
    end = tail.rfind(b"PK\x05\x06")
    if end < 0 or end + 22 > len(tail):
        raise ValueError("Invalid ZIP directory.")
    _, disk, directory_disk, disk_count, count, directory_size, directory_offset, comment_size = struct.unpack_from("<4s4H2LH", tail, end)
    end_offset = size - len(tail) + end
    invalid_count = count != len(_EXPECTED_NAMES) if maximum_members is None else not 1 <= count <= maximum_members
    if (disk or directory_disk or disk_count != count or invalid_count
            or directory_size > _MAX_DIRECTORY_BYTES or directory_offset + directory_size != end_offset
            or end + 22 + comment_size != len(tail)):
        raise ValueError("Invalid, oversized, or unsupported ZIP directory.")
    stream.seek(0)
    if stream.read(4) != b"PK\x03\x04":
        raise ValueError("Package must start with a ZIP file header.")
    stream.seek(0)
    return directory_offset


def _read_members(archive: zipfile.ZipFile, directory_offset: int, *, expected_names=None) -> dict[str, bytes]:
    expected_names = _EXPECTED_NAMES if expected_names is None else expected_names
    members = archive.infolist()
    if len(members) != len(expected_names) or {member.filename for member in members} != expected_names:
        raise ValueError("The package contains missing, duplicate, or unexpected files.")
    total = 0
    offsets = set()
    for member in members:
        mode = member.external_attr >> 16
        if (member.is_dir() or member.orig_filename != member.filename
                or stat.S_IFMT(mode) not in {0, stat.S_IFREG} or member.external_attr & 0x10
                or member.flag_bits & ~(0x800 | 0x8 | 0x6) or member.extract_version > 20
                or member.compress_type not in {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED}
                or member.header_offset < 0 or member.header_offset >= directory_offset
                or member.header_offset in offsets):
            raise ValueError("Package members must be ordinary, unencrypted stored or deflated files.")
        offsets.add(member.header_offset)
        limit = _MAX_MANIFEST_BYTES if member.filename == "manifest.json" else _MAX_MEMBER_BYTES
        if member.file_size > limit or member.compress_size > _MAX_ARCHIVE_BYTES:
            raise ValueError("A package member exceeds the verification size limit.")
        if member.file_size > max(member.compress_size, 1) * _MAX_COMPRESSION_RATIO:
            raise ValueError("A package member has an excessive compression ratio.")
        total += member.file_size
        if total > _MAX_TOTAL_BYTES:
            raise ValueError("The package exceeds the 64 MiB verification limit.")
    files = {}
    for member in members:
        limit = _MAX_MANIFEST_BYTES if member.filename == "manifest.json" else _MAX_MEMBER_BYTES
        chunks = []
        observed = 0
        with archive.open(member) as source:
            while True:
                chunk = source.read(min(_READ_CHUNK, limit - observed + 1))
                if not chunk:
                    break
                observed += len(chunk)
                if observed > limit:
                    raise ValueError("A package member exceeds the verification size limit.")
                chunks.append(chunk)
        if observed != member.file_size:
            raise ValueError("Package member length does not match its ZIP directory.")
        files[member.filename] = b"".join(chunks)
    return files


def _validate_manifest(manifest):
    if not isinstance(manifest, dict) or not isinstance(manifest.get("files"), dict):
        raise ValueError("Invalid manifest object.")
    version = manifest.get("schema_version")
    if type(version) is not int or version not in {1, 2}:
        raise ValueError("Unsupported manifest schema version.")
    fields = {"schema_version", "run_id", "collected_at", "demo", "integrity", "files"}
    if version == 2:
        fields |= {"bundle_format", "generator", "run_schema_version", "catalog_version"}
    if set(manifest) != fields or type(manifest["demo"]) is not bool or manifest["integrity"] != _INTEGRITY:
        raise ValueError("Invalid manifest metadata.")
    if set(manifest["files"]) != _EXPECTED_NAMES - {"manifest.json"}:
        raise ValueError("The manifest file list is invalid.")
    if any(not isinstance(sha, str) or not re.fullmatch(r"[0-9a-f]{64}", sha) for sha in manifest["files"].values()):
        raise ValueError("The manifest contains invalid hashes.")
    if version == 2:
        generator = manifest["generator"]
        if (manifest["bundle_format"] != _BUNDLE_FORMAT or not isinstance(generator, dict)
                or set(generator) != {"name", "version", "render_schema_version"}
                or generator["name"] != "cleartrail" or not isinstance(generator["version"], str) or generator["version"] not in _SUPPORTED_GENERATORS
                or type(generator["render_schema_version"]) is not int
                or generator["render_schema_version"] != _RENDER_SCHEMA_VERSION):
            raise ValueError("Unsupported package generator or rendering schema.")
        if type(manifest["run_schema_version"]) is not int or manifest["run_schema_version"] not in {1, 2}:
            raise ValueError("Unsupported snapshot schema version in manifest.")


def verify_bundle(path: str | Path, expected_manifest_sha256: str | None = None) -> dict:
    if expected_manifest_sha256 is not None and (not isinstance(expected_manifest_sha256, str) or not re.fullmatch(r"[0-9a-fA-F]{64}", expected_manifest_sha256)):
        raise ValueError("Expected manifest SHA-256 must be exactly 64 hexadecimal characters.")
    try:
        # Nonblocking open prevents a named pipe from hanging before fstat can
        # reject non-regular files. It has no effect on ordinary input files.
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_BINARY", 0))
        with os.fdopen(descriptor, "rb") as stream:
            directory_offset = _preflight_archive(stream)
            with zipfile.ZipFile(stream) as archive:
                files = _read_members(archive, directory_offset)
        manifest_sha256 = hashlib.sha256(files["manifest.json"]).hexdigest()
        if expected_manifest_sha256 is not None and manifest_sha256 != expected_manifest_sha256.lower():
            raise ValueError("Manifest SHA-256 does not match the independently trusted value.")
        manifest = strict_json_loads(files["manifest.json"].decode("utf-8"))
        _validate_manifest(manifest)
        failures = [name for name, sha in manifest["files"].items() if hashlib.sha256(files[name]).hexdigest() != sha]
        if failures:
            raise ValueError("File integrity failed: " + ", ".join(failures))
        run = strict_json_loads(files["run.json"].decode("utf-8"))
        validate_run(run)
        if run["id"] != manifest["run_id"] or run["demo"] != manifest["demo"] or run["collected_at"] != manifest["collected_at"]:
            raise ValueError("Snapshot metadata does not match the manifest.")
        if strict_json_loads(files["evidence.json"].decode("utf-8")) != run["evidence"]:
            raise ValueError("Evidence index does not match the snapshot.")
        rendered_views_verified = manifest["schema_version"] == 2
        if rendered_views_verified:
            if manifest["run_schema_version"] != run["schema_version"] or manifest["catalog_version"] != run.get("catalog_version", "legacy-v1"):
                raise ValueError("Snapshot provenance does not match the manifest.")
            if files["report.html"] != report_html(run, generator_version=manifest["generator"]["version"]) or files["controls.csv"] != controls_csv(run):
                raise ValueError("Rendered report or control index does not match the snapshot.")
        return dict(valid=True, files=len(_EXPECTED_NAMES) - 1, run_id=manifest["run_id"], demo=manifest["demo"],
                    manifest_sha256=manifest_sha256, trusted_manifest_matched=expected_manifest_sha256 is not None,
                    rendered_views_verified=rendered_views_verified,
                    limitation="Unsigned manifest; integrity verification does not prove provider or collector authenticity. Legacy bundle reports are not regenerated for comparison.")
    except (KeyError, TypeError, RuntimeError, NotImplementedError, zipfile.BadZipFile, UnicodeError, struct.error, RecursionError, OverflowError, zlib.error, EOFError) as exc:
        raise ValueError("Invalid evidence package.") from exc
