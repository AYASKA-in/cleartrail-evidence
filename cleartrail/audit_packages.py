"""Document-inclusive audit packages with bounded offline integrity verification."""
from __future__ import annotations

import base64
import hashlib
import html
import io
import os
import re
import stat
import tempfile
import uuid
import zipfile
import zlib

from . import __version__
from .catalog_registry import get_catalog
from .documents import MAX_FILE_BYTES, MAX_WORKSPACE_BYTES, validate_file, file_kind, TEXT_EXTENSIONS
from .reports import _preflight_archive, _read_members, _validate_content_sizes, verify_bundle
from .validation import canonical, strict_json_loads, timestamp

FORMAT = "cleartrail-audit-package"
MAX_SELECTION = 100
README = b"ClearTrail audit review package\n\nFiles are customer-supplied evidence, not an audit opinion. Review report.html and index.json. documents/ contains selected approved versions; snapshot.zip, when present, contains the automated snapshot.\nVerify without extracting or executing files: python -m cleartrail verify-audit package.zip --manifest-sha256 TRUSTED_HASH\nThe manifest is unsigned. Hashes do not authenticate provider assertions or establish operating effectiveness. A separate trusted manifest digest is needed to detect replacement. Files may contain sensitive data. Approval and scan status are recorded as of export; later withdrawals cannot recall a downloaded package. Never execute untrusted files or enable document macros.\n"


def _uuid(value):
    if not isinstance(value, str) or str(uuid.UUID(value)) != value:
        raise ValueError("Invalid audit package identifier.")


def period(start, end):
    first, last = timestamp(start), timestamp(end)
    if first >= last or (last - first).total_seconds() > 366 * 86400 * 3:
        raise ValueError("Select an increasing audit period of at most three years.")
    return first, last


def validate_index(index):
    fields = {"schema_version", "tenant_id", "organization", "created_at", "period_start", "period_end", "catalog_version", "snapshot", "documents", "control_inventory", "audit_head_before_export", "limitations"}
    if not isinstance(index, dict) or set(index) != fields or type(index["schema_version"]) is not int or index["schema_version"] != 1:
        raise ValueError("Invalid audit index.")
    _uuid(index["tenant_id"])
    period(index["period_start"], index["period_end"])
    if type(index["created_at"]) is not int or index["created_at"] <= 0:
        raise ValueError("Invalid export timestamp.")
    catalog = get_catalog(index["catalog_version"])
    if not isinstance(index["documents"], list) or len(index["documents"]) > MAX_SELECTION:
        raise ValueError("Invalid evidence selection.")
    paths, versions, total = set(), set(), 0
    for document in index["documents"]:
        if not isinstance(document, dict) or set(document) != {"id", "title", "owner", "control_ids", "version", "reviews", "path"}:
            raise ValueError("Invalid document index entry.")
        _uuid(document["id"])
        version = document["version"]
        required = {"id", "number", "filename", "size", "sha256", "uploaded_by", "owner_at_upload", "created_at", "expires_at", "scan"}
        if not isinstance(version, dict) or set(version) != required:
            raise ValueError("Invalid version metadata.")
        _uuid(version["id"])
        if version["id"] in versions or type(version["number"]) is not int or not 1 <= version["number"] <= 20 or type(version["size"]) is not int or not 1 <= version["size"] <= MAX_FILE_BYTES:
            raise ValueError("Invalid or repeated version.")
        kind = file_kind(version["filename"])
        if document["path"] != f'documents/{version["id"]}.{kind}' or document["path"] in paths:
            raise ValueError("Invalid document path.")
        if not isinstance(version["sha256"], str) or not re.fullmatch("[a-f0-9]{64}", version["sha256"]):
            raise ValueError("Invalid content digest.")
        if version["expires_at"] is not None and (type(version["expires_at"]) is not int or version["expires_at"] <= index["created_at"]):
            raise ValueError("Expired version in audit package.")
        controls = document["control_ids"]
        if not isinstance(controls, list) or not controls or any(not isinstance(c, str) or c not in catalog for c in controls) or len(set(controls)) != len(controls):
            raise ValueError("Invalid document controls.")
        reviews = document["reviews"]
        if not isinstance(reviews, list) or not 1 <= len(reviews) <= 20:
            raise ValueError("Missing approval history.")
        for sequence, review in enumerate(reviews, 1):
            if not isinstance(review, dict) or set(review) != {"id", "sequence", "decision", "reviewer", "comment", "created_at"} or review["sequence"] != sequence or type(review["sequence"]) is not int or review["decision"] not in {"approved", "rejected", "withdrawn"}:
                raise ValueError("Invalid review history.")
            _uuid(review["id"])
        approval = reviews[-1]
        if approval["decision"] != "approved" or approval["reviewer"] in {version["uploaded_by"], version["owner_at_upload"]}:
            raise ValueError("Version lacks independent approval.")
        if kind not in TEXT_EXTENSIONS:
            from .scanning import validate_clean_scan
            validate_clean_scan(version["scan"], version["sha256"])
        total += version["size"]
        versions.add(version["id"])
        paths.add(document["path"])
    if total > MAX_WORKSPACE_BYTES or (not index["documents"] and index["snapshot"] is None):
        raise ValueError("Empty or oversized audit package.")
    if index["control_inventory"] != inventory(index):
        raise ValueError("Control inventory does not match selected evidence.")
    return paths


def inventory(index):
    statuses = index["snapshot"]["control_statuses"] if index["snapshot"] else {}
    return [{"control_id": control_id, "snapshot_status": statuses.get(control_id, "not_included"),
             "document_version_ids": [document["version"]["id"] for document in index["documents"] if control_id in document["control_ids"]],
             "missing_selected_evidence": control_id not in statuses and not any(control_id in document["control_ids"] for document in index["documents"])}
            for control_id in get_catalog(index["catalog_version"])]


def audit_html(index):
    esc = lambda value: html.escape(str(value), quote=True)
    rows = "".join(f'<tr><td>{esc(d["title"])}</td><td>{esc(", ".join(d["control_ids"]))}</td><td>v{d["version"]["number"]}</td><td>{esc(d["reviews"][-1]["reviewer"])}</td><td><a href="{esc(d["path"])}">{esc(d["version"]["filename"])}</a><br>{esc(d["version"]["sha256"])}</td></tr>' for d in index["documents"])
    controls = "".join(f'<tr><td>{esc(row["control_id"])}</td><td>{esc(row["snapshot_status"])}</td><td>{len(row["document_version_ids"])}</td><td>{"Missing selected evidence" if row["missing_selected_evidence"] else "Review selected evidence"}</td></tr>' for row in index["control_inventory"])
    return (f'<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta http-equiv="Content-Security-Policy" content="default-src \'none\'; style-src \'unsafe-inline\'; base-uri \'none\'; form-action \'none\'"><title>ClearTrail audit review</title><style>body{{font:14px Arial,sans-serif;max-width:1100px;margin:36px auto;padding:16px;color:#20372f}}table{{width:100%;border-collapse:collapse}}td,th{{border:1px solid #ccc;padding:9px;text-align:left;overflow-wrap:anywhere}}h1,h2{{color:#164d39}}@media print{{body{{margin:0}}}}</style><h1>{esc(index["organization"])} · Audit evidence review</h1><p>Declared period: {esc(index["period_start"])} to {esc(index["period_end"])} (end exclusive).</p><p>Exported at Unix time {index["created_at"]}. Selected evidence supports review; it does not prove full-period operating effectiveness or certification. Approvals reflect export time. Later withdrawal cannot recall this package. Scan records are observations, not a malware-free guarantee.</p><h2>Approved documents</h2><table><tr><th>Document</th><th>Controls</th><th>Version</th><th>Reviewer</th><th>File / SHA-256</th></tr>{rows}</table><h2>Control inventory</h2><table><tr><th>Control</th><th>Snapshot status</th><th>Selected documents</th><th>Coverage</th></tr>{controls}</table><p>index.json contains source times, scan records, expiry and full review histories. '+ ('<a href="snapshot.zip">Automated snapshot package</a>.' if index["snapshot"] else 'No automated snapshot was selected.') + '</p></html>').encode()


def package_bytes(index, document_files, snapshot_bytes=None):
    paths = validate_index(index)
    if set(document_files) != paths:
        raise ValueError("File selection mismatch.")
    files = {"index.json": canonical(index), "report.html": audit_html(index), "README.txt": README, **document_files}
    if snapshot_bytes is not None:
        files["snapshot.zip"] = snapshot_bytes
    if bool(snapshot_bytes is not None) != bool(index["snapshot"] is not None):
        raise ValueError("Snapshot selection mismatch.")
    _validate_content_sizes(files)
    manifest = {"schema_version": 1, "bundle_format": FORMAT, "generator_version": __version__,
                "files": {name: hashlib.sha256(raw).hexdigest() for name, raw in sorted(files.items())}}
    files["manifest.json"] = canonical(manifest)
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", zipfile.ZIP_STORED) as archive:
        for name, raw in sorted(files.items()):
            info = zipfile.ZipInfo(name, (1980, 1, 1, 0, 0, 0))
            info.create_system = 3
            info.external_attr = (stat.S_IFREG | 0o600) << 16
            archive.writestr(info, raw)
    return output.getvalue(), hashlib.sha256(files["manifest.json"]).hexdigest()


def verify_audit_package(path, expected_manifest_sha256=None):
    if expected_manifest_sha256 is not None and (not isinstance(expected_manifest_sha256, str) or not re.fullmatch(r"[a-fA-F0-9]{64}", expected_manifest_sha256)):
        raise ValueError("Invalid trusted manifest digest.")
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_BINARY", 0))
        with os.fdopen(descriptor, "rb") as stream:
            offset = _preflight_archive(stream, maximum_members=105)
            with zipfile.ZipFile(stream) as archive:
                names = {member.filename for member in archive.infolist()}
                fixed = {"manifest.json", "index.json", "report.html", "README.txt", "snapshot.zip"}
                if any(name not in fixed and not re.fullmatch(r"documents/[a-f0-9-]{36}\.(?:txt|md|csv|pdf|docx|xlsx|pptx)", name) for name in names):
                    raise ValueError("Unsafe audit package member.")
                files = _read_members(archive, offset, expected_names=names)
        manifest = strict_json_loads(files["manifest.json"])
        if not isinstance(manifest, dict) or set(manifest) != {"schema_version", "bundle_format", "generator_version", "files"} or type(manifest["schema_version"]) is not int or manifest["schema_version"] != 1 or manifest["bundle_format"] != FORMAT or manifest["generator_version"] != "0.5.0" or not isinstance(manifest["files"], dict) or set(manifest["files"]) != set(files) - {"manifest.json"}:
            raise ValueError("Invalid audit manifest.")
        manifest_digest = hashlib.sha256(files["manifest.json"]).hexdigest()
        if expected_manifest_sha256 is not None and manifest_digest != expected_manifest_sha256.lower():
            raise ValueError("Trusted manifest mismatch.")
        if any(hashlib.sha256(files[name]).hexdigest() != sha for name, sha in manifest["files"].items()):
            raise ValueError("Audit package integrity failed.")
        index = strict_json_loads(files["index.json"])
        paths = validate_index(index)
        expected = {"manifest.json", "index.json", "report.html", "README.txt"} | paths | ({"snapshot.zip"} if index["snapshot"] is not None else set())
        if set(files) != expected or files["report.html"] != audit_html(index) or files["README.txt"] != README:
            raise ValueError("Audit package views or inventory do not match.")
        for document in index["documents"]:
            version, raw = document["version"], files[document["path"]]
            validate_file(version["filename"], base64.b64encode(raw).decode())
            if len(raw) != version["size"] or hashlib.sha256(raw).hexdigest() != version["sha256"]:
                raise ValueError("Document integrity failed.")
        if index["snapshot"] is not None:
            # Verification never extracts archive paths. The single bounded nested
            # snapshot is passed to the existing verifier through a private temp file.
            with tempfile.TemporaryFile() as temporary:
                temporary.write(files["snapshot.zip"])
                temporary.seek(0)
                directory = _preflight_archive(temporary)
                with zipfile.ZipFile(temporary) as nested:
                    contents = _read_members(nested, directory)
            from .validation import validate_run, digest
            snapshot = validate_run(strict_json_loads(contents["run.json"]))
            # Use the public verifier too, retaining all legacy rendering checks.
            with tempfile.TemporaryDirectory(prefix="cleartrail-verify-") as directory:
                from pathlib import Path
                nested_path = Path(directory) / "snapshot.zip"
                nested_path.write_bytes(files["snapshot.zip"])
                verify_bundle(nested_path)
            summary = index["snapshot"]
            first, last = period(index["period_start"], index["period_end"])
            if summary != {"id": snapshot["id"], "sha256": digest(snapshot), "collected_at": snapshot["collected_at"], "control_statuses": {c["id"]: c["status"] for c in snapshot["checks"]}} or snapshot["demo"] or not first <= timestamp(snapshot["collected_at"]) < last:
                raise ValueError("Snapshot does not match declared period or index.")
        return {"valid": True, "documents": len(paths), "snapshot_included": index["snapshot"] is not None,
                "manifest_sha256": manifest_digest, "trusted_manifest_matched": expected_manifest_sha256 is not None,
                "limitation": "Unsigned assertions; integrity does not establish authenticity, malware freedom or full-period control effectiveness."}
    except (KeyError, TypeError, AttributeError, zipfile.BadZipFile, UnicodeError, RuntimeError, OverflowError, EOFError, zlib.error) as exc:
        raise ValueError("Invalid audit package.") from exc
