"""Scanner protocol, publication boundary and bounded PDF/Office handling."""
import base64
import io
import socketserver
import struct
import threading
import time
import zipfile
from dataclasses import replace
from datetime import datetime, timezone
from unittest.mock import patch

import pytest
from sqlalchemy import select, update

from cleartrail.documents import validate_file
from cleartrail.scanning import scan_upload, ScannerUnavailable, FileRejected
from cleartrail.hosted_repository import Repository, document_versions, schema
from test_hosted import setup as setup, login
from test_documents import payload


def pdf(extra=b""):
    objects = [b"<< /Type /Catalog /Pages 2 0 R >>", b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
               b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << >> /Contents 4 0 R >>",
               b"<< /Length 0 >>\nstream\n\nendstream"]
    raw = b"%PDF-1.4\n% synthetic test\n" + extra
    positions = [0]
    for number, content in enumerate(objects, 1):
        positions.append(len(raw))
        raw += str(number).encode() + b" 0 obj\n" + content + b"\nendobj\n"
    offset = len(raw)
    raw += b"xref\n0 5\n0000000000 65535 f \n" + b"".join(f"{position:010d} 00000 n \n".encode() for position in positions[1:])
    return raw + b"trailer\n<< /Size 5 /Root 1 0 R >>\nstartxref\n" + str(offset).encode() + b"\n%%EOF\n"


def office(kind="docx", extra=None):
    main = {"docx":"word/document.xml", "xlsx":"xl/workbook.xml", "pptx":"ppt/presentation.xml"}[kind]
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w") as archive:
        archive.writestr("[Content_Types].xml", '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="xml" ContentType="application/xml"/></Types>')
        archive.writestr(main, '<root/>')
        for name, content in (extra or {}).items():
            archive.writestr(name, content)
    return output.getvalue()


@pytest.fixture
def daemon():
    state = {"reply": b"stream: OK\0", "updated": int(time.time()) - 3600, "received": []}
    class Handler(socketserver.StreamRequestHandler):
        def handle(self):
            command = self.rfile.read(1)
            while not command.endswith(b"\0") and len(command) < 30:
                command += self.rfile.read(1)
            if command == b"zVERSION\0":
                stamp = datetime.fromtimestamp(state["updated"], timezone.utc).strftime("%a %b %d %H:%M:%S %Y")
                self.wfile.write(f"ClamAV 1.5.4/28162/{stamp}\0".encode())
            elif command == b"zINSTREAM\0":
                contents = bytearray()
                while True:
                    length = struct.unpack("!I", self.rfile.read(4))[0]
                    if length == 0:
                        break
                    assert length <= 65536
                    contents.extend(self.rfile.read(length))
                state["received"].append(bytes(contents))
                self.wfile.write(state["reply"])
    with socketserver.TCPServer(("127.0.0.1", 0), Handler) as server:
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        yield state, server.server_address[1]
        server.shutdown()
        thread.join(timeout=5)


def test_binary_requires_live_fresh_scanner_and_binds_scan_record(setup, daemon):
    state, port = daemon
    settings, repo, tenant = setup[:3]
    raw = pdf()
    value = payload(filename="policy.pdf", content_base64=base64.b64encode(raw).decode())
    with pytest.raises(ScannerUnavailable):
        repo.upload_document(tenant, "alice", value)
    assert repo.document_list(tenant, "alice")["documents"] == []
    scanned = Repository(replace(settings, scanner_host="127.0.0.1", scanner_port=port))
    try:
        result = scanned.upload_document(tenant, "alice", value)
        assert state["received"] == [raw]
        item = scanned.document_detail(tenant, "alice", result["document_id"])["versions"][0]
        assert item["scan"]["status"] == "clean" and item["scan"]["sha256"] == item["sha256"]
        assert scanned.download_document(tenant, "alice", result["version_id"])[1] == raw
        with scanned.scoped(tenant) as (db, _):
            db.execute(update(document_versions).where(document_versions.c.id == result["version_id"]).values(scan='{"status":"clean"}'))
        from cleartrail.errors import EvidenceIntegrityError
        with pytest.raises(EvidenceIntegrityError):
            scanned.download_document(tenant, "alice", result["version_id"])
    finally:
        scanned.engine.dispose()


@pytest.mark.parametrize("reply,exception", [(b"stream: Eicar-Test FOUND\0", FileRejected),
    (b"stream: Heuristics.Limits.Exceeded FOUND\0", FileRejected), (b"stream: scan failed ERROR\0", ScannerUnavailable),
    (b"INSTREAM size limit exceeded\0", ScannerUnavailable), (b"OK\0", ScannerUnavailable),
    (b"stream: OK\0forged\0", ScannerUnavailable), (b"x" * 1025, ScannerUnavailable)])
def test_incomplete_detected_and_ambiguous_scans_cannot_publish(setup, daemon, reply, exception):
    state, port = daemon
    state["reply"] = reply
    settings = replace(setup[0], scanner_host="127.0.0.1", scanner_port=port)
    repo = Repository(settings)
    try:
        with pytest.raises(exception):
            repo.upload_document(setup[2], "alice", payload())
        assert repo.document_list(setup[2], "alice")["documents"] == []
    finally:
        repo.engine.dispose()


def test_stale_signatures_fail_closed_before_file_is_sent(setup, daemon):
    state, port = daemon
    state["updated"] -= 8 * 86400
    settings = replace(setup[0], scanner_host="127.0.0.1", scanner_port=port)
    with pytest.raises(ScannerUnavailable):
        scan_upload(settings, "safe.txt", b"safe")
    assert state["received"] == []


@pytest.mark.parametrize("kind", ["docx", "xlsx", "pptx"])
def test_modern_office_types_are_structurally_bounded(kind):
    raw = office(kind)
    assert validate_file("policy." + kind, base64.b64encode(raw).decode()) == raw


@pytest.mark.parametrize("extra", [{"../secret.xml":"x"}, {"word/vbaProject.bin":"macro"},
    {"word/embeddings/ole.bin":"embedded"}, {"word/_rels/document.xml.rels":'<Relationships><Relationship TargetMode="External" Target="https://example.invalid"/></Relationships>'},
    {"word/_rels/document.xml.rels":'<!DOCTYPE x [<!ENTITY a "expand">]><root/>'},
    {"word/_rels/document.xml.rels":"<broken"}])
def test_office_active_content_and_unsafe_paths_are_rejected(extra):
    with pytest.raises(ValueError):
        validate_file("policy.docx", base64.b64encode(office(extra=extra)).decode())


def test_scanner_http_errors_do_not_publish_and_keep_error_details_private(setup):
    with patch("cleartrail.document_repository.scan_upload", side_effect=ScannerUnavailable):
        response = setup[4].post("/api/documents/upload", json=payload(), headers=login(setup))
    assert response.status_code == 503 and response.json()["code"] == "scanner_unavailable"
    with patch("cleartrail.document_repository.scan_upload", side_effect=FileRejected):
        response = setup[4].post("/api/documents/upload", json=payload(), headers=login(setup))
    assert response.status_code == 422 and setup[1].document_list(setup[2], "alice")["documents"] == []


def test_schema_three_upgrade_preserves_legacy_text_envelopes(setup):
    repo, tenant = setup[1:3]
    result = repo.upload_document(tenant, "alice", payload())
    from cleartrail.validation import canonical
    from cleartrail.documents import VERSION_FIELDS
    with repo.scoped(tenant) as (db, _):
        row = db.execute(select(document_versions).where(document_versions.c.id == result["version_id"])).mappings().one()
        envelope = repo.vault.cipher.encrypt(canonical({"purpose":"cleartrail.document.v1","metadata":{key:row[key] for key in VERSION_FIELDS},"content":payload()["content_base64"]})).decode()
        db.execute(update(document_versions).where(document_versions.c.id == result["version_id"]).values(envelope=envelope, scan=None))
    with repo.engine.begin() as db:
        db.exec_driver_sql("ALTER TABLE ct_document_versions DROP COLUMN scan")
        db.execute(update(schema).values(version=3))
    repo.migrate()
    assert repo.ready() and repo.download_document(tenant,"alice",result["version_id"])[1] == base64.b64decode(payload()["content_base64"])
    repo.migrate()
