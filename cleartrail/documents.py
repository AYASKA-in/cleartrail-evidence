"""Bounded, passive evidence files and authenticated, tenant-bound envelopes.

Text, PDF and macro-free OOXML are supported. Content is never rendered or
executed. Binary files require authenticated clean-scan records before publication.
"""
from __future__ import annotations

import base64
import hashlib
import io
import re
import stat
import unicodedata
import zipfile
import zlib
from xml.etree import ElementTree

from .errors import EvidenceIntegrityError
from .validation import canonical, strict_json_loads, text

MAX_FILE_BYTES = 512 * 1024
MAX_UPLOAD_BODY = ((MAX_FILE_BYTES + 2) // 3) * 4 + 16384
MAX_WORKSPACE_BYTES = 25 * 1024 * 1024
MAX_DOCUMENTS = 100
MAX_VERSIONS = 20
MAX_REVIEWS = 20
VERSION_FIELDS = ("tenant_id", "id", "document_id", "number", "filename", "size", "sha256",
                  "uploaded_by", "owner_at_upload", "created_at", "expires_at")
TEXT_EXTENSIONS = {"txt", "md", "csv"}
EXTENSIONS = TEXT_EXTENSIONS | {"pdf", "docx", "xlsx", "pptx"}


class DocumentConflict(Exception):
    """The caller reviewed an obsolete version or submitted an obsolete form."""


class DocumentNotFound(LookupError):
    """Missing or undisclosed tenant-scoped document."""


def passive_text(value, *, maximum, multiline=False):
    value = text(value, maximum=maximum, multiline=multiline)
    if any(unicodedata.category(char) in {"Cc", "Cf", "Cs"} and not (multiline and char in "\r\n\t") for char in value):
        raise ValueError("Control and formatting characters are not permitted.")
    return value


def file_kind(filename):
    if not isinstance(filename, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_. -]{0,94}\.(?:txt|md|csv|pdf|docx|xlsx|pptx)", filename):
        raise ValueError("Unsupported filename or evidence format.")
    return filename.rsplit(".", 1)[1]


def _office(raw, kind):
    """Bound archive metadata and reject active/encrypted/embedded OOXML inputs."""
    try:
        if not raw.startswith(b"PK\x03\x04"):
            raise ValueError()
        # Check EOCD counts before ZipFile creates an unbounded member inventory.
        import struct
        end = raw.rfind(b"PK\x05\x06", max(0, len(raw) - 65557))
        if end < 0 or end + 22 > len(raw):
            raise ValueError()
        _, disk, directory_disk, disk_count, count, size, offset, comment = struct.unpack_from("<4s4H2LH", raw, end)
        if disk or directory_disk or disk_count != count or not 1 <= count <= 256 or size > 65536 or offset + size != end or end + 22 + comment != len(raw):
            raise ValueError()
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            seen, total = set(), 0
            for member in archive.infolist():
                name = member.filename
                parts = name.split("/")
                if (name in seen or member.orig_filename != name or "\\" in name or name.startswith("/")
                        or any(part in {".", ".."} for part in parts) or len(name) > 255
                        or stat.S_IFMT(member.external_attr >> 16) not in {0, stat.S_IFREG, stat.S_IFDIR}
                        or member.flag_bits & 1 or member.compress_type not in {0, 8}
                        or member.file_size > 2 * 1024 * 1024
                        or member.file_size > max(member.compress_size, 1) * 200):
                    raise ValueError()
                total += member.file_size
                if total > 8 * 1024 * 1024 or any(term in name.lower() for term in ("vba", "activex", "embedding", "oleobject", "externallink")):
                    raise ValueError()
                seen.add(name)
                if name.endswith((".xml", ".rels")) and not member.is_dir():
                    data = archive.read(member)
                    if b"\0" in data or len(data) > 2 * 1024 * 1024 or any(token in data.lower() for token in (b"<!doctype", b"<!entity", b"vbaproject", b"macroenabled")):
                        raise ValueError()
                    data.decode("utf-8-sig")
                    tree = ElementTree.fromstring(data)
                    if any(any(token in value.lower() for token in ("vbaproject", "macroenabled")) for node in tree.iter() for value in node.attrib.values()):
                        raise ValueError()
                    if name.endswith(".rels"):
                        if any(node.attrib.get("TargetMode", "").lower() == "external" or re.match(r"(?:[a-zA-Z][a-zA-Z0-9+.-]*:|//|\\\\)", node.attrib.get("Target", "")) for node in tree.iter()):
                            raise ValueError()
            required = {"docx": "word/document.xml", "xlsx": "xl/workbook.xml", "pptx": "ppt/presentation.xml"}[kind]
            if "[Content_Types].xml" not in seen or required not in seen:
                raise ValueError()
    except (ValueError, KeyError, zipfile.BadZipFile, RuntimeError, OSError, OverflowError, EOFError, zlib.error, ElementTree.ParseError) as exc:
        raise ValueError("Invalid, encrypted, active or oversized Office document.") from exc


def validate_file(filename, encoded):
    kind = file_kind(filename)
    if not isinstance(encoded, str) or len(encoded) > ((MAX_FILE_BYTES + 2) // 3) * 4:
        raise ValueError("File exceeds the upload limit.")
    try:
        raw = base64.b64decode(encoded, validate=True)
    except (ValueError, UnicodeError):
        raise ValueError("Upload valid base64 contents.") from None
    if not 1 <= len(raw) <= MAX_FILE_BYTES:
        raise ValueError("File exceeds the upload limit.")
    if kind in TEXT_EXTENSIONS:
        content = raw.decode("utf-8")
        if any(unicodedata.category(char) in {"Cc", "Cf", "Cs"} and char not in "\r\n\t" for char in content):
            raise ValueError("Unsupported text control characters.")
    elif kind == "pdf":
        if not re.match(rb"%PDF-(?:1\.[0-7]|2\.0)[\r\n ]", raw) or b"%%EOF" not in raw[-1024:]:
            raise ValueError("Invalid PDF structure.")
    else:
        _office(raw, kind)
    return raw


def seal_file(cipher, row, raw):
    metadata = {key: row[key] for key in VERSION_FIELDS}
    if row.get("scan") is not None:
        metadata["scan"] = strict_json_loads(row["scan"])
    return cipher.encrypt(canonical({"purpose": "cleartrail.document.v2" if "scan" in metadata else "cleartrail.document.v1",
                                     "metadata": metadata,
                                     "content": base64.b64encode(raw).decode("ascii")})).decode("ascii")


def open_file(cipher, row):
    # The offline package verifier uses the validators without hosted dependencies.
    from cryptography.fernet import InvalidToken
    try:
        value = strict_json_loads(cipher.decrypt(row["envelope"].encode("ascii")))
        if set(value) != {"purpose", "metadata", "content"} or value["purpose"] not in {"cleartrail.document.v1", "cleartrail.document.v2"}:
            raise ValueError()
        metadata = {key: row[key] for key in VERSION_FIELDS}
        if row.get("scan") is not None:
            metadata["scan"] = strict_json_loads(row["scan"])
        if value["metadata"] != metadata or (value["purpose"] == "cleartrail.document.v2") != ("scan" in metadata):
            raise ValueError()
        raw = validate_file(row["filename"], value["content"])
        if len(raw) != row["size"] or hashlib.sha256(raw).hexdigest() != row["sha256"]:
            raise ValueError()
        if file_kind(row["filename"]) not in TEXT_EXTENSIONS:
            from .scanning import validate_clean_scan
            validate_clean_scan(metadata.get("scan"), row["sha256"])
        return raw
    except (InvalidToken, ValueError, TypeError, KeyError, UnicodeError):
        raise EvidenceIntegrityError("Stored document integrity failed.") from None


def version_status(version, review, now):
    if version["expires_at"] is not None and version["expires_at"] <= now:
        return "expired"
    return review["decision"] if review else "pending"
