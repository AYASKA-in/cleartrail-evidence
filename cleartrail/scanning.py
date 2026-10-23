"""Private ClamD INSTREAM client. Nothing is published until scanning succeeds."""
from __future__ import annotations

import hashlib
import re
import socket
import struct
import time
from datetime import datetime, timezone

from .documents import file_kind, TEXT_EXTENSIONS


class ScannerUnavailable(Exception):
    """Unavailable, stale, limited or unrecognized scanner response."""


class FileRejected(Exception):
    """Scanner detected malware, encrypted content or a policy violation."""


def validate_clean_scan(scan, sha256):
    if (not isinstance(scan, dict) or set(scan) != {"schema", "status", "engine", "definitions_version", "definitions_at", "scanned_at", "sha256"}
            or type(scan["schema"]) is not int or scan["schema"] != 1 or scan["status"] != "clean"
            or not isinstance(scan["engine"], str) or not re.fullmatch(r"ClamAV [0-9][A-Za-z0-9. _-]{0,80}", scan["engine"])
            or type(scan["definitions_version"]) is not int or scan["definitions_version"] < 1
            or type(scan["definitions_at"]) is not int or type(scan["scanned_at"]) is not int
            or not 0 <= scan["scanned_at"] - scan["definitions_at"] <= 168 * 3600
            or scan["sha256"] != sha256):
        raise ValueError("Invalid or missing clean-scan record.")
    return scan


def _reply(connection, deadline):
    value = bytearray()
    while b"\0" not in value:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise ScannerUnavailable()
        connection.settimeout(min(remaining, 5))
        chunk = connection.recv(1025 - len(value))
        if not chunk or len(value) + len(chunk) > 1024:
            raise ScannerUnavailable()
        value.extend(chunk)
    if value[-1:] != b"\0" or b"\0" in value[:-1]:
        raise ScannerUnavailable()
    return bytes(value[:-1]).decode("ascii")


def _connect(settings, deadline):
    return socket.create_connection((settings.scanner_host, settings.scanner_port), timeout=max(.1, min(5, deadline - time.monotonic())))


def scan_upload(settings, filename, raw):
    if not settings.scanner_host:
        if file_kind(filename) not in TEXT_EXTENSIONS:
            raise ScannerUnavailable()
        return {"schema": 1, "status": "not_scanned", "kind": "text-only"}
    deadline = time.monotonic() + settings.scanner_timeout_seconds
    try:
        with _connect(settings, deadline) as connection:
            connection.sendall(b"zVERSION\0")
            version = _reply(connection, deadline)
        engine, definitions, updated = version.split("/", 2)
        definitions_at = int(datetime.strptime(updated.strip(), "%a %b %d %H:%M:%S %Y").replace(tzinfo=timezone.utc).timestamp())
        now = int(time.time())
        if not 0 <= now - definitions_at <= settings.scanner_max_age_hours * 3600:
            raise ScannerUnavailable()
        result = {"schema": 1, "status": "clean", "engine": engine.strip(), "definitions_version": int(definitions),
                  "definitions_at": definitions_at, "scanned_at": now, "sha256": hashlib.sha256(raw).hexdigest()}
        validate_clean_scan(result, result["sha256"])
        with _connect(settings, deadline) as connection:
            connection.sendall(b"zINSTREAM\0")
            for offset in range(0, len(raw), 65536):
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise ScannerUnavailable()
                connection.settimeout(min(remaining, 5))
                chunk = raw[offset:offset + 65536]
                connection.sendall(struct.pack("!I", len(chunk)) + chunk)
            connection.sendall(b"\0\0\0\0")
            reply = _reply(connection, deadline)
        if reply.endswith(" FOUND") and reply.startswith("stream: "):
            raise FileRejected()
        if reply != "stream: OK":
            raise ScannerUnavailable()
        # Do not attribute a verdict to a database that changed during the scan.
        with _connect(settings, deadline) as connection:
            connection.sendall(b"zVERSION\0")
            if _reply(connection, deadline) != version:
                raise ScannerUnavailable()
        result["scanned_at"] = int(time.time())
        if not 0 <= result["scanned_at"] - definitions_at <= settings.scanner_max_age_hours * 3600:
            raise ScannerUnavailable()
        return result
    except FileRejected:
        raise
    except (OSError, ValueError, UnicodeError, OverflowError):
        raise ScannerUnavailable() from None
