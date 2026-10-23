"""Transactional local storage. The hosted service uses its PostgreSQL repository."""
from __future__ import annotations

import os
import secrets
import sqlite3
import time
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

from .catalog import CATALOG
from .validation import canonical, digest, strict_json_loads, text, validate_run


def utcnow():
    return datetime.now(timezone.utc).isoformat(timespec="microseconds")


class Store:
    def __init__(self, path: str | Path):
        self.path = Path(path).absolute()
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        if self.path.is_symlink() or (self.path.exists() and not self.path.is_file()):
            raise ValueError("The database must be an ordinary local file.")
        try:
            fd = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except FileExistsError:
            if self.path.stat().st_nlink > 1:
                raise ValueError("Hard-linked databases are not supported.")
        else:
            os.close(fd)
        if os.name != "nt":
            os.chmod(self.path, 0o600)
        with self.connection() as db:
            db.execute("PRAGMA journal_mode=WAL")
            version = db.execute("PRAGMA user_version").fetchone()[0]
            if version > 1:
                raise ValueError("This database requires a newer ClearTrail version.")
            db.execute("CREATE TABLE IF NOT EXISTS runs (id TEXT PRIMARY KEY, collected_at TEXT NOT NULL, document TEXT NOT NULL)")
            db.execute("CREATE TABLE IF NOT EXISTS attestations (control_id TEXT PRIMARY KEY, document TEXT NOT NULL)")
            db.execute("CREATE TABLE IF NOT EXISTS attestation_revisions (id INTEGER PRIMARY KEY, control_id TEXT NOT NULL, document TEXT NOT NULL)")
            db.execute("CREATE TABLE IF NOT EXISTS workspace_metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
            db.execute("CREATE TABLE IF NOT EXISTS run_index (run_id TEXT PRIMARY KEY REFERENCES runs(id), document_sha256 TEXT NOT NULL, demo INTEGER NOT NULL, summary TEXT NOT NULL)")
            db.execute("CREATE TABLE IF NOT EXISTS collection_lease (id INTEGER PRIMARY KEY CHECK (id=1), token TEXT NOT NULL, expires_at REAL NOT NULL)")
            for run_id, document in db.execute("SELECT id, document FROM runs WHERE id NOT IN (SELECT run_id FROM run_index)").fetchall():
                run = validate_run(strict_json_loads(document))
                db.execute("INSERT INTO run_index VALUES (?,?,?,?)", (run_id, digest(run), int(run["demo"]), canonical(run["summary"]).decode()))
            old = db.execute("SELECT document FROM runs ORDER BY rowid DESC LIMIT 1").fetchone()
            if old:
                run = validate_run(strict_json_loads(old[0]))
                self._bind(db, run["organization"], run["demo"])
            db.execute("PRAGMA user_version=1")

    @contextmanager
    def connection(self):
        db = sqlite3.connect(self.path, timeout=15)
        try:
            db.execute("PRAGMA foreign_keys=ON")
            db.execute("PRAGMA trusted_schema=OFF")
            db.execute("PRAGMA synchronous=FULL")
            with db:
                yield db
        finally:
            db.close()

    @staticmethod
    def _bind(db, organization, demo):
        identity = canonical({"organization": organization, "demo": demo}).decode()
        row = db.execute("SELECT value FROM workspace_metadata WHERE key='identity'").fetchone()
        if row and row[0] != identity:
            raise ValueError("This database belongs to a different mode or organization. Choose a separate database.")
        db.execute("INSERT OR IGNORE INTO workspace_metadata VALUES ('identity',?)", (identity,))

    @contextmanager
    def collection(self, organization, demo):
        token = secrets.token_urlsafe(32)
        with self.connection() as db:
            db.execute("BEGIN IMMEDIATE")
            self._bind(db, organization, demo)
            lease = db.execute("SELECT expires_at FROM collection_lease WHERE id=1").fetchone()
            if lease and lease[0] > time.time():
                raise ValueError("A collection is already running for this database.")
            db.execute("INSERT OR REPLACE INTO collection_lease VALUES (1,?,?)", (token, time.time() + 1200))
        try:
            yield
        finally:
            with self.connection() as db:
                db.execute("DELETE FROM collection_lease WHERE id=1 AND token=?", (token,))

    def save_run(self, run: dict):
        run = validate_run(run)
        with self.connection() as db:
            db.execute("BEGIN IMMEDIATE")
            self._bind(db, run["organization"], run["demo"])
            db.execute("INSERT INTO runs VALUES (?,?,?)", (run["id"], run["collected_at"], canonical(run).decode()))
            db.execute("INSERT INTO run_index VALUES (?,?,?,?)", (run["id"], digest(run), int(run["demo"]), canonical(run["summary"]).decode()))

    def latest_id(self):
        with self.connection() as db:
            row = db.execute("SELECT id FROM runs ORDER BY rowid DESC LIMIT 1").fetchone()
        return row[0] if row else None

    def get_run(self, run_id: str):
        with self.connection() as db:
            row = db.execute("SELECT r.document,i.document_sha256 FROM runs r JOIN run_index i ON i.run_id=r.id WHERE r.id=?", (run_id,)).fetchone()
        if not row:
            return None
        run = strict_json_loads(row[0])
        if digest(run) != row[1]:
            raise ValueError("Stored snapshot integrity failed.")
        return validate_run(run)

    def latest(self):
        run_id = self.latest_id()
        return self.get_run(run_id) if run_id else None

    def history(self, limit=20):
        with self.connection() as db:
            rows = db.execute("SELECT r.id,r.collected_at,i.demo,i.summary FROM runs r JOIN run_index i ON i.run_id=r.id ORDER BY r.rowid DESC LIMIT ?", (min(max(int(limit), 1), 100),)).fetchall()
        return [dict(id=r[0], collected_at=r[1], demo=bool(r[2]), summary=strict_json_loads(r[3])) for r in rows]

    def attestations(self):
        with self.connection() as db:
            rows = db.execute("SELECT control_id,document FROM attestations").fetchall()
        return {key: strict_json_loads(doc) for key, doc in rows}

    def attest(self, control_id, owner, note):
        if not isinstance(control_id, str) or control_id not in CATALOG or CATALOG[control_id]["provider"] != "manual":
            raise ValueError("Choose a team evidence control.")
        owner = text(owner, maximum=120).strip()
        note = text(note, maximum=4000, multiline=True).strip()
        item = dict(owner=owner, note=note, recorded_at=utcnow(), kind="self-attestation", independently_verified=False)
        with self.connection() as db:
            document = canonical(item).decode()
            db.execute("INSERT OR REPLACE INTO attestations VALUES (?,?)", (control_id, document))
            db.execute("INSERT INTO attestation_revisions(control_id,document) VALUES (?,?)", (control_id, document))

    def health(self):
        with self.connection() as db:
            valid = db.execute("PRAGMA quick_check").fetchone()[0] == "ok"
            ids = [r[0] for r in db.execute("SELECT id FROM runs")]
        for run_id in ids:
            if self.get_run(run_id) is None:
                valid = False
        return {"ok": valid, "snapshots_checked": len(ids), "schema_version": 1}

    def backup(self, path):
        destination = Path(path).absolute()
        destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        os.close(fd)
        try:
            with self.connection() as source:
                target = sqlite3.connect(destination)
                try:
                    source.backup(target)
                    if target.execute("PRAGMA quick_check").fetchone()[0] != "ok":
                        raise ValueError("Backup integrity verification failed.")
                finally:
                    target.close()
        except BaseException:
            destination.unlink(missing_ok=True)
            raise
        return {"backed_up": True, "bytes": destination.stat().st_size}
