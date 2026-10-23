"""Run a tenant's read-only collectors in a private, bounded subprocess.

Tenant credentials travel through a private stdin file descriptor, never process
arguments or the inherited environment. No parent environment state is changed.
The process is a credential-isolation boundary, not a hostile-code sandbox.
"""
from __future__ import annotations

import os
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from .validation import MAX_SNAPSHOT_BYTES, bounded_json, canonical, digest, strict_json_loads, text, validate_config, validate_run

MAX_INPUT_BYTES = 256 * 1024
ALLOWED_CREDENTIALS = frozenset({"GITHUB_TOKEN", "GOOGLE_ACCESS_TOKEN", "AWS_ACCESS_KEY_ID",
                                "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN"})
_AWS_CREDENTIALS = frozenset({"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN"})


class IsolatedCollectionError(RuntimeError):
    """Stable public error code; no subprocess output or exception text escapes."""

    def __init__(self, code="collector_failed"):
        self.code = code
        super().__init__("Isolated collection failed (" + code + ").")


def _validate_request(config, credentials, attestations):
    config = validate_config(config)
    if "profile" in config["providers"].get("aws", {}):
        raise ValueError("Hosted collection does not accept AWS profiles.")
    if not isinstance(credentials, dict) or set(credentials) - ALLOWED_CREDENTIALS:
        raise ValueError("Unsupported collector credential fields.")
    credentials = {key: text(value, maximum=16384) for key, value in credentials.items()}
    provided_aws = _AWS_CREDENTIALS.intersection(credentials)
    if provided_aws and provided_aws != _AWS_CREDENTIALS:
        raise ValueError("AWS collection requires a complete temporary credential set.")
    if not isinstance(attestations, dict):
        raise ValueError("Attestations must be an object.")
    bounded_json(attestations, reject_secrets=True)
    request = {"config": config, "credentials": credentials, "attestations": attestations}
    if len(canonical(request)) > MAX_INPUT_BYTES:
        raise ValueError("Collector input exceeded the size limit.")
    return request


def _contains_secret(value, credentials):
    secrets = tuple(credentials.values())
    def visit(item):
        if isinstance(item, str):
            return any(secret in item for secret in secrets)
        if isinstance(item, dict):
            return any(visit(key) or visit(child) for key, child in item.items())
        if isinstance(item, list):
            return any(visit(child) for child in item)
        return False
    return visit(value)


def _child_environment(directory):
    # In particular: no inherited cloud tokens, profiles, credential processes,
    # web-identity/container credentials, PYTHONPATH, or proxy credentials.
    allowed_runtime = {"PATH", "SYSTEMROOT", "WINDIR", "COMSPEC", "PATHEXT", "LANG", "LC_ALL"}
    environment = {key: value for key, value in os.environ.items() if key.upper() in allowed_runtime}
    environment.update({"HOME": str(directory), "USERPROFILE": str(directory),
                        "APPDATA": str(directory), "LOCALAPPDATA": str(directory),
                        "TEMP": str(directory), "TMP": str(directory), "TMPDIR": str(directory),
                        "AWS_EC2_METADATA_DISABLED": "true",
                        "AWS_SHARED_CREDENTIALS_FILE": str(directory / "aws-credentials"),
                        "AWS_CONFIG_FILE": str(directory / "aws-config"),
                        "PYTHONNOUSERSITE": "1", "PYTHONUNBUFFERED": "1"})
    return environment


def _private_file(path):
    descriptor = os.open(path, os.O_RDWR | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0), 0o600)
    return os.fdopen(descriptor, "w+b")


def _terminate(process):
    if process.poll() is None:
        try:
            if os.name == "posix":
                os.killpg(process.pid, signal.SIGKILL)
            else:
                process.kill()
        except (OSError, ProcessLookupError):
            try:
                process.kill()
            except OSError:
                pass
    # Reap on every failure path; worker code does not launch child processes.
    process.wait(timeout=10)


def _execute(directory, child_input, child_output, timeout):
    options = {"cwd": str(directory), "env": _child_environment(directory),
               "stdin": child_input, "stdout": child_output,
               "stderr": subprocess.DEVNULL, "close_fds": True}
    if os.name == "nt":
        options["creationflags"] = subprocess.CREATE_NO_WINDOW | subprocess.CREATE_NEW_PROCESS_GROUP
    elif os.name == "posix":
        options["start_new_session"] = True
    command = [sys.executable, "-I", str(Path(__file__).resolve().with_name("collector_process.py"))]
    process = None
    try:
        process = subprocess.Popen(command, **options)
        deadline = time.monotonic() + timeout
        while True:
            if os.fstat(child_output.fileno()).st_size > MAX_SNAPSHOT_BYTES:
                raise IsolatedCollectionError("output_limit")
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise IsolatedCollectionError("collector_timeout")
            try:
                returncode = process.wait(timeout=min(0.1, remaining))
                break
            except subprocess.TimeoutExpired:
                continue
        if returncode != 0:
            raise IsolatedCollectionError("collector_failed")
        child_output.seek(0)
        raw = child_output.read(MAX_SNAPSHOT_BYTES + 1)
        if len(raw) > MAX_SNAPSHOT_BYTES:
            raise IsolatedCollectionError("output_limit")
        return raw
    finally:
        # Terminate and reap before descriptors and TemporaryDirectory close,
        # including on Windows where an open child file prevents cleanup.
        if process is not None:
            _terminate(process)


def run_isolated_collection(config: dict, credentials: dict, attestations: dict, *, timeout=650) -> dict:
    """Return a validated live snapshot, or a generic IsolatedCollectionError.

    Each invocation has private home/config files, stdin, and bounded output.
    The worker process receives only this tenant's allowlisted credentials.
    """
    try:
        if type(timeout) not in (int, float) or not 0 < timeout <= 900:
            raise ValueError("Invalid collector timeout.")
        request = _validate_request(config, credentials, attestations)
        payload = canonical(request)
    except Exception:
        raise IsolatedCollectionError("invalid_request") from None

    try:
        with tempfile.TemporaryDirectory(prefix="cleartrail-collector-") as temporary:
            directory = Path(temporary)
            os.chmod(directory, 0o700)
            for name in ("aws-credentials", "aws-config"):
                with _private_file(directory / name):
                    pass
            with _private_file(directory / "stdin.json") as child_input, _private_file(directory / "stdout.json") as child_output:
                child_input.write(payload)
                child_input.seek(0)
                raw = _execute(directory, child_input, child_output, timeout)
                result = strict_json_loads(raw)
                validate_run(result, allow_legacy=False)
                if (result["demo"] is not False or result["config_fingerprint"] != digest(request["config"])
                        or result["organization"] != request["config"]["organization"]):
                    raise IsolatedCollectionError("invalid_snapshot")
                if _contains_secret(result, request["credentials"]):
                    raise IsolatedCollectionError("credential_in_output")
                return result
    except IsolatedCollectionError:
        raise
    except Exception:
        raise IsolatedCollectionError("collector_failed") from None
