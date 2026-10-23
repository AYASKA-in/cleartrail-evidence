"""Private stdin/stdout entry point for one tenant's collector subprocess."""
from __future__ import annotations

import contextlib
import os
import sys
from pathlib import Path


def main():
    # -I deliberately excludes CWD, PYTHONPATH and user packages. Only the
    # installed package's explicit parent is added for this entry point.
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    output = sys.stdout.buffer
    try:
        with open(os.devnull, "w") as quiet, contextlib.redirect_stdout(quiet), contextlib.redirect_stderr(quiet):
            from cleartrail.isolated import ALLOWED_CREDENTIALS, MAX_INPUT_BYTES, _contains_secret, _validate_request
            from cleartrail.validation import MAX_SNAPSHOT_BYTES, canonical, strict_json_loads, validate_run
            raw = sys.stdin.buffer.read(MAX_INPUT_BYTES + 1)
            if len(raw) > MAX_INPUT_BYTES:
                raise ValueError("Collector input limit")
            request = strict_json_loads(raw)
            if not isinstance(request, dict) or set(request) != {"config", "credentials", "attestations"}:
                raise ValueError("Invalid collector request")
            request = _validate_request(**request)
            for key in ALLOWED_CREDENTIALS:
                os.environ.pop(key, None)
            os.environ.update(request["credentials"])
            if os.name == "posix":
                import resource
                resource.setrlimit(resource.RLIMIT_FSIZE, (MAX_SNAPSHOT_BYTES, MAX_SNAPSHOT_BYTES))
                resource.setrlimit(resource.RLIMIT_CPU, (620, 620))
            from cleartrail.core import build_run, collect_observations, now
            started = now()
            observations = collect_observations(request["config"], demo=False)
            snapshot = build_run(request["config"], observations, request["attestations"],
                                 demo=False, collection_started_at=started)
            validate_run(snapshot, allow_legacy=False)
            if _contains_secret(snapshot, request["credentials"]):
                raise ValueError("Credential in collector output")
            body = canonical(snapshot)
            if len(body) > MAX_SNAPSHOT_BYTES:
                raise ValueError("Collector output limit")
        output.write(body)
        output.flush()
        return 0
    except BaseException:
        # API, SDK, import, and validation errors cannot publish traceback text.
        try:
            output.write(b'{"error":"collection_failed"}')
            output.flush()
        except Exception:
            pass
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
