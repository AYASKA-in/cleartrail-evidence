from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .core import Store, collect_run
from .reports import export_bundle, verify_bundle
from .server import create_server
from .validation import strict_json_loads, validate_config


def load_config(path):
    if path is None:
        return validate_config({})
    raw = Path(path).read_bytes()
    if len(raw) > 128 * 1024:
        raise ValueError("Configuration exceeds its size limit.")
    return validate_config(strict_json_loads(raw.decode("utf-8-sig")))


def main(argv=None):
    parser = argparse.ArgumentParser(description="ClearTrail — free, local compliance evidence collection")
    sub = parser.add_subparsers(dest="command", required=True)
    for name, help_text in [("serve", "Open the local dashboard"), ("collect", "Collect a point-in-time snapshot"), ("export", "Export the latest review package"), ("attest", "Record a team self-attestation")]:
        cmd = sub.add_parser(name, help=help_text)
        cmd.add_argument("--db", help="SQLite database (default .cleartrail/live.sqlite3; demo uses demo.sqlite3)")
        cmd.add_argument("--demo", action="store_true", help="Use a separate synthetic demonstration database; never connect to external accounts")
        if name in {"serve", "collect"}:
            cmd.add_argument("--config", help="Path to local JSON configuration")
        if name == "serve":
            cmd.add_argument("--port", type=int, default=8090)
        if name in {"export", "collect"}:
            cmd.add_argument("--output", required=name == "export", help="Write a new ZIP review package")
        if name == "export":
            cmd.add_argument("--run-id", help="Export a specific historical snapshot")
        if name == "attest":
            cmd.add_argument("control_id", choices=["MAN-POLICY", "MAN-ACCESS", "MAN-INCIDENT"])
            cmd.add_argument("--owner", required=True)
            cmd.add_argument("--note", required=True)
    verify = sub.add_parser("verify", help="Verify bundle file hashes against its unsigned manifest")
    verify.add_argument("bundle")
    verify.add_argument("--expected-manifest-sha256", "--manifest-sha256", dest="expected_manifest_sha256", help="Compare against an independently trusted manifest digest")
    audit_verify = sub.add_parser("verify-audit", help="Verify a document-inclusive audit package without extracting files")
    audit_verify.add_argument("bundle")
    audit_verify.add_argument("--expected-manifest-sha256", "--manifest-sha256", dest="expected_manifest_sha256")
    governance_verify = sub.add_parser("verify-governance", help="Verify a governance register offline without executing content")
    governance_verify.add_argument("register")
    governance_verify.add_argument("--expected-sha256")
    for name in ("doctor", "backup"):
        item = sub.add_parser(name)
        item.add_argument("--db", required=True)
        if name == "backup":
            item.add_argument("--output", required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "verify-governance":
            from .governance import verify_governance
            print(json.dumps(verify_governance(args.register, args.expected_sha256), indent=2))
            return 0
        if args.command == "verify-audit":
            from .audit_packages import verify_audit_package
            print(json.dumps(verify_audit_package(args.bundle, args.expected_manifest_sha256), indent=2))
            return 0
        if args.command == "verify":
            print(json.dumps(verify_bundle(args.bundle, expected_manifest_sha256=args.expected_manifest_sha256), indent=2))
            return 0
        if args.command in {"doctor", "backup"}:
            store = Store(args.db)
            if args.command == "doctor":
                print(json.dumps(store.health(), indent=2))
            else:
                store.backup(args.output)
                print("Verified database backup saved.")
            return 0
        db_path = args.db or (".cleartrail/demo.sqlite3" if args.demo else ".cleartrail/live.sqlite3")
        store = Store(db_path)
        config = load_config(getattr(args, "config", None))
        if args.demo:
            config["organization"] = "Northstar Labs (demo)"
        if args.command == "attest":
            store.attest(args.control_id, args.owner, args.note)
            print("Note saved. Collect a new snapshot to include this attestation in exports.")
        elif args.command == "export":
            run = store.get_run(args.run_id) if args.run_id else store.latest()
            if not run:
                raise ValueError("No snapshot found. Run collect first.")
            export_bundle(run, args.output)
            print(f"Exported {args.output}")
        elif args.command == "collect":
            run = collect_run(store, config, args.demo)
            print(json.dumps({"id": run["id"], "demo": run["demo"], **run["summary"]}, indent=2))
            if args.output:
                export_bundle(run, args.output)
                print(f"Exported {args.output}")
        else:
            if args.demo and store.latest() is None:
                collect_run(store, config, True)
            server = create_server(store, config, args.demo, args.port)
            print(f"ClearTrail {'DEMO (synthetic data)' if args.demo else 'live collection'}: {server.bootstrap_url}", flush=True)
            print("Open the complete private launch URL to sign in. Press Ctrl+C to stop.", flush=True)
            try:
                server.serve_forever()
            except KeyboardInterrupt:
                pass
            finally:
                server.server_close()
        return 0
    except (ValueError, OSError) as exc:
        # Do not echo upstream errors or arbitrary config values.
        safe = str(exc) if isinstance(exc, ValueError) else "Could not read or write the requested file, or bind the local port."
        print("ClearTrail: " + safe, file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
