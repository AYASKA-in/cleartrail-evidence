"""Explicit administrative bootstrap and maintenance, never a public API."""
import argparse
import json
import os
import sys

from .hosted_repository import Repository
from .hosted_settings import HostedSettings


def main(argv=None):
    parser = argparse.ArgumentParser(description="ClearTrail hosted administration")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("migrate")
    create = sub.add_parser("create-tenant")
    create.add_argument("--name", required=True)
    create.add_argument("--issuer", required=True)
    create.add_argument("--subject", required=True)
    validate = sub.add_parser("validate-providers", help="Run read-only live provider preflight and isolated collection")
    validate.add_argument("--tenant", required=True)
    validate.add_argument("--report", required=True, help="New private JSON report path; never overwritten")
    for name in ("audit", "rotate-vault", "rebuild-monitoring"):
        item = sub.add_parser(name)
        item.add_argument("--tenant", required=True)
        if name == "audit":
            item.add_argument("--expected-head")
    args = parser.parse_args(argv)
    try:
        repo = Repository(HostedSettings.from_env())
        try:
            if args.command == "migrate":
                repo.migrate()
                repo.ready()
                print("Hosted schema is ready.")
            else:
                repo.ready()
                if args.command == "validate-providers":
                    from .deployment_checks import validate_providers
                    # Reserve before contacting providers; a path error must not
                    # trigger external collection followed by a lost report.
                    descriptor = os.open(args.report, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
                        report = validate_providers(repo, args.tenant)
                        json.dump(report, stream, indent=2)
                        stream.flush()
                        os.fsync(stream.fileno())
                    print(json.dumps({"provider_validation_complete": report["provider_validation_complete"], "report_written": True}))
                    return 0 if report["provider_validation_complete"] else 2
                elif args.command == "create-tenant":
                    print(json.dumps({"tenant_id": repo.create_tenant(args.name, args.issuer, args.subject)}))
                elif args.command == "audit":
                    print(json.dumps(repo.audit_verify(args.tenant, args.expected_head), indent=2))
                elif args.command == "rotate-vault":
                    print(json.dumps({"rotated": repo.rotate_credentials(args.tenant), "document_envelopes_rotated": True}))
                else:
                    print(json.dumps({"rebuilt": repo.rebuild_monitoring(args.tenant)}))
            return 0
        finally:
            repo.engine.dispose()
    except Exception:
        print("Administration failed. Check configuration, database availability, and schema version. No credentials were printed.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
