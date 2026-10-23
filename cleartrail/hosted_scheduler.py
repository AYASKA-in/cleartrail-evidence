"""Small supervised recurring dispatcher using the existing PostgreSQL queue."""
from __future__ import annotations

import argparse
import logging
import signal
import threading

from .hosted_repository import Repository
from .hosted_settings import HostedSettings

LOGGER = logging.getLogger(__name__)


def main(argv=None):
    parser = argparse.ArgumentParser(description="ClearTrail recurring collection scheduler")
    parser.add_argument("--once", action="store_true", help="Dispatch due occurrences once and exit")
    args = parser.parse_args(argv)
    stop = threading.Event()
    for kind in (signal.SIGTERM, signal.SIGINT):
        signal.signal(kind, lambda *_: stop.set())
    repo = Repository(HostedSettings.from_env())
    try:
        repo.ready()
        while not stop.is_set():
            try:
                repo.dispatch_due()
            except Exception:
                LOGGER.error("scheduler_dispatch_failed")
                if args.once:
                    return 1
            if args.once:
                return 0
            stop.wait(30)
    finally:
        repo.engine.dispose()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
