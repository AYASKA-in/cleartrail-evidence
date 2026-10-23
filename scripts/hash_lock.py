"""Attach PyPI-published release hashes to a pip-compile pinned requirements file.

Usage: python scripts/hash_lock.py .cleartrail/requirements-resolved.txt
This avoids downloading every platform wheel solely to compute its hash.
Dependency resolution remains pip-compile's responsibility; this script rejects
unpinned, editable, URL, directive, or ambiguous requirements.
"""
import concurrent.futures
import json
import re
import sys
from pathlib import Path
from urllib.request import urlopen


def hashes(requirement):
    match = re.fullmatch(r"([A-Za-z0-9_.-]+)==([A-Za-z0-9_.+!-]+)(\s*;[^\r\n]+)?", requirement)
    if not match:
        raise ValueError("Expected an exact package pin: " + requirement)
    name, version, marker = match.groups()
    with urlopen("https://pypi.org/pypi/" + name + "/" + version + "/json", timeout=30) as response:
        metadata = json.load(response)
    values = sorted({item["digests"]["sha256"] for item in metadata["urls"] if not item.get("yanked")})
    if not values or any(not re.fullmatch(r"[a-f0-9]{64}", value) for value in values):
        raise ValueError("No usable release hashes for " + name)
    return requirement + " \\\n" + " \\\n".join("    --hash=sha256:" + value for value in values)


if __name__ == "__main__":
    lines = [line.strip() for line in Path(sys.argv[1]).read_text().splitlines() if line.strip() and not line.lstrip().startswith("#")]
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        result = list(pool.map(hashes, lines))
    Path("requirements-hosted.lock").write_text("# Resolved by pip-compile; hashes from https://pypi.org/pypi/PACKAGE/VERSION/json\n# Install with --require-hashes. Regeneration: see docs/HOSTED_DEPLOYMENT.md.\n\n" + "\n".join(result) + "\n", encoding="utf-8")
    print("Pinned and hashed", len(result), "runtime distributions.")
