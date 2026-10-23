"""Packaged, hash-pinned historical catalogs. Never resolve versions from URLs."""
import copy
import hashlib
import json
from functools import lru_cache
from pathlib import Path

CURRENT_CATALOG_VERSION = "2026.10.1"
CATALOG_DIGESTS = {"2026.10.1": "b562ab2378ad4a055765d268275908b737d32c1a4c728ea5ae04ce584e40aa81"}


@lru_cache(maxsize=32)
def _load(version):
    raw = (Path(__file__).with_name("data") / "catalogs" / (version + ".json")).read_bytes()
    if hashlib.sha256(raw).hexdigest() != CATALOG_DIGESTS[version]:
        raise ValueError("Packaged control catalog integrity failed.")
    value = json.loads(raw)
    if value["version"] != version:
        raise ValueError("Packaged control catalog version mismatch.")
    controls = {control["id"]: control for control in value["controls"]}
    if len(controls) != len(value["controls"]):
        raise ValueError("Duplicate packaged control identity.")
    return controls


def get_catalog(version):
    if not isinstance(version, str) or version not in CATALOG_DIGESTS:
        raise ValueError("Unsupported catalog version.")
    return copy.deepcopy(_load(version))
