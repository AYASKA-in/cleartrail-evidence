"""Current control catalog; historical versions remain in the packaged registry."""
from .catalog_registry import CURRENT_CATALOG_VERSION, get_catalog

CATALOG = get_catalog(CURRENT_CATALOG_VERSION)
CONTROLS = [
    (c["id"], c["title"], c["provider"], c["category"], c["frameworks"]["SOC 2"],
     c["frameworks"]["ISO 27001:2022"], c["remediation"])
    for c in CATALOG.values()
]
PROVIDERS = {"github": "GitHub", "google": "Google Workspace", "aws": "Amazon Web Services", "manual": "Team evidence"}
