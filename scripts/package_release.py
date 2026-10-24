"""Allowlisted source ZIP; runtime evidence excluded, synthetic fixtures included."""
import hashlib
import zipfile
from pathlib import Path

root = Path(__file__).resolve().parents[1]
output = root / "dist" / "cleartrail-0.6.0-source.zip"
output.parent.mkdir(exist_ok=True)
paths = [root / name for name in ("README.md", "LICENSE", "SECURITY.md", "CONTRIBUTING.md", "pyproject.toml", "MANIFEST.in", "config.example.json", ".gitignore", ".dockerignore", "Dockerfile", "compose.yaml", ".env.hosted.example", "requirements-hosted.in", "requirements-hosted.lock", ".github/workflows/ci.yml")]
paths.extend(path for path in (root / ".github").rglob("*") if path.is_file() and path.suffix in {".yml", ".md"})
paths.append(root / ".gitattributes")
paths.append(root / "docs" / "research" / "manifest.json")
paths.extend(root / name for name in ("docs/qa/results-0.5.json", "docs/security/application-image-0.5.json", "docs/security/application-image-0.6.json", "docs/security/scanner-image-1.5.4-r1.json", "docs/qa/governance-desktop-0.6.png", "docs/qa/governance-mobile-0.6.png", "docs/qa/workspace-desktop-ui.png", "docs/qa/workspace-mobile-ui.png"))
paths.extend((root / "deploy").glob("*.conf"))
paths.append(root / "deploy" / "clamav.Dockerfile")
paths.append(root / "docs" / "security" / "scanner-image-1.5.4-r2.json")
paths.extend((root / "deploy" / "aws").glob("*.yaml"))
for folder in ("cleartrail", "tests", "scripts", "docs"):
    for path in (root / folder).rglob("*"):
        catalog_data = path.parent == root / "cleartrail" / "data" / "catalogs" and path.suffix == ".json"
        compatibility_fixture = path.parent == root / "tests" / "fixtures" and path.suffix in {".json", ".sql", ".b64"}
        if path.is_file() and (path.suffix in {".py", ".md", ".html", ".js", ".cjs", ".css", ".jpg"} or catalog_data or compatibility_fixture):
            if "__pycache__" not in path.parts and path.resolve().is_relative_to(root):
                paths.append(path)
with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as archive:
    for path in sorted(set(paths)):
        archive.write(path, "cleartrail/" + path.relative_to(root).as_posix())
checksum = hashlib.sha256(output.read_bytes()).hexdigest()
output.with_suffix(".zip.sha256").write_text(checksum + "  " + output.name + "\n", encoding="ascii")
print(output)
print(f"{len(paths)} source files; SHA-256 {checksum}")
