"""Run pure presentation regressions without browser or application dependencies."""
from pathlib import Path
import shutil
import subprocess

import pytest


@pytest.mark.skipif(not shutil.which("node"), reason="Optional Node.js development runtime unavailable")
def test_workspace_presentation_rules():
    root = Path(__file__).resolve().parents[1]
    result = subprocess.run([shutil.which("node"), "--test", str(root / "tests/frontend/workspace-ui.test.cjs")],
                            capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stdout + result.stderr
