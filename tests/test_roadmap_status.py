"""The roadmap's status table must match its checkboxes."""
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def test_roadmap_table_matches_checkboxes():
    r = subprocess.run([sys.executable, str(ROOT / "scripts" / "roadmap_status.py"), "--check"],
                       capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
