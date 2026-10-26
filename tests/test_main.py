"""The package entry point delegates to the supported CLI."""

import subprocess
import sys


def test_python_dash_m_cyberjury_runs():
    """Running python -m cyberjury --version in a subprocess exits 0 and prints the cyberjury name."""
    r = subprocess.run([sys.executable, "-m", "cyberjury", "--version"], capture_output=True, text=True)
    assert r.returncode == 0
    assert "cyberjury" in r.stdout.lower()
