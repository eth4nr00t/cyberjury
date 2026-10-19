"""The package entry point delegates to the supported CLI."""

import subprocess


def test_python_dash_m_cyberjury_runs():
    """Running python -m cyberjury --version in a subprocess exits 0 and prints the cyberjury name."""
    import sys

    r = subprocess.run([sys.executable, "-m", "cyberjury", "--version"], capture_output=True, text=True)
    assert r.returncode == 0
    assert "cyberjury" in r.stdout.lower()
