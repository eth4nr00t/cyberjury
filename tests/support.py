"""Builders shared by every test package."""

import os
import subprocess
from pathlib import Path


def git(cwd: Path, *args: str) -> str:
    """Run one git command with a fixed test identity and return its trimmed output."""
    env = {
        **os.environ,
        "GIT_AUTHOR_NAME": "Test",
        "GIT_AUTHOR_EMAIL": "test@example.com",
        "GIT_COMMITTER_NAME": "Test",
        "GIT_COMMITTER_EMAIL": "test@example.com",
    }
    return subprocess.run(
        ["git", "-C", str(cwd), *args], check=True, capture_output=True, text=True, env=env
    ).stdout.strip()
