"""The working directory environment file that CLI commands load, and the settings read from the environment."""

import os
from pathlib import Path


def load_env_file() -> None:
    """Load only the current directory's .env without replacing exported values."""
    path = Path.cwd() / ".env"
    if path.is_file():
        from dotenv import load_dotenv

        load_dotenv(path, override=False)


def env_setting(name: str) -> str | None:
    """Return the named environment setting without surrounding whitespace, treating a blank value as unset."""
    return os.getenv(name, "").strip() or None
