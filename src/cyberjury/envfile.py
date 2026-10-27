"""The working directory environment file that CLI commands load."""

from pathlib import Path


def load_env_file() -> None:
    """Load only the current directory's .env without replacing exported values."""
    path = Path.cwd() / ".env"
    if path.is_file():
        from dotenv import load_dotenv

        load_dotenv(path, override=False)
