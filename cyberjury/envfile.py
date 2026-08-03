"""Load a project .env into the process environment for the CLI.

Both review paths read their backend config from os.environ and from defaults frozen at
import, so the CLI loads a `.env` from the working directory before those reads happen. A
value already set in the real environment wins, the file only fills what is unset, so an
explicit export is never overridden by a stale file. Library callers that import the provider
factory directly do not trigger this, the auto-load is a CLI convenience and not engine
behavior. A missing file is not an error, invariant 4 stays on the model call and not on
config discovery.
"""

from __future__ import annotations

import os
from pathlib import Path


def parse_env(text: str) -> dict[str, str]:
    """Parse the KEY=VALUE subset of dotenv syntax the CLI config needs.

    One layer of surrounding single or double quotes is stripped from the value. A line with no
    = is ignored rather than raised on, so a hand-edited file with a stray note does not fail a run.
    """
    out: dict[str, str] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line.removeprefix("export ").lstrip()
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        if not key:
            continue
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        out[key] = value
    return out


def load_env_file(path: str | os.PathLike = ".env", *, override: bool = False) -> list[str]:
    """Load `path` into os.environ if it exists, return the names actually set.

    A key already present in the environment is left untouched unless `override`, so a value
    exported in the shell wins over the file.
    """
    p = Path(path)
    if not p.is_file():
        return []
    loaded = []
    for key, value in parse_env(p.read_text(encoding="utf-8")).items():
        if not override and key in os.environ:
            continue
        os.environ[key] = value
        loaded.append(key)
    return loaded
