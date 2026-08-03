"""Locations of the content bundled inside the installed package.

The constants here are the default domain's content paths, the web domain today, resolved
through the registry so the default lives in one place rather than being named here too.
They are the paths the engine reads when no domain is selected, so every existing importer
keeps resolving the same files. A non-default domain is reached through `cyberjury.domains`,
whose `Domain.paths` returns the same `ContentPaths` shape these constants come from.
Content lives per domain under `domains/<name>/`: `knowledge/` is the pluggable security
knowledge, `playbook/` is the repository-review agent path's assets, `detection.yaml` is the file
classification config.
"""

from pathlib import Path

from cyberjury.domains.registry import default_domain

_PATHS = default_domain().paths

# The slash command is one domain-agnostic file, not a per-domain asset: it threads --domain
# through to Cyberjury, which detects or is told the domain, so a single installed command drives
# both web and evm. The per-domain playbook assets below stay domain-specific.
SLASH_COMMAND_FILE = Path(__file__).parent / "playbook" / "slash-command.md"

VULNERABILITIES_DIR = _PATHS.vulnerabilities_dir
LANGUAGES_DIR = _PATHS.languages_dir
FRAMEWORKS_DIR = _PATHS.frameworks_dir
PROTOCOLS_DIR = _PATHS.protocols_dir
KNOWLEDGE_INDEX = _PATHS.knowledge_index

METHODOLOGY_FILE = _PATHS.methodology_file
UNIT_REVIEW_FILE = _PATHS.unit_review_file
SEVERITY_RUBRIC_FILE = _PATHS.severity_rubric_file
FALSE_POSITIVE_TRAPS_FILE = _PATHS.false_positive_traps_file

DETECTION_FILE = _PATHS.detection_file
