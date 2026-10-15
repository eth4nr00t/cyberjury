"""Locations of package content that does not belong to a review profile.

Profile content is reached through `ReviewProfile.paths`.
"""

from pathlib import Path

SLASH_COMMAND_FILE = Path(__file__).parent / "commands" / "slash-command.md"
