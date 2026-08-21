"""Provider settings reject invalid retry relationships."""

import pytest

from cyberjury.providers.settings import ProviderSettings


def test_provider_settings_reject_a_backoff_range_in_reverse():
    """The initial retry delay must respect the operator's maximum delay."""
    with pytest.raises(ValueError, match="cannot exceed"):
        ProviderSettings(retry_initial_delay_seconds=2, retry_max_delay_seconds=1)
