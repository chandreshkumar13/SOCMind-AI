"""The application's clock. Timestamps are stored as naive UTC, as they always were; this helper returns that value through the
timezone-aware API, because the older naive-UTC shortcut is deprecated."""
from datetime import datetime, timezone


def utc_now() -> datetime:
    """The current time as a naive UTC datetime (tzinfo removed, so it compares with the stored timestamps)."""
    return datetime.now(timezone.utc).replace(tzinfo=None)
