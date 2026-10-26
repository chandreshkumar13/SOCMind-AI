from datetime import datetime, timezone
from typing import Annotated

from pydantic import PlainSerializer


def utc_iso(value: datetime) -> str:
    """ISO-8601 in UTC with a 'Z' suffix. Naive datetimes are stored as UTC throughout SOCMind AI."""
    value = value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)
    return value.isoformat().replace("+00:00", "Z")


# A datetime that API responses always render as explicit UTC (e.g. 2026-09-03T08:14:00Z), so clients
# never have to guess the timezone of a bare timestamp.
UTCDateTime = Annotated[datetime, PlainSerializer(utc_iso, return_type=str, when_used="json")]
