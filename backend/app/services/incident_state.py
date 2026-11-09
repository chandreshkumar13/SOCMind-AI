"""One definition of a merged incident, shared by every query and guard that needs it.

An incident is merged into another when correlation folds it into the surviving incident. The merge sets its status to
MERGED and writes a `merged_into` mark into its details. Both are checked, because either one can be missing or out of
date on its own: an older request could change a merged incident's status, so the status alone is not reliable; the mark
is what says the incident was folded into another. Lists, statistics, correlation, the pipeline and staleness therefore all
use the same two conditions, and a merged incident is never treated as active.
"""
from typing import Any, Optional

from sqlalchemy import and_

from app.models.models import IncidentModel

MERGED = "MERGED"


def merged_into_of(incident: Any) -> Optional[str]:
    """The id of the incident this one was merged into, or None when it has not been merged."""
    return (incident.details or {}).get("merged_into")


def is_merged(incident: Any) -> bool:
    """True when the incident is merged, by its status or by its merge mark."""
    return incident.status == MERGED or merged_into_of(incident) is not None


def active_incidents_clause():
    """SQL condition selecting the incidents that are still active (the mirror of is_merged)."""
    return and_(IncidentModel.status.is_not(MERGED), IncidentModel.details["merged_into"].as_string().is_(None))
