"""One definition of an incident's lifecycle state, shared by every query and guard that needs it.

Two states take an incident out of work:

* MERGED - correlation folded the incident into another one. The merge sets the status to MERGED and writes a `merged_into`
  mark into the details. Both are checked, because either can be out of date on its own: an older request could change a
  merged incident's status, but the mark is what says it was folded into another incident.
* CLOSED - every alert of the incident was closed, so there is nothing left to analyse or decide.

Lists, statistics, correlation, the pipeline and staleness all use the same conditions, so a merged or closed incident is never
treated as active, and a closed alert cannot silently re-enter an active incident.
"""
from typing import Any, Optional

from sqlalchemy import and_, or_

from app.models.models import IncidentModel

MERGED = "MERGED"
CLOSED = "CLOSED"
INACTIVE_STATUSES = (MERGED, CLOSED)


def merged_into_of(incident: Any) -> Optional[str]:
    """The id of the incident this one was merged into, or None when it has not been merged."""
    return (incident.details or {}).get("merged_into")


def is_merged(incident: Any) -> bool:
    """True when the incident was merged, by its status or by its merge mark."""
    return incident.status == MERGED or merged_into_of(incident) is not None


def is_closed(incident: Any) -> bool:
    """True when every alert of the incident was closed."""
    return incident.status == CLOSED


def not_merged_clause():
    """SQL condition: the incident was not merged (its status and its merge mark agree)."""
    return and_(or_(IncidentModel.status.is_(None), IncidentModel.status.is_not(MERGED)),
                IncidentModel.details["merged_into"].as_string().is_(None))


def active_incidents_clause():
    """SQL condition: the incidents still in work (neither merged nor closed)."""
    return and_(not_merged_clause(), or_(IncidentModel.status.is_(None), IncidentModel.status.not_in(INACTIVE_STATUSES)))
