"""Pipeline orchestrator.

Runs the five agents in order on the alerts stored in the database:
    Triage -> Enrichment -> Correlation -> Investigation -> Response recommendation
Human review (approve/reject) is deliberately NOT part of the pipeline.

Design rules
- Real data flow: every stage reads the records the previous stage stored (triage/enrichment results in
  alert.normalized_data, correlated incidents in the incidents table, investigation in incident.details).
- Idempotent: running it twice without new data creates and changes nothing.
- Fault tolerant: every item and every stage is wrapped; a failure is recorded and the run continues.
- Honest outcome: `outcome` is "success", "partial" (some stage failed or partly failed) or "failure"
  (nothing succeeded); it is never reported as success when a stage failed.
- Single run at a time: a second concurrent run is refused instead of racing the first.
- Every run writes a PIPELINE_RUN audit entry containing the per-stage report.
- Scope: `alert_ids` limits triage and enrichment. Correlation always considers every non-closed alert,
  because an incident can only be recognised against all open alerts.
"""
import threading
import time
import uuid
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional

from sqlalchemy.orm import Session

from app.models.models import AlertModel, IncidentModel
from app.services.audit import log_action
from app.services.incident_service import (
    DecisionError, correlate_and_store, investigate_incident, recommend_for_incident,
)
from app.services.pipeline_steps import enrich_alert_record, triage_alert_record

_RUN_LOCK = threading.Lock()
MAX_ERROR_LENGTH = 300


class PipelineBusy(Exception):
    """Raised when a pipeline run is already in progress."""


class UnknownAlerts(Exception):
    """Raised when none of the requested alert ids exist."""

    def __init__(self, ids: List[str]):
        super().__init__(f"None of the requested alert ids exist: {', '.join(ids)}")
        self.ids = ids


def _error_text(exc: Exception) -> str:
    return f"{type(exc).__name__}: {exc}"[:MAX_ERROR_LENGTH]


class PipelineOrchestrator:
    agent_name = "Orchestrator"

    def run(self, db: Session, alert_ids: Optional[List[str]] = None, window_hours: int = 24) -> Dict[str, Any]:
        if not _RUN_LOCK.acquire(blocking=False):
            raise PipelineBusy("A pipeline run is already in progress.")
        try:
            return self._run(db, alert_ids, window_hours)
        finally:
            _RUN_LOCK.release()

    def _run(self, db: Session, alert_ids: Optional[List[str]], window_hours: int) -> Dict[str, Any]:
        run_id = uuid.uuid4().hex[:12]
        started = datetime.utcnow()
        t0 = time.perf_counter()
        stages: List[Dict[str, Any]] = []
        warnings: List[str] = []

        requested = list(dict.fromkeys(alert_ids or []))
        q = db.query(AlertModel)
        if requested:
            q = q.filter(AlertModel.id.in_(requested))
        found = q.all()
        unknown = [i for i in requested if i not in {a.id for a in found}]
        if requested and not found:
            raise UnknownAlerts(unknown)
        closed = sorted(a.id for a in found if a.status == "CLOSED")
        alerts = [a for a in found if a.status != "CLOSED"]
        alert_pks = [a.id for a in alerts]
        if unknown:
            warnings.append(f"Unknown alert id(s) ignored: {', '.join(unknown)}")
        if closed and requested:
            warnings.append(f"Closed alert(s) skipped: {', '.join(closed)}")

        stages.append(self._per_item_stage(db, "Triage Agent", alert_pks,
                                           lambda a: "triage" not in (a.normalized_data or {}), triage_alert_record))
        stages.append(self._per_item_stage(db, "Enrichment Agent", alert_pks,
                                           lambda a: "enrichment" not in (a.normalized_data or {}), enrich_alert_record))
        if stages[1]["status"] != "success":
            warnings.append("Some alerts have no enrichment result; investigation and recommendations ran without that intelligence.")

        corr = self._stage(db, "Correlation Agent", lambda: correlate_and_store(db, window_hours))
        stages.append(corr["stage"])
        corr_result = corr["result"] or {"created": [], "updated": [], "unchanged": []}
        if corr_result.get("alerts_without_valid_timestamp"):
            warnings.append("Alerts without a valid timestamp cannot be correlated: "
                            + ", ".join(corr_result["alerts_without_valid_timestamp"]))

        # Investigation: new/updated incidents and any whose investigation is missing or stale
        incidents = db.query(IncidentModel).filter(IncidentModel.status != "MERGED").all()
        to_investigate = [i.id for i in incidents if not (i.details or {}).get("investigation") or (i.details or {}).get("investigation_stale")]
        stages.append(self._per_item_stage(db, "Investigation Agent", to_investigate, None, lambda inc: investigate_incident(db, inc), model=IncidentModel))

        db.expire_all()
        incidents = db.query(IncidentModel).filter(IncidentModel.status != "MERGED").all()
        to_recommend = [i.id for i in incidents
                        if i.human_approval_status == "PENDING"
                        and ((i.details or {}).get("recommendations_stale") or not (i.details or {}).get("recommendations"))]
        stages.append(self._per_item_stage(db, "Response Agent", to_recommend, None, lambda inc: recommend_for_incident(db, inc), model=IncidentModel))

        failed = [s for s in stages if s["status"] in ("failed", "partial")]
        # A stage "attempted" work if it processed something or hit an error; stages with nothing to do don't count
        attempted_ok = [s for s in stages if s["status"] == "success" and s["processed"] > 0]
        if not failed:
            outcome, status = "success", "completed"
        elif not attempted_ok:
            outcome, status = "failure", "failed"
        else:
            outcome, status = "partial", "completed_with_errors"
        pending = db.query(IncidentModel).filter(IncidentModel.human_approval_status == "PENDING",
                                                 IncidentModel.status == "RESPONSE_PROPOSED").count()
        report = {
            "run_id": run_id, "started_at": started.isoformat(), "finished_at": datetime.utcnow().isoformat(),
            "duration_ms": int((time.perf_counter() - t0) * 1000),
            "status": status, "outcome": outcome,
            "alerts_in_scope": len(alert_pks), "unknown_alert_ids": unknown, "closed_alert_ids": closed if requested else [],
            "stages": stages, "warnings": warnings,
            "incidents_created": corr_result["created"], "incidents_updated": corr_result["updated"],
            "incidents_unchanged": corr_result["unchanged"], "incidents_awaiting_human_review": pending,
            "message": corr["result"].get("message") if corr["result"] else None,
        }
        log_action(db, self.agent_name, "PIPELINE_RUN", run_id, report)
        db.commit()
        return report

    # ---- helpers -------------------------------------------------------------------------
    def _stage(self, db: Session, name: str, fn: Callable[[], Any]) -> Dict[str, Any]:
        t = time.perf_counter()
        try:
            result = fn()
            stage = {"agent": name, "status": "success", "processed": len(result.get("created", [])) + len(result.get("updated", [])) if isinstance(result, dict) else 0,
                     "skipped": 0, "duration_ms": int((time.perf_counter() - t) * 1000), "errors": [], "notes": []}
            return {"stage": stage, "result": result}
        except Exception as exc:  # noqa: BLE001 - a failing agent must not stop the pipeline
            db.rollback()
            stage = {"agent": name, "status": "failed", "processed": 0, "skipped": 0,
                     "duration_ms": int((time.perf_counter() - t) * 1000), "errors": [_error_text(exc)], "notes": []}
            log_action(db, name, "AGENT_FAILED", None, {"error": stage["errors"][0]})
            db.commit()
            return {"stage": stage, "result": None}

    def _per_item_stage(self, db: Session, name: str, ids: List[str], needs_work, fn, model=AlertModel) -> Dict[str, Any]:
        t = time.perf_counter()
        done, errors, notes, skipped = 0, [], [], 0
        for item_id in ids:
            try:
                item = db.query(model).filter(model.id == item_id).first()
                if item is None:
                    continue
                if needs_work is not None and not needs_work(item):
                    skipped += 1
                    continue
                fn(item) if model is IncidentModel else fn(db, item)
                db.commit()
                done += 1
            except DecisionError as exc:
                db.rollback()
                skipped += 1
                notes.append(f"{item_id}: skipped ({exc})")
            except Exception as exc:  # noqa: BLE001
                db.rollback()
                errors.append(f"{item_id}: {_error_text(exc)}")
                log_action(db, name, "AGENT_FAILED", item_id, {"error": _error_text(exc)})
                db.commit()
        status = "success" if not errors else ("failed" if done == 0 and ids else "partial")
        return {"agent": name, "status": status, "processed": done, "skipped": skipped,
                "duration_ms": int((time.perf_counter() - t) * 1000), "errors": errors, "notes": notes}
