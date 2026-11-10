"""
verify_preservation.py

Verification script ONLY. It does not modify any production module and never touches the project database.

It runs against a throw-away SQLite database in a temporary directory (set below, BEFORE the application is imported),
and it removes that directory when it finishes. It confirms that:
  * the alert status moves NEW -> TRIAGED -> ENRICHED, and
  * enrichment keeps the triage result in normalized_data.

Run:  python verify_preservation.py   (from the backend directory)
"""
import os
import shutil
import sys
import tempfile

BACKEND_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BACKEND_DIR)

_WORK_DIR = tempfile.mkdtemp(prefix="socmind-verify-")
# Must be set before any app module is imported: the engine reads DATABASE_URL when it is created.
os.environ["DATABASE_URL"] = "sqlite:///" + os.path.join(_WORK_DIR, "verify.db").replace("\\", "/")
os.environ["THREAT_INTEL_PROVIDER"] = "mock"      # offline: no network lookups from a verification run
os.environ["VIRUSTOTAL_API_KEY"] = ""


def main() -> int:
    from fastapi.testclient import TestClient

    from app.db.session import engine, init_db
    from app.main import app

    try:
        init_db()
        client = TestClient(app)

        # Step 1: ingest
        ingest = client.post("/api/v1/alerts", json={
            "alert_title": "Triage-then-Enrich Preservation Test",
            "source": "Splunk SIEM",
            "severity": "HIGH",
            "source_ip": "185.220.101.5",
            "file_hash": "71961ab144a1b3a0a452bf2b13861433ea750a028981f3efd0fc302e0ec0dabc",
            "command_line": "powershell.exe -ExecutionPolicy Bypass",
        })
        assert ingest.status_code == 201, f"Ingest failed: {ingest.text}"
        alert_id = ingest.json()["id"]
        status_after_ingest = ingest.json()["status"]
        print(f"[1] Ingested  alert_id={alert_id}  status={status_after_ingest}")
        assert status_after_ingest == "NEW", f"Expected NEW after ingest, got {status_after_ingest}"

        # Step 2: triage
        triage = client.post(f"/api/v1/alerts/{alert_id}/triage")
        assert triage.status_code == 200, f"Triage failed: {triage.text}"
        triage_score = triage.json()["triage_result"]["suspicion_score"]
        status_after_triage = triage.json()["alert"]["status"]
        print(f"[2] Triaged   suspicion_score={triage_score}  status={status_after_triage}")
        assert status_after_triage == "TRIAGED", f"Expected TRIAGED after triage, got {status_after_triage}"

        # Step 3: status immediately before enrichment
        pre_enrich_fetch = client.get(f"/api/v1/alerts/{alert_id}")
        assert pre_enrich_fetch.status_code == 200
        status_before_enrich = pre_enrich_fetch.json()["status"]
        print(f"[3] Status immediately BEFORE enrichment call: {status_before_enrich}")

        # Step 4: enrich
        enrich = client.post(f"/api/v1/alerts/{alert_id}/enrich")
        assert enrich.status_code == 200, f"Enrich failed: {enrich.text}"
        enrich_data = enrich.json()
        alert_after_enrich = enrich_data["alert"]
        status_after_enrich = alert_after_enrich["status"]
        norm_data = alert_after_enrich["normalized_data"]
        print(f"[4] Enriched  total_iocs={enrich_data['enrichment_result']['total_iocs_extracted']}")
        print(f"              malicious={enrich_data['enrichment_result']['summary']['malicious']}")
        print(f"    Status immediately AFTER enrichment call : {status_after_enrich}")

        # Step 5: the status transition
        print()
        print("[5] Asserting status-transition chain ...")
        assert status_before_enrich == "TRIAGED", \
            f"FAIL: Expected status before enrich='TRIAGED', got '{status_before_enrich}'"
        assert status_after_enrich == "ENRICHED", \
            f"FAIL: Expected status after enrich='ENRICHED', got '{status_after_enrich}'"
        print(f"    status_before_enrich : {status_before_enrich}")
        print(f"    status_after_enrich  : {status_after_enrich}")
        print("    Transition TRIAGED -> ENRICHED confirmed: PASS")

        # Step 6: triage data is preserved, not overwritten
        print()
        print("[6] Asserting triage data preserved in normalized_data ...")
        assert "triage" in norm_data, "FAIL: 'triage' key missing from normalized_data after enrichment!"
        assert "enrichment" in norm_data, "FAIL: 'enrichment' key missing from normalized_data after enrichment!"
        preserved_score = norm_data["triage"]["suspicion_score"]
        assert preserved_score == triage_score, f"FAIL: triage score changed from {triage_score} to {preserved_score}!"
        print("    'triage' key present              : YES")
        print(f"    triage.suspicion_score preserved  : {preserved_score}  (matches original {triage_score})")
        print("    'enrichment' key present          : YES")
        print(f"    enrichment.agent                  : {norm_data['enrichment']['agent']}")
        print(f"    enrichment.total_iocs_extracted   : {norm_data['enrichment']['total_iocs_extracted']}")

        print()
        print("=" * 60)
        print("OVERALL RESULT: ALL ASSERTIONS PASSED")
        print("  - Triage data not overwritten by enrichment.")
        print("  - Alert status transitioned TRIAGED -> ENRICHED as expected.")
        print("  - Both triage and enrichment keys coexist in normalized_data.")
        print("  - Run against a temporary database; the project database was not used.")
        print("=" * 60)
        return 0
    finally:
        engine.dispose()                     # Windows cannot delete an open SQLite file
        shutil.rmtree(_WORK_DIR, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
