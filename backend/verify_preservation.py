"""
verify_preservation.py
Verification script ONLY. Does not modify any production module.
Confirms that enrichment preserves triage data and that alert
status immediately before enrichment matches the expected pre-enrichment state.
"""
import sys
sys.path.insert(0, '.')

from app.db.session import init_db
from app.main import app
from fastapi.testclient import TestClient

init_db()
client = TestClient(app)

# â”€â”€ Step 1: Ingest â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
ingest = client.post('/api/v1/alerts', json={
    'alert_title': 'Triage-then-Enrich Preservation Test',
    'source': 'Splunk SIEM',
    'severity': 'HIGH',
    'source_ip': '185.220.101.5',
    'file_hash': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    'command_line': 'powershell.exe -ExecutionPolicy Bypass'
})
assert ingest.status_code == 201, f"Ingest failed: {ingest.text}"
alert_id = ingest.json()['id']
status_after_ingest = ingest.json()['status']
print(f"[1] Ingested  alert_id={alert_id}  status={status_after_ingest}")
assert status_after_ingest == 'NEW', f"Expected NEW after ingest, got {status_after_ingest}"

# â”€â”€ Step 2: Triage â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
triage = client.post(f'/api/v1/alerts/{alert_id}/triage')
assert triage.status_code == 200, f"Triage failed: {triage.text}"
triage_score = triage.json()['triage_result']['suspicion_score']
status_after_triage = triage.json()['alert']['status']
print(f"[2] Triaged   suspicion_score={triage_score}  status={status_after_triage}")
assert status_after_triage == 'TRIAGED', f"Expected TRIAGED after triage, got {status_after_triage}"

# â”€â”€ Step 3: Capture status immediately BEFORE enrichment call â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
pre_enrich_fetch = client.get(f'/api/v1/alerts/{alert_id}')
assert pre_enrich_fetch.status_code == 200
status_before_enrich = pre_enrich_fetch.json()['status']
print(f"[3] Status immediately BEFORE enrichment call: {status_before_enrich}")

# â”€â”€ Step 4: Enrich â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
enrich = client.post(f'/api/v1/alerts/{alert_id}/enrich')
assert enrich.status_code == 200, f"Enrich failed: {enrich.text}"
enrich_data = enrich.json()
alert_after_enrich = enrich_data['alert']
status_after_enrich = alert_after_enrich['status']
norm_data = alert_after_enrich['normalized_data']

print(f"[4] Enriched  total_iocs={enrich_data['enrichment_result']['total_iocs_extracted']}")
print(f"              malicious={enrich_data['enrichment_result']['summary']['malicious']}")
print(f"    Status immediately AFTER enrichment call : {status_after_enrich}")

# â”€â”€ Step 5: Assert status transition is correct and intentional â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
print()
print("[5] Asserting status-transition chain ...")
assert status_before_enrich == 'TRIAGED', \
    f"FAIL: Expected status before enrich='TRIAGED', got '{status_before_enrich}'"
assert status_after_enrich == 'ENRICHED', \
    f"FAIL: Expected status after enrich='ENRICHED', got '{status_after_enrich}'"
assert status_before_enrich != status_after_enrich, \
    "FAIL: Status should change from TRIAGED to ENRICHED during enrichment"
print(f"    status_before_enrich : {status_before_enrich}")
print(f"    status_after_enrich  : {status_after_enrich}")
print(f"    Transition TRIAGED â†’ ENRICHED confirmed: PASS")

# â”€â”€ Step 6: Assert triage data is preserved (not overwritten) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
print()
print("[6] Asserting triage data preserved in normalized_data ...")
assert 'triage' in norm_data, \
    "FAIL: 'triage' key missing from normalized_data after enrichment!"
assert 'enrichment' in norm_data, \
    "FAIL: 'enrichment' key missing from normalized_data after enrichment!"
preserved_score = norm_data['triage']['suspicion_score']
assert preserved_score == triage_score, \
    f"FAIL: triage score changed from {triage_score} to {preserved_score}!"
print(f"    'triage' key present              : YES")
print(f"    triage.suspicion_score preserved  : {preserved_score}  (matches original {triage_score})")
print(f"    'enrichment' key present          : YES")
print(f"    enrichment.agent                  : {norm_data['enrichment']['agent']}")
print(f"    enrichment.total_iocs_extracted   : {norm_data['enrichment']['total_iocs_extracted']}")

print()
print("=" * 60)
print("OVERALL RESULT: ALL ASSERTIONS PASSED")
print("  - Triage data not overwritten by enrichment.")
print("  - Alert status transitioned TRIAGED â†’ ENRICHED as expected.")
print("  - Both triage and enrichment keys coexist in normalized_data.")
print("=" * 60)
