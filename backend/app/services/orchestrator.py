from typing import Dict, Any, List
from app.agents.triage.triage_agent import TriageAgent
from app.agents.correlation.correlation_agent import CorrelationAgent
from app.agents.enrichment.enrichment_agent import EnrichmentAgent
from app.agents.investigation.investigation_agent import InvestigationAgent
from app.agents.response.response_agent import ResponseAgent


class PipelineOrchestrator:
    """
    Central orchestrator managing execution flow across all 5 AI Agents.
    """
    def __init__(self):
        self.triage_agent = TriageAgent()
        self.correlation_agent = CorrelationAgent()
        self.enrichment_agent = EnrichmentAgent()
        self.investigation_agent = InvestigationAgent()
        self.response_agent = ResponseAgent()

    def run_pipeline_on_alerts(self, alerts: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Executes the sequential 5-agent pipeline workflow on raw/normalized alerts.
        """
        # Step 1: Triage
        triaged_alerts = [self.triage_agent.analyze_alert(a) for a in alerts]

        # Step 2: Correlation
        correlated_incidents = self.correlation_agent.correlate_alerts(alerts)

        # Step 3: Enrichment
        enrichment_results = self.enrichment_agent.enrich_iocs(
            [{"type": "ip", "value": a.get("destination_ip")} for a in alerts if a.get("destination_ip")]
        )

        # Step 4: Investigation
        investigation_results = self.investigation_agent.investigate_incident(
            incident_id="INC-CANDIDATE-001", logs=[]
        )

        # Step 5: Response Recommendation
        response_recommendation = self.response_agent.recommend_response(
            incident_id="INC-CANDIDATE-001", severity="High"
        )

        return {
            "status": "completed",
            "triaged_alerts_count": len(triaged_alerts),
            "incidents_created": len(correlated_incidents),
            "enrichment_summary": enrichment_results,
            "investigation_summary": investigation_results,
            "recommended_action": response_recommendation
        }
