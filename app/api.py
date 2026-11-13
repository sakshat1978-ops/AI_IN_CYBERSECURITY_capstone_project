import sys
from pathlib import Path

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field
from typing import Dict, Any, List, Optional
import pandas as pd

from src.config import (
    load_config, REMEDIATION_GUIDELINES, PROJECT_METADATA,
    MULTI_SECTOR_THREAT_PROFILES, CISO_ROADMAP
)
from src.predict import ThreatPredictor

app = FastAPI(
    title="AI-Powered Cyber Defense & Threat Intelligence API",
    description=(
        f"Grand Unified Capstone Project API by {PROJECT_METADATA['student_name']} (Roll: {PROJECT_METADATA['roll_number']}). "
        "Provides real-time dual-stage network threat classification, Explainable AI (XAI) attributions, "
        "multi-sector CISO threat landscape telemetry, and automated SecOps incident response."
    ),
    version="2.0.0"
)

# Global Predictor instance
predictor: Optional[ThreatPredictor] = None


@app.on_event("startup")
def startup_event():
    global predictor
    predictor = ThreatPredictor()
    if not predictor.is_ready:
        from src.cli import command_train
        import argparse
        command_train(argparse.Namespace(data=None, samples=3000))
        predictor = ThreatPredictor()


class FlowRecord(BaseModel):
    destination_port: int = Field(default=80, alias="Destination Port")
    flow_duration: float = Field(default=1000.0, alias="Flow Duration")
    flow_bytes_s: float = Field(default=50000.0, alias="Flow Bytes/s")
    flow_packets_s: float = Field(default=100.0, alias="Flow Packets/s")
    total_fwd_packets: int = Field(default=10, alias="Total Fwd Packets")
    total_backward_packets: int = Field(default=10, alias="Total Backward Packets")
    syn_flag_count: int = Field(default=0, alias="SYN Flag Count")
    ack_flag_count: int = Field(default=1, alias="ACK Flag Count")

    class Config:
        populate_by_name = True
        extra = "allow"


class XAIAttribution(BaseModel):
    feature: str
    observed_value: Any
    attribution_weight: float
    interpretation: str


class PredictionResponse(BaseModel):
    index: int
    verdict: str
    threat_score: int
    attack_category: str
    severity: str
    mitre_technique: str
    compliance_impact: str
    recommended_action: str
    mitigation_strategy: str
    requires_hitl: bool
    xai_attributions: List[XAIAttribution]
    raw_probability: float


class CopilotQueryRequest(BaseModel):
    query: str


class CopilotQueryResponse(BaseModel):
    query: str
    copilot_assessment: str
    recommended_action: str
    governance_notes: str


@app.get("/")
def root():
    return {
        "project": PROJECT_METADATA["project_title"],
        "student": PROJECT_METADATA["student_name"],
        "roll_number": PROJECT_METADATA["roll_number"],
        "program": PROJECT_METADATA["program"],
        "status": "online",
        "documentation": "/docs",
        "version": "2.0.0"
    }


@app.get("/health")
def health():
    if predictor and predictor.is_ready:
        return {"status": "healthy", "dual_stage_engine": "online", "xai_engine": "active"}
    return {"status": "degraded", "model_loaded": False}


@app.get("/ciso/threat-landscape")
def get_threat_landscape():
    """Returns the Multi-Sector Threat Landscape Profile (Assignment 1 Question 2)."""
    return {
        "organization_sectors": MULTI_SECTOR_THREAT_PROFILES,
        "adversary_dynamics": {
            "velocity": "Exploitation execution accelerated from days to milliseconds via AI automation.",
            "scale": "Near-zero marginal cost for polymorphic attack and contextual spear phishing generation.",
            "adaptability": "Polymorphic runtime crypters and GAN-generated traffic evading static thresholds."
        }
    }


@app.get("/ciso/roadmap")
def get_ciso_roadmap():
    """Returns the CISO 3-Phase Strategic Implementation Roadmap (Assignment 1 Question 5)."""
    return {
        "framework": "NIST AI Risk Management Framework (AI RMF 1.0)",
        "roadmap": CISO_ROADMAP
    }


@app.post("/secops/copilot/query", response_model=CopilotQueryResponse)
def query_secops_copilot(req: CopilotQueryRequest):
    """AI SecOps Copilot query endpoint for alert triage and compliance audits."""
    q = req.query.lower()
    if "ddos" in q:
        assessment = "Detected high-volume packet flooding matching MITRE T1498 (Network Denial of Service)."
        action = "Initiate BGP routing through Anycast scrubbing centers and enable SYN proxy cookies."
        notes = "Evaluate ISO 27001 A.17 business continuity obligations."
    elif "ssh" in q:
        assessment = "Credential stuffing probe detected on Port 22 matching MITRE T1110.001."
        action = "Enforce Fail2Ban IP lock, rotate administrative SSH keys, restrict port to VPN."
        notes = "Log security event under GDPR Article 32 access control safeguards."
    elif "hipaa" in q or "healthcare" in q:
        assessment = "Potential unencrypted telemetry movement or ransomware staging in healthcare network."
        action = "Trigger network micro-segmentation; mandate Human-In-The-Loop before disconnecting ICU assets."
        notes = "Audit HIPAA Security Rule §164.312 (Technical Safeguards)."
    else:
        assessment = f"Telemetry inquiry processed for '{req.query}'. Dual-stage engine monitoring."
        action = "Consult SOC analysts and review XAI feature attribution charts."
        notes = "Align with NIST AI RMF 1.0 accountability standards."

    return {
        "query": req.query,
        "copilot_assessment": assessment,
        "recommended_action": action,
        "governance_notes": notes
    }


@app.post("/predict/flow", response_model=PredictionResponse)
def predict_single_flow(flow: FlowRecord):
    if not predictor or not predictor.is_ready:
        raise HTTPException(status_code=503, detail="Model is not ready.")
    
    flow_dict = flow.model_dump(by_alias=True)
    res = predictor.predict_single(flow_dict)
    return res


@app.post("/predict/batch", response_model=List[PredictionResponse])
def predict_batch_flows(flows: List[FlowRecord]):
    if not predictor or not predictor.is_ready:
        raise HTTPException(status_code=503, detail="Model is not ready.")
    
    flow_dicts = [f.model_dump(by_alias=True) for f in flows]
    df_flows = pd.DataFrame(flow_dicts)
    results = predictor.predict_batch(df_flows)
    return results
