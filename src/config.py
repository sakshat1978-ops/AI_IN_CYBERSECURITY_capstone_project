import os
import yaml
from pathlib import Path
from typing import Dict, Any

# Root directory of the Capstone project
BASE_DIR = Path(__file__).resolve().parent.parent
CONFIG_PATH = BASE_DIR / "config" / "config.yaml"

# Student & Academic Metadata (Grand Unified Capstone: Assignment 1 + Assignment 2)
PROJECT_METADATA = {
    "student_name": "Adarsh Kumar Sharma",
    "roll_number": "2301420058",
    "program": "B.Tech Computer Science & Engineering (Data Science)",
    "course": "Artificial Intelligence for Cyber Security",
    "role": "Junior Cyber Security Analyst / AI Security Consultant",
    "target_audience": "Chief Information Security Officer (CISO) & Executive Security Board",
    "project_title": "Adopting AI in Cyber Defense: An Evidence-Based Dual-Stage Detection, Threat Landscape, Ethical Governance, and Strategic Implementation System"
}


def load_config(config_path: Path = CONFIG_PATH) -> Dict[str, Any]:
    """Loads configuration yaml file safely."""
    if not os.path.exists(config_path):
        return {
            "paths": {
                "data_dir": str(BASE_DIR / "data"),
                "raw_data_dir": str(BASE_DIR / "data"),
                "primary_dataset": str(BASE_DIR / "data" / "cicids2017_cleaned.csv"),
                "telemetry_stream": str(BASE_DIR / "data" / "network_telemetry_stream.csv"),
                "models_dir": str(BASE_DIR / "models"),
            },
            "training": {"random_state": 42, "test_size": 0.25, "sample_size": 35000},
            "stage1_binary": {"model_type": "decision_tree", "params": {"max_depth": 12}},
            "stage2_multiclass": {"model_type": "random_forest", "params": {"n_estimators": 100, "max_depth": 15}},
        }
    with open(config_path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


# Standard 78 CICIDS2017 features
CORE_FEATURES = [
    "Destination Port", "Flow Duration", "Total Fwd Packets", "Total Backward Packets",
    "Total Length of Fwd Packets", "Total Length of Bwd Packets", "Fwd Packet Length Max",
    "Fwd Packet Length Min", "Fwd Packet Length Mean", "Fwd Packet Length Std",
    "Bwd Packet Length Max", "Bwd Packet Length Min", "Bwd Packet Length Mean",
    "Bwd Packet Length Std", "Flow Bytes/s", "Flow Packets/s", "Flow IAT Mean",
    "Flow IAT Std", "Flow IAT Max", "Flow IAT Min", "Fwd IAT Total", "Fwd IAT Mean",
    "Fwd IAT Std", "Fwd IAT Max", "Fwd IAT Min", "Bwd IAT Total", "Bwd IAT Mean",
    "Bwd IAT Std", "Bwd IAT Max", "Bwd IAT Min", "Fwd PSH Flags", "Bwd PSH Flags",
    "Fwd URG Flags", "Bwd URG Flags", "Fwd Header Length", "Bwd Header Length",
    "Fwd Packets/s", "Bwd Packets/s", "Min Packet Length", "Max Packet Length",
    "Packet Length Mean", "Packet Length Std", "Packet Length Variance", "FIN Flag Count",
    "SYN Flag Count", "RST Flag Count", "PSH Flag Count", "ACK Flag Count", "URG Flag Count",
    "CWE Flag Count", "ECE Flag Count", "Down/Up Ratio", "Average Packet Size",
    "Avg Fwd Segment Size", "Avg Bwd Segment Size", "Fwd Header Length.1",
    "Fwd Avg Bytes/Bulk", "Fwd Avg Packets/Bulk", "Fwd Avg Bulk Rate",
    "Bwd Avg Bytes/Bulk", "Bwd Avg Packets/Bulk", "Bwd Avg Bulk Rate",
    "Subflow Fwd Packets", "Subflow Fwd Bytes", "Subflow Bwd Packets", "Subflow Bwd Bytes",
    "Init_Win_bytes_forward", "Init_Win_bytes_backward", "act_data_pkt_fwd",
    "min_seg_size_forward", "Active Mean", "Active Std", "Active Max", "Active Min",
    "Idle Mean", "Idle Std", "Idle Max", "Idle Min"
]

# Enriched Incident Remediation Playbooks with MITRE ATT&CK & Compliance Impacts (Assignment 1 Integration)
REMEDIATION_GUIDELINES = {
    "Normal": {
        "severity": "LOW",
        "mitre_technique": "N/A (Benign Baseline)",
        "compliance_impact": "Compliant (GDPR/HIPAA/DPDP Normal Operations)",
        "action": "Allow traffic. No anomaly detected in flow metrics.",
        "mitigation": "Normal baseline operations. Continue standard logging.",
        "requires_hitl": False
    },
    "DDoS Attack": {
        "severity": "CRITICAL",
        "mitre_technique": "T1498 - Network Denial of Service (Direct & Reflection Flood)",
        "compliance_impact": "Service Availability Violation (ISO 27001 A.17, HIPAA §164.308)",
        "action": "Trigger automated IP rate limiting and upstream BGP blackholing.",
        "mitigation": "Deploy Anycast scrubbing centers and enable SYN proxy cookies on perimeter firewalls.",
        "requires_hitl": True
    },
    "DoS (Hulk)": {
        "severity": "HIGH",
        "mitre_technique": "T1499.003 - Endpoint Denial of Service: Application Exhaustion",
        "compliance_impact": "Service Level Agreement (SLA) & Payment Portal Downtime",
        "action": "Block source IP addresses exhibiting high HTTP GET/POST request velocities.",
        "mitigation": "Enforce Web Application Firewall (WAF) rate-limits and TLS connection renegotiation limits.",
        "requires_hitl": False
    },
    "DoS (GoldenEye)": {
        "severity": "HIGH",
        "mitre_technique": "T1499.002 - HTTP Keep-Alive Connection Pool Starvation",
        "compliance_impact": "E-Commerce Gateway Disruption (PCI-DSS Req 10)",
        "action": "Terminate keep-alive sessions and limit concurrent HTTP connections per host.",
        "mitigation": "Tune web server worker threads and enforce strict client header timeout limits.",
        "requires_hitl": False
    },
    "DoS (Slowloris)": {
        "severity": "HIGH",
        "mitre_technique": "T1499.001 - Incomplete Header Slow HTTP Starvation",
        "compliance_impact": "Banking Web Service Denial",
        "action": "Drop incomplete HTTP headers and lower client header timeout thresholds.",
        "mitigation": "Deploy reverse proxy (Nginx/HAProxy) configured with min_data_rate and client_header_timeout.",
        "requires_hitl": False
    },
    "DoS (Slowhttptest)": {
        "severity": "HIGH",
        "mitre_technique": "T1499.001 - Slow POST Body Transmission Denial",
        "compliance_impact": "Web Tier Availability Risk",
        "action": "Isolate slow POST connections and enforce minimum payload transfer rates.",
        "mitigation": "Configure Apache/Nginx request body timeouts to reject delayed body streams.",
        "requires_hitl": False
    },
    "PortScan Reconnaissance": {
        "severity": "MEDIUM",
        "mitre_technique": "T1046 - Network Service Discovery (SYN/FIN/Null Scans)",
        "compliance_impact": "Early Reconnaissance Indicator (NIST SP 800-53 RA-5)",
        "action": "Quarantine scanning IP and block TCP SYN / FIN probes across unmapped ports.",
        "mitigation": "Deploy iptables/Snort rules with recent module to ban scanning IPs for 24 hours.",
        "requires_hitl": False
    },
    "Brute Force (SSH)": {
        "severity": "HIGH",
        "mitre_technique": "T1110.001 - Password Guessing: SSH Credential Stuffing",
        "compliance_impact": "Access Control Breach Risk (GDPR Art. 32, HIPAA §164.312)",
        "action": "Drop SSH connection attempts from source host. Alert SOC team.",
        "mitigation": "Enforce Fail2Ban, SSH key-only authentication; restrict port 22 access via VPN or allowlist.",
        "requires_hitl": True
    },
    "Brute Force (FTP)": {
        "severity": "HIGH",
        "mitre_technique": "T1110.001 - Password Guessing: FTP Authentication Flood",
        "compliance_impact": "Data Exfiltration Precursor (PCI-DSS Req 8)",
        "action": "Temporarily lock user account and blacklist offending external IP address.",
        "mitigation": "Enforce TLS-secured FTPS/SFTP and disable plain FTP; implement exponential backoff on login failures.",
        "requires_hitl": False
    },
    "Botnet Activity": {
        "severity": "CRITICAL",
        "mitre_technique": "T1071.001 - Application Layer Protocol: C2 Communication",
        "compliance_impact": "Compromised Asset & Lateral Movement (DPDP Act 2023 Sec 8)",
        "action": "Isolate infected host from internal VLAN to prevent C2 communications and lateral spread.",
        "mitigation": "Sinkhole command-and-control (C2) domains; perform memory forensics and endpoint antivirus scan.",
        "requires_hitl": True
    },
    "Web Attack (Brute Force)": {
        "severity": "HIGH",
        "mitre_technique": "T1110.003 - Password Spraying on Web Portals",
        "compliance_impact": "Account Takeover (ATO) & Customer Identity Fraud",
        "action": "Block IP on WAF and require CAPTCHA / multi-factor authentication (MFA).",
        "mitigation": "Enforce adaptive rate-limiting on authentication endpoints and credential-stuffing defense.",
        "requires_hitl": False
    },
    "Web Attack (XSS)": {
        "severity": "HIGH",
        "mitre_technique": "T1189 - Drive-by Compromise: Stored & Reflected Script Injection",
        "compliance_impact": "Session Hijacking & Patient/Customer Data Breach (HIPAA/GDPR)",
        "action": "Sanitize and block malicious HTTP input containing script tags and encoded URI payloads.",
        "mitigation": "Implement Content Security Policy (CSP) and automated HTML context-aware output encoding.",
        "requires_hitl": False
    },
    "Web Attack (SQL Injection)": {
        "severity": "CRITICAL",
        "mitre_technique": "T1190 - Exploit Public-Facing Application: SQL Command Injection",
        "compliance_impact": "Catastrophic Database Breach (Severe GDPR & HIPAA Penalties)",
        "action": "Instantly abort database transaction and block client session.",
        "mitigation": "Enforce parameterized queries (PreparedStatements) and ORMs; restrict database user privileges.",
        "requires_hitl": True
    },
    "Infiltration Attack": {
        "severity": "CRITICAL",
        "mitre_technique": "T1078 - Valid Accounts & Internal Privilege Escalation",
        "compliance_impact": "Systemic Core Infrastructure Compromise",
        "action": "Revoke compromised user credentials, disconnect target host, and trigger incident response.",
        "mitigation": "Conduct network packet analysis, inspect lateral movement, and audit privilege escalation logs.",
        "requires_hitl": True
    },
    "Heartbleed Vulnerability Exploit": {
        "severity": "CRITICAL",
        "mitre_technique": "T1190 - OpenSSL TLS Heartbeat Extension Buffer Over-read (CVE-2014-0160)",
        "compliance_impact": "Private Key & Secret Exposure (Breach of All Confidentiality Controls)",
        "action": "Block OpenSSL TLS heartbeat extension requests.",
        "mitigation": "Patch OpenSSL package immediately; reissue TLS certificates and invalidate active sessions.",
        "requires_hitl": True
    }
}

# Multi-Sector Threat Landscape Profiles (Assignment 1 Question 2)
MULTI_SECTOR_THREAT_PROFILES = {
    "Banking": {
        "environment": "Ultra-low latency transaction processing, SWIFT backbone, core banking portals",
        "primary_threats": ["Account Takeover (ATO)", "SWIFT Wire Fraud", "High-frequency Credential Stuffing", "Distributed DDoS"],
        "ai_defense_priority": "High-throughput Supervised Classification + Graph Neural Networks (GNNs) for transaction topologies",
        "regulatory_framework": "PCI-DSS 4.0, GLBA, RBI Cyber Security Framework, Basel III",
        "critical_sla": "Zero downtime tolerated; sub-millisecond fraud scoring"
    },
    "E-Commerce": {
        "environment": "High-volume public web traffic, dynamic microservices, checkout carts",
        "primary_threats": ["Automated Botnet Scraping", "Inventory Hoarding", "Payment Gateway Flooding", "Credential Stuffing"],
        "ai_defense_priority": "User & Entity Behavior Analytics (UEBA) + Headless Browser Fingerprinting",
        "regulatory_framework": "PCI-DSS, GDPR, Consumer Protection Regulations, DPDP Act 2023",
        "critical_sla": "Must not block legitimate human shoppers (False Positive minimization)"
    },
    "Healthcare": {
        "environment": "Connected medical IoT (IoMT), Electronic Health Record (EHR) databases, clinic telemetry",
        "primary_threats": ["Disruptive Ransomware Lockouts", "Silent PHI Exfiltration", "IoMT Device Hijacking"],
        "ai_defense_priority": "Network Micro-segmentation + Unsupervised Anomaly Detection + Privacy-Preserving DLP",
        "regulatory_framework": "HIPAA Security Rule, HITECH Act, EU GDPR, Indian DISHA / DPDP",
        "critical_sla": "Human life safety: zero autonomous disconnection of patient life-support or ICU network segments"
    }
}

# CISO 3-Phase Implementation Roadmap (Assignment 1 Question 5)
CISO_ROADMAP = {
    "Phase 1: Foundation, Governance & Data Hygiene (Months 1–6)": [
        "Establish AI Security Governance Committee aligned with NIST AI RMF 1.0.",
        "Implement automated telemetry hygiene, stripping inf/NaN values and deduplicating flow logs.",
        "Enforce automated tokenization & pseudonymization for PII/PHI prior to model ingestion.",
        "Deploy Stage 1 Decision Tree & Supervised Baseline filters for line-rate perimeter threat gating."
    ],
    "Phase 2: Hybrid AI Operations, XAI & HITL Integration (Months 7–18)": [
        "Deploy Unsupervised UEBA & Isolation Forest anomaly detectors across cloud and identity providers.",
        "Implement Explainable AI (XAI) feature attribution dashboards (SHAP/LIME) alongside threat alerts.",
        "Integrate Human-in-the-Loop (HITL) authorization gates for all critical containment playbooks.",
        "Deploy locally hosted GenAI SecOps Copilot to accelerate SOC alert triage and query translation."
    ],
    "Phase 3: Federated Intelligence, GNNs & Continuous Red Teaming (Months 19–36)": [
        "Roll out Federated Learning across Banking, E-Commerce, and Healthcare to train models without centralizing raw data.",
        "Deploy Graph Neural Networks (GNNs) on transaction and login graphs to detect synthetic identity fraud rings.",
        "Conduct continuous Adversarial Red Teaming (ART) to audit AI models against data poisoning and evasion attacks."
    ]
}
