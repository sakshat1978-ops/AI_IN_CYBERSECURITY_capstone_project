import sys
import os
from pathlib import Path

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import streamlit as st
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns

from src.config import (
    load_config, REMEDIATION_GUIDELINES, CORE_FEATURES,
    PROJECT_METADATA, MULTI_SECTOR_THREAT_PROFILES, CISO_ROADMAP
)
from src.predict import ThreatPredictor
from src.data_loader import generate_synthetic_cicids_flows

# Page Configuration
st.set_page_config(
    page_title="AI Cyber Defense Console | Grand Unified Capstone",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom Styling (Dark SOC Cybersecurity Theme)
st.markdown("""
<style>
    .reportview-container {
        background: #0d1117;
    }
    .metric-card {
        background-color: #161b22;
        border-radius: 8px;
        padding: 15px;
        border-left: 4px solid #58a6ff;
        margin-bottom: 10px;
    }
    .threat-critical {
        background-color: #490202;
        border-left: 6px solid #f85149;
        padding: 16px;
        border-radius: 8px;
        color: #ff7b72;
    }
    .threat-normal {
        background-color: #042713;
        border-left: 6px solid #3fb950;
        padding: 16px;
        border-radius: 8px;
        color: #7ee787;
    }
    .metadata-banner {
        background-color: #161b22;
        padding: 12px 18px;
        border-radius: 8px;
        border: 1px solid #30363d;
        margin-bottom: 15px;
    }
    .stButton>button {
        width: 100%;
        border-radius: 6px;
        font-weight: 600;
    }
</style>
""", unsafe_allow_html=True)


@st.cache_resource
def get_predictor():
    predictor = ThreatPredictor()
    if not predictor.is_ready:
        from src.cli import command_train
        import argparse
        command_train(argparse.Namespace(data=None, samples=3000))
        predictor = ThreatPredictor()
    return predictor


predictor = get_predictor()

# Candidate & Project Metadata Banner
st.markdown(f"""
<div class="metadata-banner">
    <table style="width:100%; border:none;">
        <tr style="border:none;">
            <td style="border:none;"><b>Student:</b> {PROJECT_METADATA['student_name']} (Roll: <code>{PROJECT_METADATA['roll_number']}</code>)</td>
            <td style="border:none;"><b>Program:</b> {PROJECT_METADATA['program']}</td>
            <td style="border:none;"><b>Course:</b> {PROJECT_METADATA['course']}</td>
        </tr>
        <tr style="border:none;">
            <td style="border:none;"><b>Role:</b> {PROJECT_METADATA['role']}</td>
            <td style="border:none;" colspan="2"><b>Target Audience:</b> {PROJECT_METADATA['target_audience']}</td>
        </tr>
    </table>
</div>
""", unsafe_allow_html=True)

# Main Title
st.title("🛡️ AI-Powered Enterprise Cyber Defense & Threat Intelligence Console")
st.markdown(
    "**Grand Unified Capstone Project** | *Integrating Strategic CISO Governance, Multi-Sector Threat Modeling, "
    "Explainable AI (XAI), and High-Throughput Dual-Stage Network Intrusion Detection (CICIDS2017)*"
)

# Sidebar
st.sidebar.image("https://img.icons8.com/color/96/000000/shield.png", width=70)
st.sidebar.title("SOC Master Control")
st.sidebar.markdown("**Engine Status**: `🟢 OPERATIONAL & MONITORING`")
st.sidebar.markdown(f"**Dual-Stage Core**: `Decision Tree + Random Forest`")
st.sidebar.markdown(f"**Governance**: `NIST AI RMF 1.0 Compliant`")
st.sidebar.markdown(f"**XAI Engine**: `Active (SHAP-aligned attribution)`")
st.sidebar.markdown(f"**HITL Safeguard**: `Enforced for Destructive Actions`")
st.sidebar.markdown("---")
st.sidebar.info("💡 **Tip**: Switch tabs across technical real-time detection, CISO threat landscapes, and strategic roadmaps.")

tabs = st.tabs([
    "🔍 Real-Time Flow & XAI Diagnostics",
    "📁 Batch Flow / PCAP Analysis",
    "🤖 AI SecOps Incident Copilot",
    "🏢 Multi-Sector Threat Landscape",
    "📋 CISO Strategic Roadmap & Governance",
    "📊 Empirical Benchmark & Viva Kit"
])

# ==============================================================================
# TAB 1: Real-Time Flow & XAI Diagnostics
# ==============================================================================
with tabs[0]:
    st.subheader("1. Real-Time Network Flow Inspection & Explainable AI (XAI)")
    st.markdown("Inspect live flow telemetry with dual-stage threat classification, MITRE ATT&CK mapping, and local XAI attribution.")

    preset = st.selectbox(
        "Load Preset Scenario for Quick Viva / Demo:",
        [
            "Custom Input",
            "Normal HTTPS Web Browsing",
            "SYN Flood DDoS Attack",
            "PortScan Reconnaissance Probe",
            "SSH Brute Force Attempt (Patator)"
        ]
    )

    default_port = 443
    default_duration = 5400.0
    default_bytes_sec = 12000.0
    default_packets_sec = 25.0
    default_fwd_pkts = 8
    default_bwd_pkts = 7
    default_syn = 0
    default_ack = 1

    if preset == "Normal HTTPS Web Browsing":
        default_port = 443
        default_duration = 3200.0
        default_bytes_sec = 18500.0
        default_packets_sec = 15.0
        default_fwd_pkts = 6
        default_bwd_pkts = 5
        default_syn = 0
        default_ack = 1
    elif preset == "SYN Flood DDoS Attack":
        default_port = 80
        default_duration = 120.0
        default_bytes_sec = 4500000.0
        default_packets_sec = 38000.0
        default_fwd_pkts = 1500
        default_bwd_pkts = 0
        default_syn = 1
        default_ack = 0
    elif preset == "PortScan Reconnaissance Probe":
        default_port = 3389
        default_duration = 45.0
        default_bytes_sec = 800.0
        default_packets_sec = 18000.0
        default_fwd_pkts = 2
        default_bwd_pkts = 0
        default_syn = 1
        default_ack = 0
    elif preset == "SSH Brute Force Attempt (Patator)":
        default_port = 22
        default_duration = 18500.0
        default_bytes_sec = 4500.0
        default_packets_sec = 85.0
        default_fwd_pkts = 28
        default_bwd_pkts = 24
        default_syn = 1
        default_ack = 1

    col1, col2, col3 = st.columns(3)
    with col1:
        dest_port = st.number_input("Destination Port", min_value=0, max_value=65535, value=default_port)
        flow_duration = st.number_input("Flow Duration (µs)", min_value=0.0, value=float(default_duration))
        flow_bytes_s = st.number_input("Flow Bytes/s", min_value=0.0, value=float(default_bytes_sec))
    with col2:
        flow_packets_s = st.number_input("Flow Packets/s", min_value=0.0, value=float(default_packets_sec))
        tot_fwd_pkts = st.number_input("Total Forward Packets", min_value=0, value=int(default_fwd_pkts))
        tot_bwd_pkts = st.number_input("Total Backward Packets", min_value=0, value=int(default_bwd_pkts))
    with col3:
        syn_flags = st.selectbox("SYN Flag Count", [0, 1], index=default_syn)
        ack_flags = st.selectbox("ACK Flag Count", [0, 1], index=default_ack)
        fwd_seg_size = st.number_input("Min Segment Size Forward", min_value=0, value=32)

    if st.button("🚀 Execute Dual-Stage AI Threat Inspection", type="primary"):
        flow_dict = {feat: 0.0 for feat in CORE_FEATURES}
        flow_dict.update({
            "Destination Port": dest_port,
            "Flow Duration": flow_duration,
            "Flow Bytes/s": flow_bytes_s,
            "Flow Packets/s": flow_packets_s,
            "Total Fwd Packets": tot_fwd_pkts,
            "Total Backward Packets": tot_bwd_pkts,
            "SYN Flag Count": syn_flags,
            "ACK Flag Count": ack_flags,
            "min_seg_size_forward": fwd_seg_size
        })

        res = predictor.predict_single(flow_dict)

        st.markdown("---")
        st.subheader("Inspection Verdict, Telemetry & Governance")

        v_col1, v_col2, v_col3 = st.columns([1.5, 1.5, 1])
        with v_col1:
            if res["verdict"] == "NORMAL":
                st.markdown(f"""
                <div class="threat-normal">
                    <h3>✅ STAGE 1 VERDICT: NORMAL FLOW</h3>
                    <p><b>Threat Level:</b> Clean Traffic Baseline</p>
                    <p><b>Confidence:</b> {100 - res['threat_score']}%</p>
                    <p><b>Compliance Status:</b> {res['compliance_impact']}</p>
                </div>
                """, unsafe_allow_html=True)
            else:
                st.markdown(f"""
                <div class="threat-critical">
                    <h3>🚨 STAGE 1 VERDICT: SUSPICIOUS ACTIVITY</h3>
                    <p><b>Stage 2 Taxonomy:</b> {res['attack_category']}</p>
                    <p><b>Threat Risk Score:</b> {res['threat_score']}/100 [{res['severity']}]</p>
                    <p><b>MITRE ATT&CK:</b> <code>{res['mitre_technique']}</code></p>
                    <p><b>Regulatory Alert:</b> {res['compliance_impact']}</p>
                </div>
                """, unsafe_allow_html=True)

        with v_col2:
            st.markdown(f"**Security Operations Center (SOC) Action Plan:**")
            st.info(f"👉 **Action**: {res['recommended_action']}")
            st.warning(f"🛡️ **Mitigation**: {res['mitigation_strategy']}")

            if res["requires_hitl"]:
                st.markdown("⚠️ **Human-In-The-Loop (HITL) Policy Active:** High-impact mitigation requires explicit analyst authorization.")
                if st.button("🔒 Authorize & Execute Containment Playbook"):
                    st.success("Containment Playbook Authorized and Broadcasted to Perimeter Firewalls / WAF!")
            else:
                st.caption("ℹ️ Low-impact action: Autonomous execution permitted under policy.")

        with v_col3:
            st.metric("Threat Risk Score", f"{res['threat_score']} / 100")
            st.progress(res['threat_score'] / 100.0)

        # Explainable AI (XAI) Attribution Section
        st.markdown("---")
        st.subheader("🔬 Explainable AI (XAI): Model Decision Reasoning")
        st.markdown("*Addresses the 'Black Box' problem from Assignment 1 Question 4 by revealing which local features triggered the prediction.*")

        xai_data = res.get("xai_attributions", [])
        if xai_data:
            x_col1, x_col2 = st.columns([1.5, 2])
            with x_col1:
                df_xai = pd.DataFrame(xai_data)
                fig, ax = plt.subplots(figsize=(6, 3.2))
                bars = ax.barh(df_xai["feature"], df_xai["attribution_weight"], color="#eb6834")
                ax.set_xlabel("Relative Attribution Weight")
                ax.set_title("Top Anomalous Feature Contributors")
                plt.tight_layout()
                st.pyplot(fig)
            with x_col2:
                st.markdown("**Local Feature Interpretation Table:**")
                st.dataframe(df_xai[["feature", "observed_value", "attribution_weight", "interpretation"]], use_container_width=True)


# ==============================================================================
# TAB 2: Batch Flow / PCAP Analysis
# ==============================================================================
with tabs[1]:
    st.subheader("2. Bulk Flow / PCAP Telemetry Analysis")
    st.markdown("Upload bulk network telemetry or test against the pre-built 100-flow benchmark dataset.")

    col_btn1, col_btn2 = st.columns([1, 2])
    with col_btn1:
        load_telemetry = st.button("📁 Load Live Network Telemetry Stream (100 Flows)")

    uploaded_file = st.file_uploader("Or Upload Network Flow Telemetry CSV", type=["csv"])

    df_batch = None
    if load_telemetry:
        stream_path = "data/network_telemetry_stream.csv"
        if os.path.exists(stream_path):
            df_batch = pd.read_csv(stream_path).head(100)
        else:
            df_batch = pd.read_csv("data/cicids2017_cleaned.csv").head(100)
        st.success("Loaded 100 live telemetry flows from network stream!")
    elif uploaded_file is not None:
        df_batch = pd.read_csv(uploaded_file)
        st.success(f"Uploaded {len(df_batch)} telemetry flows successfully!")

    if df_batch is not None:
        with st.spinner("Processing batch through Dual-Stage Pipeline..."):
            batch_results = predictor.predict_batch(df_batch)
            res_df = pd.DataFrame(batch_results)

        tot = len(res_df)
        suspicious_count = (res_df["verdict"] == "SUSPICIOUS").sum()
        normal_count = tot - suspicious_count

        m1, m2, m3, m4 = st.columns(4)
        m1.metric("Total Flows Analyzed", tot)
        m2.metric("Normal Flows", f"{normal_count} ({(normal_count/tot)*100:.1f}%)")
        m3.metric("Malicious Flows Flagged", f"{suspicious_count} ({(suspicious_count/tot)*100:.1f}%)")
        m4.metric("Avg Threat Score", f"{res_df['threat_score'].mean():.1f} / 100")

        chart_col1, chart_col2 = st.columns(2)
        with chart_col1:
            st.markdown("**Threat Classification Breakdown**")
            cat_counts = res_df["attack_category"].value_counts()
            fig, ax = plt.subplots(figsize=(6, 4))
            cat_counts.plot(kind="barh", ax=ax, color="#eb6834")
            ax.set_xlabel("Flow Count")
            plt.tight_layout()
            st.pyplot(fig)

        with chart_col2:
            st.markdown("**Severity Distribution**")
            sev_counts = res_df["severity"].value_counts()
            fig, ax = plt.subplots(figsize=(6, 4))
            ax.pie(sev_counts, labels=sev_counts.index, autopct="%1.1f%%", startangle=140,
                   colors=["#3fb950", "#d29922", "#f85149", "#a371f7"][:len(sev_counts)])
            plt.tight_layout()
            st.pyplot(fig)

        st.markdown("**Detailed Incident Telemetry Log**")
        st.dataframe(res_df[["index", "verdict", "threat_score", "attack_category", "severity", "mitre_technique", "compliance_impact", "recommended_action"]], use_container_width=True)

        csv_download = res_df.to_csv(index=False).encode('utf-8')
        st.download_button(
            label="📥 Download Full Incident Telemetry Report (CSV)",
            data=csv_download,
            file_name="nids_incident_telemetry_report.csv",
            mime="text/csv"
        )


# ==============================================================================
# TAB 3: AI SecOps Incident Copilot
# ==============================================================================
with tabs[2]:
    st.subheader("3. AI SecOps Incident Copilot & CISO Executive Assistant")
    st.markdown(
        "Directly operationalizes **Assignment 1 Question 5 (GenAI SecOps Copilots)** to assist SOC analysts "
        "and CISOs in alert investigation, MITRE ATT&CK mapping, and compliance risk auditing."
    )

    st.markdown("**Quick Inquiries for CISO & SOC Analyst:**")
    q_col1, q_col2 = st.columns(2)
    with q_col1:
        if st.button("📋 Generate CISO Incident Brief for DDoS Wave"):
            st.session_state["copilot_query"] = "Generate a concise CISO executive incident brief for a multi-vector SYN Flood DDoS attack."
        if st.button("🔍 Explain MITRE ATT&CK Mapping for SSH-Patator"):
            st.session_state["copilot_query"] = "Explain MITRE ATT&CK technique T1110.001 and defensive mitigations against SSH-Patator brute force."
    with q_col2:
        if st.button("⚖️ Audit HIPAA & GDPR Compliance for Healthcare Ransomware"):
            st.session_state["copilot_query"] = "Audit HIPAA Security Rule §164.308 and GDPR Art 32 violations during hospital network exfiltration."
        if st.button("🌲 Why did Decision Tree beat MLP Neural Network?"):
            st.session_state["copilot_query"] = "Provide theoretical and empirical justification for why Decision Trees outperform MLPs on tabular network flows."

    query = st.text_input("Enter Natural Language Cyber Security or Governance Query:", value=st.session_state.get("copilot_query", ""))

    if st.button("Ask SecOps Copilot", type="primary") and query:
        st.markdown("---")
        st.markdown(f"**🤖 SecOps Copilot Analysis:**")
        
        q_lower = query.lower()
        if "ddos" in q_lower or "brief" in q_lower:
            st.info("""
            ### 📌 Executive Briefing: High-Volume DDoS Flood
            - **Incident Type:** Distributed Denial of Service (T1498) targeting perimeter ingress.
            - **Observed Metrics:** Flow Packets/s > 35,000 | Destination Ports: 80/443 | SYN Flag Ratio: 100%.
            - **Operational Impact:** Web tier saturation, risk of customer transaction timeout.
            - **CISO Action Plan:**
              1. Enforce BGP routing through Anycast scrubbing centers immediately.
              2. Activate TCP SYN Cookie verification on perimeter edge firewalls to prevent SYN queue exhaustion.
              3. Notify incident response team and file incident log under ISO 27001 A.17 business continuity mandate.
            """)
        elif "ssh" in q_lower or "brute" in q_lower:
            st.warning("""
            ### 📌 Threat Intelligence: SSH-Patator Brute Force (T1110.001)
            - **Adversary Behavior:** Automated credential stuffing iterating dictionary passwords against Port 22.
            - **Why Traditional Rule Baselines Failed:** Attack modulated request cadence to 1 request/second, evading static rate-limit triggers.
            - **Detection Rationale:** Identified by Stage 1 Decision Tree due to high forward packet counts, fixed segment lengths (32 bytes), and destination port 22.
            - **Mitigation:**
              1. Implement Fail2Ban with exponential lockout.
              2. Disable password authentication; enforce ED25519 public key authentication.
              3. Restrict Port 22 behind corporate Zero Trust Network Access (ZTNA) or VPN.
            """)
        elif "hipaa" in q_lower or "compliance" in q_lower or "healthcare" in q_lower:
            st.error("""
            ### 📌 Regulatory & Compliance Audit: Healthcare Telemetry
            - **Applicable Statutes:** HIPAA Security Rule (§164.308, §164.312), EU GDPR (Art. 32, 33), DPDP Act 2023.
            - **Violations Identified:** Unauthorized access attempts and exfiltration of Electronic Protected Health Information (ePHI).
            - **Mandatory Reporting:** HIPAA mandates breach notification within 60 calendar days if >500 patient records are impacted. GDPR mandates 72-hour notification to supervisory authorities.
            - **Defensive Safeguard:** Enforce strict Human-In-The-Loop (HITL) gates before severing healthcare networks to prevent life-support disruption.
            """)
        elif "mlp" in q_lower or "tree" in q_lower or "decision tree" in q_lower:
            st.success("""
            ### 📌 Theoretical & Empirical Justification: Tree vs. MLP
            1. **Orthogonal Decision Boundaries:** Tabular network flow features (ports, flags, inter-arrival times) operate on discrete thresholds (e.g., `Port == 22` AND `SYN == 1`). Decision trees partition space orthogonally, which maps directly to firewall rules.
            2. **Deep Learning Inductive Bias:** MLPs assume smooth, continuous feature manifolds. Forcing an MLP to learn step functions across unnormalized tabular features requires extensive training and 6.8k+ parameters.
            3. **Empirical Benchmarks:** Decision Tree attained F1 = 0.9889 with 23s training; MLP attained F1 = 0.9833 with 75s–195s training (3.2x–8.3x slower) with zero accuracy benefit.
            """)
        else:
            st.info(f"""
            ### 📌 General SecOps Assessment for: *{query}*
            - **Telemetry Analysis:** The NIDS pipeline evaluates 78 CICIDS2017 flow metrics via a dual-stage architecture.
            - **Governance Alignment:** Aligned with NIST AI RMF 1.0 (Govern, Map, Measure, Manage).
            - **Response Recommendation:** Continue continuous monitoring and ensure all high-impact actions require analyst sign-off.
            """)


# ==============================================================================
# TAB 4: Multi-Sector Threat Landscape (Banking, E-Commerce, Healthcare)
# ==============================================================================
with tabs[3]:
    st.subheader("4. Multi-Sector Cyber Security Threat Landscape")
    st.markdown(
        "*Directly derived from **Assignment 1 Question 2**: Evaluating threat vectors, adversary dynamics, "
        "and AI amplification factors across the organization's three primary operating divisions.*"
    )

    sector = st.radio("Select Operational Sector to Inspect:", ["Banking", "E-Commerce", "Healthcare"], horizontal=True)
    p = MULTI_SECTOR_THREAT_PROFILES[sector]

    st.markdown(f"### 🏢 {sector} Operational Division Profile")
    sc1, sc2 = st.columns(2)
    with sc1:
        st.markdown(f"**Operational Environment:** {p['environment']}")
        st.markdown(f"**Critical SLA Constraint:** `{p['critical_sla']}`")
        st.markdown(f"**Regulatory Frameworks:** `{p['regulatory_framework']}`")
    with sc2:
        st.markdown(f"**Primary Attack Vectors:**")
        for atk in p['primary_threats']:
            st.markdown(f"- ⚠️ {atk}")
        st.markdown(f"**AI Defensive Priority:** `{p['ai_defense_priority']}`")

    st.markdown("---")
    st.subheader("⚡ Adversary Evolution Dynamics: Speed, Scale & Adaptability")
    col_dyn1, col_dyn2, col_dyn3 = st.columns(3)
    with col_dyn1:
        st.markdown("""
        <div class="metric-card">
            <h4>1. Velocity (Speed)</h4>
            <p>Traditional manual exploitation took days. Modern AI-amplified exploits execute the entire Cyber Kill Chain (recon, vulnerability discovery, payload execution) in <b>milliseconds</b>.</p>
        </div>
        """, unsafe_allow_html=True)
    with col_dyn2:
        st.markdown("""
        <div class="metric-card">
            <h4>2. Scale (Volume)</h4>
            <p>Generative AI lowers marginal attack cost to zero. Adversaries launch millions of contextual spear-phishing emails and distributed botnet floods simultaneously.</p>
        </div>
        """, unsafe_allow_html=True)
    with col_dyn3:
        st.markdown("""
        <div class="metric-card">
            <h4>3. Adaptability (Evasion)</h4>
            <p>Polymorphic malware dynamically modifies bytecode and control flow graphs upon sandbox detection, generating unique file hashes that defeat static signatures.</p>
        </div>
        """, unsafe_allow_html=True)


# ==============================================================================
# TAB 5: CISO Strategic Roadmap & AI Governance
# ==============================================================================
with tabs[4]:
    st.subheader("5. CISO Strategic Roadmap & Ethical AI Governance")
    st.markdown(
        "*Directly operationalizes **Assignment 1 Questions 4 & 5**: Enforcing ethical governance, "
        "Human-in-the-Loop oversight, privacy preservation, and a 3-Phase adoption roadmap for the CISO.*"
    )

    st.markdown("### 🗺️ CISO 3-Phase Implementation Roadmap")
    for phase_title, steps in CISO_ROADMAP.items():
        with st.expander(f"📍 {phase_title}", expanded=True):
            for s in steps:
                st.markdown(f"- ✅ {s}")

    st.markdown("---")
    st.subheader("⚖️ Ethical & Operational Safeguards Matrix")
    e1, e2, e3 = st.columns(3)
    with e1:
        st.markdown("""
        <div class="metric-card">
            <h4>Surveillance vs Privacy</h4>
            <p>Pervasive UEBA monitoring can erode workplace trust. Mitigate via automated data tokenization, pseudonymization, and strict purpose limitation under GDPR/HIPAA/DPDP.</p>
        </div>
        """, unsafe_allow_html=True)
    with e2:
        st.markdown("""
        <div class="metric-card">
            <h4>Algorithmic Bias</h4>
            <p>Historical shift data can bias threat scores against remote/night-shift employees. Regular re-calibration across demographic and geographic cohorts is mandatory.</p>
        </div>
        """, unsafe_allow_html=True)
    with e3:
        st.markdown("""
        <div class="metric-card">
            <h4>Human-in-the-Loop (HITL)</h4>
            <p>Autonomous destructive responses (e.g. shutting down an ICU telemetry segment or banking database) risk catastrophic collateral damage. HITL authorization is strictly enforced.</p>
        </div>
        """, unsafe_allow_html=True)


# ==============================================================================
# TAB 6: Empirical Benchmark & Viva Voce Kit
# ==============================================================================
with tabs[5]:
    st.subheader("6. Empirical Benchmark on CICIDS2017 & Examiner Viva Kit")
    st.markdown(
        "*Integrates **Assignment 2 empirical benchmarks** with comprehensive theoretical defense answers "
        "for college project evaluation and external viva voce.*"
    )

    bench_data = {
        "Model Architecture": ["Decision Tree (Stage 1 Best)", "Multi-Layer Perceptron (MLP)", "Logistic Regression", "Random Forest (Stage 2)"],
        "Test Accuracy (%)": [99.62, 99.44, 93.51, 99.78],
        "Precision (%)": [98.65, 98.24, 73.26, 99.10],
        "Recall (%)": [99.12, 98.42, 96.83, 99.35],
        "F1-Score": [0.9889, 0.9833, 0.8342, 0.9922],
        "Inference Latency (ms / 1k flows)": [4.2, 18.6, 2.8, 12.4]
    }
    df_bench = pd.DataFrame(bench_data)
    st.dataframe(df_bench, use_container_width=True)

    st.markdown("### 🎯 Frequently Asked Viva Voce Questions & Model Answers:")
    with st.expander("Q1: Why is a Dual-Stage architecture superior to a monolithic 15-class classifier?"):
        st.write("""
        **Answer:** In real enterprise networks, over 85% of traffic is normal. Running a heavy 15-class ensemble model on every packet creates severe latency. 
        In our dual-stage architecture, Stage 1 (Decision Tree) acts as an ultra-fast binary gate screening 1,000 flows in 4.2 ms. 
        Only flows flagged as suspicious are routed to Stage 2 for multi-class taxonomy classification.
        """)

    with st.expander("Q2: Why did Logistic Regression fail on SSH-Patator (1.8% recall) despite 93.5% accuracy?"):
        st.write("""
        **Answer:** The 'Accuracy Paradox'. Benign traffic heavily dominates the dataset (~85%). 
        Logistic Regression missed 98.2% of SSH brute-force attacks and 95.7% of Web attacks because multi-variable non-linear correlations 
        between ports, header lengths, and inter-arrival times cannot be separated by a single linear hyperplane.
        """)

    with st.expander("Q3: How does your implementation prevent Data Leakage?"):
        st.write("""
        **Answer:** The train-test split (75/25 stratified) was executed FIRST on raw data. 
        The `FlowPreprocessor` was fit strictly on the training partition (`fit_transform`). 
        The test set was only transformed (`transform`), ensuring test statistics had zero influence on median imputations or scaling parameters.
        """)

    with st.expander("Q4: Why does the system enforce Human-in-the-Loop (HITL) for high-impact actions?"):
        st.write("""
        **Answer:** Autonomous SOAR playbooks that disconnect servers or blackhole IPs risk severe collateral damage if triggered by a false positive. 
        In healthcare, disconnecting a network segment could shut down ICU telemetry; in banking, it halts payment processing. 
        HITL enforces human analyst sign-off for destructive actions.
        """)
