# 🛡️ AI-Powered Dual-Stage Cyber Defense & Strategic Threat Intelligence System
### Grand Unified Capstone Project | Cyber Security, AI Governance & Machine Learning

![Student](https://img.shields.io/badge/Student-Adarsh%20Kumar%20Sharma-blue?style=flat&logo=user)
![Roll No](https://img.shields.io/badge/Roll%20No-2301420058-blue)
![Program](https://img.shields.io/badge/Program-B.Tech%20CSE%20(Data%20Science)-green)
![Python](https://img.shields.io/badge/Python-3.10%2B-blue?logo=python)
![Scikit-Learn](https://img.shields.io/badge/scikit--learn-1.3%2B-orange?logo=scikit-learn)
![Streamlit](https://img.shields.io/badge/Streamlit-1.50%2B-FF4B4B?logo=streamlit)
![FastAPI](https://img.shields.io/badge/FastAPI-0.115%2B-009688?logo=fastapi)
![NIST AI RMF](https://img.shields.io/badge/Governance-NIST%20AI%20RMF%201.0-purple)

---

## 📌 1. Project Overview & Scope

This Capstone Project unifies **Strategic CISO Governance, Multi-Sector Threat Landscape Modeling, and Explainable AI (Assignment 1)** with an **Empirical, High-Throughput Dual-Stage Network Intrusion Detection System (NIDS) on CICIDS2017 (Assignment 2)** into an enterprise-grade cyber defense suite.

In modern enterprise networks, over 85% of traffic is normal. Running heavy multi-class neural networks on every raw packet creates severe network latency bottlenecks. This project solves that trade-off through a decoupled **Dual-Stage Architecture**:

1. **Stage 1 (Binary Threat Gate):** An ultra-fast **Decision Tree filter** that classifies inbound flows as **Normal** or **Suspicious** in just **4.2 ms per 1,000 flows** with **99.62% test accuracy** and **0.9889 F1-score**.
2. **Stage 2 (Multi-Class Attack Taxonomy):** An ensemble **Random Forest classifier** triggered *only* when an anomaly is detected, categorizing the exact threat (DDoS, PortScan, SSH Brute Force, Web Attacks, Botnet) without choking benign traffic throughput.
3. **Explainable AI (XAI) Engine:** Demystifies the "Black Box" problem by computing local feature attributions (aligned with SHAP principles) for every flagged flow.
4. **Human-In-The-Loop (HITL) Policy:** Enforces explicit analyst authorization for high-impact containment playbooks (e.g., BGP blackholing, network isolation).
5. **Multi-Sector Threat Modeling:** Evaluates operational threat vectors and AI amplification across **Banking**, **E-Commerce**, and **Healthcare** platforms.
6. **CISO 3-Phase Strategic Roadmap:** A structured adoption roadmap aligned with the **NIST AI Risk Management Framework (AI RMF 1.0)**.

---

## 🏛️ 2. Unified System Architecture

```
[ Inbound Network Flow Stream / PCAP CSV ]
                   |
                   v
+--------------------------------------------------------+
| 1. Ingestion & Preprocessing Pipeline (Leak-Free)      |
| - Header sanitization & infinity/NaN median imputation |
| - Port Bucketing: well_known / registered / dynamic    |
| - StandardScaler (Fit strictly on Train partition)    |
+--------------------------------------------------------+
                   |
                   v
+--------------------------------------------------------+
| 2. STAGE 1: BINARY THREAT GATE (Decision Tree)        |
| - Evaluates: Normal (0) vs. Suspicious (1)             |
| - Latency: 4.2 ms / 1,000 flows | Test F1: 0.9889      |
+--------------------------------------------------------+
                  /          \
   Normal (0)    /            \   Suspicious (1)
                v              v
+--------------------+   +---------------------------------------+
| ALLOW TRAFFIC      |   | 3. STAGE 2: MULTI-CLASS TAXONOMY      |
| - Threat Score: 0  |   | (Ensemble Random Forest Classifier)   |
| - Severity: LOW    |   +---------------------------------------+
+--------------------+                     |
                                           v
                         +---------------------------------------+
                         | 4. THREAT IDENTIFICATION & ENRICHMENT  |
                         | - DoS / DDoS / PortScan / SSH / Bot   |
                         | - MITRE ATT&CK Technique Mapping      |
                         | - Regulatory & Compliance Alert       |
                         +---------------------------------------+
                                           |
                                           v
                         +---------------------------------------+
                         | 5. EXPLAINABLE AI (XAI) ENGINE        |
                         | - Local feature attribution bar chart |
                         | - Overcomes the 'Black Box' dilemma   |
                         +---------------------------------------+
                                           |
                                           v
                         +---------------------------------------+
                         | 6. GOVERNED SOC INCIDENT MITIGATION   |
                         | - Automated low-impact response       |
                         | - Enforced HITL Authorization Gate    |
                         +---------------------------------------+
```

---

## 📊 3. Empirical Benchmark Results on CICIDS2017

| Model Architecture | Accuracy | Precision | Recall | F1-Score | ROC AUC | Train Time | Inference Latency |
|---|---|---|---|---|---|---|---|
| **Decision Tree (Stage 1 Best)** | **99.62%** | **98.65%** | **99.12%** | **0.9889** | **0.9983** | **23.4 s** | **4.2 ms / 1k flows** |
| **Neural Network (MLP 64–32)** | 99.44% | 98.24% | 98.42% | 0.9833 | 0.9972 | 75.1 s – 195 s | 18.6 ms / 1k flows |
| **Logistic Regression** | 93.51% | 73.26% | 96.83% | 0.8342 | 0.9857 | 17.6 s | 2.8 ms / 1k flows |

> **Key Theoretical Finding:** Tabular network flow features are orthogonal and threshold-governed. The Decision Tree outperforms the Multi-Layer Perceptron (MLP) while training **3.2x–8.3x faster** and remaining fully explainable to security analysts.

---

## 💻 4. How to Run the Project

Navigate to the project root in PowerShell:
```powershell
cd C:\Users\adars\Downloads\Cybersecurity-Capstone-Project
```

### A. Launch Interactive Streamlit SOC Console (Best for Viva / Defense)
```powershell
streamlit run app/streamlit_app.py
```
*Opens an interactive security operations console at `http://localhost:8501` featuring 6 tabs:*
- **Tab 1: Real-Time Flow & XAI Diagnostics:** Test presets (Normal HTTPS, DDoS SYN Flood, PortScan, SSH Brute Force), display local XAI feature attribution bar charts, and execute Human-In-The-Loop (HITL) authorization for destructive mitigations.
- **Tab 2: Batch Flow / PCAP CSV Telemetry:** Upload flow CSVs, visualize attack distributions, and download formal incident reports.
- **Tab 3: AI SecOps Incident Copilot:** An interactive generative AI assistant for SOC analysts and CISOs.
- **Tab 4: Multi-Sector Threat Landscape:** Dynamic threat matrices for Banking, E-Commerce, and Healthcare with adversary dynamics (Speed, Scale, Adaptability).
- **Tab 5: CISO Strategic Roadmap & Governance:** 3-Phase adoption roadmap and NIST AI RMF 1.0 checklist.
- **Tab 6: Empirical Benchmark & Viva Kit:** Quantitative model benchmarks and embedded examiner viva questions.

---

### B. Launch FastAPI REST Server
```powershell
uvicorn app.api:app --reload --port 8000
```
*Interactive OpenAPI documentation available at:* `http://localhost:8000/docs`

**Sample POST Request (`/predict/flow`):**
```json
{
  "Destination Port": 80,
  "Flow Duration": 120.0,
  "Flow Bytes/s": 4500000.0,
  "Flow Packets/s": 38000.0,
  "Total Fwd Packets": 1500,
  "Total Backward Packets": 0,
  "SYN Flag Count": 1,
  "ACK Flag Count": 0
}
```

---

### C. Run Command-Line Interface (CLI)
```powershell
# Run instant live defense demonstration
python -m src.cli demo

# Retrain the dual-stage models on custom dataset
python -m src.cli train --samples 50000

# Generate 200 benchmark test flow samples
python -m src.cli generate-samples --count 200
```

---

### D. Run Automated Test Suite
```powershell
pytest tests/ -v
```
*Verifies schema integrity, port bucketing, dual-stage model predictions, and end-to-end pipeline without data leakage.*

---

## 📂 5. Project Directory Structure

```
Cybersecurity-Capstone-Project/
├── app/
│   ├── streamlit_app.py               # SOC Interactive Dashboard (6 Tabs)
│   └── api.py                         # FastAPI REST Endpoints & Copilot
├── config/
│   └── config.yaml                    # Hyperparameters, Bins & Mappings
├── data/
│   └── sample_test_flows.csv          # Benchmark Demonstration Flows
├── docs/
│   ├── CAPSTONE_PROJECT_REPORT.md     # Formal University Capstone Report (Assignments 1 & 2)
│   ├── ARCHITECTURE.md                # System Architecture & Diagrams
│   ├── VIVA_QUESTIONS_GUIDE.md        # Examiner Viva Voce Preparation Guide (Sections A & B)
│   ├── evaluation_metrics.json        # Benchmark Metric Outputs
│   └── per_attack_breakdown.csv       # Per-Attack Detection Breakdown
├── models/
│   ├── preprocessor.joblib            # Serialized ColumnTransformer
│   └── dual_stage_model.joblib        # Serialized Dual-Stage Classifiers
├── notebooks/
│   ├── 01_exploratory_data_analysis.ipynb
│   └── 02_dual_stage_model_training.ipynb
├── src/
│   ├── __init__.py
│   ├── config.py                      # Metadata, Playbooks & Multi-Sector Profiles
│   ├── data_loader.py                 # Ingestion & Data Hygiene
│   ├── preprocessor.py                # Port Bucketing & Scaling Pipeline
│   ├── models.py                      # DualStageNIDS Class
│   ├── evaluate.py                    # Evaluation Metrics & Reports
│   ├── predict.py                     # High-Level Inference & XAI Engine
│   └── cli.py                         # Command-Line Interface
├── tests/
│   └── test_pipeline.py               # Automated Pytest Suite
├── requirements.txt                   # Pinned Dependencies
└── README.md                          # Project Documentation
```

---

## 🎓 6. Academic Deliverables & Assignment Mapping

| Document | Scope | Assignment Role |
|---|---|---|
| 📄 **[Assignment 1: Strategic Assessment Report](file:///C:/Users/adars/Downloads/Cybersecurity-Capstone-Project/docs/ASSIGNMENT_1_STRATEGIC_ASSESSMENT_REPORT.md)** | Full 2,850-word CISO problem-based report covering Questions 1 to 5. | **Assignment 1 Deliverable** |
| 📄 **[Assignment 2: Technical Empirical Report](file:///C:/Users/adars/Downloads/Cybersecurity-Capstone-Project/docs/ASSIGNMENT_2_TECHNICAL_REPORT.md)** | Full technical benchmark report on CICIDS2017 (Decision Tree vs MLP vs Logistic Regression). | **Assignment 2 Deliverable** |
| 📄 **[Comprehensive Capstone Project Report](file:///C:/Users/adars/Downloads/Cybersecurity-Capstone-Project/docs/CAPSTONE_PROJECT_REPORT.md)** | Grand Unified Capstone Report following university guidelines. | **Unified Final Thesis** |
| 📐 **[Technical Architecture Specification](file:///C:/Users/adars/Downloads/Cybersecurity-Capstone-Project/docs/ARCHITECTURE.md)** | Dual-stage data flow diagrams, latency budgets, and REST contracts. | **System Architecture** |
| 🎯 **[Comprehensive Viva Voce Preparation Guide](file:///C:/Users/adars/Downloads/Cybersecurity-Capstone-Project/docs/VIVA_QUESTIONS_GUIDE.md)** | 10 examiner questions with model answers (Governance, XAI, HITL, Class Imbalance, Tree vs MLP). | **Examiner Viva Kit** |
