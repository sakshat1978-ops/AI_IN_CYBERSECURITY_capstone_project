# Capstone Project: Comprehensive Viva Voce & Examiner Q&A Guide
## AI-Powered Dual-Stage Cyber Defense & Strategic Threat Intelligence System
**Candidate:** Adarsh Kumar Sharma | **Roll Number:** 2301420058 | **Program:** B.Tech CSE (Data Science)

This guide provides technically rigorous, academically sound answers to the most common and difficult questions asked by university professors, project guides, and external examiners during capstone defense, spanning both **Strategic Governance (Assignment 1)** and **Empirical Dual-Stage Implementation (Assignment 2)**.

---

### **SECTION A: STRATEGIC, THREAT LANDSCAPE & GOVERNANCE (ASSIGNMENT 1)**

#### **Q1: Why are traditional signature and rule-based defenses failing against modern cyber threats?**
**Answer:**  
1. **Zero-Day Blind Spot:** Signature matching relies on cryptographic hashes (MD5, SHA-256) or known byte strings. An exploit must be captured, analyzed, and published by vendors—a window of exposure lasting 48 to 72 hours during which signatures are blind.
2. **Polymorphic Obfuscation:** Attackers use automated compilers and runtime crypters to modify a binary's code structure and packing. This produces unique hashes on every execution without altering the malicious payload.
3. **Alert Fatigue:** Static threshold rules cannot evaluate context. Security Operations Centers (SOCs) ingest tens of thousands of alerts daily, of which 80% are false alarms, causing critical indicators of compromise (IoCs) to be missed.

#### **Q2: How does the threat landscape differ across Banking, E-Commerce, and Healthcare?**
**Answer:**  
- **Banking:** Ultra-low latency transaction environments. Primary threats are real-time account takeover (ATO), SWIFT wire fraud, and high-frequency credential stuffing. AI must prioritize high-throughput supervised classification and Graph Neural Networks (GNNs) for transaction graphs under PCI-DSS 4.0.
- **E-Commerce:** High public web traffic. Primary threats are automated botnet scraping, inventory hoarding, and payment gateway flooding. AI must prioritize User & Entity Behavior Analytics (UEBA) and headless browser fingerprinting with minimal false positives.
- **Healthcare:** Connected medical devices (IoMT) and Electronic Health Records (EHR). Primary threats are disruptive ransomware and patient data exfiltration under HIPAA/GDPR. AI must prioritize network micro-segmentation and strict Human-In-The-Loop (HITL) policies so medical telemetry is never severed autonomously.

#### **Q3: What is the "Black Box" problem in security AI, and how does your project address it?**
**Answer:**  
Deep neural networks and ensemble models output predictions without showing their internal mathematical decision reasoning. In a SOC, an analyst cannot distinguish a true breach from a benign administrative script. Furthermore, regulations like GDPR Article 22 mandate a "Right to Explanation."  
**Our Solution:** We implemented an **Explainable AI (XAI)** engine in `src/predict.py` that calculates local feature attributions (aligned with SHAP principles) for every inspected flow, displaying a bar chart showing the exact metrics (e.g., elevated `Flow Packets/s` or anomalous `SYN Flag Count`) that triggered the alert.

#### **Q4: Why is Human-In-The-Loop (HITL) critical for automated SOAR response playbooks?**
**Answer:**  
Autonomous response engines that disconnect servers or blackhole IPs risk catastrophic collateral damage if triggered by a false positive. In a hospital, severing an ICU network segment directly endangers patient lives; in banking, taking down a payment gateway causes massive financial loss. We enforced a **tiered HITL policy**: low-impact actions (quarantining emails) execute autonomously, but high-impact destructive mitigations strictly require human analyst authorization via the dashboard.

#### **Q5: Explain the CISO 3-Phase Implementation Roadmap.**
**Answer:**  
Aligned with the **NIST AI Risk Management Framework (AI RMF 1.0)**:
- **Phase 1 (Months 1–6): Foundation & Data Hygiene:** Establish AI governance committee, sanitize telemetry (strip inf/NaN, tokenize PII/PHI), and deploy baseline Stage 1 Decision Tree filters.
- **Phase 2 (Months 7–18): Hybrid AI, XAI & HITL:** Deploy unsupervised UEBA, mandate XAI attribution dashboards, enforce HITL authorization gates, and deploy local GenAI SecOps copilots.
- **Phase 3 (Months 19–36): Federated Intelligence & Advanced Defense:** Roll out Federated Learning across business divisions to preserve data privacy, deploy GNNs for fraud ring detection, and conduct continuous Adversarial Red Teaming (ART).

---

### **SECTION B: EMPIRICAL DUAL-STAGE IMPLEMENTATION (ASSIGNMENT 2)**

#### **Q6: Why did you choose the CICIDS2017 dataset over KDD99 or NSL-KDD?**
**Answer:**  
- **KDD99 and NSL-KDD are outdated (25+ years old).** They do not reflect modern web traffic, encrypted protocols, or modern attacks.
- **CICIDS2017** was generated using realistic user behavior profiles (B-Profile system) over 5 continuous days and includes 14 modern attack types (DDoS, DoS Hulk, PortScan, SSH-Patator, Botnets, Web Attacks) with 78 rich flow-level numeric features extracted by CICFlowMeter.

#### **Q7: Why use a "Dual-Stage" architecture instead of a single multi-class model?**
**Answer:**  
1. **Line-Rate Throughput:** In real-world enterprise switches, over 85% of traffic is normal. Running a 15-class ensemble model on every packet creates severe latency. In our architecture, **Stage 1 (Decision Tree)** acts as an ultra-fast binary gate screening 1,000 flows in just **4.2 ms**.
2. **Mitigating Class Imbalance:** Normal traffic dwarfs rare attacks (e.g., SQL Injection with only a few samples vs millions of normal flows). Decoupling allows Stage 2 (Random Forest) to train specifically on the attack distribution.

#### **Q8: Why did the Decision Tree beat the Neural Network (MLP) on this data?**
**Answer:**  
1. **Orthogonal Decision Boundaries:** Network flow features (ports, flags, inter-arrival times) operate on discrete thresholds (e.g., `Port == 22` AND `SYN == 1`). Decision trees partition space orthogonally, perfectly matching network security logic.
2. **Deep Learning Inductive Bias:** Multi-Layer Perceptrons assume smooth, continuous feature manifolds. Forcing an MLP to approximate step functions on unnormalized tabular features requires thousands of gradient updates and extensive compute.
3. **Empirical Results:** Decision Tree achieved an F1-score of **0.9889** in 23 seconds of training, whereas the MLP achieved an F1 of 0.9833 while taking **3.2x–8.3x longer to train**.

#### **Q9: How did you ensure there is ZERO data leakage in your pipeline?**
**Answer:**  
1. We split the raw dataset into training (75%) and testing (25%) partitions **before** any normalization or imputation.
2. The `FlowPreprocessor` (`SimpleImputer`, `StandardScaler`, and `OneHotEncoder`) was fit **strictly on the training partition (`fit_transform`)**.
3. The test set was only transformed (`transform`), ensuring test statistics had zero influence on calculated medians or standard deviations.

#### **Q10: Your Logistic Regression model had 93.5% accuracy. Why did it fail on attacks?**
**Answer:**  
This is the **Accuracy Paradox**. Because benign traffic comprises ~85% of flows, predicting "Normal" for everything yields 85% accuracy. Evaluating the **per-attack recall breakdown** revealed that Logistic Regression completely collapsed on targeted attacks:
- **SSH-Patator:** 1.8% recall (missed 98.2% of attacks).
- **Web Attack - Brute Force:** 4.3% recall.
- **Web Attack - XSS:** 14.3% recall.
- **Botnet:** 24.5% recall.  
These attacks have complex non-linear feature interactions that cannot be separated by a single linear hyperplane. The Decision Tree, by contrast, achieved **100% recall on SSH-Patator and XSS**.
