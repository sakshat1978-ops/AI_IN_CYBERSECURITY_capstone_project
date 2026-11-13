# CYBER SECURITY THREAT DETECTION WITH MACHINE LEARNING AND DEEP LEARNING (CICIDS2017)
## Assignment 02: Technical Experimentation & Empirical Benchmark Report

**Course:** Artificial Intelligence for Cyber Security  
**Student Name:** Adarsh Kumar Sharma  
**Roll Number:** 2301420058  
**Program:** B.Tech Computer Science & Engineering (Data Science)  

---

### **1. EXPERIMENTAL OVERVIEW**
This empirical investigation evaluates Machine Learning baselines (Logistic Regression and Decision Tree) against a small Multi-Layer Perceptron (MLP) neural network on flow-level network traffic from the **CICIDS2017** benchmark dataset.

The system performs **Dual-Stage Classification**:
- **Stage 1 (Binary Threat Gate):** Detects whether a flow is `BENIGN` (0) or `Suspicious` (1).
- **Stage 2 (Multi-Class Taxonomy):** Identifies the exact attack vector (DDoS, DoS Hulk, PortScan, SSH-Patator, Botnet, Web Attacks).

---

### **2. DATA PREPROCESSING & LEAKAGE CONTROL**
- **Sanitization:** Leading/trailing header whitespaces stripped; infinite values (`inf` / `-inf` common in `Flow Bytes/s`) replaced with `NaN`.
- **Imputation & Normalization:** `SimpleImputer(strategy="median")` followed by `StandardScaler()`.
- **Hierarchical Port Bucketing:** `Destination Port` bucketed into `well_known` (0–1023), `registered` (1024–49151), and `dynamic` (49152–65535) and one-hot encoded. Raw numeric ports are retained as continuous features.
- **Strict Leakage Prevention:** The `ColumnTransformer` is fit strictly on the 75% training split (`fit_transform`) and only applied (`transform`) to the 25% test split.

---

### **3. MODEL BENCHMARKS ON TEST SPLIT**

| Metric | Decision Tree | Neural Network (MLP 64–32) | Logistic Regression | Random Forest |
|---|---|---|---|---|
| **Test Accuracy** | **99.62%** | 99.44% | 93.51% | **99.78%** |
| **Precision** | **98.65%** | 98.24% | 73.26% | **99.10%** |
| **Recall** | **99.12%** | 98.42% | 96.83% | **99.35%** |
| **F1-Score** | **0.9889** | 0.9833 | 0.8342 | **0.9922** |
| **ROC AUC** | **0.9983** | 0.9972 | 0.9857 | **0.9991** |
| **PR AUC** | **0.9941** | 0.9918 | 0.9388 | **0.9964** |
| **Training Time** | **23.4 s** | 75.1 s – 195 s (3.2x–8.3x slower) | 17.6 s | 38.2 s |
| **Inference Latency** | **4.2 ms / 1k flows** | 18.6 ms / 1k flows | 2.8 ms / 1k flows | 12.4 ms / 1k flows |

---

### **4. DETECTION RATE (RECALL) PER ATTACK TYPE**

| Attack Category | Sample Size ($n$) | Decision Tree Detection Rate | Logistic Regression Detection Rate |
|---|---:|---:|---:|
| **DDoS** | 2,455 | **99.9%** | 99.9% |
| **DoS Hulk** | 3,502 | **99.8%** | 99.6% |
| **PortScan** | 1,782 | **99.8%** | 99.0% |
| **DoS GoldenEye** | 227 | **93.8%** | 88.1% |
| **DoS Slowloris** | 108 | **93.5%** | 77.8% |
| **DoS Slowhttptest** | 99 | **88.9%** | 79.8% |
| **FTP-Patator** | 115 | **97.4%** | 72.2% |
| **SSH-Patator** | 57 | **100.0%** | **1.8%** (Severe Failure) |
| **Web Attack - Brute Force** | 23 | **87.0%** | **4.3%** (Severe Failure) |
| **Web Attack - XSS** | 14 | **100.0%** | **14.3%** (Severe Failure) |
| **Botnet (ARES)** | 49 | **53.1%** | **24.5%** (Severe Failure) |
| **Web Attack - SQL Injection** | 2 | 0.0% | 0.0% |

---

### **5. KEY FINDINGS & THEORETICAL DISCUSSION**
1. **Decision Trees Outperform Neural Networks on Tabular Flows:** Network flow features are threshold-governed (e.g. `Destination Port == 22`, `SYN Flag == 1`). Tree models split orthogonal to feature axes naturally, whereas MLPs require extensive backpropagation to approximate step functions with zero gain in F1 score.
2. **The Accuracy Paradox:** Monolithic accuracy (~99%) is dominated by high-volume DoS/DDoS flows. Logistic Regression collapses on subtle, low-volume attacks (1.8% on SSH-Patator, 4.3% on Web Brute Force) due to linear non-separability.
3. **Operational Feasibility:** The Stage 1 Decision Tree processes 1,000 flows in 4.2 ms, making it ideal for inline edge firewall filtering.
