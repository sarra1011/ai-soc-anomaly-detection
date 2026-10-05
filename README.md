# 🔐 AI-Based SOC Anomaly Detection System

> **Next-generation Security Operations Center (SOC) framework leveraging Machine Learning for automated log analysis and threat detection**[cite: 4]

---

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.10+-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python" />
  <img src="https://img.shields.io/badge/scikit--learn-ML-F7931E?style=for-the-badge&logo=scikit-learn&logoColor=white" alt="scikit-learn" />
  <img src="https://img.shields.io/badge/pandas-Data-150458?style=for-the-badge&logo=pandas&logoColor=white" alt="pandas" />
  <img src="https://img.shields.io/badge/Status-In_Progress-yellow?style=for-the-badge" alt="Status" />
</p>

---

## 💡 Quick Navigation

- [📌 Overview](#-overview)
- [🛡️ Security Operations Center (SOC) with AI](#️-security-operations-center-soc-with-ai)
- [🧠 Architecture](#-architecture)
- [📊 Features](#-features)
- [🛠️ Tech Stack](#️-tech-stack)
- [📂 Project Structure](#-project-structure)
- [🚀 Getting Started](#-getting-started)
- [🚧 Status & Future Improvements](#-status--future-improvements)

---

## 📌 Overview

This project simulates a **Security Operations Center (SOC)** enhanced with machine learning to detect anomalous behavior and potential security incidents within system logs[cite: 4]. By pairing traditional log analysis with AI models, it identifies suspicious activities and highlights deviations from baseline user behavior in real time[cite: 4].

---

## 🛡️ Security Operations Center (SOC) with AI

This project builds a modern SOC environment combining[cite: 4]:

* 📜 **Log Collection & Analysis:** Processing Linux system logs and structured data feeds[cite: 4].
* 🧠 **Machine Learning Detection:** Training models to identify zero-day or non-rule-based anomalies[cite: 4].
* 📊 **Exploratory Data Analysis (EDA):** Interactive notebooks for feature extraction and pattern discovery[cite: 4].
* 🚨 **Automated Alerting:** Real-time console notifications when suspicious behavior occurs[cite: 4].

---

## 🧠 Architecture

```
                                      System Architecture
┌─────────────────────────┐       ┌───────────────────────────┐       ┌──────────────────────────┐
│   Log Ingestion & Data  │ ───►  │    Data Preprocessing     │ ───►  │   AI Anomaly Detection   │
│   (sample.log / CSV)    │       │   (src/data_prep.py)      │       │ (src/anomaly_detection) │
└─────────────────────────┘       └───────────────────────────┘       └──────────────────────────┘
                                                                                   │
                                                                                   ▼
                                                                      ┌──────────────────────────┐
                                                                      │    Alert Generation      │
                                                                      │   (print_alerts engine)  │
                                                                      └──────────────────────────┘
```

1. **Log Ingestion:** Reads raw log files (`sample.log`) and structured CSV logs (`sample_logs.csv`)[cite: 4].
2. **Preprocessing & Feature Engineering:** Extracts features, cleans timestamps, and encodes categorical attributes[cite: 4].
3. **Anomaly Inference:** Applies statistical and machine learning logic to flag irregular events[cite: 4].
4. **Alert Triggering:** Generates security alerts for identified suspicious user activity[cite: 4].

---

## 📊 Features

* 🔍 **Log Parsing & Preprocessing:** Handles raw system logs and tabular log datasets effortlessly[cite: 4].
* 🚨 **Suspicious Activity Detection:** Built-in alert logic to notify analysts of anomalous user behaviors[cite: 4].
* 📈 **Interactive Exploratory Notebooks:** Included Jupyter notebooks for testing models and data visualization[cite: 4].
* 🧩 **Modular Architecture:** Clean separation between preprocessing, models, and execution entry points[cite: 4].

---

## 🛠️ Technologies

| Category | Technology |
| :--- | :--- |
| **Language** | Python 3.10+[cite: 4] |
| **Data Processing** | Pandas, NumPy[cite: 4] |
| **Machine Learning** | Scikit-Learn[cite: 4] |
| **Data Visualization** | Matplotlib[cite: 4] |
| **Analysis Environment** | Jupyter Notebooks (`.ipynb`)[cite: 4] |

---

## 📁 Project Structure

Below is the complete file organization matching the repository layout[cite: 4]:

```text
ai-soc-anomaly-detection-main/
├── .gitignore                   # Git tracking exclusion rules[cite: 4]
├── LICENSE                      # Project license[cite: 4]
├── README.md                    # Root repository documentation[cite: 4]
├── requirements.txt             # Python dependencies (pandas, scikit-learn, etc.)[cite: 4]
├── data/                        # Datasets & log repositories[cite: 4]
│   ├── README.md                # Data directory overview[cite: 4]
│   └── sample_logs.csv          # Sample structured CSV log dataset[cite: 4]
├── docs/                        # System documentation[cite: 4]
│   └── architecture.md          # Detailed architecture notes[cite: 4]
├── logs/                        # Raw system log samples[cite: 4]
│   └── sample.log               # Test sample log file[cite: 4]
├── notebooks/                   # Jupyter analysis & experimentation[cite: 4]
│   └── analysis.ipynb           # EDA and initial model training notebook[cite: 4]
└── src/                         # Core Python source code[cite: 4]
    ├── data_preprocessing.py    # Log cleaning & feature extraction module[cite: 4]
    ├── anomaly_detection.py     # AI model execution and anomaly scoring[cite: 4]
    └── main.py                  # Main entry point for SOC system pipeline[cite: 4]
```

---

## 🚀 Getting Started

### 1. Clone & Setup Environment

```bash
# Clone the repository
git clone [https://github.com/your-username/ai-soc-anomaly-detection.git](https://github.com/your-username/ai-soc-anomaly-detection.git)
cd ai-soc-anomaly-detection-main

# Install dependencies
pip install -r requirements.txt
```

### 2. Run the Main Pipeline

```bash
# Initialize and execute the anomaly detection workflow
python src/main.py
```

### 3. Run Notebook Analysis

```bash
# Launch Jupyter Notebook to explore data
jupyter notebook notebooks/analysis.ipynb
```

---

## 🚧 Status & Future Improvements

> ⚠️ **Project Status:** **In Progress** — Currently moving toward advanced ML-based detection model integration[cite: 4].

- [ ] 🌲 **Isolation Forest & Autoencoders:** Integrate unsupervised models for deep anomaly scoring.
- [ ] ⚡ **Real-time Streaming:** Implement log streaming via Apache Kafka or syslog listener.
- [ ] 📊 **Interactive Dashboard:** Develop a Streamlit or Kibana/Grafana monitoring dashboard.
- [ ] 🛡️ **SIEM Integration:** Add native connectors for Wazuh / Elastic Stack rules.

---

## 📝 License

Distributed under the project LICENSE[cite: 4]. See [`LICENSE`](LICENSE) for more information[cite: 4].
