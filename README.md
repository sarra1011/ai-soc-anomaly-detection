# 🔐 AI-Based SOC Anomaly Detection System

## 📌 Overview
This project simulates a Security Operations Center (SOC) enhanced with machine learning to detect anomalous behavior in system logs.

## 🧠 Architecture
- Log ingestion (simulated logs / Wazuh)
- Data preprocessing & feature engineering
- Anomaly detection (rule-based / ML-ready)
- Alert generation

## ⚙️ Technologies
- Python (pandas, scikit-learn)
- SIEM concepts (Wazuh)
- Linux logs

## 📊 Features
- Log parsing and preprocessing
- Suspicious login detection
- Basic anomaly detection logic
- Modular pipeline (extensible to ML models)

## 📁 Structure
- `src/` → core logic
- `data/` → datasets
- `logs/` → raw logs
- `notebooks/` → experiments
- `docs/` → architecture design

## 🚧 Status
In Progress – moving toward ML-based detection

## 🔮 Future Improvements
- Isolation Forest / ML models
- Real-time streaming (Kafka)
- Dashboard (Streamlit)
