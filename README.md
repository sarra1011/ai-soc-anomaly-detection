# 🔐 AI-Based SOC Anomaly Detection System

## 📌 Overview
This project simulates a Security Operations Center (SOC) enhanced with machine learning to detect anomalous behavior in system logs.

## 🛡️ Security Operations Center (SOC) with AI

This project simulates a modern SOC environment by combining:

- SIEM system (Wazuh)
- Log analysis & detection rules
- AI-based anomaly detection
- Attack simulation
- Dashboard visualization (Kibana / Grafana)

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

## 📁 Project Structure

```bash
soc-project/
├── README.md
├── requirements.txt
│
├── data/
│   ├── logs/
│   ├── alerts/
│
├── siem/
│   ├── wazuh_config/
│   ├── log_parser.py
│   ├── detection_rules.xml
│
├── ai_model/
│   ├── train.py
│   ├── anomaly_detection.py
│   ├── feature_engineering.py
│
├── dashboards/
│   ├── kibana_exports/
│   ├── grafana_panels.json
│
├── simulations/
│   ├── brute_force_attack.py
│   ├── suspicious_login_generator.py
│
├── notebooks/
│   ├── 01_data_exploration.ipynb
│   ├── 02_anomaly_detection.ipynb
│
├── docs/
│   ├── architecture.md
│   ├── incident_response.md
│
└── tests/
    ├── test_logs.py
```

## 🚧 Status
In Progress – moving toward ML-based detection

## 🔮 Future Improvements
- Isolation Forest / ML models
- Real-time streaming (Kafka)
- Dashboard (Streamlit)
