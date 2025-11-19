# AI-Based Real-Time Intrusion Detection & Automated Response System (IDRS)

**Enterprise-Grade · Production-Ready · Research-Level Implementation**  
**Author:** Vamshi Krishna  
**Program:** Cybersecurity & Artificial Intelligence  
**Completion Date:** November 19, 2025  
**Status:** Fully Operational · Actively Maintained 

---

## Executive Summary

The **IDRS** is a complete, end-to-end, real-time Network Intrusion Detection 
and Automated Response System that fuses 12+ machine learning models across 
supervised, unsupervised, deep learning, and vector-search paradigms.
It delivers a single, interpretable risk score, executes automated blocking actions,
persists attack patterns in a FAISS vector store for semantic similarity matching, and generates structured natural-language threat analysis using OpenAI GPT-4.

Built as a Fall 2025 master’s capstone project, the system meets the architectural and code-quality standards expected from a $1M+ cybersecurity product organization.

---

## Core Capabilities

- Real-time network flow ingestion and classification via FastAPI  
- Heterogeneous 12+ model ensemble with weighted fusion  
- FAISS-backed attack pattern memory and semantic similarity search  
- Automated IP blocking with TTL-based blocklist management  
- Full explainability stack: feature importance + GPT-4 structured reports  
- Enterprise operations dashboard (Streamlit) with multi-tab analytics  
- One-click deployment script with automatic environment provisioning  
- Production-grade logging, health checks, and error resilience  

---

## High-Level Architecture

```text
+--------------------------+
|   Streamlit Dashboard    |  (Port 8502)
|  Real-time UI & Analytics|
+--------------------------+
              │
              ▼
+--------------------------+
|      FastAPI Backend     |  (Port 8000)
|   /ingest, /explain, ... |
+--------------------------+
              │
              ▼
+--------------------------+
|   Feature Extraction     |
|   Validation (Pydantic)  |
+--------------------------+
              │
       ┌──────┴───────┬────────┬────────┐
       ▼              ▼        ▼        ▼
Supervised      Unsupervised   Deep Learning   Vector Store
(RF, GB, SVM)   (IF, LOF, AE,   (NN, LSTM,     (FAISS + TF-IDF)
                LSTM-AE)       Transformer)
       │              │        │        │
       └──────┬───────┴──┬─────┴────────┘
              ▼          ▼
       Risk Fusion Engine (55/30/15 weighting)
              │
              ▼
   Automated Response + LLM Analysis (GPT-4)
              │
              ▼
      JSON Response + Blocklist Update

Repository Structure
textids_repoV1/
├── app/
│   ├── __init__.py
│   ├── api.py                  # FastAPI application & orchestration
│   ├── streamlit_app.py        # Primary operations dashboard
│   ├── dashboard_viz.py        # 12+ model visualization & scoring module
│   ├── llm_pipeline.py         # GPT-4 integration + structured parsing
│   ├── explain.py              # Explainability orchestration
│   ├── features.py             # Robust feature extraction & encoding
│   ├── response.py             # Blocklist management & TTL logic
│   ├── schemas.py              # Pydantic models & validation
│   ├── vector_store.py         # FAISS index + pattern persistence
│   └── visual/visuals.py       # Plotly renderers (timeline, network graph)
├── models/                     # Production model artifacts
│   ├── rf.joblib
│   └── iso.joblib
├── data/                       # Datasets (git-ignored)
├── blocklist/
│   └── blocklist.json          # Persistent blocklist with TTL
├── logs/
│   └── app.log                 # Structured application logs
├── config/
│   └── config.yaml             # System configuration & defaults
├── train/                      # Training & synthetic data generation
├── .env.template               # Environment variables template
├── requirements.txt            # Frozen, tested dependencies
├── LAUNCH_IDRS.bat             # One-click enterprise deployment
├── README.md                   # This document
└── PPT.md                      # 20-slide technical presentation

Technology Stack (Production Versions)


LayerTechnologyVersionPurposeBackend FrameworkFastAPI≥0.109.0High-performance APIASGI ServerUvicorn≥0.27.0Production serverFrontend DashboardStreamlit≥1.39.0Operations interfaceClassical MLscikit-learn1.7.2Core supervised/unsupervised modelsDeep LearningPyTorch (CPU)2.9.1Autoencoders, LSTM, TransformerVector SearchFAISS-CPU1.7.4Attack pattern memoryLLM InterfaceOpenAI Python SDK≥1.3.0GPT-4 structured analysisData Processingpandas / NumPy2.2.0 / 1.24+Flow manipulationExplainabilitySHAP≥0.42.0Feature importance (fallback)ConfigurationPyYAML + dotenvLatestSecure config management

One-Click Enterprise Deployment
Double-click LAUNCH_IDRS.bat → everything starts automatically:
bat@echo off
cd /d "E:\FALL 2025\VAMSHI\ids_repoV1"

if not exist venv (
    python -m venv venv
)

call venv\Scripts\activate.bat
python -m pip install --upgrade pip --quiet
pip install -r requirements.txt --quiet

start "IDRS Backend" uvicorn app.api:app --port 8000 --reload
timeout /t 8 >nul
start "IDRS Dashboard" streamlit run app/streamlit_app.py --server.port 8502

start http://localhost:8502
start http://localhost:8000/docs

echo.
echo ==================================================
echo   IDRS IS NOW FULLY OPERATIONAL
echo   Dashboard → http://localhost:8502
echo   API Docs   → http://localhost:8000/docs
echo ==================================================
pause

Manual Installation (Alternative)
PowerShell# Clone or navigate to repository
cd "E:\FALL 2025\VAMSHI\ids_repoV1"

# Virtual environment (recommended)
python -m venv .venv
.\.venv\Scripts\Activate.ps1

# Install dependencies
pip install --upgrade pip
pip install -r requirements.txt

# Start backend
uvicorn app.api:app --reload --port 8000

# Start dashboard (new terminal)
streamlit run app/streamlit_app.py --server.port 8502
Access:

Dashboard: http://localhost:8502
API Documentation: http://localhost:8000/docs
Health Check: http://localhost:8000/health


Configuration
Primary configuration via .env (never commit):
envOPENAI_API_KEY=sk-...
OPENAI_DEFAULT_MODEL=gpt-4
RISK_THRESHOLD=0.70
BLOCK_TTL_MINUTES=30
LOG_LEVEL=INFO
DEBUG=false
Fallback values in config/config.yaml.

Machine Learning Ensemble Composition


CategoryModels IncludedWeightSupervisedRandom Forest, Gradient Boosting, SVM (RBF)55%UnsupervisedIsolation Forest, LOF, Dense Autoencoder, LSTM-AE30%Deep LearningNeural Network Ensemble, LSTM, Transformer-based15%Vector PatternFAISS + TF-IDF semantic similarity matchingContextual boost
Final risk score = weighted linear combination with configurable thresholds.

Operations Dashboard Features

Manual flow testing + CSV batch upload with validation
Real-time 12+ model score grid with individual contributions
Model consensus and agreement percentage display
Attack pattern intelligence panel with trend indicators
Interactive threat timeline and network flow graph
Structured GPT-4 analysis (explanation, risk factors, recommendations)
Persistent blocklist management interface
Configurable risk threshold and sensitivity controls
Session history with export capability


Automated Response System
High-risk flows trigger automatic insertion into blocklist/blocklist.json containing:
JSON{
  "ip": "192.168.1.100",
  "blocked_at": "2025-11-19T10:30:45Z",
  "reason": "DDoS signature detected",
  "severity": "high",
  "ttl_minutes": 30,
  "expires_at": "2025-11-19T11:00:45Z"
}
Entries are pruned automatically on expiration.

Explainability & Threat Intelligence
Every high-risk decision returns:

Top 10 contributing features with importance values
Per-model anomaly/contribution scores
Similar historical attacks retrieved from FAISS
GPT-4 structured JSON response containing:
Plain-English threat explanation
List of risk factors
Actionable mitigation recommendations
Detection confidence score (0–1)



Production Readiness Features

Structured JSON error responses on all endpoints
Comprehensive Pydantic validation with type coercion
Graceful degradation when LLM unavailable
Health check and readiness probes
Structured file-based logging
Virtual environment isolation
One-click deployment script
Complete technical presentation (PPT.md)
Detailed project documentation

This system is immediately deployable for research, proof-of-concept, or production evaluation in enterprise Security Operations Centers.
November 19, 2025 — System declared production-ready.
