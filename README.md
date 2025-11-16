AI-Based Intrusion Detection and Response System (IDRS)
This repository contains a master's-level prototype for an AI-Based Intrusion Detection and Response System (IDRS). It leverages machine learning to detect network intrusions, implements automated response mechanisms via a blocklist, and provides natural language explanations of detections using the OpenAI API. The system is designed for academic research and prototyping, supporting both synthetic and real network traffic data.
Features

Supervised Detection: Random Forest classifier for detecting known threats.
Unsupervised Detection: Isolation Forest for anomaly detection (e.g., zero-day attacks).
Model Fusion: Combines supervised and unsupervised scores for robust risk assessment (weighted: 60% supervised, 40% unsupervised).
Automated Response: Temporary IP blocking via a JSON-based blocklist with time-to-live (TTL).
Explainability: SHAP for feature importance, with OpenAI API generating human-readable explanations.
Dashboard: Streamlit interface for real-time monitoring, blocklist management, and testing flows.
Logging and Configuration: Centralized logging (logs/app.log) and configuration (config/config.yaml).

Repository Structure
ids_repoV1/
├── data/                      # Synthetic and captured datasets
│   ├── synth_flows.parquet    # Synthetic data (5800 rows)
│   ├── flows.parquet          # Processed data for training
│   └── flows.csv              # Captured real traffic (optional)
├── models/                    # Trained ML models
│   ├── rf.joblib              # Random Forest model
│   └── iso.joblib             # Isolation Forest model
├── blocklist/                 # JSON blocklist for response actions
│   └── blocklist.json
├── logs/                      # Application logs
│   └── app.log
├── config/                    # Configuration files
│   └── config.yaml
├── train/                     # Data generation and training scripts
│   ├── generate_synth.py
│   ├── prepare.py
│   ├── train_supervised.py
│   └── train_unsupervised.py
├── app/                       # FastAPI, Streamlit, and utility modules
│   ├── api.py
│   ├── explain.py
│   ├── features.py
│   ├── response.py
│   ├── schemas.py
│   └── streamlit_app.py
├── utils/                     # Shared utilities
│   ├── __init__.py
│   └── utils.py
├── data.py                    # Captures real traffic with TShark
├── requirements.txt           # Python dependencies
├── .gitignore                 # Git ignore rules
└── README.md                  # This file

Prerequisites

Python: 3.11 or higher
TShark: Required for real traffic capture (install Wireshark).
OpenAI API Key: Required for explainability (sign up at platform.openai.com).
PowerShell: For running commands on Windows.

Setup

Clone the Repository (if using Git):
git clone <repository-url>
cd ids_repoV1


Create and Activate Virtual Environment:
python -m venv .venv
.\.venv\Scripts\Activate.ps1


Install Dependencies:
python -m pip install --upgrade pip
pip install -r requirements.txt

Required packages: pandas==2.2.3, scikit-learn==1.4.2, openai, pyyaml, shap, fastapi, uvicorn, streamlit, requests.

Create Directories:
mkdir data,models,blocklist,logs,config,app,utils,train -Force


Configure OpenAI API Key (preferred: `.env`)

You can provide your OpenAI credentials either via `config/config.yaml` (legacy) or via a `.env` file in the project root (recommended for local development).

1) Using `.env` (recommended)

Copy the template and fill in your API key (do not commit `.env` to git):

```powershell
copy .env.template .env
# then edit .env and paste your OPENAI_API_KEY value
```

The `.env` supports the following variables:

- OPENAI_API_KEY (required) — your OpenAI API key
- OPENAI_API_BASE (optional) — custom OpenAI-compatible API base (e.g. Azure or proxy)
- OPENAI_DEFAULT_MODEL (optional) — default model for explanations (e.g. text-davinci-003)

2) Using `config/config.yaml` (legacy fallback)

If you prefer YAML, set `openai_api_key` in `config/config.yaml` as before:

```yaml
risk_threshold: 0.85
block_ttl_minutes: 15
openai_api_key: "sk-..."
log_level: INFO
```

The application prefers values from the environment (`.env`), and will fall back to values in `config/config.yaml` to preserve backward compatibility.



Running (Synthetic Data)
The system uses synthetic data (data/synth_flows.parquet, 5800 rows) by default. Follow these steps:

Verify Synthetic Data:If data/synth_flows.parquet is missing, regenerate it:
python train/generate_synth.py

Output: Wrote data/synth_flows.parquet with 5800 rows

Preprocess Data:
python train/prepare.py

Output: Wrote data/flows.parquet with 5800 rows

Train Models:
python train/train_supervised.py
python train/train_unsupervised.py

Output: Classification report for Random Forest, models saved to models/rf.joblib and models/iso.joblib.

Start FastAPI:
python -m uvicorn app.api:app --reload --port 8000

Output: INFO: Uvicorn running on http://127.0.0.1:8000

Start Dashboard (in a new PowerShell window):
cd "E:\FALL 2025\VAMSHI\ids_repoV1"
.\.venv\Scripts\Activate.ps1
python -m streamlit run app/streamlit_app.py

Note: Do not run the Streamlit app by executing the file directly with Python
(e.g. `python app/streamlit_app.py`). Always use the Streamlit CLI (`streamlit run`)
so Streamlit creates the proper runtime context (ScriptRunContext) and session
state. Running the file directly produces warnings like "missing ScriptRunContext".

Output: Dashboard at http://localhost:8501. Use "Test Flow" to send sample flows and view risk scores, actions (allowed or blocked), and OpenAI explanations. Use "Refresh Blocklist" to view blocked IPs.

Important: The Streamlit dashboard sends API requests to the backend at http://127.0.0.1:8000 (for example when you click "Test Flow"). Start the FastAPI server before opening the dashboard to avoid connection errors:

PowerShell:

cd "E:path/Activate.ps1
python -m uvicorn app.api:app --reload --port 8000

Then open the dashboard (in a separate shell) with:

.\.venv\Scripts\Activate.ps1
python -m streamlit run app/streamlit_app.py


Running (Captured Data)
To use real network traffic:

Verify TShark:
tshark -v
tshark -D

Note the interface number (e.g., 2 for Wi-Fi).

Update data.py:Edit data.py to set INTERFACE to your network interface (e.g., INTERFACE = '2').

Capture Traffic:
python data.py --interface 2 --duration 120
python train/prepare.py

Generate activity (e.g., ping 8.8.8.8, browse websites). Manually label attacks in data/flows.csv for supervised training.

Re-run Training and Services:
python train/train_supervised.py
python train/train_unsupervised.py
python -m uvicorn app.api:app --reload --port 8000
python -m streamlit run app/streamlit_app.py



Troubleshooting

Virtual Environment Issues:If pip install fails:
deactivate
Remove-Item -Recurse -Force .venv
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt


ModuleNotFoundError:

Verify utils/:dir utils

Ensure utils.py and __init__.py exist.
Check Python path:python -c "import sys; print(sys.path)"

If E:\FALL 2025\VAMSHI\ids_repoV1 is missing, set it:$env:PYTHONPATH = "E:\FALL 2025\VAMSHI\ids_repoV1"




OpenAI API Errors:Test your API key:
python -c "from openai import OpenAI; client = OpenAI(api_key='sk-...'); print(client.models.list())"

If it fails, verify your key in config/config.yaml or check your OpenAI account for credits.

Model Loading Errors:Ensure models exist:
dir models

If missing, re-run:
python train/train_supervised.py
python train/train_unsupervised.py


Data Type Issues:Verify data/flows.parquet:
python -c "import pandas as pd; df = pd.read_parquet('data/flows.parquet'); print(df.dtypes)"

Ensure proto and state are int8.

Logs:Check logs/app.log for errors:
Get-Content logs/app.log


Diagnostics:If issues persist, share:
pwd
dir
dir app
dir utils
dir models
dir blocklist
python -V
pip -V
python -c "import sys; print(sys.path)"
Get-Content logs/app.log



Components

FastAPI: Backend API for real-time scoring and response (app/api.py).
Streamlit: Interactive dashboard for alerts and blocklist management (app/streamlit_app.py).
Scikit-learn: Random Forest for supervised classification, Isolation Forest for unsupervised anomaly detection (train/train_supervised.py, train/train_unsupervised.py).
SHAP: Feature importance for model explainability (app/explain.py).
OpenAI API: Natural language explanations of detections (app/explain.py).
Blocklist: JSON-based IP blocking with TTL (blocklist/blocklist.json, app/response.py).
Logging and Config: Centralized logging (logs/app.log) and configuration (config/config.yaml).

Notes

The system currently uses synthetic data (data/synth_flows.parquet) for testing. Real traffic capture requires TShark and manual labeling for supervised training.
The OpenAI API key must be configured in config/config.yaml for explanations to work.
The blocklist is software-based for prototyping; production systems should integrate with firewall rules.
The Random Forest model achieved near-perfect performance (accuracy 1.0) on synthetic data, but real-world performance depends on data quality and labeling.

Run the app (PowerShell)

Use the project's virtual environment and Streamlit's CLI wrapper so Streamlit prints the correct access URLs and creates the ScriptRunContext.

cd "E:\FALL 2025\VAMSHI\ids_repoV1"
.\.venv\Scripts\Activate.ps1
& ".\.venv\Scripts\python.exe" -m streamlit run "app/streamlit_app.py"

Example output:

  You can now view your Streamlit app in your browser.

  Local URL: http://localhost:8501
  Network URL: http://192.168.0.103:8501

Open http://localhost:8501 in your browser to view the dashboard.
