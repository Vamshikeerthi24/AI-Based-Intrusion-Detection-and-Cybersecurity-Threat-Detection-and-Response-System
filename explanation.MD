# Intrusion Detection System (IDS) — Project Explanation

This repository implements a lightweight intrusion-detection demonstration comprised of a FastAPI backend for scoring network flows and a Streamlit dashboard UI for testing and visualization. It is intended as a local, educational IDS prototype that shows how supervised/unsupervised models can be combined to flag suspicious flows and manage a blocklist.

## High-level overview

- Backend (FastAPI): located in `app/api.py`. Exposes an `/ingest` endpoint that accepts a JSON payload representing a network flow. The backend runs model inference (supervised and unsupervised) and returns a decision and metadata. It may also trigger entries into the blocklist via response handling.

- Frontend (Streamlit): located in `app/streamlit_app.py`. Provides a simple dashboard to:
  - Send "Test Flow" JSON to the backend `/ingest` route.
  - View the session history of test flows and backend responses.
  - Manage a blocklist (view, add, remove, import/export) persisted to `blocklist/blocklist.json`.
  - Show simple visualizations (risk distribution / action counts) via `app/visual/visuals.py`.

- Models: saved under `models/` (e.g., `rf.joblib`). The training scripts live in `train/` and can be used to retrain or generate synthetic flows.

- Utilities: general helper functions are in `utils/utils.py` and common functionality or configuration may live in `common/` or `config/`.

## File structure (important files)

- `app/api.py` — FastAPI backend exposing `/ingest` and other related endpoints.
- `app/streamlit_app.py` — Streamlit dashboard (frontend). Sends test flows and manages the blocklist.
- `app/visual/visuals.py` — Visual rendering helpers used by Streamlit.
- `blocklist/blocklist.json` — JSON file (array) storing blocked IP addresses. Created automatically when missing.
- `models/` — trained model artifacts (e.g., `rf.joblib`).
- `train/` — training and data-generation scripts.
- `requirements.txt` — Python dependencies.
- `README.md` — previously updated notes about running the app.
- `explanation.MD` — this file (project explanation).

## How it works (runtime flow)

1. Start the backend (FastAPI) with Uvicorn. The backend loads model artifacts from `models/` and serves an `/ingest` route.
2. Start the Streamlit dashboard (`app/streamlit_app.py`). Use the sidebar to point to the backend URL (default: `http://127.0.0.1:8000`).
3. Use the "Test Flow" form in the dashboard to assemble a synthetic flow and click "Send Test Flow". The Streamlit app POSTs the JSON to `/ingest`.
4. The backend processes the flow, runs model(s), and returns a JSON response indicating risk scores and recommended action(s). The dashboard shows the response and stores it in session history.
5. The Blocklist Manager in the dashboard persists any manual additions to `blocklist/blocklist.json`.

## How to run locally (recommended order)

Open two terminals (PowerShell recommended on Windows):

1) Start backend (FastAPI + Uvicorn):

```powershell
python -m uvicorn app.api:app --reload --port 8000
```

If `uvicorn` is missing, install dependencies with:

```powershell
python -m pip install -r requirements.txt
```

2) Start Streamlit UI:

```powershell
python -m streamlit run app/streamlit_app.py
```

Navigate to the Streamlit URL printed in the terminal (default: http://localhost:8501) and make sure the backend URL in the sidebar points at `http://127.0.0.1:8000`.

## Troubleshooting

- Connection refused / "No connection could be made because the target machine actively refused it": Ensure the backend Uvicorn process is running and listening on the same host/port as the Streamlit sidebar setting.
- Backend returned invalid JSON: Backend may have crashed or returned an error page. Check the Uvicorn terminal logs for tracebacks.
- Blocklist import failure (encoding): If import fails with a UTF-8 decode error, the uploaded file may be in a different encoding or contain binary data. Convert the CSV to UTF-8 (e.g., in Notepad++ or using Python) and retry.

## Development notes and extension ideas

- Add authentication to the dashboard and API for secure operations.
- Add unit/integration tests for the API and for blocklist helper functions.
- Improve visualizations (time series, clustering visual explanation using SHAP, confusion matrices for supervised model results).
- Persist session history to disk or a small database for longer-term analysis.

## Contact

If you need further assistance running the project or want me to start the backend and run an end-to-end test from this environment, tell me and I will proceed.
