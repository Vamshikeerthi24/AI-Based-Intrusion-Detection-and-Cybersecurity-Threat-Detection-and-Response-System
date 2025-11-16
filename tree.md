ids_repoV1/
├── README.md                  # Project overview, setup, and run instructions
├── requirements.txt           # Dependencies: pandas<2.3, scikit-learn<1.5, joblib, fastapi, uvicorn, pydantic, streamlit, requests, pyarrow, shap, openai
├── .gitignore                 # Ignore data/, models/, logs/, blocklist/, __pycache__, .venv
├── data/                      # Datasets (not committed)
│   ├── synth_flows.parquet    # Synthetic network flows (5800 rows)
│   ├── flows.csv              # Captured real traffic (from data.py)
│   └── flows.parquet          # Processed data for training
├── models/                    # Trained model artifacts
│   ├── rf.joblib              # Random Forest classifier
│   └── iso.joblib             # Isolation Forest anomaly detector
├── blocklist/                 # Blocklist for response actions
│   └── blocklist.json         # JSON file with blocked IPs and TTL
├── logs/                      # Log files for debugging/auditing
│   └── app.log                # Application logs (API, responses, explanations)
├── config/                    # Configuration files
│   └── config.yaml            # Settings (thresholds, TTL, OpenAI API key)
├── train/                     # Data generation and training scripts
│   ├── generate_synth.py      # Generates synthetic network flows
│   ├── prepare.py             # Preprocesses data (encoding, cleaning)
│   ├── train_supervised.py    # Trains Random Forest classifier
│   └── train_unsupervised.py  # Trains Isolation Forest anomaly detector
├── app/                       # Core application logic
│   ├── api.py                 # FastAPI backend for inference and fusion
│   ├── response.py            # Manages blocklist and response actions
│   ├── explain.py             # OpenAI API for explaining detections with SHAP
│   ├── features.py            # Feature extraction utilities
│   ├── schemas.py             # Pydantic models for data validation
│   └── streamlit_app.py       # Streamlit dashboard for visualization
├── utils/                     # Shared utilities
│   └── utils.py               # Logging, config loading
└── data.py                    # Captures real network traffic with TShark