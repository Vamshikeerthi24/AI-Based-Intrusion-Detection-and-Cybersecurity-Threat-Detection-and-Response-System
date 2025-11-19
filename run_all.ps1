# run_all.ps1 - Launch FastAPI + Streamlit with one double-click or ".\run_all.ps1"

Set-Location "e:\FALL 2025\VAMSHI\ids_repoV1"

Write-Host "Starting FastAPI backend on http://localhost:8000" -ForegroundColor Green
Start-Process python -ArgumentList "-m uvicorn app.api:app --host 0.0.0.0 --port 8000 --reload"

Write-Host "Waiting 5 seconds for backend to start..." -ForegroundColor Yellow
Start-Sleep -Seconds 5

Write-Host "Starting Streamlit dashboard on http://localhost:8502" -ForegroundColor Cyan
python -m streamlit run app/streamlit_app.py --server.port 8502 --server.address 0.0.0.0