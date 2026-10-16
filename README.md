# BankScam Sentinel

A responsive message-review tool for identifying common banking, phishing, and payment-fraud signals. The analysis runs with deterministic local rules and does not require an API key.

## Run locally

Python 3.10 or newer is required.

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
uvicorn main:app --reload
```

Open http://127.0.0.1:8000.

## Deploy

- **Render:** Create a Blueprint from this repository and use `render.yaml`.
- **Vercel:** Import this repository. The static interface is served from `index.html`; `/api/analyze` is handled by `api/analyze.py`.

## API

`POST /api/analyze` accepts `{ "sender": "...", "content": "..." }` and returns a validated `ScamAnalysisResult`. `GET /health` returns the service health status.

Analysis is guidance, not proof that a message is legitimate. Never share an OTP, password, CVV, or UPI PIN. In India, report financial cyber fraud at 1930 or cybercrime.gov.in.
