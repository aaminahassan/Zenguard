# ZenGuard – Universal SIEM Orchestrator (TRL Proof)

This project provides a runnable **Flask** app and a **high-end Bootstrap/Chart.js front-end** to support your paper's screenshots and a functional demo.

- **Connectors** for **QRadar, Splunk, Elastic** (placeholders ready to implement).
- **UEBA model** loader (IsolationForest via scikit-learn if available; heuristic fallback).
- **ZTA policy engine** for **auto** and **manual** responses (MFA, endpoint isolation, block IP).
- **Demo mode**: if no SIEM credentials are provided, simulation works for screenshots.

## Quick start

```bash
python -m venv .venv
# Windows: .venv\Scripts\activate
# macOS/Linux: source .venv/bin/activate
pip install -r requirements.txt

# optional: copy .env.example -> .env and set credentials
python app.py
# open http://127.0.0.1:5000
```

## Environment variables (.env)

- `QRADAR_URL`, `QRADAR_TOKEN`, `QRADAR_VERIFY_SSL=true`
- `SPLUNK_URL`, `SPLUNK_TOKEN`
- `ELASTIC_URL`, `ELASTIC_USER`, `ELASTIC_PASS`
- `MODEL_PATH` (e.g., `models/default_iforest.pkl`)

If no SIEM credentials are set, **Demo mode** remains enabled and you can use **Simulate** and **Attack Drill** buttons.

## Replace/Train model

Put your `.pkl` or `.joblib` model under `models/` and set `MODEL_PATH` accordingly. The UEBA loader uses **IsolationForest.decision_function** if available; otherwise falls back to a statistics-based heuristic.

## Where to implement real SIEM pulls

- `services/qradar_client.py` → implement AQL calls, normalize rows
- `services/splunk_client.py` → implement Splunk REST/SDK search
- `services/elastic_client.py` → implement Elasticsearch query

Each connector should normalize to:
```json
{
  "timestamp": 1710000000.0,
  "username": "alice",
  "hostname": "WKS-001",
  "event_type": "login_success",
  "details": "message ...",
  "session_duration": 8.0,
  "failed_logins": 0.0,
  "access_hour": 11.0,
  "device_trust": 0.85,
  "privilege_change": 0.0,
  "external_conn": 1.0,
  "mfa_bypass": 0.0
}
```

## Screenshots for the paper

- Top **KPIs + Sparkline**
- **Live Events** table (inject `Privilege Escalation` or `Session Hijack` for a red-tinted row)
- **UEBA & SOAR Panel** after clicking an event
- **Action Log** after using **Auto-Respond** or manual buttons

## License & Disclaimer

For academic/demo purposes. Mentions of commercial tools are illustrative; this project is **vendor-neutral** and **complements** existing platforms.
