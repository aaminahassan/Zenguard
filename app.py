# -*- coding: utf-8 -*-
"""
ZenGuard – Universal SIEM Orchestrator (Flask)
- Demo & Live modes
- Connectors: QRadar, Splunk, Elastic (placeholders ready for creds)
- UEBA model loader (IsolationForest if available; heuristic fallback)
- ZTA policy engine: auto/manual actions (MFA, isolate, block IP)
- Screenshot-friendly API + high-end front-end
"""
from __future__ import annotations
import os
from flask import Flask, send_from_directory, jsonify
from routes.events import events_bp
from routes.respond import respond_bp

# Optional: load .env if present (no error if missing)
try:
    from dotenv import load_dotenv  # pip install python-dotenv
    load_dotenv()
except Exception:
    pass

# Optional: allow local front-ends to talk to the API during dev
try:
    from flask_cors import CORS  # pip install flask-cors (optional)
    _HAS_CORS = True
except Exception:
    _HAS_CORS = False


def create_app() -> Flask:
    app = Flask(__name__, static_folder="static", static_url_path="")

    # ---------- App configuration exposed to blueprints ----------
    # If these are unset, events blueprint stays in DEMO mode, but simulate endpoints keep working.
    app.config["QRADAR_URL"] = os.getenv("QRADAR_URL", "").rstrip("/")
    app.config["QRADAR_TOKEN"] = os.getenv("QRADAR_TOKEN", "")
    app.config["QRADAR_VERIFY_SSL"] = os.getenv("QRADAR_VERIFY_SSL", "true").lower() == "true"

    app.config["SPLUNK_URL"] = os.getenv("SPLUNK_URL", "").rstrip("/")
    app.config["SPLUNK_TOKEN"] = os.getenv("SPLUNK_TOKEN", "")

    app.config["ELASTIC_URL"] = os.getenv("ELASTIC_URL", "").rstrip("/")
    app.config["ELASTIC_USER"] = os.getenv("ELASTIC_USER", "")
    app.config["ELASTIC_PASS"] = os.getenv("ELASTIC_PASS", "")

    app.config["QRADAR_AQL_WINDOW_MIN"] = int(os.getenv("QRADAR_AQL_WINDOW_MIN", "15"))
    app.config["QRADAR_AQL_LIMIT"] = int(os.getenv("QRADAR_AQL_LIMIT", "200"))

    app.config["MODEL_PATH"] = os.getenv("MODEL_PATH", "models/default_iforest.pkl")

    # Derive an "operational mode" flag that blueprints can read.
    app.config["DEMO_MODE"] = not any([
        app.config["QRADAR_URL"] and app.config["QRADAR_TOKEN"],
        app.config["SPLUNK_URL"] and app.config["SPLUNK_TOKEN"],
        app.config["ELASTIC_URL"] and app.config["ELASTIC_USER"],
    ])

    # ---------- Extensions ----------
    if _HAS_CORS:
        # In dev you can relax origins as needed; tighten for prod
        CORS(app, resources={r"/api/*": {"origins": "*"}})

    # ---------- Blueprints ----------
    app.register_blueprint(events_bp, url_prefix="/api")
    app.register_blueprint(respond_bp, url_prefix="/api")

    # ---------- Health & mode probes ----------
    @app.get("/api/health")
    def health():
        return jsonify(
            status="ok",
            demo_mode=bool(app.config["DEMO_MODE"]),
            qradar=bool(app.config["QRADAR_URL"] and app.config["QRADAR_TOKEN"]),
            splunk=bool(app.config["SPLUNK_URL"] and app.config["SPLUNK_TOKEN"]),
            elastic=bool(app.config["ELASTIC_URL"] and app.config["ELASTIC_USER"]),
            model_path=app.config["MODEL_PATH"],
        )

    @app.get("/api/mode")
    def mode():
        return jsonify(
            mode="demo" if app.config["DEMO_MODE"] else "live",
            verify_ssl=bool(app.config["QRADAR_VERIFY_SSL"]),
            window_min=int(app.config["QRADAR_AQL_WINDOW_MIN"]),
            limit=int(app.config["QRADAR_AQL_LIMIT"]),
        )

    # ---------- Static file serving ----------
    @app.route("/")
    def index():
        # Serve the front-end
        return send_from_directory(app.static_folder, "index.html")

    @app.route("/<path:path>")
    def static_files(path: str):
        return send_from_directory(app.static_folder, path)

    # ---------- Dev no-cache so HTML/JS refresh instantly ----------
    @app.after_request
    def add_no_cache_headers(resp):
        # Don’t aggressively cache during dev; adjust for prod as needed
        resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        resp.headers["Pragma"] = "no-cache"
        return resp

    return app


if __name__ == "__main__":
    app = create_app()
    # host=0.0.0.0 so you can open from LAN
    app.run(debug=True, host="0.0.0.0", port=int(os.getenv("PORT", "5000")))
