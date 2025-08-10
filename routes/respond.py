# -*- coding: utf-8 -*-
from __future__ import annotations
import time
from typing import Dict, Any
from flask import Blueprint, jsonify, request
from .events import ACTIONS_LOG

respond_bp = Blueprint("respond", __name__)

ACTIONS = {
    "enforce_mfa": "IdP challenge issued",
    "isolate_endpoint": "EDR isolation command sent",
    "block_ip": "Firewall rule pushed",
}

def _now() -> float:
    import time as _t
    return _t.time()

def log_action(event_id: int, action: str, note: str):
    ACTIONS_LOG.append({
        "ts": _now(),
        "event_id": int(event_id),
        "action": str(action),
        "note": str(note),
    })

@respond_bp.post("/respond")
def respond_manual():
    data = request.get_json(force=True) or {}
    event_id = int(data.get("event_id", 0))
    action = str(data.get("action", ""))
    note = ACTIONS.get(action, "custom action")
    log_action(event_id, action, note)
    return jsonify({"status": "ok", "event_id": event_id, "action": action})

@respond_bp.post("/respond/auto")
def respond_auto():
    """
    Very simple ZTA policy:
      - if risk >= 90: isolate + block + MFA
      - if 75 <= risk < 90: enforce MFA
      - else: log only
    """
    data = request.get_json(force=True) or {}
    ev = data.get("event", {})
    risk = float(ev.get("risk", 0.0))
    eid = int(ev.get("id", 0))
    if risk >= 90.0:
        log_action(eid, "isolate_endpoint", "Auto: high risk (>=90)")
        log_action(eid, "block_ip", "Auto: high risk (>=90)")
        log_action(eid, "enforce_mfa", "Auto: high risk (>=90)")
    elif risk >= 75.0:
        log_action(eid, "enforce_mfa", "Auto: risk >=75")
    else:
        log_action(eid, "log_only", "Auto: benign/pending")
    return jsonify({"status": "ok", "event_id": eid, "risk": risk})
