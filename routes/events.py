# -*- coding: utf-8 -*-
from __future__ import annotations
import time, random
from dataclasses import dataclass, asdict
from typing import List, Dict, Any
from flask import Blueprint, current_app, jsonify, request

from services.ueba import UEBAModel, FeatureVector
from services import qradar_client, splunk_client, elastic_client

events_bp = Blueprint("events", __name__)

# ---------------- Data Model ----------------
@dataclass
class Event:
    id: int
    timestamp: float
    source: str
    user: str
    device: str
    event_type: str
    details: str
    features: Dict[str, float]
    risk: float = 0.0
    verdict: str = "pending"  # pending|benign|anomalous

EVENTS: List[Event] = []
ACTIONS_LOG: List[Dict[str, Any]] = []
NEXT_ID = 1

def _now() -> float:
    return time.time()

def _next_id() -> int:
    global NEXT_ID
    i = NEXT_ID
    NEXT_ID += 1
    return i

def _add_event(e: Event) -> Event:
    EVENTS.append(e)
    return e

# Seed benign data for scoring context (first boot, demo mode)
if not EVENTS:
    base_users = ["alice", "bob", "charlie", "dana"]
    base_devices = ["WKS-001", "WKS-002", "LAP-003", "SRV-DB01"]
    base_types = ["login_success", "file_read", "vpn_connect", "http_request"]
    for _ in range(18):
        _add_event(Event(
            id=_next_id(),
            timestamp=_now(),
            source="seed",
            user=random.choice(base_users),
            device=random.choice(base_devices),
            event_type=random.choice(base_types),
            details="baseline activity",
            features={
                "session_duration": random.uniform(2, 20),
                "failed_logins": random.choice([0, 0, 0, 1]),
                "access_hour": random.uniform(8, 20),
                "device_trust": random.uniform(0.7, 0.95),
                "privilege_change": 0.0,
                "external_conn": random.choice([0.0, 0.0, 1.0]),
                "mfa_bypass": 0.0,
            },
        ))

# One UEBA instance shared
UEBA = UEBAModel(model_path=None)  # will auto-fit/fallback if needed

# ---------------- API ----------------
@events_bp.get("/events")
def list_events():
    # score last items for display
    for e in EVENTS[-20:]:
        try:
            e.risk = float(UEBA.score(FeatureVector(e.features)))
            e.verdict = "anomalous" if e.risk >= 75 else ("benign" if e.risk <= 40 else "pending")
        except Exception:
            e.risk = e.risk or 50.0
    # newest first
    data = [asdict(e) for e in sorted(EVENTS, key=lambda x: x.id, reverse=True)]
    return jsonify({"events": data})

@events_bp.get("/event/<int:event_id>")
def get_event(event_id: int):
    for e in EVENTS:
        if e.id == event_id:
            e.risk = float(UEBA.score(FeatureVector(e.features)))
            e.verdict = "anomalous" if e.risk >= 75 else ("benign" if e.risk <= 40 else "pending")
            return jsonify(asdict(e))
    return jsonify({"error": "not found"}), 404

@events_bp.get("/actions")
def get_actions():
    return jsonify({"log": ACTIONS_LOG[-300:]})

@events_bp.post("/simulate")
def simulate_event():
    data = request.get_json(force=True) or {}
    kind = str(data.get("kind", "normal"))
    user = random.choice(["alice", "bob", "charlie", "dana"])
    device = random.choice(["WKS-001", "WKS-002", "LAP-003", "SRV-DB01"])
    if kind == "normal":
        f = dict(session_duration=random.uniform(5, 30), failed_logins=0.0, access_hour=random.uniform(9, 18),
                 device_trust=random.uniform(0.8, 0.95), privilege_change=0.0, external_conn=1.0, mfa_bypass=0.0)
        e = Event(_next_id(), _now(), "Sim", user, device, "vpn_connect", "normal vpn usage", f)
    elif kind == "privilege_escalation":
        f = dict(session_duration=random.uniform(1, 4), failed_logins=random.choice([0.0,2.0,3.0]), access_hour=random.uniform(0, 6),
                 device_trust=random.uniform(0.3, 0.6), privilege_change=1.0, external_conn=1.0, mfa_bypass=random.choice([0.0,1.0]))
        e = Event(_next_id(), _now(), "Sim", user, device, "privilege_change", "sudden admin role grant", f)
    else:
        f = dict(session_duration=random.uniform(0.2, 2.0), failed_logins=random.choice([0.0,4.0,5.0]), access_hour=random.uniform(23, 4),
                 device_trust=random.uniform(0.2, 0.5), privilege_change=0.0, external_conn=1.0, mfa_bypass=1.0)
        e = Event(_next_id(), _now(), "Sim", user, device, "session_hijack", "impossible travel + token replay", f)
    e.risk = float(UEBA.score(FeatureVector(e.features)))
    e.verdict = "anomalous" if e.risk >= 75 else ("benign" if e.risk <= 40 else "pending")
    _add_event(e)
    return jsonify({"created": e.id})

@events_bp.post("/refresh")
def refresh_from_siem():
    """
    Pull recent events from whichever SIEM creds are present.
    - QRadar via AQL
    - Splunk via REST search
    - Elastic via DSL
    In demo mode, returns without changes.
    """
    app = current_app
    added = 0
    # Prefer QRadar > Splunk > Elastic (order arbitrary; adjust as you like)
    if app.config["QRADAR_URL"] and app.config["QRADAR_TOKEN"]:
        rows = qradar_client.fetch_recent(app)
        added += _ingest_rows(rows, source="QRadar")
    if app.config["SPLUNK_URL"] and app.config["SPLUNK_TOKEN"]:
        rows = splunk_client.fetch_recent(app)
        added += _ingest_rows(rows, source="Splunk")
    if app.config["ELASTIC_URL"] and app.config["ELASTIC_USER"]:
        rows = elastic_client.fetch_recent(app)
        added += _ingest_rows(rows, source="Elastic")
    return jsonify({"status": "ok", "added": added})

@events_bp.post("/scenario/attack_drill")
def scenario_attack_drill():
    """
    Deterministic 3-step scenario for screenshots:
      1) Normal VPN event (low)
      2) Privilege escalation (mid/high)
      3) Session hijack (high)
    """
    created_ids = []
    def _mk(event_type, details, feats):
        e = Event(_next_id(), _now(), "Demo", random.choice(["alice","bob","charlie","dana"]),
                  random.choice(["WKS-001","WKS-002","LAP-003","SRV-DB01"]), event_type, details, feats)
        e.risk = float(UEBA.score(FeatureVector(e.features)))
        e.verdict = "anomalous" if e.risk >= 75 else ("benign" if e.risk <= 40 else "pending")
        _add_event(e)
        created_ids.append(e.id)
    _mk("vpn_connect", "normal vpn usage", dict(session_duration=12.0, failed_logins=0.0, access_hour=10.0,
        device_trust=0.90, privilege_change=0.0, external_conn=1.0, mfa_bypass=0.0))
    _mk("privilege_change", "sudden admin role grant", dict(session_duration=2.0, failed_logins=2.0, access_hour=2.0,
        device_trust=0.45, privilege_change=1.0, external_conn=1.0, mfa_bypass=0.0))
    _mk("session_hijack", "impossible travel + token replay", dict(session_duration=0.6, failed_logins=4.0, access_hour=23.0,
        device_trust=0.30, privilege_change=0.0, external_conn=1.0, mfa_bypass=1.0))
    return jsonify({"created_ids": created_ids})

# --------------- helpers ---------------
def _ingest_rows(rows: list[dict], source: str) -> int:
    added = 0
    for r in rows:
        try:
            feats = _extract_features(r)
            e = Event(
                id=_next_id(),
                timestamp=float(r.get("timestamp", _now())),
                source=source,
                user=str(r.get("username", r.get("user", "unknown"))),
                device=str(r.get("hostname", r.get("device", "unknown"))),
                event_type=str(r.get("event_type", r.get("name", "event"))),
                details=str(r.get("details", r.get("message", ""))),
                features=feats,
            )
            e.risk = float(UEBA.score(FeatureVector(e.features)))
            e.verdict = "anomalous" if e.risk >= 75 else ("benign" if e.risk <= 40 else "pending")
            _add_event(e)
            added += 1
        except Exception:
            continue
    return added

def _extract_features(r: dict) -> Dict[str, float]:
    # Map from generic row dict -> UEBA features; customize per SIEM fields
    return {
        "session_duration": float(r.get("session_duration", 5.0)),
        "failed_logins": float(r.get("failed_logins", 0.0)),
        "access_hour": float(r.get("access_hour", 12.0)),
        "device_trust": float(r.get("device_trust", 0.8)),
        "privilege_change": float(r.get("privilege_change", 0.0)),
        "external_conn": float(r.get("external_conn", 1.0)),
        "mfa_bypass": float(r.get("mfa_bypass", 0.0)),
    }
