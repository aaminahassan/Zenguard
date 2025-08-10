# -*- coding: utf-8 -*-
from __future__ import annotations
from typing import List, Dict
import time

# Minimal QRadar fetch via AQL (placeholder). Replace with real client or REST calls.
def fetch_recent(app) -> List[Dict]:
    """
    Return a list of normalized dict rows.
    Each row should include: username, hostname, event_type, details, plus UEBA features if available.
    This stub returns an empty list unless you implement real calls with your QRadar instance.
    """
    # Example normalized result you can shape from QRadar properties:
    # return [{
    #   "timestamp": time.time(),
    #   "username": "alice",
    #   "hostname": "WKS-001",
    #   "event_type": "login_success",
    #   "details": "pulled via QRadar AQL",
    #   "session_duration": 8.0, "failed_logins": 0.0, "access_hour": 11.0,
    #   "device_trust": 0.85, "privilege_change": 0.0, "external_conn": 1.0, "mfa_bypass": 0.0
    # }]
    return []
