"""
Honeypot — REST API
Serves the dashboard and exposes all capture/intel data as JSON endpoints.
"""

import json
import logging
import os
import sys
from pathlib import Path

from flask import Flask, jsonify, request, send_from_directory
from flask_cors import CORS

sys.path.insert(0, str(Path(__file__).parent))
from capture.event_store import CaptureStore
from analysis.intel      import IntelEngine

log = logging.getLogger("honeypot.api")

app    = Flask(__name__, static_folder="dashboard")
CORS(app)

store  = CaptureStore()
intel  = IntelEngine()


# ── Stats ─────────────────────────────────────────────────────────────────────

@app.get("/api/stats")
def api_stats():
    s = store.stats()
    s.update(intel.stats())
    return jsonify(s)


# ── Captures ──────────────────────────────────────────────────────────────────

@app.get("/api/captures")
def api_captures():
    limit = min(int(request.args.get("limit", 100)), 1000)
    sev   = request.args.get("severity")
    trap  = request.args.get("trap")
    if sev:
        return jsonify(store.by_severity(sev, limit))
    return jsonify(store.recent(limit))


@app.get("/api/captures/by-severity")
def api_by_severity():
    return jsonify(store.counts_by_severity())


@app.get("/api/captures/by-trap")
def api_by_trap():
    return jsonify(store.counts_by_trap())


@app.get("/api/captures/by-event-type")
def api_by_event_type():
    return jsonify(store.counts_by_event_type())


# ── Attackers ─────────────────────────────────────────────────────────────────

@app.get("/api/attackers")
def api_attackers():
    limit = min(int(request.args.get("limit", 20)), 100)
    return jsonify(intel.top_attackers(limit))


@app.get("/api/attackers/top-ips")
def api_top_ips():
    return jsonify(store.top_ips())


@app.get("/api/attackers/<ip>")
def api_attacker_detail(ip):
    profile  = intel.get_profile(ip)
    captures = store.by_ip(ip, limit=50)
    if not profile and not captures:
        return jsonify({"error": "IP not found"}), 404
    return jsonify({"profile": profile, "captures": captures})


# ── Export ────────────────────────────────────────────────────────────────────

@app.get("/api/export")
def api_export():
    path = "exports/captures.json"
    Path("exports").mkdir(exist_ok=True)
    store.export_json(path)
    return jsonify({"exported": path, "message": "JSON export ready"})


# ── SIEM-Lite integration feed ────────────────────────────────────────────────

@app.get("/api/siem-feed")
def api_siem_feed():
    """
    Returns captures in SIEM-Lite compatible event format.
    Point SIEM-Lite's JSON log ingester at this endpoint.
    """
    limit    = min(int(request.args.get("limit", 50)), 500)
    captures = store.recent(limit)
    events   = []
    for c in captures:
        events.append({
            "source":     f"honeypot_{c['trap_type']}",
            "event_type": c["event_type"],
            "severity":   c["severity"],
            "src_ip":     c["src_ip"],
            "timestamp":  c["timestamp"],
            **c.get("data", {}),
        })
    return jsonify(events)


# ── Dashboard SPA ─────────────────────────────────────────────────────────────

@app.get("/")
def index():
    return send_from_directory("dashboard", "index.html")


def create_api(capture_store: CaptureStore, intel_engine: IntelEngine):
    """Wire in the shared store and intel engine from main."""
    global store, intel
    store = capture_store
    intel = intel_engine
    return app
