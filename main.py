"""
Honeypot — Main Orchestrator
Boots all traps concurrently, starts the Intel engine enrichment loop,
and serves the dashboard API.
"""

import asyncio
import logging
import os
import sys
import threading
import time
from pathlib import Path

from flask import Flask

# ── logging setup ─────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s — %(message)s",
)
log = logging.getLogger("honeypot")

sys.path.insert(0, str(Path(__file__).parent))

from capture.event_store import CaptureStore
from analysis.intel      import IntelEngine
from traps.ssh_trap      import start_ssh_trap
from traps.tcp_trap      import start_tcp_traps
from traps.http_trap     import HTTPHoneypot
from api                 import create_api

# ── auto-reset on startup ─────────────────────────────────────────────────────
if os.getenv("RESET_ON_START", "true").lower() == "true":
    db = os.getenv("HONEYPOT_DB", "honeypot.db")
    if os.path.exists(db):
        os.remove(db)
        log.info("Fresh start — previous database cleared")

store = CaptureStore()
intel = IntelEngine()

# ── intel enrichment loop (runs every 30s in background) ─────────────────────

def intel_loop():
    while True:
        time.sleep(30)
        try:
            intel.enrich_all()
            # persist profiles to DB
            for profile in intel.top_attackers(100):
                store.save_profile(profile)
        except Exception as exc:
            log.error("Intel loop error: %s", exc)


# ── hook store saves into intel engine ───────────────────────────────────────

_original_save = store.save

def _instrumented_save(capture):
    rowid = _original_save(capture)
    try:
        intel.ingest(capture)
    except Exception:
        pass
    return rowid

store.save = _instrumented_save


# ── async trap runner ─────────────────────────────────────────────────────────

async def run_traps():
    log.info("Starting honeypot traps…")

    # SSH trap on port 2222 (use 22 if running as root)
    ssh_port = int(os.getenv("SSH_TRAP_PORT", "2222"))
    await start_ssh_trap(store, port=ssh_port)

    # TCP traps (FTP, Telnet, MySQL, Redis, VNC, etc.)
    await start_tcp_traps(store)

    # HTTP trap
    http_port = int(os.getenv("HTTP_TRAP_PORT", "8080"))
    http_hp   = HTTPHoneypot(store, port=http_port)
    await http_hp.start()

    log.info("All traps active. Waiting for attackers…")
    await asyncio.Event().wait()   # run forever


def start_async_traps():
    """Run the asyncio trap loop in a background thread."""
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        loop.run_until_complete(run_traps())
    except Exception as exc:
        log.error("Trap loop crashed: %s", exc)


# ── entrypoint ────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    Path("exports").mkdir(exist_ok=True)

    # start trap thread
    trap_thread = threading.Thread(target=start_async_traps, daemon=True, name="traps")
    trap_thread.start()

    # start intel enrichment thread
    intel_thread = threading.Thread(target=intel_loop, daemon=True, name="intel")
    intel_thread.start()

    # start Flask dashboard
    flask_app = create_api(store, intel)
    api_port  = int(os.getenv("API_PORT", "5001"))
    log.info("Dashboard → http://localhost:%d", api_port)
    flask_app.run(host="0.0.0.0", port=api_port, debug=False, use_reloader=False)
