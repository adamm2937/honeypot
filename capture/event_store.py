"""
Honeypot — Capture Store
SQLite-backed persistence for all honeypot captures.
Thread-safe, indexed for fast dashboard queries.
"""

import json
import logging
import os
import sqlite3
import threading
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Generator

log = logging.getLogger("honeypot.store")

DB_PATH = os.getenv("HONEYPOT_DB", "honeypot.db")


def make_capture(
    trap_type:  str,
    src_ip:     str,
    src_port:   int,
    trap_port:  int,
    event_type: str,
    severity:   str,
    data:       dict,
    tags:       list[str] | None = None,
) -> dict:
    """Create a normalised capture event."""
    return {
        "timestamp":  datetime.now(timezone.utc).isoformat(),
        "trap_type":  trap_type,
        "src_ip":     src_ip,
        "src_port":   src_port,
        "trap_port":  trap_port,
        "event_type": event_type,
        "severity":   severity,
        "data":       data,
        "tags":       tags or [],
    }


class CaptureStore:
    def __init__(self, db_path: str = DB_PATH):
        self.db_path = db_path
        self._local  = threading.local()
        self._init_db()
        log.info("CaptureStore initialised at %s", db_path)

    def _conn(self) -> sqlite3.Connection:
        if not hasattr(self._local, "conn"):
            self._local.conn = sqlite3.connect(self.db_path, check_same_thread=False)
            self._local.conn.row_factory = sqlite3.Row
        return self._local.conn

    @contextmanager
    def _cur(self) -> Generator[sqlite3.Cursor, None, None]:
        conn = self._conn()
        cur  = conn.cursor()
        try:
            yield cur
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            cur.close()

    def _init_db(self) -> None:
        with self._cur() as c:
            c.executescript("""
                CREATE TABLE IF NOT EXISTS captures (
                    id         INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp  TEXT NOT NULL,
                    trap_type  TEXT NOT NULL,
                    src_ip     TEXT NOT NULL,
                    src_port   INTEGER,
                    trap_port  INTEGER,
                    event_type TEXT NOT NULL,
                    severity   TEXT NOT NULL,
                    data_json  TEXT,
                    tags_json  TEXT
                );

                CREATE TABLE IF NOT EXISTS attacker_profiles (
                    ip           TEXT PRIMARY KEY,
                    profile_json TEXT,
                    updated_at   TEXT
                );

                CREATE INDEX IF NOT EXISTS idx_cap_ts     ON captures(timestamp);
                CREATE INDEX IF NOT EXISTS idx_cap_ip     ON captures(src_ip);
                CREATE INDEX IF NOT EXISTS idx_cap_sev    ON captures(severity);
                CREATE INDEX IF NOT EXISTS idx_cap_type   ON captures(event_type);
                CREATE INDEX IF NOT EXISTS idx_cap_trap   ON captures(trap_type);
            """)

    # ── write ──────────────────────────────────────────────────────────────

    def save(self, capture: dict) -> int:
        with self._cur() as c:
            c.execute(
                "INSERT INTO captures "
                "(timestamp,trap_type,src_ip,src_port,trap_port,"
                " event_type,severity,data_json,tags_json) "
                "VALUES (?,?,?,?,?,?,?,?,?)",
                (capture["timestamp"], capture["trap_type"], capture["src_ip"],
                 capture["src_port"], capture["trap_port"], capture["event_type"],
                 capture["severity"],
                 json.dumps(capture.get("data", {})),
                 json.dumps(capture.get("tags", []))),
            )
            return c.lastrowid

    def save_profile(self, profile: dict) -> None:
        with self._cur() as c:
            c.execute(
                "INSERT OR REPLACE INTO attacker_profiles (ip, profile_json, updated_at) "
                "VALUES (?,?,?)",
                (profile["ip"], json.dumps(profile),
                 datetime.now(timezone.utc).isoformat()),
            )

    # ── read ───────────────────────────────────────────────────────────────

    def _row_to_capture(self, row) -> dict:
        d = dict(row)
        d["data"] = json.loads(d.pop("data_json", "{}") or "{}")
        d["tags"] = json.loads(d.pop("tags_json", "[]") or "[]")
        return d

    def recent(self, limit: int = 100) -> list[dict]:
        with self._cur() as c:
            c.execute("SELECT * FROM captures ORDER BY timestamp DESC LIMIT ?", (limit,))
            return [self._row_to_capture(r) for r in c.fetchall()]

    def by_ip(self, ip: str, limit: int = 50) -> list[dict]:
        with self._cur() as c:
            c.execute(
                "SELECT * FROM captures WHERE src_ip=? ORDER BY timestamp DESC LIMIT ?",
                (ip, limit),
            )
            return [self._row_to_capture(r) for r in c.fetchall()]

    def by_severity(self, severity: str, limit: int = 50) -> list[dict]:
        with self._cur() as c:
            c.execute(
                "SELECT * FROM captures WHERE severity=? ORDER BY timestamp DESC LIMIT ?",
                (severity, limit),
            )
            return [self._row_to_capture(r) for r in c.fetchall()]

    def counts_by_severity(self) -> dict:
        with self._cur() as c:
            c.execute("SELECT severity, COUNT(*) n FROM captures GROUP BY severity")
            return {r["severity"]: r["n"] for r in c.fetchall()}

    def counts_by_trap(self) -> dict:
        with self._cur() as c:
            c.execute("SELECT trap_type, COUNT(*) n FROM captures GROUP BY trap_type")
            return {r["trap_type"]: r["n"] for r in c.fetchall()}

    def counts_by_event_type(self) -> list[dict]:
        with self._cur() as c:
            c.execute(
                "SELECT event_type, COUNT(*) n FROM captures "
                "GROUP BY event_type ORDER BY n DESC LIMIT 20"
            )
            return [dict(r) for r in c.fetchall()]

    def top_ips(self, limit: int = 20) -> list[dict]:
        with self._cur() as c:
            c.execute(
                "SELECT src_ip, COUNT(*) n, MAX(timestamp) last_seen "
                "FROM captures GROUP BY src_ip ORDER BY n DESC LIMIT ?",
                (limit,),
            )
            return [dict(r) for r in c.fetchall()]

    def unique_ip_count(self) -> int:
        with self._cur() as c:
            c.execute("SELECT COUNT(DISTINCT src_ip) n FROM captures")
            return c.fetchone()["n"]

    def stats(self) -> dict:
        with self._cur() as c:
            c.execute("SELECT COUNT(*) n FROM captures")
            total = c.fetchone()["n"]
            c.execute("SELECT COUNT(*) n FROM captures WHERE severity IN ('critical','high')")
            high  = c.fetchone()["n"]
        return {
            "total_captures": total,
            "high_critical":  high,
            "unique_ips":     self.unique_ip_count(),
            "by_severity":    self.counts_by_severity(),
            "by_trap":        self.counts_by_trap(),
        }

    def export_json(self, path: str, limit: int = 5000) -> None:
        captures = self.recent(limit=limit)
        with open(path, "w") as f:
            json.dump(captures, f, indent=2, default=str)
        log.info("Exported %d captures to %s", len(captures), path)
