"""
Honeypot — SSH Trap
A fake SSH server that accepts connections, presents a realistic banner,
records every credential attempt, and logs attacker behaviour.
Uses raw asyncio — no real SSH is ever established.
"""

import asyncio
import hashlib
import json
import logging
import os
import random
import time
from datetime import datetime, timezone
from pathlib import Path

from capture.event_store import CaptureStore, make_capture

log = logging.getLogger("honeypot.ssh")

# ── Realistic SSH banners (rotated to look like different servers) ─────────────
SSH_BANNERS = [
    b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n",
    b"SSH-2.0-OpenSSH_7.4p1 Debian-10+deb9u7\r\n",
    b"SSH-2.0-OpenSSH_8.0\r\n",
    b"SSH-2.0-dropbear_2022.83\r\n",
    b"SSH-2.0-OpenSSH_9.3p1\r\n",
]

# ── Fake credentials that trigger "almost worked" responses ───────────────────
HONEYPOT_CREDENTIALS = {
    ("admin", "admin"), ("root", "root"), ("admin", "password"),
    ("root", "123456"), ("admin", "1234"), ("pi", "raspberry"),
}

# ── Realistic delay ranges (seconds) to mimic real SSH timing ─────────────────
AUTH_DELAY   = (0.3, 1.2)
BANNER_DELAY = (0.1, 0.4)


class SSHHoneypotProtocol(asyncio.Protocol):
    """
    Simulates just enough of the SSH handshake to:
    1. Send a convincing banner
    2. Accept data (credentials, commands)
    3. Log everything without ever granting access
    """

    def __init__(self, store: CaptureStore, port: int):
        self.store    = store
        self.port     = port
        self.peer     = None
        self.buf      = b""
        self.session_start = time.monotonic()
        self.attempt_count = 0
        self.commands_seen: list[str] = []

    def connection_made(self, transport):
        self.transport = transport
        self.peer      = transport.get_extra_info("peername")
        ip             = self.peer[0] if self.peer else "unknown"
        log.info("SSH connection from %s", ip)

        # send banner after a small realistic delay
        asyncio.get_event_loop().call_later(
            random.uniform(*BANNER_DELAY),
            self._send_banner,
        )

    def _send_banner(self):
        banner = random.choice(SSH_BANNERS)
        try:
            self.transport.write(banner)
        except Exception:
            pass

    def data_received(self, data: bytes):
        self.buf += data
        ip = self.peer[0] if self.peer else "unknown"

        # try to extract printable strings (credential attempts arrive as text
        # in early SSH negotiation or when scanners don't speak real SSH)
        try:
            decoded = data.decode("utf-8", errors="ignore").strip()
        except Exception:
            decoded = ""

        if decoded:
            self.attempt_count += 1
            self.commands_seen.append(decoded[:200])

            # parse username:password patterns common in scanner traffic
            user, pw = self._extract_creds(decoded)

            capture = make_capture(
                trap_type   = "ssh",
                src_ip      = ip,
                src_port    = self.peer[1] if self.peer else 0,
                trap_port   = self.port,
                event_type  = "ssh_credential_attempt",
                severity    = "high",
                data        = {"raw": decoded[:500], "username": user,
                               "password": pw, "attempt_num": self.attempt_count},
                tags        = ["credential", "brute-force"],
            )
            self.store.save(capture)

            # send a fake "authentication failed" to keep them engaged longer
            asyncio.get_event_loop().call_later(
                random.uniform(*AUTH_DELAY),
                self._send_auth_fail,
            )

    def _extract_creds(self, raw: str) -> tuple[str, str]:
        """Best-effort extraction of username/password from raw data."""
        parts = raw.split()
        if len(parts) >= 2:
            return parts[0][:64], parts[1][:64]
        if ":" in raw:
            u, _, p = raw.partition(":")
            return u.strip()[:64], p.strip()[:64]
        return raw[:64], ""

    def _send_auth_fail(self):
        # SSH auth failure packet (enough to fool basic scanners)
        try:
            self.transport.write(b"\x00" * 4 + b"\x33")
        except Exception:
            pass

    def connection_lost(self, exc):
        ip       = self.peer[0] if self.peer else "unknown"
        duration = time.monotonic() - self.session_start

        if self.attempt_count > 0:
            capture = make_capture(
                trap_type  = "ssh",
                src_ip     = ip,
                src_port   = self.peer[1] if self.peer else 0,
                trap_port  = self.port,
                event_type = "ssh_session_ended",
                severity   = "medium",
                data       = {
                    "duration_s":    round(duration, 2),
                    "attempt_count": self.attempt_count,
                    "commands_seen": self.commands_seen[:20],
                },
                tags=["session"],
            )
            self.store.save(capture)

        log.info("SSH session from %s closed (%.1fs, %d attempts)",
                 ip, duration, self.attempt_count)


async def start_ssh_trap(store: CaptureStore, host: str = "0.0.0.0", port: int = 2222):
    loop   = asyncio.get_event_loop()
    server = await loop.create_server(
        lambda: SSHHoneypotProtocol(store, port),
        host, port,
    )
    log.info("SSH trap listening on %s:%d", host, port)
    return server
