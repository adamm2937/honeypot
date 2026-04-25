"""
Honeypot — Generic TCP Port Traps
Listens on commonly scanned ports (FTP, Telnet, MySQL, Redis, etc.)
Records what scanners send — banner grabs, protocol probes, exploit attempts.
"""

import asyncio
import logging
import time

from capture.event_store import CaptureStore, make_capture

log = logging.getLogger("honeypot.tcp")

# ── Port → fake service config ─────────────────────────────────────────────────
PORT_PROFILES = {
    21:    {
        "name":    "FTP",
        "banner":  b"220 ProFTPD 1.3.5e Server (Debian) [::ffff:10.0.0.1]\r\n",
        "prompt":  b"530 Login incorrect.\r\n",
        "severity":"medium",
    },
    23:    {
        "name":    "Telnet",
        "banner":  b"\xff\xfd\x18\xff\xfd \xff\xfd#\xff\xfd'Ubuntu 20.04 LTS\r\nlogin: ",
        "prompt":  b"Password: ",
        "severity":"high",
    },
    3306:  {
        "name":    "MySQL",
        "banner":  b"\x4a\x00\x00\x00\x0a\x38\x2e\x30\x2e\x33\x32\x00",  # MySQL 8.0.32 handshake start
        "prompt":  b"",
        "severity":"high",
    },
    5432:  {
        "name":    "PostgreSQL",
        "banner":  b"",   # PostgreSQL speaks binary; scanner will send startup packet
        "prompt":  b"E\x00\x00\x00\x63SFATAL\x00C28P01\x00Mpassword authentication failed\x00\x00",
        "severity":"high",
    },
    6379:  {
        "name":    "Redis",
        "banner":  b"+OK\r\n",
        "prompt":  b"-ERR Client sent AUTH, but no password is set\r\n",
        "severity":"critical",
    },
    27017: {
        "name":    "MongoDB",
        "banner":  b"",
        "prompt":  b'\x4f\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\xd4\x07\x00\x00',
        "severity":"high",
    },
    5900:  {
        "name":    "VNC",
        "banner":  b"RFB 003.008\n",
        "prompt":  b"\x00\x00\x00\x01",  # security type: none (looks open!)
        "severity":"critical",
    },
    8888:  {
        "name":    "Jupyter",
        "banner":  b"HTTP/1.1 200 OK\r\nServer: tornado/6.1\r\nContent-Type: text/html\r\n\r\n<title>Jupyter</title>",
        "prompt":  b"",
        "severity":"critical",
    },
}


class TCPTrapProtocol(asyncio.Protocol):
    def __init__(self, store: CaptureStore, port: int, profile: dict):
        self.store   = store
        self.port    = port
        self.profile = profile
        self.peer    = None
        self.buf     = b""
        self.greeted = False
        self.start   = time.monotonic()

    def connection_made(self, transport):
        self.transport = transport
        self.peer      = transport.get_extra_info("peername")
        ip             = self.peer[0] if self.peer else "unknown"
        log.info("%s connection from %s", self.profile["name"], ip)

        capture = make_capture(
            trap_type  = "tcp",
            src_ip     = ip,
            src_port   = self.peer[1] if self.peer else 0,
            trap_port  = self.port,
            event_type = f"tcp_{self.profile['name'].lower()}_connect",
            severity   = self.profile["severity"],
            data       = {"service": self.profile["name"], "port": self.port},
            tags       = ["port-scan", "probe"],
        )
        self.store.save(capture)

        if self.profile["banner"]:
            asyncio.get_event_loop().call_later(0.1, self._send_banner)

    def _send_banner(self):
        try:
            self.transport.write(self.profile["banner"])
            self.greeted = True
        except Exception:
            pass

    def data_received(self, data: bytes):
        self.buf += data
        ip = self.peer[0] if self.peer else "unknown"

        try:
            decoded = data.decode("utf-8", errors="replace").strip()
        except Exception:
            decoded = data.hex()

        capture = make_capture(
            trap_type  = "tcp",
            src_ip     = ip,
            src_port   = self.peer[1] if self.peer else 0,
            trap_port  = self.port,
            event_type = f"tcp_{self.profile['name'].lower()}_probe",
            severity   = self.profile["severity"],
            data       = {
                "service":  self.profile["name"],
                "port":     self.port,
                "raw_text": decoded[:300],
                "raw_hex":  data[:64].hex(),
                "length":   len(data),
            },
            tags=["probe", "banner-grab"],
        )
        self.store.save(capture)

        if self.profile["prompt"]:
            try:
                self.transport.write(self.profile["prompt"])
            except Exception:
                pass

    def connection_lost(self, exc):
        duration = time.monotonic() - self.start
        ip = self.peer[0] if self.peer else "unknown"
        log.info("%s disconnected from %s (%.1fs)", self.profile["name"], ip, duration)


async def start_tcp_traps(store: CaptureStore) -> list:
    loop    = asyncio.get_event_loop()
    servers = []
    for port, profile in PORT_PROFILES.items():
        try:
            server = await loop.create_server(
                lambda p=port, pr=profile: TCPTrapProtocol(store, p, pr),
                "0.0.0.0", port,
            )
            servers.append(server)
            log.info("TCP trap [%s] listening on port %d", profile["name"], port)
        except OSError as e:
            log.warning("Could not bind port %d (%s): %s — skipping", port, profile["name"], e)
    return servers
