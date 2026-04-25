"""
Honeypot — HTTP Web Trap
A fake admin panel / login page that looks enticing to attackers.
Captures credential stuffing, path traversal, SQLi attempts, and scanner fingerprints.
Built on aiohttp for async performance.
"""

import json
import logging
import re
import time
from datetime import datetime, timezone

from aiohttp import web

from capture.event_store import CaptureStore, make_capture

log = logging.getLogger("honeypot.http")

# ── Fingerprinting patterns ────────────────────────────────────────────────────
SCANNER_UAS = re.compile(
    r"(sqlmap|nikto|nmap|masscan|zgrab|nuclei|dirbuster|gobuster|"
    r"wfuzz|hydra|medusa|burpsuite|acunetix|nessus|openvas|whatweb|"
    r"curl|python-requests|go-http|wget|scrapy)", re.I
)

INJECTION_PATTERNS = re.compile(
    r"(\.\./|/etc/passwd|/proc/self|union.{0,10}select|<script|"
    r"eval\(|base64_decode|exec\(|system\(|cmd=|;ls|&&cat|"
    r"'--|\bOR\b.{0,5}=|DROP.TABLE|INSERT.INTO)", re.I
)

COMMON_PATHS = {
    "/admin", "/administrator", "/wp-admin", "/phpmyadmin",
    "/login", "/signin", "/.env", "/config.php", "/backup",
    "/.git/config", "/server-status", "/api/v1/users",
    "/manager/html", "/console", "/actuator", "/actuator/env",
}

# ── Fake admin panel HTML ──────────────────────────────────────────────────────
FAKE_LOGIN_PAGE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Admin Panel — SecureNet v3.2.1</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { background: #1a1a2e; display: flex; align-items: center;
         justify-content: center; min-height: 100vh; font-family: Arial, sans-serif; }
  .card { background: #16213e; border: 1px solid #0f3460; border-radius: 8px;
          padding: 40px; width: 380px; box-shadow: 0 20px 60px rgba(0,0,0,0.5); }
  h1 { color: #e94560; font-size: 22px; margin-bottom: 6px; }
  .sub { color: #888; font-size: 12px; margin-bottom: 28px; }
  label { color: #aaa; font-size: 13px; display: block; margin-bottom: 6px; }
  input { width: 100%; padding: 10px 14px; background: #0f3460;
          border: 1px solid #1a4a7a; border-radius: 4px; color: #fff;
          font-size: 14px; margin-bottom: 16px; outline: none; }
  input:focus { border-color: #e94560; }
  button { width: 100%; padding: 12px; background: #e94560; color: #fff;
           border: none; border-radius: 4px; font-size: 15px; cursor: pointer; }
  button:hover { background: #c73652; }
  .ver { color: #333; font-size: 10px; text-align: center; margin-top: 20px; }
</style>
</head>
<body>
<div class="card">
  <h1>🔐 SecureNet Admin</h1>
  <p class="sub">Enterprise Security Management Console v3.2.1</p>
  <form method="POST" action="/admin/login">
    <label>Username</label>
    <input type="text" name="username" placeholder="admin" autocomplete="off">
    <label>Password</label>
    <input type="password" name="password" placeholder="••••••••">
    <button type="submit">Sign In</button>
  </form>
  <p class="ver">SecureNet © 2024 | Build 20240115-prod</p>
</div>
</body>
</html>"""

FAKE_AUTH_FAIL = """<!DOCTYPE html>
<html><head><title>Admin Panel</title>
<style>body{background:#1a1a2e;color:#e94560;font-family:Arial;
display:flex;align-items:center;justify-content:center;height:100vh;}</style>
</head><body><h2>⚠ Authentication Failed. Account locked after 3 attempts.</h2>
</body></html>"""

# ── Fake exposed files ─────────────────────────────────────────────────────────
FAKE_ENV = """DB_HOST=10.0.0.5
DB_PORT=5432
DB_NAME=production_db
DB_USER=dbadmin
DB_PASS=Sup3rS3cr3t!2024
JWT_SECRET=hs256-secret-key-do-not-share
AWS_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
REDIS_URL=redis://10.0.0.6:6379
ADMIN_EMAIL=admin@company.internal
"""

FAKE_GIT_CONFIG = """[core]
\trepositoryformatversion = 0
\tfilemode = true
[remote "origin"]
\turl = git@github.com:company/internal-app.git
\tfetch = +refs/heads/*:refs/remotes/origin/*
[branch "main"]
\tremote = origin
\tmerge = refs/heads/main
"""


class HTTPHoneypot:
    def __init__(self, store: CaptureStore, port: int = 8080):
        self.store = store
        self.port  = port
        self.app   = web.Application(middlewares=[self._capture_middleware])
        self._setup_routes()

    def _setup_routes(self):
        self.app.router.add_get("/",              self._handle_index)
        self.app.router.add_get("/admin",         self._handle_admin)
        self.app.router.add_get("/admin/login",   self._handle_admin)
        self.app.router.add_post("/admin/login",  self._handle_login_post)
        self.app.router.add_get("/.env",          self._handle_env)
        self.app.router.add_get("/.git/config",   self._handle_git)
        self.app.router.add_get("/wp-admin",      self._handle_admin)
        self.app.router.add_get("/phpmyadmin",    self._handle_admin)
        self.app.router.add_route("*", "/{path_info:.*}", self._handle_catch_all)

    @web.middleware
    async def _capture_middleware(self, request: web.Request, handler):
        start = time.monotonic()
        ip    = request.headers.get("X-Forwarded-For", request.remote)
        ua    = request.headers.get("User-Agent", "")
        path  = request.path
        qs    = str(request.query_string)

        # detect scanners
        is_scanner    = bool(SCANNER_UAS.search(ua))
        is_injection  = bool(INJECTION_PATTERNS.search(path + "?" + qs))
        is_known_path = path in COMMON_PATHS

        severity = "info"
        tags     = ["http"]
        etype    = "http_request"

        if is_injection:
            severity, etype = "high", "http_injection_attempt"
            tags.append("injection")
        elif is_scanner:
            severity, etype = "medium", "http_scanner_detected"
            tags.append("scanner")
        elif is_known_path:
            severity, etype = "medium", "http_sensitive_path"
            tags.append("recon")

        capture = make_capture(
            trap_type = "http",
            src_ip    = ip or "unknown",
            src_port  = 0,
            trap_port = self.port,
            event_type= etype,
            severity  = severity,
            data      = {
                "method":     request.method,
                "path":       path,
                "query":      qs[:200],
                "user_agent": ua[:200],
                "headers":    dict(list(request.headers.items())[:15]),
                "is_scanner": is_scanner,
                "is_injection": is_injection,
            },
            tags=tags,
        )
        self.store.save(capture)

        response = await handler(request)
        return response

    async def _handle_index(self, request):
        return web.Response(
            text="<html><body><h1>403 Forbidden</h1></body></html>",
            content_type="text/html", status=403,
        )

    async def _handle_admin(self, request):
        return web.Response(text=FAKE_LOGIN_PAGE, content_type="text/html")

    async def _handle_login_post(self, request: web.Request):
        ip = request.headers.get("X-Forwarded-For", request.remote)
        try:
            data = await request.post()
            user = data.get("username", "")[:64]
            pw   = data.get("password", "")[:64]
        except Exception:
            user, pw = "", ""

        capture = make_capture(
            trap_type  = "http",
            src_ip     = ip or "unknown",
            src_port   = 0,
            trap_port  = self.port,
            event_type = "http_credential_submit",
            severity   = "critical",
            data       = {"username": user, "password": pw,
                          "path": "/admin/login"},
            tags       = ["credential", "login-attempt"],
        )
        self.store.save(capture)
        log.warning("CREDENTIAL CAPTURE: %s tried user=%r pw=%r", ip, user, pw)

        return web.Response(text=FAKE_AUTH_FAIL, content_type="text/html", status=401)

    async def _handle_env(self, request):
        ip = request.headers.get("X-Forwarded-For", request.remote)
        capture = make_capture(
            trap_type="http", src_ip=ip or "unknown", src_port=0,
            trap_port=self.port, event_type="http_env_file_access",
            severity="critical",
            data={"path": "/.env", "note": "attacker accessed fake .env file"},
            tags=["credential", "data-exfil"],
        )
        self.store.save(capture)
        return web.Response(text=FAKE_ENV, content_type="text/plain")

    async def _handle_git(self, request):
        ip = request.headers.get("X-Forwarded-For", request.remote)
        capture = make_capture(
            trap_type="http", src_ip=ip or "unknown", src_port=0,
            trap_port=self.port, event_type="http_git_config_access",
            severity="high",
            data={"path": "/.git/config"},
            tags=["recon", "source-code"],
        )
        self.store.save(capture)
        return web.Response(text=FAKE_GIT_CONFIG, content_type="text/plain")

    async def _handle_catch_all(self, request: web.Request):
        return web.Response(
            text='{"error":"Not found"}',
            content_type="application/json", status=404,
        )

    async def start(self):
        runner = web.AppRunner(self.app)
        await runner.setup()
        site = web.TCPSite(runner, "0.0.0.0", self.port)
        await site.start()
        log.info("HTTP trap listening on 0.0.0.0:%d", self.port)
        return runner
