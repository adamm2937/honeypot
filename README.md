# 🍯 HoneyNet — Attacker Intelligence Platform

> A multi-trap honeypot system that lures attackers, captures their behaviour in real time, enriches IPs with geolocation and threat intelligence, and displays everything on a live dashboard.

![Python](https://img.shields.io/badge/Python-3.12-blue?style=flat-square&logo=python)
![asyncio](https://img.shields.io/badge/asyncio-concurrent-green?style=flat-square)
![Docker](https://img.shields.io/badge/Docker-ready-2496ED?style=flat-square&logo=docker)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)

---

## What Is a Honeypot?

A honeypot is a deliberately exposed decoy system designed to attract attackers. It has no real users, no real data — its only purpose is to look vulnerable and log everything that interacts with it.

This project deploys multiple traps simultaneously, each simulating a different service, and correlates everything into a unified attacker intelligence dashboard.

---

## Architecture

```
Internet / Local Network
         │
         ▼
┌────────────────────────────────────────────────────────────┐
│                     TRAP LAYER                             │
│                                                            │
│  SSH Trap :2222        HTTP Trap :8080                     │
│  ─────────────         ───────────────                     │
│  Fake OpenSSH          Fake Admin Panel                    │
│  banner + auth         Fake /.env file                     │
│  logging               Fake /.git/config                   │
│                        SQL injection detection             │
│                                                            │
│  TCP Traps (multiple ports)                                │
│  ─────────────────────────                                 │
│  FTP :21   Telnet :23   MySQL :3306                        │
│  Redis :6379   VNC :5900   MongoDB :27017                  │
│  Jupyter :8888  PostgreSQL :5432                           │
└────────────────────────┬───────────────────────────────────┘
                         │ normalised captures
                         ▼
┌────────────────────────────────────────────────────────────┐
│                   CAPTURE STORE                            │
│           SQLite — indexed, persistent                     │
└──────────┬──────────────────────────┬──────────────────────┘
           │                          │
           ▼                          ▼
┌──────────────────┐      ┌──────────────────────────────────┐
│  Intel Engine    │      │         REST API (Flask)          │
│                  │      │                                   │
│  GeoIP lookup    │      │  /api/stats                       │
│  ASN detection   │      │  /api/captures                    │
│  Threat scoring  │      │  /api/attackers                   │
│  Attacker        │      │  /api/siem-feed  ← SIEM-Lite feed │
│  classification  │      └──────────────┬───────────────────┘
└──────────────────┘                     │
                                         ▼
                              ┌─────────────────────┐
                              │   Live Dashboard     │
                              │   localhost:5001     │
                              └─────────────────────┘
```

---

## Traps

### SSH Trap (port 2222)
- Sends a realistic OpenSSH / Dropbear banner
- Accepts credential attempts without granting access
- Logs username, password, attempt count, session duration
- Introduces realistic delays to fool automated tools

### HTTP Trap (port 8080)
Serves a convincing fake admin panel and captures:
- **Credential submissions** — exact username/password pairs entered
- **Path traversal attempts** — `../../../etc/passwd`, `wp-admin`, `phpmyadmin`
- **SQL injection / XSS probes** — `UNION SELECT`, `<script>`, `eval(`
- **Scanner fingerprinting** — detects sqlmap, nikto, gobuster, Hydra, Nessus by User-Agent
- **Fake /.env file** — appears to expose database credentials and API keys
- **Fake /.git/config** — appears to expose source repository

### TCP Traps (8 services)
| Port  | Service    | What it captures |
|-------|------------|-----------------|
| 21    | FTP        | Banner grabs, auth attempts |
| 23    | Telnet     | Login attempts, command injection |
| 3306  | MySQL      | Protocol probes, auth packets |
| 5432  | PostgreSQL | Startup packets, auth attempts |
| 6379  | Redis      | Commands sent (GET, SET, CONFIG) |
| 27017 | MongoDB    | Wire protocol probes |
| 5900  | VNC        | Connection attempts |
| 8888  | Jupyter    | HTTP probes for notebook access |

---

## Attacker Intelligence

Every captured IP is automatically enriched with:

- **Geolocation** — country, city, ISP (via ip-api.com, free)
- **ASN detection** — flags known malicious/hosting ASNs (AWS, OVH, DigitalOcean...)
- **Proxy/VPN detection** — flags Tor exits and VPN endpoints
- **Threat score** — 0–100 based on behaviour, volume, and origin
- **Attacker classification**:
  - `Credential Stuffer` — submitting username/password pairs
  - `Injection Attacker` — SQLi/XSS/path traversal
  - `Data Harvester` — targeting .env, .git, config files
  - `Automated Scanner` — hitting many paths/ports systematically
  - `Port Scanner` — TCP probing across multiple ports

---

## Dashboard

Live dashboard at `http://localhost:5001` — updates every 4 seconds:

- Real-time capture feed with severity classification
- Attacker profiles table with threat scores and geo flags
- Trap activity breakdown (SSH vs HTTP vs TCP)
- Severity distribution
- Geographic origins map
- Event type frequency analysis

---

## Quick Start

```bash
git clone https://github.com/YOUR_USERNAME/honeynet
cd honeynet
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python3 main.py
```

Open `http://localhost:5001`

**To test it immediately:**
```bash
# simulate an SSH brute force (in another terminal)
for i in $(seq 1 10); do
  nc localhost 2222
done

# simulate a web scanner
curl http://localhost:8080/.env
curl http://localhost:8080/wp-admin
curl http://localhost:8080/admin/login -d "username=admin&password=admin123"
curl "http://localhost:8080/search?q=../../etc/passwd"
```

---

## SIEM-Lite Integration

HoneyNet exports a SIEM-compatible event feed at `/api/siem-feed`. Point your SIEM-Lite JSON ingester at this endpoint to see real honeypot captures flowing into the SIEM dashboard automatically — closing the loop between deception, detection, and response.

---

## Legal Notice

This honeypot is designed to run on **systems you own**. Deploying it on your own machine or VM is completely legal — attackers who connect do so uninvited. Never deploy on systems you do not own or without explicit authorisation.

---

## Project Structure

```
honeynet/
├── traps/
│   ├── ssh_trap.py       # Fake SSH server (asyncio)
│   ├── http_trap.py      # Fake admin panel (aiohttp)
│   └── tcp_trap.py       # 8 generic TCP service traps
├── capture/
│   └── event_store.py    # SQLite persistence layer
├── analysis/
│   └── intel.py          # GeoIP, ASN, threat scoring, classification
├── dashboard/
│   └── index.html        # Live attacker intelligence dashboard
├── api.py                # Flask REST API
├── main.py               # Orchestrator — boots all traps
├── Dockerfile
├── docker-compose.yml
└── requirements.txt
```

---

## Tech Stack

- **Python 3.12 asyncio** — concurrent trap handling (thousands of connections)
- **aiohttp** — async HTTP trap server
- **Flask** — REST API and dashboard server
- **SQLite** — zero-dependency persistent capture storage
- **ip-api.com** — free geolocation API (no key required)
- **Docker** — one-command deployment

---

## License

MIT — educational use, research, and personal lab environments.
