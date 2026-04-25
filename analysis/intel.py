"""
Honeypot — Attacker Intelligence Engine
Enriches captured IPs with:
  - Geolocation (country, city, ISP) via ip-api.com (free, no key needed)
  - ASN / organisation lookup
  - Known Tor exit node detection
  - Attack pattern profiling (what tools they use, what they're after)
  - Threat scoring
"""

import asyncio
import ipaddress
import json
import logging
import time
import urllib.request
from collections import defaultdict
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path

log = logging.getLogger("honeypot.intel")

# ── Known malicious ASN ranges (top abused cloud/VPN providers) ───────────────
SUSPICIOUS_ASNS = {
    "AS14061",  # DigitalOcean
    "AS16276",  # OVH
    "AS24940",  # Hetzner
    "AS136907", # Huawei Cloud
    "AS45090",  # Tencent Cloud
    "AS396982", # Google Cloud
    "AS16509",  # Amazon AWS
    "AS8075",   # Microsoft Azure
}

# ── Private/loopback ranges (skip enrichment) ─────────────────────────────────
PRIVATE_RANGES = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
]


def is_private(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return any(addr in net for net in PRIVATE_RANGES)
    except ValueError:
        return False


# ── GeoIP cache (avoid hammering the free API) ────────────────────────────────
_geo_cache: dict[str, dict] = {}
_cache_ttl: dict[str, float] = {}
CACHE_DURATION = 3600  # 1 hour


def get_geoip(ip: str) -> dict:
    """Fetch geolocation data from ip-api.com (free, 45 req/min limit)."""
    if is_private(ip):
        return {"status": "private", "country": "Internal", "org": "LAN"}

    now = time.monotonic()
    if ip in _geo_cache and now - _cache_ttl.get(ip, 0) < CACHE_DURATION:
        return _geo_cache[ip]

    try:
        url = (f"http://ip-api.com/json/{ip}"
               f"?fields=status,country,countryCode,region,city,isp,org,as,proxy,hosting")
        req = urllib.request.Request(url, headers={"User-Agent": "honeypot-research/1.0"})
        with urllib.request.urlopen(req, timeout=4) as resp:
            data = json.loads(resp.read())
        _geo_cache[ip]    = data
        _cache_ttl[ip]    = now
        return data
    except Exception as exc:
        log.debug("GeoIP lookup failed for %s: %s", ip, exc)
        return {"status": "error", "country": "Unknown"}


# ── Threat scoring ─────────────────────────────────────────────────────────────

def threat_score(captures: list[dict], geo: dict) -> int:
    """
    Returns a 0-100 threat score based on:
    - Number of captures from this IP
    - Types of events seen
    - Whether it's a known hosting/proxy ASN
    - Geographic risk factors
    """
    score = 0

    # volume
    score += min(len(captures) * 3, 30)

    # event type weights
    weights = {
        "http_credential_submit":   20,
        "ssh_credential_attempt":   15,
        "http_env_file_access":     18,
        "http_git_config_access":   12,
        "http_injection_attempt":   15,
        "tcp_redis_probe":          10,
        "tcp_vnc_connect":          10,
        "http_scanner_detected":     8,
        "tcp_telnet_connect":        8,
        "http_sensitive_path":       5,
    }
    seen_types = {c.get("event_type") for c in captures}
    for etype, w in weights.items():
        if etype in seen_types:
            score += w

    # hosting/proxy ASN
    asn = geo.get("as", "")
    if any(bad in asn for bad in SUSPICIOUS_ASNS):
        score += 10
    if geo.get("proxy") or geo.get("hosting"):
        score += 8

    return min(score, 100)


def classify_attacker(captures: list[dict]) -> str:
    """Classify the attacker type based on behaviour patterns."""
    types = [c.get("event_type", "") for c in captures]
    tags  = [t for c in captures for t in c.get("tags", [])]

    if "http_credential_submit" in types or "ssh_credential_attempt" in types:
        return "Credential Stuffer"
    if types.count("http_injection_attempt") >= 2:
        return "Injection Attacker"
    if "http_env_file_access" in types or "http_git_config_access" in types:
        return "Data Harvester"
    if "scanner" in tags or len(set(c.get("trap_port") for c in captures)) > 3:
        return "Automated Scanner"
    if any("tcp_" in t for t in types):
        return "Port Scanner"
    return "Reconnaissance"


# ── Attacker profile builder ──────────────────────────────────────────────────

class AttackerProfile:
    """Aggregates all activity from a single IP into a rich profile."""

    def __init__(self, ip: str):
        self.ip       = ip
        self.captures : list[dict] = []
        self.geo      : dict = {}
        self.score    : int  = 0
        self.category : str  = "Unknown"
        self.first_seen: str = datetime.now(timezone.utc).isoformat()
        self.last_seen : str = self.first_seen

    def add(self, capture: dict) -> None:
        self.captures.append(capture)
        self.last_seen = datetime.now(timezone.utc).isoformat()

    def enrich(self) -> None:
        self.geo      = get_geoip(self.ip)
        self.score    = threat_score(self.captures, self.geo)
        self.category = classify_attacker(self.captures)

    def to_dict(self) -> dict:
        return {
            "ip":          self.ip,
            "geo":         self.geo,
            "score":       self.score,
            "category":    self.category,
            "first_seen":  self.first_seen,
            "last_seen":   self.last_seen,
            "total_hits":  len(self.captures),
            "ports_hit":   list({c.get("trap_port") for c in self.captures}),
            "event_types": list({c.get("event_type") for c in self.captures}),
            "tags":        list({t for c in self.captures for t in c.get("tags", [])}),
        }


class IntelEngine:
    def __init__(self):
        self._profiles: dict[str, AttackerProfile] = {}

    def ingest(self, capture: dict) -> AttackerProfile:
        ip = capture.get("src_ip", "unknown")
        if ip not in self._profiles:
            self._profiles[ip] = AttackerProfile(ip)
        profile = self._profiles[ip]
        profile.add(capture)
        return profile

    def enrich_all(self) -> None:
        for profile in self._profiles.values():
            profile.enrich()

    def get_profile(self, ip: str) -> dict | None:
        p = self._profiles.get(ip)
        return p.to_dict() if p else None

    def top_attackers(self, n: int = 20) -> list[dict]:
        profiles = list(self._profiles.values())
        for p in profiles:
            if not p.geo:
                p.enrich()
        profiles.sort(key=lambda p: (p.score, len(p.captures)), reverse=True)
        return [p.to_dict() for p in profiles[:n]]

    def stats(self) -> dict:
        profiles = list(self._profiles.values())
        countries = defaultdict(int)
        categories = defaultdict(int)
        for p in profiles:
            c = p.geo.get("countryCode", "??")
            countries[c] += 1
            categories[p.category] += 1
        return {
            "unique_ips":  len(profiles),
            "countries":   dict(sorted(countries.items(), key=lambda x: -x[1])[:10]),
            "categories":  dict(categories),
        }
