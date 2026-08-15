"""
vt_client.py

Thin wrapper around the VirusTotal v3 API for domain reputation lookups.

Built around three constraints of the free tier:
  - 500 requests/day, 4 requests/minute -- so we rate-limit ourselves
    and cache every result to disk so re-running the tool on the same
    case doesn't burn quota.
  - No API key at all is a completely normal, supported case -- the
    tool should still produce a useful triage summary using only the
    local checks in checks.py, just with a note that VT wasn't checked.
  - A key that's invalid, rate-limited, or the API being briefly down
    should degrade the same way -- log it, move on, never crash the
    whole triage over one failed network call.
"""

import os
import json
import time
import hashlib
from dataclasses import dataclass

try:
    import requests
except ImportError:
    requests = None

CACHE_DIR = os.path.join(os.path.dirname(__file__), ".vt_cache")
CACHE_TTL_SECONDS = 60 * 60 * 24 * 7  # a week -- domain reputation doesn't change hourly
MIN_SECONDS_BETWEEN_CALLS = 16        # keeps us under 4 req/min with margin

VT_BASE = "https://www.virustotal.com/api/v3"


@dataclass
class VTResult:
    domain: str
    checked: bool                 # False if we never actually called the API
    malicious: int = 0
    suspicious: int = 0
    harmless: int = 0
    undetected: int = 0
    reputation: int | None = None
    error: str | None = None
    from_cache: bool = False


class VirusTotalClient:
    def __init__(self, api_key: str | None = None):
        self.api_key = api_key or os.environ.get("VT_API_KEY")
        self._last_call_time = 0.0
        os.makedirs(CACHE_DIR, exist_ok=True)

    @property
    def enabled(self) -> bool:
        return bool(self.api_key) and requests is not None

    def _cache_path(self, domain: str) -> str:
        h = hashlib.sha256(domain.encode()).hexdigest()[:32]
        return os.path.join(CACHE_DIR, f"{h}.json")

    def _read_cache(self, domain: str) -> dict | None:
        path = self._cache_path(domain)
        if not os.path.exists(path):
            return None
        try:
            with open(path, "r", encoding="utf-8") as f:
                cached = json.load(f)
            if time.time() - cached.get("_cached_at", 0) > CACHE_TTL_SECONDS:
                return None
            return cached
        except Exception:
            return None

    def _write_cache(self, domain: str, data: dict):
        data = dict(data)
        data["_cached_at"] = time.time()
        try:
            with open(self._cache_path(domain), "w", encoding="utf-8") as f:
                json.dump(data, f)
        except Exception:
            pass  # cache is best-effort, never fatal

    def _throttle(self):
        elapsed = time.time() - self._last_call_time
        if elapsed < MIN_SECONDS_BETWEEN_CALLS:
            time.sleep(MIN_SECONDS_BETWEEN_CALLS - elapsed)
        self._last_call_time = time.time()

    def check_domain(self, domain: str) -> VTResult:
        if not requests:
            return VTResult(domain=domain, checked=False, error="'requests' package not installed")
        if not self.api_key:
            return VTResult(domain=domain, checked=False, error="No VT_API_KEY configured")

        cached = self._read_cache(domain)
        if cached:
            stats = cached.get("stats", {})
            return VTResult(
                domain=domain, checked=True, from_cache=True,
                malicious=stats.get("malicious", 0),
                suspicious=stats.get("suspicious", 0),
                harmless=stats.get("harmless", 0),
                undetected=stats.get("undetected", 0),
                reputation=cached.get("reputation"),
            )

        self._throttle()
        try:
            resp = requests.get(
                f"{VT_BASE}/domains/{domain}",
                headers={"x-apikey": self.api_key},
                timeout=15,
            )
        except Exception as e:
            return VTResult(domain=domain, checked=False, error=f"Network error: {e}")

        if resp.status_code == 401:
            return VTResult(domain=domain, checked=False, error="Invalid VT API key")
        if resp.status_code == 429:
            return VTResult(domain=domain, checked=False, error="VT rate limit hit -- try again later")
        if resp.status_code == 404:
            # VT has no record of this domain at all -- not the same as "clean",
            # just "unknown," which is worth recording as its own state.
            result = {"stats": {}, "reputation": None, "unknown": True}
            self._write_cache(domain, result)
            return VTResult(domain=domain, checked=True)
        if resp.status_code != 200:
            return VTResult(domain=domain, checked=False, error=f"VT API returned HTTP {resp.status_code}")

        try:
            payload = resp.json()
            attrs = payload["data"]["attributes"]
            stats = attrs.get("last_analysis_stats", {})
            reputation = attrs.get("reputation")
        except Exception as e:
            return VTResult(domain=domain, checked=False, error=f"Unexpected VT response shape: {e}")

        self._write_cache(domain, {"stats": stats, "reputation": reputation})
        return VTResult(
            domain=domain, checked=True,
            malicious=stats.get("malicious", 0),
            suspicious=stats.get("suspicious", 0),
            harmless=stats.get("harmless", 0),
            undetected=stats.get("undetected", 0),
            reputation=reputation,
        )

    def check_domains(self, domains: list[str]) -> list[VTResult]:
        return [self.check_domain(d) for d in domains]
