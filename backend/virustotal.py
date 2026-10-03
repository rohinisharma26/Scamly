import base64
import os
import time
from collections import deque
from urllib.parse import urlparse

import requests
from dotenv import load_dotenv

load_dotenv()  # reads backend/.env so the key never goes in the code

VT_BASE = "https://www.virustotal.com/api/v3"
CACHE_SECONDS = 3600          # remember answers for an hour to save the daily quota
MAX_PER_MINUTE = 4            # VirusTotal free tier limit
MAX_PER_DAY = 450             # stay under the 500/day free limit

_cache: dict[str, tuple[float, dict]] = {}
_recent_calls: deque = deque()
_day_start = time.time()
_day_count = 0


def _url_id(url: str) -> str:
    return base64.urlsafe_b64encode(url.encode()).decode().strip("=")


def _normalize(url: str) -> str:
    url = url.strip()
    if "://" not in url:
        url = "http://" + url
    return url


def _allow_call() -> bool:
    """Our own limiter so we never hit VirusTotal's limits."""
    global _day_start, _day_count
    now = time.time()
    if now - _day_start > 86400:
        _day_start, _day_count = now, 0
    while _recent_calls and now - _recent_calls[0] > 60:
        _recent_calls.popleft()
    if len(_recent_calls) >= MAX_PER_MINUTE or _day_count >= MAX_PER_DAY:
        return False
    _recent_calls.append(now)
    _day_count += 1
    return True


def _summarize(attrs: dict) -> dict:
    stats = attrs.get("last_analysis_stats") or {}
    malicious = int(stats.get("malicious", 0))
    suspicious = int(stats.get("suspicious", 0))
    total = sum(int(v) for k, v in stats.items() if k != "timeout")

    if malicious >= 3:
        level = "high"
        summary = f"{malicious} of {total} security vendors flagged this link as malicious."
    elif malicious > 0 or suspicious > 0:
        level = "medium"
        summary = f"{malicious + suspicious} of {total} security vendors flagged this link. That can be a false alarm."
    else:
        level = "none"
        summary = f"None of {total} security vendors flagged this link. That does not prove it is safe."

    return {
        "status": "ok",
        "level": level,
        "summary": summary,
        "counts": {"malicious": malicious, "suspicious": suspicious, "total": total},
        "last_analysis_date": attrs.get("last_analysis_date"),
    }


def check_url(raw_url: str) -> dict:
    """Looks up an EXISTING VirusTotal report. It never submits the link, so nothing becomes public."""
    api_key = os.getenv("VT_API_KEY")
    if not api_key:
        return {"status": "not_configured", "level": "none",
                "summary": "The VirusTotal check is not set up on this server yet."}

    url = _normalize(raw_url)
    hit = _cache.get(url)
    if hit and time.time() - hit[0] < CACHE_SECONDS:
        return hit[1]

    # Some addresses are stored with a trailing slash when there is no path
    candidates = [url]
    if urlparse(url).path == "":
        candidates.append(url + "/")

    result = None
    for candidate in candidates:
        if not _allow_call():
            return {"status": "rate_limited", "level": "none",
                    "summary": "Too many checks right now. Please try again in a minute."}
        try:
            r = requests.get(
                f"{VT_BASE}/urls/{_url_id(candidate)}",
                headers={"x-apikey": api_key},
                timeout=10,
            )
        except requests.RequestException:
            return {"status": "error", "level": "none",
                    "summary": "Could not reach VirusTotal. Try again later."}

        if r.status_code == 404:
            continue
        if r.status_code == 429:
            return {"status": "rate_limited", "level": "none",
                    "summary": "VirusTotal is busy. Please try again in a minute."}
        if r.status_code in (401, 403):
            return {"status": "error", "level": "none",
                    "summary": "VirusTotal rejected the API key. Check the key in backend/.env."}
        if not r.ok:
            return {"status": "error", "level": "none",
                    "summary": f"VirusTotal returned an error ({r.status_code})."}

        result = _summarize(r.json().get("data", {}).get("attributes", {}))
        break

    if result is None:
        result = {"status": "unknown", "level": "none",
                  "summary": "VirusTotal has no report for this link yet. New scam links are often unknown, so this is not a sign of safety."}

    _cache[url] = (time.time(), result)
    return result