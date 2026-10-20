from __future__ import annotations

import hmac
import logging
import os
import re
import threading
import time
from pathlib import Path
from threading import Lock
from typing import Literal

import requests
from cachetools import TTLCache
from fastapi import FastAPI, Header, HTTPException, Query
from pydantic import BaseModel, Field

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("signup-shield")

APP_VERSION = "0.5.0"
RAPIDAPI_PROXY_SECRET = os.getenv("RAPIDAPI_PROXY_SECRET")
BLOCKLIST_PATH = Path(os.getenv("DISPOSABLE_DOMAINS_FILE", "disposable_domains.txt"))
REMOTE_BLOCKLIST_URL = "https://raw.githubusercontent.com/disposable-email-domains/disposable-email-domains/master/disposable_email_blocklist.conf"

STARTER_DISPOSABLE_DOMAINS = {
    "10minutemail.com", "guerrillamail.com", "guerrillamail.net",
    "mailinator.com", "tempmail.com", "temp-mail.org", "yopmail.com",
    "getnada.com", "throwawaymail.com", "trashmail.com", "fakeinbox.com",
    "sharklasers.com", "dispostable.com"
}

PLUS_ADDRESSING_PROVIDERS = {
    "gmail.com", "googlemail.com", "outlook.com", "hotmail.com",
    "live.com", "icloud.com", "me.com", "proton.me", "protonmail.com", "fastmail.com"
}

ROLE_BASED_PREFIXES = {
    "admin", "administrator", "billing", "compliance", "contact",
    "devnull", "finance", "help", "info", "infrastructure", "jobs",
    "legal", "marketing", "media", "no-reply", "noreply", "postmaster",
    "privacy", "root", "sales", "security", "support", "sysadmin", "team"
}

EMAIL_RE = re.compile(r"^[^\s@<>]+@[^\s@<>]+\.[^\s@<>]+$")

_mx_cache = TTLCache(maxsize=10_000, ttl=3600)
_mx_lock = Lock()
_disposable_lock = Lock()
DISPOSABLE_DOMAINS = set(STARTER_DISPOSABLE_DOMAINS)


def fetch_blocklist() -> set[str]:
    domains = set(STARTER_DISPOSABLE_DOMAINS)
    try:
        res = requests.get(REMOTE_BLOCKLIST_URL, timeout=4.0)
        if res.status_code == 200:
            for line in res.text.splitlines():
                d = line.strip().lower().rstrip(".")
                if d and not d.startswith("#"):
                    domains.add(d.lstrip("."))
            logger.info(f"Loaded {len(domains)} disposable domains.")
            return domains
    except Exception as e:
        logger.warning(f"Remote blocklist fetch failed ({e}). Checking local file.")

    if BLOCKLIST_PATH.exists():
        for line in BLOCKLIST_PATH.read_text(encoding="utf-8").splitlines():
            d = line.strip().lower().rstrip(".")
            if d and not d.startswith("#"):
                domains.add(d.lstrip("."))
    return domains


def background_blocklist_refresher():
    """Refreshes the blocklist every 24 hours in the background."""
    global DISPOSABLE_DOMAINS
    while True:
        time.sleep(86400)
        new_domains = fetch_blocklist()
        with _disposable_lock:
            DISPOSABLE_DOMAINS = new_domains


# Initial load & start background worker
DISPOSABLE_DOMAINS = fetch_blocklist()
threading.Thread(target=background_blocklist_refresher, daemon=True).start()

app = FastAPI(
    title="SaaS Signup Shield API",
    version=APP_VERSION,
    description="Deterministic API for disposable email detection, alias canonicalization, and role account checks.",
)


class CheckRequest(BaseModel):
    email: str = Field(..., min_length=3, max_length=320, description="Email to evaluate")


class CheckResponse(BaseModel):
    email: str
    canonical_email: str
    domain: str
    is_disposable: bool
    is_role_account: bool
    has_alias_trick: bool
    has_mx_records: bool | None = Field(
        description="True if MX records exist, False if NXDOMAIN/No-MX/Null-MX, null if inconclusive or skipped."
    )
    dns_status: Literal["HAS_MX", "NO_MX", "NULL_MX", "NXDOMAIN", "INCONCLUSIVE", "SKIPPED"]
    risk_score: float = Field(ge=0.0, le=1.0)
    verdict: Literal["ALLOW", "REVIEW", "BLOCK"]
    reasons: list[str]


def is_disposable_domain(domain: str) -> bool:
    clean = domain.rstrip(".")
    parts = clean.split(".")
    with _disposable_lock:
        for i in range(len(parts) - 1):
            candidate = ".".join(parts[i:])
            if candidate in DISPOSABLE_DOMAINS:
                return True
    return False


def _resolve_mx_doh(domain: str) -> Literal["HAS_MX", "NO_MX", "NULL_MX", "NXDOMAIN", "INCONCLUSIVE"]:
    try:
        res = requests.get(
            "https://cloudflare-dns.com/dns-query",
            params={"name": domain, "type": "MX"},
            headers={"Accept": "application/dns-json"},
            timeout=2.0,
        )
        if res.status_code != 200:
            return "INCONCLUSIVE"
        data = res.json()
    except Exception:
        return "INCONCLUSIVE"

    status = data.get("Status")
    if status == 3:
        return "NXDOMAIN"
    if status != 0:
        return "INCONCLUSIVE"

    answers = [ans for ans in data.get("Answer", []) if ans.get("type") == 15]
    if not answers:
        return "NO_MX"

    # RFC 7505: "0 ." explicitly declares the domain refuses all email
    if len(answers) == 1 and answers[0].get("data", "").strip().endswith("."):
        data_field = answers[0].get("data", "").strip()
        if data_field in ("0 .", "0."):
            return "NULL_MX"

    return "HAS_MX"


def get_mx_status(domain: str) -> Literal["HAS_MX", "NO_MX", "NULL_MX", "NXDOMAIN", "INCONCLUSIVE"]:
    with _mx_lock:
        if domain in _mx_cache:
            return _mx_cache[domain]

    result = _resolve_mx_doh(domain)
    if result in ("HAS_MX", "NO_MX", "NULL_MX", "NXDOMAIN"):
        with _mx_lock:
            _mx_cache[domain] = result
    return result


def canonicalize_email(local_part: str, domain: str) -> tuple[str, str, bool]:
    clean_domain = domain.lower().strip().rstrip(".")
    clean_local = local_part.lower().strip()
    had_alias = False

    if clean_domain == "googlemail.com":
        clean_domain = "gmail.com"

    if clean_domain in PLUS_ADDRESSING_PROVIDERS and "+" in clean_local:
        prefix = clean_local.split("+")[0]
        if prefix:
            clean_local = prefix
            had_alias = True

    if clean_domain == "gmail.com" and "." in clean_local:
        clean_local = clean_local.replace(".", "")
        had_alias = True

    return clean_local, clean_domain, had_alias


def evaluate_email(raw_email: str) -> CheckResponse:
    raw_email = raw_email.strip()
    if not EMAIL_RE.fullmatch(raw_email):
        raise HTTPException(status_code=422, detail="Invalid email syntax.")

    local_part, domain = raw_email.rsplit("@", 1)
    canonical_local, canonical_domain, had_alias = canonicalize_email(local_part, domain)
    if not canonical_local:
        # e.g. ".@gmail.com" -> dot-stripping leaves an empty local part
        raise HTTPException(status_code=422, detail="Invalid email syntax.")
    canonical_email = f"{canonical_local}@{canonical_domain}"

    is_disposable = is_disposable_domain(canonical_domain)
    is_role = canonical_local in ROLE_BASED_PREFIXES

    if is_disposable:
        dns_state = "SKIPPED"
        has_mx = None
    else:
        dns_state = get_mx_status(canonical_domain)
        has_mx = True if dns_state == "HAS_MX" else (False if dns_state in ("NO_MX", "NULL_MX", "NXDOMAIN") else None)

    reasons: list[str] = []
    score = 0.0

    if is_disposable:
        reasons.append("disposable_domain")
        score += 0.85

    if dns_state == "NXDOMAIN":
        reasons.append("domain_does_not_exist_nxdomain")
        score += 0.60
    elif dns_state == "NULL_MX":
        reasons.append("rfc7505_null_mx_refuses_email")
        score += 0.60
    elif dns_state == "NO_MX":
        reasons.append("no_explicit_mx_records_fallback_possible")
        score += 0.20
    elif dns_state == "INCONCLUSIVE":
        reasons.append("dns_lookup_inconclusive")

    if is_role:
        reasons.append("role_based_account")
        score += 0.15

    if had_alias:
        reasons.append("alias_or_subaddressing_used")
        score += 0.05

    score = round(min(score, 1.0), 2)

    if is_disposable or dns_state in ("NXDOMAIN", "NULL_MX"):
        verdict: Literal["ALLOW", "REVIEW", "BLOCK"] = "BLOCK"
    elif is_role or dns_state == "NO_MX" or score >= 0.30:
        verdict = "REVIEW"
    else:
        verdict = "ALLOW"

    return CheckResponse(
        email=raw_email,
        canonical_email=canonical_email,
        domain=canonical_domain,
        is_disposable=is_disposable,
        is_role_account=is_role,
        has_alias_trick=had_alias,
        has_mx_records=has_mx,
        dns_status=dns_state,
        risk_score=score,
        verdict=verdict,
        reasons=reasons,
    )


def verify_proxy_secret(x_rapidapi_proxy_secret: str | None):
    if RAPIDAPI_PROXY_SECRET:
        # Compare as bytes: str compare_digest raises TypeError on non-ASCII
        # headers (attacker-triggerable 500). Bytes comparison never raises.
        provided = (x_rapidapi_proxy_secret or "").encode("utf-8", errors="replace")
        if not hmac.compare_digest(provided, RAPIDAPI_PROXY_SECRET.encode("utf-8")):
            raise HTTPException(status_code=403, detail="Unauthorized proxy request.")


@app.get("/health")
def health() -> dict[str, str | int]:
    with _disposable_lock:
        count = len(DISPOSABLE_DOMAINS)
    return {"status": "ok", "version": APP_VERSION, "disposable_domains_loaded": count}


@app.get("/v1/check", response_model=CheckResponse)
def check_email_get(
    email: str = Query(..., min_length=3, max_length=320, description="Email to evaluate"),
    x_rapidapi_proxy_secret: str | None = Header(None, alias="X-RapidAPI-Proxy-Secret"),
) -> CheckResponse:
    verify_proxy_secret(x_rapidapi_proxy_secret)
    return evaluate_email(email)


@app.post("/v1/check", response_model=CheckResponse)
def check_email_post(
    body: CheckRequest,
    x_rapidapi_proxy_secret: str | None = Header(None, alias="X-RapidAPI-Proxy-Secret"),
) -> CheckResponse:
    verify_proxy_secret(x_rapidapi_proxy_secret)
    return evaluate_email(body.email)
