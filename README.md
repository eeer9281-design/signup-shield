# SaaS Signup Shield API — v0.5.0

Deterministic signup-fraud detection: disposable-domain blocking (3,000+ domains,
auto-refreshed every 24h), Gmail alias/dot canonicalization, role-account flagging,
and DNS MX verification via Cloudflare DoH — including RFC 7505 Null MX detection.

## Endpoints

| Method | Path         | Purpose                                             |
|--------|--------------|-----------------------------------------------------|
| GET    | `/health`    | Liveness + blocklist size (no auth)                 |
| GET    | `/v1/check?email=...` | Quick browser/curl testing                |
| POST   | `/v1/check`  | **Preferred.** JSON body `{"email": "..."}` — keeps PII out of URL/proxy logs |

When `RAPIDAPI_PROXY_SECRET` is set, both check endpoints require the
`X-RapidAPI-Proxy-Secret` header (compared with `hmac.compare_digest`).

## Verdicts

- **BLOCK** — disposable domain, NXDOMAIN, or RFC 7505 Null MX (`0 .`)
- **REVIEW** — role account, no MX records, or risk score ≥ 0.30
- **ALLOW** — everything else

## Run locally

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements-dev.txt
pytest -q                                   # 25 hermetic tests
RUN_LIVE_TESTS=1 pytest -q                  # + live DNS smoke test
uvicorn main:app --reload                   # http://127.0.0.1:8000/docs
```

## Deploy (Render free tier)

Build: `pip install -r requirements.txt`
Start: `uvicorn main:app --host 0.0.0.0 --port $PORT`
Health check path: `/health`
Python: pinned to 3.12 via `.python-version` (Render-native; Heroku-style
`runtime.txt` is ignored by Render, and Render's 3.14 default has no wheels
for the pinned pydantic).
Env: `RAPIDAPI_PROXY_SECRET` — **RapidAPI generates this value**: copy it from
Provider Studio → Hub Listing → Gateway tab → Firewall Settings, then paste it
into Render. `render.yaml` is included for Blueprint deploys.
Free tier spins down after 15 min idle — keep it warm with a cron-job.org ping
to `/health` every 10 minutes.
