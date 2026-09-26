# StackSurface

StackSurface is a local Dockerized reconnaissance/PTaaS platform using FastAPI, PostgreSQL, Redis, and one scan worker (one active scan at a time).

## Architecture

- `api`: REST API + frontend
- `postgres`: persistent source of truth
- `redis`: job queue
- `worker`: single scan executor

## Scan profiles

- `Full Recon`: passive discovery → AlterX → DNSx → HTTPx (200/401/403/404 only) → CDN → Shodan on non-CDN IPs → GAU/Katana → technology/WAF → Nuclei → JS/secrets → changes.
- `Discovery`: discovery → AlterX → DNSx → HTTPx → changes.
- `Web Surface`: HTTPx → GAU/Katana → technology/WAF → endpoint analysis → JS analysis → changes.
- `Vulnerability Focus`: Nuclei + JS/secret analysis using the latest existing web assets for the target.

## Storage rule

Persistent scan data goes into PostgreSQL. Tool inputs that require files are materialized only in temporary directories and removed after the tool exits. Custom FFUF wordlists are stored in PostgreSQL. SecLists is a read-only worker image resource and selected lists are snapshotted into PostgreSQL when used.

## Run

```bash
cp .env.example .env
# put your Shodan key and other values in .env

docker compose build
docker compose up -d
```

Open `http://localhost:8000`.

## Tests

The checked-in test suite validates target normalization, the single-scan/stop contract, HTTP status filtering, CDN→Shodan data flow, frontend/backend contract consistency, and Python compilation. Full runtime/container validation requires a host with Docker Engine; this build environment does not provide Docker or external package-network access.
