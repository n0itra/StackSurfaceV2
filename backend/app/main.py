import asyncio
import json
import mimetypes
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

from fastapi import FastAPI, HTTPException, UploadFile, File, WebSocket, WebSocketDisconnect, Query
from fastapi.responses import FileResponse, PlainTextResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy import select, func, desc, text

from .config import settings
from .db import SessionLocal, init_db
from .models import (
    Target,
    TargetLink,
    Scan,
    ScanLink,
    ScanStage,
    Subdomain,
    WebService,
    OpenPort,
    Endpoint,
    Directory,
    Secret,
    Finding,
    Change,
    Wordlist,
    FFUFRuns,
    FFUFEvent,
    InfrastructureIP,
)
from .schemas import ScanCreate, ScanOut, FFUFCreate, FFUFOut, WordlistOut
from .queue import enqueue_scan, enqueue_ffuf
from .repository import get_or_create_target, attach_target_link, serialize_scan, scan_counts
from .utils import normalize_input, in_scope


app = FastAPI(title="StackSurface API", version="1.0.0")


# ---------------------------------------------------------------------------
# Frontend
# ---------------------------------------------------------------------------

FRONTEND = Path(__file__).resolve().parents[1] / "frontend"

if FRONTEND.exists():
    app.mount(
        "/assets",
        StaticFiles(directory=FRONTEND / "assets"),
        name="assets",
    )


@app.on_event("startup")
def startup():
    init_db()


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------

@app.get("/api/health")
def health():
    db_ok = False
    redis_ok = False

    try:
        with SessionLocal() as db:
            db.execute(select(func.now()))
            db_ok = True
    except Exception:
        pass

    try:
        from .queue import redis_client

        redis_ok = bool(redis_client.ping())
    except Exception:
        pass

    return {
        "status": "ok" if db_ok and redis_ok else "degraded",
        "database": db_ok,
        "redis": redis_ok,
    }


# ---------------------------------------------------------------------------
# Frontend root
# ---------------------------------------------------------------------------

@app.get("/")
def root():
    return FileResponse(FRONTEND / "index.html")


# ---------------------------------------------------------------------------
# Dashboard
# ---------------------------------------------------------------------------

@app.get("/api/dashboard")
def dashboard():
    with SessionLocal() as db:
        targets = db.scalar(select(func.count(Target.id))) or 0
        subdomains = db.scalar(select(func.count(Subdomain.id))) or 0
        alive = db.scalar(select(func.count(WebService.id))) or 0
        endpoints = db.scalar(select(func.count(Endpoint.id))) or 0
        findings = db.scalar(select(func.count(Finding.id))) or 0
        changes = db.scalar(select(func.count(Change.id))) or 0

        running = (
            db.scalar(
                select(func.count(Scan.id)).where(
                    Scan.status.in_(["running", "stopping"])
                )
            )
            or 0
        )

        queued = (
            db.scalar(
                select(func.count(Scan.id)).where(
                    Scan.status == "queued"
                )
            )
            or 0
        )

        recent_changes = db.scalars(
            select(Change, Scan, Target)
            .join(Scan, Change.scan_id == Scan.id)
            .join(Target, Scan.target_id == Target.id)
            .order_by(Change.id.desc())
            .limit(10)
        ).all()

        return {
            "targets": targets,
            "subdomains": subdomains,
            "alive": alive,
            "endpoints": endpoints,
            "findings": findings,
            "changes": changes,
            "running": running,
            "queued": queued,
            "recent_changes": [
                {
                    "type": c.change_type,
                    "asset": c.asset,
                    "target": t.canonical,
                    "current": c.current_value,
                }
                for c, _s, t in recent_changes
            ],
        }


# ---------------------------------------------------------------------------
# Create scan
# ---------------------------------------------------------------------------

@app.post("/api/scans", response_model=ScanOut)
def create_scan(payload: ScanCreate):
    scan_type = payload.scan_type.lower().strip()

    if scan_type not in {"full", "discovery", "web", "vuln"}:
        raise HTTPException(400, "Invalid scan type")

    parsed = []
    errors = []

    for item in payload.links:
        try:
            parsed.append((item, *normalize_input(item)))
        except ValueError as exc:
            errors.append(str(exc))

    if not parsed:
        raise HTTPException(
            400,
            {
                "message": "No valid target links",
                "errors": errors,
            },
        )

    canonical = parsed[0][1]

    mismatched = [p[0] for p in parsed if p[1] != canonical]

    if mismatched:
        raise HTTPException(
            400,
            {
                "message": "All links in one scan must belong to the same canonical target",
                "mismatched": mismatched,
                "canonical": canonical,
            },
        )

    with SessionLocal() as db:
        # PostgreSQL advisory lock makes the one-scan rule atomic
        # across API instances.
        db.execute(text("SELECT pg_advisory_xact_lock(771231)"))

        active = db.scalar(
            select(Scan)
            .where(
                Scan.status.in_(
                    ["queued", "running", "stopping"]
                )
            )
            .order_by(Scan.created_at.desc())
            .limit(1)
        )

        if active:
            raise HTTPException(
                status_code=409,
                detail={
                    "message": "A scan is already active",
                    "scan_id": active.id,
                    "target": active.target.canonical,
                    "status": active.status,
                },
            )

        target = get_or_create_target(db, canonical)

        links = []

        for raw, _host, normalized in parsed:
            link = attach_target_link(
                db,
                target,
                raw,
                normalized,
            )
            links.append(link)

        scan = Scan(
            target_id=target.id,
            scan_type=scan_type,
            status="queued",
        )

        db.add(scan)
        db.flush()

        for link in links:
            db.add(
                ScanLink(
                    scan_id=scan.id,
                    target_link_id=link.id,
                )
            )

        db.commit()

        try:
            enqueue_scan(scan.id)

        except Exception as exc:
            with SessionLocal() as rollback_db:
                broken = rollback_db.get(Scan, scan.id)

                if broken:
                    broken.status = "failed"
                    broken.error = f"Queue unavailable: {exc}"
                    broken.finished_at = datetime.now(timezone.utc)
                    rollback_db.commit()

            raise HTTPException(
                503,
                "Unable to enqueue scan",
            )

        return serialize_scan(scan)


# ---------------------------------------------------------------------------
# Scans
# ---------------------------------------------------------------------------

@app.get("/api/scans")
def list_scans(limit: int = Query(100, ge=1, le=500)):
    with SessionLocal() as db:
        rows = db.scalars(
            select(Scan)
            .order_by(Scan.created_at.desc())
            .limit(limit)
        ).all()

        return [serialize_scan(x) for x in rows]


@app.get("/api/scans/{scan_id}")
def scan_detail(scan_id: str):
    with SessionLocal() as db:
        scan = db.get(Scan, scan_id)

        if not scan:
            raise HTTPException(404, "Scan not found")

        stages = db.scalars(
            select(ScanStage)
            .where(ScanStage.scan_id == scan_id)
            .order_by(ScanStage.position)
        ).all()

        return {
            **serialize_scan(scan),

            "links": [
                db.get(
                    TargetLink,
                    link.target_link_id,
                ).normalized_url
                for link in scan.links
            ],

            "counts": scan_counts(
                db,
                scan_id,
            ),

            "stages": [
                {
                    "name": s.name,
                    "status": s.status,
                    "progress": s.progress,
                    "error": s.error,
                    "started_at": s.started_at,
                    "finished_at": s.finished_at,
                }
                for s in stages
            ],
        }


# ---------------------------------------------------------------------------
# Stop scan
# ---------------------------------------------------------------------------

@app.post("/api/scans/{scan_id}/stop")
def stop_scan(scan_id: str):
    from .queue import publish_stop

    with SessionLocal() as db:
        scan = db.get(Scan, scan_id)

        if not scan:
            raise HTTPException(
                404,
                "Scan not found",
            )

        if scan.status in {
            "completed",
            "completed_with_warnings",
            "failed",
            "cancelled",
        }:
            raise HTTPException(
                409,
                "Scan is already finished",
            )

        scan.cancel_requested = True
        scan.status = "stopping"

        db.commit()

    publish_stop(scan_id)

    return {
        "ok": True,
        "status": "stopping",
        "scan_id": scan_id,
    }


@app.post("/api/scans/{scan_id}/cancel")
def cancel_scan(scan_id: str):
    return stop_scan(scan_id)


# ---------------------------------------------------------------------------
# Scan event stream
# ---------------------------------------------------------------------------

@app.get("/api/scans/{scan_id}/stream")
async def scan_stream(scan_id: str):

    async def generator():
        last = None

        while True:
            with SessionLocal() as db:
                scan = db.get(
                    Scan,
                    scan_id,
                )

                if not scan:
                    yield "event: error\ndata: {}\n\n"
                    return

                payload = json.dumps(
                    {
                        "id": scan.id,
                        "status": scan.status,
                        "progress": scan.progress,
                        "stage": scan.current_stage,
                        "error": scan.error,
                    },
                    default=str,
                )

                if payload != last:
                    yield f"data: {payload}\n\n"
                    last = payload

                if scan.status in {
                    "completed",
                    "completed_with_warnings",
                    "failed",
                    "cancelled",
                }:
                    return

            await asyncio.sleep(1)

    return StreamingResponse(
        generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )


# ---------------------------------------------------------------------------
# Resource map
# ---------------------------------------------------------------------------

RESOURCE_MAP = {
    "subdomains": (
        Subdomain,
        ["fqdn"],
    ),

    "alive": (
        WebService,
        [
            "url",
            "status_code",
            "title",
            "ip",
            "technologies",
            "waf_name",
        ],
    ),

    "ips": (
        InfrastructureIP,
        [
            "ip",
            "hostnames",
            "cdn",
            "cdn_name",
            "waf_name",
        ],
    ),

    "ports": (
        OpenPort,
        [
            "ip",
            "port",
            "protocol",
            "service",
            "version",
            "source",
        ],
    ),

    "endpoints": (
        Endpoint,
        [
            "url",
            "source",
            "status_code",
            "method",
            "kind",
        ],
    ),

    "directories": (
        Directory,
        [
            "url",
            "status_code",
            "words",
            "lines",
            "size",
        ],
    ),

    "secrets": (
        Secret,
        [
            "source",
            "kind",
            "location",
            "value_masked",
            "severity",
            "verified",
        ],
    ),

    "findings": (
        Finding,
        [
            "name",
            "tool",
            "severity",
            "target",
            "status",
        ],
    ),

    "bugs": (
        Finding,
        [
            "name",
            "tool",
            "severity",
            "target",
            "status",
        ],
    ),

    "technologies": (
        WebService,
        [
            "url",
            "technologies",
        ],
    ),

    "waf": (
        WebService,
        [
            "url",
            "waf_name",
        ],
    ),

    "changes": (
        Change,
        [
            "change_type",
            "asset",
            "previous_value",
            "current_value",
        ],
    ),
}


def model_to_dict(obj, fields):
    return {
        f: getattr(obj, f)
        for f in fields
    }


# ---------------------------------------------------------------------------
# Scan resources
# ---------------------------------------------------------------------------

@app.get("/api/scans/{scan_id}/{resource}")
def resource_list(scan_id: str, resource: str):
    if resource not in RESOURCE_MAP:
        raise HTTPException(
            404,
            "Unknown resource",
        )

    model, fields = RESOURCE_MAP[resource]

    with SessionLocal() as db:
        if not db.get(
            Scan,
            scan_id,
        ):
            raise HTTPException(
                404,
                "Scan not found",
            )

        rows = db.scalars(
            select(model)
            .where(
                getattr(model, "scan_id") == scan_id
            )
            .order_by(model.id)
        ).all()

        return [
            model_to_dict(x, fields)
            for x in rows
        ]


# ---------------------------------------------------------------------------
# Export resources
# ---------------------------------------------------------------------------

@app.get("/api/scans/{scan_id}/export/{resource}.{fmt}")
def export_resource(
    scan_id: str,
    resource: str,
    fmt: str,
):
    if resource not in RESOURCE_MAP or fmt not in {
        "json",
        "txt",
    }:
        raise HTTPException(
            404,
            "Unknown export",
        )

    model, fields = RESOURCE_MAP[resource]

    with SessionLocal() as db:
        rows = db.scalars(
            select(model)
            .where(
                getattr(model, "scan_id") == scan_id
            )
            .order_by(model.id)
        ).all()

        data = [
            model_to_dict(x, fields)
            for x in rows
        ]

    if fmt == "json":
        return StreamingResponse(
            iter(
                [
                    json.dumps(
                        data,
                        default=str,
                        indent=2,
                    )
                ]
            ),
            media_type="application/json",
            headers={
                "Content-Disposition":
                    f'attachment; filename="{resource}.json"'
            },
        )

    lines = []

    for row in data:
        values = [
            str(row.get(f, ""))
            for f in fields
        ]
        lines.append(
            "\t".join(values)
        )

    return PlainTextResponse(
        "\n".join(lines),
        headers={
            "Content-Disposition":
                f'attachment; filename="{resource}.txt"'
        },
    )


# ---------------------------------------------------------------------------
# Wordlists
# ---------------------------------------------------------------------------

@app.get(
    "/api/wordlists",
    response_model=list[WordlistOut],
)
def list_wordlists():
    with SessionLocal() as db:
        rows = db.scalars(
            select(Wordlist)
            .order_by(Wordlist.name)
        ).all()

        custom = [
            WordlistOut.model_validate(x)
            for x in rows
        ]

    # Built-in SecLists are read-only tool assets,
    # not scan artifacts.
    seclists = Path("/opt/seclists")
    builtin = []

    if seclists.exists():
        for p in sorted(
            seclists.rglob("*.txt")
        ):
            rel = p.relative_to(
                seclists
            ).as_posix()

            pseudo_id = (
                f"builtin:{rel}"
            )

            builtin.append(
                {
                    "id": pseudo_id,
                    "name": f"SecLists / {rel}",
                    "source": "seclists",
                }
            )

    return custom + builtin


@app.post(
    "/api/wordlists/custom",
    response_model=WordlistOut,
)
async def upload_wordlist(
    file: UploadFile = File(...),
):
    content = await file.read()

    if len(content) > 50 * 1024 * 1024:
        raise HTTPException(
            413,
            "Wordlist too large (max 50 MB)",
        )

    with SessionLocal() as db:
        row = Wordlist(
            name=file.filename or "custom.txt",
            source="custom",
            content=content,
        )

        db.add(row)
        db.commit()
        db.refresh(row)

        return WordlistOut.model_validate(
            row
        )


# ---------------------------------------------------------------------------
# FFUF
# ---------------------------------------------------------------------------

@app.post(
    "/api/ffuf-runs",
    response_model=FFUFOut,
)
def create_ffuf_run(
    payload: FFUFCreate,
):
    with SessionLocal() as db:
        scan = db.get(
            Scan,
            payload.scan_id,
        )

        if not scan:
            raise HTTPException(
                404,
                "Scan not found",
            )

        if scan.status not in {
            "completed",
            "completed_with_warnings",
        }:
            raise HTTPException(
                409,
                "FFUF is available after the scan finishes",
            )

        host = (
            urlparse(
                payload.url
            ).hostname
            or ""
        ).lower()

        if not in_scope(
            host,
            scan.target.canonical,
        ):
            raise HTTPException(
                400,
                "FFUF target is outside the scan target",
            )

        if payload.subdomain:
            sub = db.scalar(
                select(Subdomain).where(
                    Subdomain.scan_id == payload.scan_id,
                    Subdomain.fqdn == payload.subdomain,
                )
            )

            if not sub:
                raise HTTPException(
                    400,
                    "Selected subdomain is not part of this scan",
                )

        mode = payload.mode.lower().strip()

        if mode not in {
            "path",
            "parameter",
            "header",
            "body",
        }:
            raise HTTPException(
                400,
                "Invalid FFUF mode",
            )

        if (
            mode in {"path", "parameter"}
            and "FUZZ" not in payload.url
        ):
            raise HTTPException(
                400,
                "URL must contain FUZZ for path/parameter mode",
            )

        if (
            mode == "header"
            and not any(
                "FUZZ" in str(v)
                for v in payload.headers.values()
            )
        ):
            raise HTTPException(
                400,
                "At least one header value must contain FUZZ",
            )

        if (
            mode == "body"
            and (
                not payload.body
                or "FUZZ" not in payload.body
            )
        ):
            raise HTTPException(
                400,
                "Body must contain FUZZ",
            )

        wordlist_id = payload.wordlist_id

        if wordlist_id.startswith(
            "builtin:"
        ):
            name = wordlist_id.removeprefix(
                "builtin:"
            )

            path = (
                Path("/opt/seclists")
                / name
            )

            if (
                not path.exists()
                or not path.is_file()
            ):
                raise HTTPException(
                    404,
                    "Built-in wordlist not found",
                )

            row = db.scalar(
                select(Wordlist).where(
                    Wordlist.name
                    == f"SecLists / {name}",
                    Wordlist.source
                    == "seclists",
                )
            )

            if not row:
                row = Wordlist(
                    name=f"SecLists / {name}",
                    source="seclists",
                    content=path.read_bytes(),
                )

                db.add(row)
                db.flush()

            wordlist_id = row.id

        if not db.get(
            Wordlist,
            wordlist_id,
        ):
            raise HTTPException(
                404,
                "Wordlist not found",
            )

        config = payload.model_dump()
        config["wordlist_id"] = wordlist_id

        run = FFUFRuns(
            scan_id=payload.scan_id,
            subdomain=payload.subdomain,
            url=payload.url,
            config=config,
        )

        db.add(run)
        db.commit()
        db.refresh(run)

        enqueue_ffuf(run.id)

        return FFUFOut.model_validate(
            run
        )


@app.get(
    "/api/ffuf-runs/{run_id}",
    response_model=FFUFOut,
)
def get_ffuf_run(
    run_id: str,
):
    with SessionLocal() as db:
        run = db.get(
            FFUFRuns,
            run_id,
        )

        if not run:
            raise HTTPException(
                404,
                "FFUF run not found",
            )

        return FFUFOut.model_validate(
            run
        )


@app.get(
    "/api/ffuf-runs/{run_id}/stream"
)
async def ffuf_stream(
    run_id: str,
):

    async def generator():
        last_count = 0

        while True:
            with SessionLocal() as db:
                run = db.get(
                    FFUFRuns,
                    run_id,
                )

                if not run:
                    return

                events = db.scalars(
                    select(FFUFEvent)
                    .where(
                        FFUFEvent.ffuf_run_id == run_id,
                        FFUFEvent.seq > last_count,
                    )
                    .order_by(FFUFEvent.seq)
                ).all()

                for event in events:
                    yield (
                        f"data: "
                        f"{json.dumps({'seq': event.seq, 'line': event.line})}"
                        "\n\n"
                    )

                    last_count = event.seq

                if run.status in {
                    "completed",
                    "failed",
                }:
                    yield (
                        "event: done\n"
                        f"data: {json.dumps({'status': run.status, 'error': run.error})}"
                        "\n\n"
                    )
                    return

            await asyncio.sleep(0.5)

    return StreamingResponse(
        generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )


# ---------------------------------------------------------------------------
# WebSocket
# ---------------------------------------------------------------------------

@app.websocket("/ws/scans/{scan_id}")
async def scan_ws(
    websocket: WebSocket,
    scan_id: str,
):
    await websocket.accept()

    try:
        while True:
            with SessionLocal() as db:
                scan = db.get(
                    Scan,
                    scan_id,
                )

                if not scan:
                    await websocket.send_json(
                        {"error": "not found"}
                    )
                    return

                await websocket.send_json(
                    {
                        "status": scan.status,
                        "progress": scan.progress,
                        "stage": scan.current_stage,
                    }
                )

                if scan.status in {
                    "completed",
                    "completed_with_warnings",
                    "failed",
                    "cancelled",
                }:
                    return

            await asyncio.sleep(1)

    except WebSocketDisconnect:
        return