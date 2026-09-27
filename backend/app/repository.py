from __future__ import annotations
from datetime import datetime, timezone
from sqlalchemy import select, func
from sqlalchemy.orm import Session
from .models import Target, TargetLink, Scan, ScanLink, ScanStage, Subdomain, WebService, OpenPort, Endpoint, Directory, Secret, Finding, Change, FFUFRuns, Wordlist, InfrastructureIP


def get_or_create_target(db: Session, canonical: str) -> Target:
    target = db.scalar(select(Target).where(Target.canonical == canonical))
    if target:
        return target
    target = Target(canonical=canonical)
    db.add(target)
    db.flush()
    return target


def attach_target_link(db: Session, target: Target, raw: str, normalized: str) -> TargetLink:
    link = db.scalar(select(TargetLink).where(TargetLink.target_id == target.id, TargetLink.normalized_url == normalized))
    if link:
        return link
    link = TargetLink(target_id=target.id, raw_input=raw, normalized_url=normalized)
    db.add(link)
    db.flush()
    return link


def previous_completed_scan(db: Session, scan: Scan) -> Scan | None:
    terminal_statuses = [
        "completed",
        "completed_with_warnings",
    ]

    return db.scalar(
        select(Scan)
        .where(
            Scan.target_id == scan.target_id,
            Scan.id != scan.id,
            Scan.status.in_(terminal_statuses),
        )
        .order_by(
            Scan.finished_at.desc().nullslast(),
            Scan.created_at.desc(),
        )
        .limit(1)
    )


def scan_counts(db: Session, scan_id: str) -> dict:
    return {
        "subdomains": db.scalar(select(func.count(Subdomain.id)).where(Subdomain.scan_id == scan_id)) or 0,
        "alive": db.scalar(select(func.count(WebService.id)).where(WebService.scan_id == scan_id)) or 0,
        "ips": db.scalar(select(func.count(InfrastructureIP.id)).where(InfrastructureIP.scan_id == scan_id)) or 0,
        "ports": db.scalar(select(func.count(OpenPort.id)).where(OpenPort.scan_id == scan_id)) or 0,
        "endpoints": db.scalar(select(func.count(Endpoint.id)).where(Endpoint.scan_id == scan_id)) or 0,
        "directories": db.scalar(select(func.count(Directory.id)).where(Directory.scan_id == scan_id)) or 0,
        "secrets": db.scalar(select(func.count(Secret.id)).where(Secret.scan_id == scan_id)) or 0,
        "findings": db.scalar(select(func.count(Finding.id)).where(Finding.scan_id == scan_id)) or 0,
        "changes": db.scalar(select(func.count(Change.id)).where(Change.scan_id == scan_id)) or 0,
    }


def serialize_scan(scan: Scan) -> dict:
    return {
        "id": scan.id,
        "target": scan.target.canonical,
        "scan_type": scan.scan_type,
        "status": scan.status,
        "current_stage": scan.current_stage,
        "progress": scan.progress,
        "created_at": scan.created_at,
        "started_at": scan.started_at,
        "finished_at": scan.finished_at,
        "error": scan.error,
    }
