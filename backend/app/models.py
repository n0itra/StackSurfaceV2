from __future__ import annotations

from datetime import datetime, timezone
from uuid import uuid4

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, LargeBinary, String, Text, UniqueConstraint, Index
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .db import Base


def now() -> datetime:
    return datetime.now(timezone.utc)


class Target(Base):
    __tablename__ = "targets"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    canonical: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now, onupdate=now)

    links: Mapped[list[TargetLink]] = relationship(back_populates="target", cascade="all, delete-orphan")
    scans: Mapped[list[Scan]] = relationship(back_populates="target", cascade="all, delete-orphan")


class TargetLink(Base):
    __tablename__ = "target_links"
    __table_args__ = (UniqueConstraint("target_id", "normalized_url", name="uq_target_link"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    target_id: Mapped[str] = mapped_column(ForeignKey("targets.id", ondelete="CASCADE"), index=True)
    raw_input: Mapped[str] = mapped_column(Text)
    normalized_url: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)

    target: Mapped[Target] = relationship(back_populates="links")


class Scan(Base):
    __tablename__ = "scans"
    __table_args__ = (Index("ix_scans_target_created", "target_id", "created_at"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    target_id: Mapped[str] = mapped_column(ForeignKey("targets.id", ondelete="CASCADE"), index=True)
    scan_type: Mapped[str] = mapped_column(String(40))
    status: Mapped[str] = mapped_column(String(40), default="queued", index=True)
    current_stage: Mapped[str | None] = mapped_column(String(80), nullable=True)
    progress: Mapped[int] = mapped_column(Integer, default=0)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    cancel_requested: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    target: Mapped[Target] = relationship(back_populates="scans")
    links: Mapped[list[ScanLink]] = relationship(back_populates="scan", cascade="all, delete-orphan")
    stages: Mapped[list[ScanStage]] = relationship(back_populates="scan", cascade="all, delete-orphan")
    tool_runs: Mapped[list[ToolRun]] = relationship(back_populates="scan", cascade="all, delete-orphan")
    subdomains: Mapped[list[Subdomain]] = relationship(back_populates="scan", cascade="all, delete-orphan")
    web_services: Mapped[list[WebService]] = relationship(back_populates="scan", cascade="all, delete-orphan")
    ports: Mapped[list[OpenPort]] = relationship(back_populates="scan", cascade="all, delete-orphan")
    infrastructure_ips: Mapped[list[InfrastructureIP]] = relationship(back_populates="scan", cascade="all, delete-orphan")
    endpoints: Mapped[list[Endpoint]] = relationship(back_populates="scan", cascade="all, delete-orphan")
    directories: Mapped[list[Directory]] = relationship(back_populates="scan", cascade="all, delete-orphan")
    secrets: Mapped[list[Secret]] = relationship(back_populates="scan", cascade="all, delete-orphan")
    findings: Mapped[list[Finding]] = relationship(back_populates="scan", cascade="all, delete-orphan")
    changes: Mapped[list[Change]] = relationship(back_populates="scan", cascade="all, delete-orphan")
    ffuf_runs: Mapped[list[FFUFRuns]] = relationship(back_populates="scan", cascade="all, delete-orphan")


class ScanLink(Base):
    __tablename__ = "scan_links"
    __table_args__ = (UniqueConstraint("scan_id", "target_link_id", name="uq_scan_link"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    scan_id: Mapped[str] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"))
    target_link_id: Mapped[str] = mapped_column(ForeignKey("target_links.id", ondelete="CASCADE"))

    scan: Mapped[Scan] = relationship(back_populates="links")


class ScanStage(Base):
    __tablename__ = "scan_stages"
    __table_args__ = (UniqueConstraint("scan_id", "name", name="uq_scan_stage"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    scan_id: Mapped[str] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), index=True)
    name: Mapped[str] = mapped_column(String(80))
    position: Mapped[int] = mapped_column(Integer)
    status: Mapped[str] = mapped_column(String(30), default="pending")
    progress: Mapped[int] = mapped_column(Integer, default=0)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)

    scan: Mapped[Scan] = relationship(back_populates="stages")


class ToolRun(Base):
    __tablename__ = "tool_runs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    scan_id: Mapped[str] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), index=True)
    tool: Mapped[str] = mapped_column(String(80))
    stage: Mapped[str] = mapped_column(String(80))
    status: Mapped[str] = mapped_column(String(30), default="running")
    exit_code: Mapped[int | None] = mapped_column(Integer, nullable=True)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    stdout: Mapped[str | None] = mapped_column(Text, nullable=True)
    stderr: Mapped[str | None] = mapped_column(Text, nullable=True)

    scan: Mapped[Scan] = relationship(back_populates="tool_runs")


class Subdomain(Base):
    __tablename__ = "subdomains"
    __table_args__ = (UniqueConstraint("scan_id", "fqdn", name="uq_scan_subdomain"), Index("ix_subdomains_scan_fqdn", "scan_id", "fqdn"))

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    scan_id: Mapped[str] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), index=True)
    fqdn: Mapped[str] = mapped_column(String(255))
    sources: Mapped[list[str]] = mapped_column(JSONB, default=list)
    is_new: Mapped[bool] = mapped_column(Boolean, default=False)

    scan: Mapped[Scan] = relationship(back_populates="subdomains")
    web_services: Mapped[list[WebService]] = relationship(back_populates="subdomain", cascade="all, delete-orphan")


class WebService(Base):
    __tablename__ = "web_services"
    __table_args__ = (UniqueConstraint("scan_id", "url", name="uq_scan_web_url"), Index("ix_web_services_scan_status", "scan_id", "status_code"))

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    scan_id: Mapped[str] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), index=True)
    subdomain_id: Mapped[str | None] = mapped_column(ForeignKey("subdomains.id", ondelete="SET NULL"), nullable=True, index=True)
    url: Mapped[str] = mapped_column(Text)
    status_code: Mapped[int | None] = mapped_column(Integer, nullable=True)
    title: Mapped[str | None] = mapped_column(Text, nullable=True)
    ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    technologies: Mapped[list[str]] = mapped_column(JSONB, default=list)
    cdn: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    cdn_name: Mapped[str | None] = mapped_column(String(120), nullable=True)
    waf_name: Mapped[str | None] = mapped_column(String(120), nullable=True)
    response_time_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)
    raw: Mapped[dict] = mapped_column(JSONB, default=dict)

    scan: Mapped[Scan] = relationship(back_populates="web_services")
    subdomain: Mapped[Subdomain | None] = relationship(back_populates="web_services")


class InfrastructureIP(Base):
    __tablename__ = "infrastructure_ips"
    __table_args__ = (UniqueConstraint("scan_id", "ip", name="uq_scan_infrastructure_ip"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    scan_id: Mapped[str] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), index=True)
    ip: Mapped[str] = mapped_column(String(64))
    hostnames: Mapped[list[str]] = mapped_column(JSONB, default=list)
    cdn: Mapped[bool] = mapped_column(Boolean, default=False)
    cdn_name: Mapped[str | None] = mapped_column(String(120), nullable=True)
    waf_name: Mapped[str | None] = mapped_column(String(120), nullable=True)

    scan: Mapped[Scan] = relationship(back_populates="infrastructure_ips")


class OpenPort(Base):
    __tablename__ = "open_ports"
    __table_args__ = (UniqueConstraint("scan_id", "ip", "port", "protocol", name="uq_scan_port"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    scan_id: Mapped[str] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), index=True)
    ip: Mapped[str] = mapped_column(String(64))
    port: Mapped[int] = mapped_column(Integer)
    protocol: Mapped[str | None] = mapped_column(String(20), nullable=True)
    service: Mapped[str | None] = mapped_column(String(120), nullable=True)
    version: Mapped[str | None] = mapped_column(String(255), nullable=True)
    source: Mapped[str] = mapped_column(String(40), default="shodan")
    raw: Mapped[dict] = mapped_column(JSONB, default=dict)

    scan: Mapped[Scan] = relationship(back_populates="ports")


class Endpoint(Base):
    __tablename__ = "endpoints"
    __table_args__ = (UniqueConstraint("scan_id", "url", name="uq_scan_endpoint"), Index("ix_endpoints_scan_url", "scan_id", "url"))

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    scan_id: Mapped[str] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), index=True)
    url: Mapped[str] = mapped_column(Text)
    source: Mapped[str] = mapped_column(String(40))
    status_code: Mapped[int | None] = mapped_column(Integer, nullable=True)
    method: Mapped[str | None] = mapped_column(String(20), nullable=True)
    kind: Mapped[str | None] = mapped_column(String(40), nullable=True)
    raw: Mapped[dict] = mapped_column(JSONB, default=dict)

    scan: Mapped[Scan] = relationship(back_populates="endpoints")


class Directory(Base):
    __tablename__ = "directories"
    __table_args__ = (UniqueConstraint("scan_id", "url", name="uq_scan_directory"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    scan_id: Mapped[str] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), index=True)
    url: Mapped[str] = mapped_column(Text)
    status_code: Mapped[int | None] = mapped_column(Integer, nullable=True)
    words: Mapped[int | None] = mapped_column(Integer, nullable=True)
    lines: Mapped[int | None] = mapped_column(Integer, nullable=True)
    size: Mapped[int | None] = mapped_column(Integer, nullable=True)
    raw: Mapped[dict] = mapped_column(JSONB, default=dict)

    scan: Mapped[Scan] = relationship(back_populates="directories")


class Secret(Base):
    __tablename__ = "secrets"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    scan_id: Mapped[str] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), index=True)
    source: Mapped[str] = mapped_column(String(40))
    kind: Mapped[str] = mapped_column(String(120))
    location: Mapped[str | None] = mapped_column(Text, nullable=True)
    value_masked: Mapped[str | None] = mapped_column(Text, nullable=True)
    severity: Mapped[str | None] = mapped_column(String(20), nullable=True)
    verified: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    raw: Mapped[dict] = mapped_column(JSONB, default=dict)

    scan: Mapped[Scan] = relationship(back_populates="secrets")


class Finding(Base):
    __tablename__ = "findings"
    __table_args__ = (UniqueConstraint("scan_id", "dedupe_key", name="uq_scan_finding"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    scan_id: Mapped[str] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), index=True)
    name: Mapped[str] = mapped_column(String(255))
    tool: Mapped[str | None] = mapped_column(String(80), nullable=True)
    severity: Mapped[str | None] = mapped_column(String(20), nullable=True)
    target: Mapped[str | None] = mapped_column(Text, nullable=True)
    dedupe_key: Mapped[str] = mapped_column(String(512))
    status: Mapped[str] = mapped_column(String(30), default="open")
    raw: Mapped[dict] = mapped_column(JSONB, default=dict)

    scan: Mapped[Scan] = relationship(back_populates="findings")


class Change(Base):
    __tablename__ = "changes"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    scan_id: Mapped[str] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), index=True)
    change_type: Mapped[str] = mapped_column(String(40))
    asset: Mapped[str] = mapped_column(Text)
    previous_value: Mapped[str | None] = mapped_column(Text, nullable=True)
    current_value: Mapped[str | None] = mapped_column(Text, nullable=True)

    scan: Mapped[Scan] = relationship(back_populates="changes")


class Wordlist(Base):
    __tablename__ = "wordlists"
    __table_args__ = (UniqueConstraint("name", "source", name="uq_wordlist"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    name: Mapped[str] = mapped_column(String(512))
    source: Mapped[str] = mapped_column(String(30), default="custom")
    content: Mapped[bytes] = mapped_column(LargeBinary)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class FFUFRuns(Base):
    __tablename__ = "ffuf_runs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    scan_id: Mapped[str] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), index=True)
    subdomain: Mapped[str | None] = mapped_column(String(255), nullable=True)
    url: Mapped[str] = mapped_column(Text)
    config: Mapped[dict] = mapped_column(JSONB, default=dict)
    status: Mapped[str] = mapped_column(String(30), default="queued")
    output: Mapped[str] = mapped_column(Text, default="")
    exit_code: Mapped[int | None] = mapped_column(Integer, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)

    scan: Mapped[Scan] = relationship(back_populates="ffuf_runs")


class FFUFEvent(Base):
    __tablename__ = "ffuf_events"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    ffuf_run_id: Mapped[str] = mapped_column(ForeignKey("ffuf_runs.id", ondelete="CASCADE"), index=True)
    seq: Mapped[int] = mapped_column(Integer)
    line: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
