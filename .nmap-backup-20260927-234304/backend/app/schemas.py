from __future__ import annotations
from datetime import datetime
from pydantic import BaseModel, Field, ConfigDict


class ScanCreate(BaseModel):
    links: list[str] = Field(min_length=1)
    scan_type: str = "full"


class ScanOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    target: str
    scan_type: str
    status: str
    current_stage: str | None
    progress: int
    created_at: datetime
    started_at: datetime | None
    finished_at: datetime | None
    error: str | None


class FFUFCreate(BaseModel):
    scan_id: str
    subdomain: str | None = None
    mode: str = "path"
    url: str
    method: str = "GET"
    headers: dict[str, str] = Field(default_factory=dict)
    body: str | None = None
    wordlist_id: str
    match_status: str | None = None
    filter_status: str | None = None
    match_size: str | None = None
    filter_size: str | None = None
    match_words: str | None = None
    filter_words: str | None = None
    match_lines: str | None = None
    filter_lines: str | None = None
    regex: str | None = None
    extensions: str | None = None
    threads: int = 20
    rate: int = 0
    recursion: bool = False


class FFUFOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    scan_id: str
    subdomain: str | None
    url: str
    status: str
    output: str
    error: str | None


class WordlistOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    name: str
    source: str
