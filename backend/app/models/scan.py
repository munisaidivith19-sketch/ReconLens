from datetime import datetime
from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, Field

from app.models.finding import Finding
from app.models.report import AiReport


class ScanStatus(StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    INTERRUPTED = "interrupted"


class StageStatus(StrEnum):
    PENDING = "pending"
    RUNNING = "running"
    DONE = "done"
    FAILED = "failed"
    SKIPPED = "skipped"


class Stage(BaseModel):
    name: str
    label: str
    status: StageStatus = StageStatus.PENDING
    started_at: datetime | None = None
    finished_at: datetime | None = None
    error: str | None = None


class ScanCreate(BaseModel):
    target: str = Field(min_length=1, max_length=2048)
    confirmed_authorized: Literal[True] = Field(
        description="Must be true: the user confirms they own or are authorized to test the target."
    )


class ScoreFactor(BaseModel):
    label: str
    points: float
    severity: str | None = None


class ScanSummary(BaseModel):
    id: str
    domain: str
    input: str
    status: ScanStatus
    risk_score: int | None = None
    findings_count: int = 0
    created_at: datetime
    finished_at: datetime | None = None
    cached: bool = False


class ScanDetail(ScanSummary):
    stages: list[Stage]
    results: dict[str, Any] = Field(default_factory=dict)
    findings: list[Finding] = Field(default_factory=list)
    score_factors: list[ScoreFactor] = Field(default_factory=list)
    ai_report: AiReport | None = None
    confirmed_authorized: bool
    authorized_at: datetime
    started_at: datetime | None = None
    error: str | None = None


class ScanPage(BaseModel):
    items: list[ScanSummary]
    total: int
    page: int
    page_size: int
