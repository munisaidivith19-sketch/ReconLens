from enum import StrEnum

from pydantic import BaseModel, Field


class Severity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return SEVERITY_ORDER.index(self)

    def raised(self, levels: int = 1) -> "Severity":
        return SEVERITY_ORDER[min(len(SEVERITY_ORDER) - 1, self.rank + levels)]


SEVERITY_ORDER = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]


class Finding(BaseModel):
    id: str = Field(description="Stable identifier, e.g. headers.missing_hsts")
    title: str
    severity: Severity
    category: str
    scanner: str
    evidence: str = ""
    recommendation: str = ""
    references: list[str] = Field(default_factory=list)
