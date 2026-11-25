"""Schema for the AI-written report (also used for the template fallback)."""

from typing import Literal

from pydantic import BaseModel, Field

SeverityStr = Literal["info", "low", "medium", "high", "critical"]


class PrioritizedFinding(BaseModel):
    title: str = Field(max_length=300)
    severity: SeverityStr
    why_it_matters: str = Field(max_length=1500)
    abuse_scenario: str = Field(max_length=1500, description="High-level only, no exploit steps")
    remediation: str = Field(max_length=1500)


class AttackPath(BaseModel):
    name: str = Field(max_length=200)
    steps: list[str] = Field(max_length=8)
    related_findings: list[str] = Field(default_factory=list, max_length=10)


class AiReport(BaseModel):
    executive_summary: str = Field(max_length=3000)
    risk_level: SeverityStr
    prioritized_findings: list[PrioritizedFinding] = Field(max_length=15)
    attack_paths: list[AttackPath] = Field(default_factory=list, max_length=6)
    next_steps: list[str] = Field(default_factory=list, max_length=12)
    data_gaps: list[str] = Field(default_factory=list, max_length=12)
    generated_by: str = "template"
