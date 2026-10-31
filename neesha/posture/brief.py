"""Security Posture Brief models and rendering.

The brief always carries the raw records behind every grade (transparent
drill-down), per the "never show a grade without the underlying record" rule.
"""
from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field


class Grade(BaseModel):
    letter: str
    score: float
    rationale: str


class Trigger(BaseModel):
    signal: str
    why_now: str
    offering: str


class Check(BaseModel):
    name: str
    category: str
    status: str  # ok | warn | gap | info | error | neutral | unstable
    detail: str
    records: list[str] = Field(default_factory=list)
    evidence_ids: list[str] = Field(default_factory=list)


class PostureBrief(BaseModel):
    target: str
    collected_at: datetime
    overall: Grade
    categories: dict[str, Grade]
    checks: list[Check] = Field(default_factory=list)
    triggers: list[Trigger] = Field(default_factory=list)
    flags: list[str] = Field(default_factory=list)
    evidence_count: int = 0

    def offerings(self) -> list[str]:
        seen: list[str] = []
        for t in self.triggers:
            if t.offering not in seen:
                seen.append(t.offering)
        return seen

    def to_markdown(self) -> str:
        lines = [
            f"# Security Posture Brief — {self.target}",
            "",
            f"Collected: {self.collected_at.isoformat()}  ",
            f"Overall: **{self.overall.letter}** ({self.overall.score:.0f}/100)",
            "",
        ]
        if self.flags:
            lines.append("## Flags")
            lines.append("")
            for flag in self.flags:
                lines.append(f"- `{flag}`")
            lines.append("")

        lines += ["## Grades", "", "| Category | Grade | Score |", "| --- | --- | --- |"]
        for name, grade in self.categories.items():
            lines.append(f"| {name} | {grade.letter} | {grade.score:.0f} |")
        lines.append("")
        lines.append(f"Rationale: {self.overall.rationale}")
        lines.append("")

        lines += ["## Checks", ""]
        for check in self.checks:
            lines.append(f"### {check.name} — `{check.status}`")
            lines.append(check.detail)
            if check.records:
                lines.append("")
                lines.append("Records:")
                lines.append("")
                for rec in check.records:
                    lines.append(f"```\n{rec}\n```")
            lines.append("")

        if self.triggers:
            lines += ["## Triggers / Opportunities", ""]
            for t in self.triggers:
                lines.append(f"- **{t.signal}** — {t.why_now} → *{t.offering}*")
            lines.append("")

        if self.offerings():
            lines += ["## Mapped Services", ""]
            for offering in self.offerings():
                lines.append(f"- {offering}")
            lines.append("")

        return "\n".join(lines)
