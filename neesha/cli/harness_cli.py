"""CLI for the new harness: engagements, budget, and runs.

Separate from `cli/main.py` on purpose. That module drives the legacy
Evidence path, which still works and is still useful; this one drives the
typed-fact layer. They will converge when the posture collector is ported,
and keeping them apart until then means neither breaks the other.
"""
from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from pathlib import Path
from typing import Optional
from uuid import uuid4

import sqlalchemy as sa
import typer
from rich.console import Console
from rich.table import Table

from neesha.db import schema
from neesha.harness.gate import EngagementView, PolicyGate, RunCaps
from neesha.harness.run import execute_run
from neesha.ledger.ledger import Ledger, period_of

console = Console()

DEFAULT_DATABASE_URL = "sqlite:///./data/neesha.sqlite3"

harness_app = typer.Typer(help="Intelligence harness operations.", no_args_is_help=True)
engagement_app = typer.Typer(help="Authorization for collection.", no_args_is_help=True)
budget_app = typer.Typer(help="Spend caps and the ledger.", no_args_is_help=True)

harness_app.add_typer(engagement_app, name="engagement")
harness_app.add_typer(budget_app, name="budget")

AUTHORITY_BASES = ("own_org", "prospect_company", "client_engagement")


def get_engine() -> sa.Engine:
    url = os.environ.get("NEESHA_DATABASE_URL") or DEFAULT_DATABASE_URL
    if url.startswith("sqlite"):
        from pathlib import Path

        Path("./data").mkdir(parents=True, exist_ok=True)
    return sa.create_engine(url)


def _require_schema(engine: sa.Engine) -> None:
    if not sa.inspect(engine).has_table("engagement"):
        console.print(
            "[red]database not initialized[/red] — run [bold]make migrate[/bold] "
            "(or `alembic upgrade head`) first"
        )
        raise typer.Exit(1)


def _now() -> datetime:
    return datetime.now(timezone.utc)


# ---- engagements ---------------------------------------------------------


@engagement_app.command("create")
def engagement_create(
    domain: list[str] = typer.Option(
        ..., "--domain", help="Authorized domain (repeatable)"
    ),
    authority: str = typer.Option(
        "prospect_company", "--authority", help="|".join(AUTHORITY_BASES)
    ),
    authorized_by: str = typer.Option(..., "--by", help="Who authorized this"),
    client: Optional[str] = typer.Option(None, "--client", help="Client name"),
    technique: Optional[list[str]] = typer.Option(
        None, "--technique", help="Permitted technique (repeatable)"
    ),
    days: int = typer.Option(30, "--days", help="How long this stays valid"),
    document: Optional[str] = typer.Option(
        None, "--document", help="Reference to the signed authorization"
    ),
) -> None:
    """Authorize collection against one or more domains."""
    if authority not in AUTHORITY_BASES:
        console.print(f"[red]unknown authority {authority!r}[/red]")
        raise typer.Exit(1)
    if authority == "client_engagement" and not client:
        console.print("[red]--client is required for a client engagement[/red]")
        raise typer.Exit(1)

    engine = get_engine()
    _require_schema(engine)
    engagement_id = uuid4().hex
    now = _now()
    with engine.begin() as conn:
        conn.execute(
            schema.engagement.insert().values(
                id=engagement_id,
                authority_basis=authority,
                client_name=client,
                permitted_techniques=sorted(set(technique or [])),
                authorized_domains=[d.strip().lower().rstrip(".") for d in domain],
                authorized_by=authorized_by,
                document_ref=document,
                starts_at=now,
                expires_at=now + timedelta(days=days),
                created_at=now,
            )
        )
    console.print(f"[green]engagement[/green] {engagement_id}")
    console.print(f"  authority:  {authority}")
    console.print(f"  domains:    {', '.join(domain)}")
    console.print(f"  techniques: {', '.join(technique or []) or 'none'}")
    console.print(f"  expires:    {(now + timedelta(days=days)).date().isoformat()}")


@engagement_app.command("list")
def engagement_list() -> None:
    """List engagements and whether they are still in force."""
    engine = get_engine()
    _require_schema(engine)
    with engine.connect() as conn:
        rows = conn.execute(
            sa.select(schema.engagement).order_by(schema.engagement.c.created_at.desc())
        ).all()
    if not rows:
        console.print("[yellow]no engagements[/yellow] — create one first")
        return
    table = Table(box=None)
    for column in ("id", "authority", "domains", "techniques", "expires", "state"):
        table.add_column(column)
    now = _now()
    for row in rows:
        expires = row.expires_at
        if expires.tzinfo is None:
            expires = expires.replace(tzinfo=timezone.utc)
        live = expires > now
        table.add_row(
            row.id[:12],
            row.authority_basis,
            ", ".join(row.authorized_domains or []),
            ", ".join(row.permitted_techniques or []) or "-",
            expires.date().isoformat(),
            "[green]in force[/green]" if live else "[red]expired[/red]",
        )
    console.print(table)


# ---- budget --------------------------------------------------------------


@budget_app.command("set")
def budget_set(
    cap: float = typer.Argument(..., help="Cap in USD"),
    adapter: str = typer.Option("*", "--adapter", help="'*' for the monthly cap"),
    period: Optional[str] = typer.Option(None, "--period", help="YYYY-MM"),
) -> None:
    """Set the monthly cap, or a per-adapter sub-budget."""
    engine = get_engine()
    _require_schema(engine)
    period = period or period_of()
    Ledger(engine).set_cap(cap, period=period, adapter=adapter)
    scope = "monthly cap" if adapter == "*" else f"sub-budget for {adapter}"
    console.print(f"[green]set[/green] {scope} for {period}: ${cap:.2f}")


@budget_app.command("show")
def budget_show(
    period: Optional[str] = typer.Option(None, "--period", help="YYYY-MM"),
) -> None:
    """Show committed spend against the cap."""
    engine = get_engine()
    _require_schema(engine)
    summary = Ledger(engine).summary(period or period_of())
    if summary.cap_usd == 0:
        console.print(
            f"[yellow]no cap set for {summary.period}[/yellow] — "
            "metered sources will be refused until you set one:\n"
            "  neesha harness budget set 100"
        )
        return

    pct = summary.fraction_used * 100
    colour = "green" if pct < 75 else ("yellow" if pct < 90 else "red")
    console.print(
        f"[bold]{summary.period}[/bold]  "
        f"[{colour}]${summary.committed_usd:.4f}[/{colour}] of "
        f"${summary.cap_usd:.2f} committed  "
        f"(${summary.remaining_usd:.4f} left, {pct:.1f}% used)"
    )
    for alert in summary.alerts:
        console.print(f"[yellow]alert:[/yellow] past {alert} of the monthly cap")
    if summary.exhausted:
        console.print("[red]cap reached — metered sources are now refused[/red]")
    if summary.by_adapter:
        table = Table(box=None)
        table.add_column("adapter")
        table.add_column("committed", justify="right")
        for name, amount in sorted(
            summary.by_adapter.items(), key=lambda kv: -kv[1]
        ):
            table.add_row(name, f"${amount:.4f}")
        console.print(table)


# ---- runs ----------------------------------------------------------------


@harness_app.command("run")
def harness_run(
    company: str = typer.Argument(..., help="Company domain to research"),
    engagement_id: Optional[str] = typer.Option(
        None, "--engagement", help="Engagement id (default: newest in force)"
    ),
    pir: Optional[list[str]] = typer.Option(
        None, "--pir", help="PIR template (repeatable)"
    ),
    analyst: Optional[str] = typer.Option(None, "--analyst"),
    max_steps: int = typer.Option(25, "--max-steps"),
    max_spend: float = typer.Option(1.00, "--max-spend", help="Per-run USD cap"),
    max_seconds: int = typer.Option(600, "--max-seconds"),
    out: Path = typer.Option(Path("reports"), "--out", help="Briefing output directory"),
) -> None:
    """Run one intelligence cycle against a company."""
    engine = get_engine()
    _require_schema(engine)

    view = _resolve_engagement(engine, engagement_id)
    if not view.covers(company):
        console.print(
            f"[red]blocked:[/red] engagement {view.id[:12]} does not authorize "
            f"{company!r}"
        )
        console.print(
            f"  authorized: {', '.join(view.authorized_domains) or 'nothing'}"
        )
        raise typer.Exit(1)

    ledger = Ledger(engine)
    gate = PolicyGate(engine, ledger)
    templates = tuple(pir or ("attack-surface",))

    console.print(f"[bold]{company}[/bold]  engagement {view.id[:12]}  "
                  f"PIRs: {', '.join(templates)}")

    try:
        report = execute_run(
            engine=engine,
            ledger=ledger,
            gate=gate,
            company=company,
            engagement=view,
            analyst=analyst or os.environ.get("USER", "analyst"),
            pir_templates=templates,
            caps=RunCaps(
                max_steps=max_steps,
                max_spend_usd=Decimal(str(max_spend)),
                max_wall_secs=max_seconds,
            ),
        )
    except KeyError as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(1)

    _print_report(report)
    from neesha.harness.brief import write_brief

    for path in write_brief(engine, report.run_id, out):
        console.print(f"briefing: {path}")


def _resolve_engagement(engine: sa.Engine, engagement_id: Optional[str]) -> EngagementView:
    with engine.connect() as conn:
        query = sa.select(schema.engagement)
        if engagement_id:
            query = query.where(schema.engagement.c.id.like(f"{engagement_id}%"))
        else:
            query = query.where(schema.engagement.c.expires_at > _now()).order_by(
                schema.engagement.c.created_at.desc()
            )
        row = conn.execute(query).first()

    if row is None:
        console.print(
            "[red]no engagement in force[/red] — collection is not authorized.\n"
            "  neesha harness engagement create --domain acme.com --by you@example"
        )
        raise typer.Exit(1)

    def _aware(value):
        return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value

    return EngagementView(
        id=row.id,
        authority_basis=row.authority_basis,
        permitted_techniques=frozenset(row.permitted_techniques or []),
        authorized_domains=tuple(row.authorized_domains or []),
        authorized_emails=tuple(row.authorized_emails or []),
        starts_at=_aware(row.starts_at),
        expires_at=_aware(row.expires_at),
    )


def _print_report(report) -> None:
    console.print()
    steps = Table(box=None)
    for column in ("step", "outcome", "facts", "cost", "detail"):
        steps.add_column(column)
    colour = {
        "collected": "green",
        "cached": "cyan",
        "denied": "red",
        "paused": "yellow",
        "failed": "red",
    }
    for step in report.steps:
        c = colour.get(step.outcome, "white")
        steps.add_row(
            step.adapter,
            f"[{c}]{step.outcome}[/{c}]",
            str(step.facts_written),
            f"${step.cost_usd:.4f}",
            step.reason[:60],
        )
    console.print(steps)

    console.print()
    console.print("[bold]Requirements[/bold]")
    mark = {"answered": "[green]answered[/green]", "partial": "[yellow]partial[/yellow]"}
    for pir in report.pirs:
        label = mark.get(pir.status, "[red]unanswerable[/red]")
        console.print(f"  {label}  {pir.question}")
        if pir.gap_reason:
            console.print(f"            [dim]{pir.gap_reason}[/dim]")

    console.print()
    console.print(
        f"[bold]{report.facts_written}[/bold] facts  ·  "
        f"spend ${report.spend_usd:.4f}  ·  "
        f"{report.status} ({report.stop_reason})"
    )
    if report.skipped:
        console.print("[yellow]skipped:[/yellow]")
        for entry in report.skipped:
            console.print(f"  - {entry['adapter']}: {entry['reason'][:80]}")
    console.print(f"[dim]run {report.run_id}[/dim]")


@harness_app.command('serve')
def harness_serve(
    port: int = typer.Option(8765, '--port', min=1, max=65535),
) -> None:
    """Open the local investigator workspace (loopback only)."""
    from neesha.console.server import serve

    engine = get_engine()
    _require_schema(engine)
    serve(engine, port=port)
