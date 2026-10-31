"""Neesha Intelligence Console — CLI entry point.

Phase 0 (scaffold): ``init``, ``preflight``, ``scope create``, and the
evidence ledger are functional. Collection commands are stubs that report
their planned phase.
"""
from __future__ import annotations

import json
from contextlib import contextmanager
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console

from neesha import __version__
from neesha.audit import AuditLog
from neesha.collectors.posture import PostureCollector, normalize_domain
from neesha.config import Config, DEFAULT_CONFIG_PATH
from neesha.evidence.models import CollectionMode, Evidence
from neesha.evidence.crypto import StoreEncryptionError
from neesha.evidence.store import EvidenceStore
from neesha.guardrail.engine import Guardrail
from neesha.orchestrator import Orchestrator
from neesha.preflight.gate import Preflight, PreflightError, PreflightGate
from neesha.scope.engine import ScopeEngine, ScopeViolation
from neesha.scope.models import Scope

app = typer.Typer(
    help="Neesha — OSINT targeting for the cybersecurity sales cycle.",
    no_args_is_help=True,
)
console = Console()

evidence_app = typer.Typer(help="Evidence ledger operations.", no_args_is_help=True)
app.add_typer(evidence_app, name="evidence")

scope_app = typer.Typer(help="Scope engine operations.", no_args_is_help=True)
app.add_typer(scope_app, name="scope")

guardrail_app = typer.Typer(help="Accuracy guardrail operations.", no_args_is_help=True)
app.add_typer(guardrail_app, name="guardrail")


@contextmanager
def open_store(path: Path):
    """Open the evidence store, reporting key problems as messages not tracebacks.

    Covers both failure points: opening a store whose encryption state does
    not match the environment, and decrypting a row with the wrong key.
    """
    try:
        store = EvidenceStore(path)
    except StoreEncryptionError as exc:
        console.print(f"[red]store error:[/red] {exc}")
        raise typer.Exit(1)
    try:
        yield store
    except StoreEncryptionError as exc:
        console.print(f"[red]store error:[/red] {exc}")
        raise typer.Exit(1)
    finally:
        store.close()



@app.command()
def version() -> None:
    """Print the Neesha version."""
    console.print(f"Neesha [bold]{__version__}[/bold]")


@app.command()
def init(
    mode: str = typer.Option("local", "--mode", help="Deployment mode: local|vps|hybrid"),
    out: Path = typer.Option(DEFAULT_CONFIG_PATH, "--out", help="Config file path"),
) -> None:
    """Scaffold a default config file."""
    if mode not in {"local", "vps", "hybrid"}:
        console.print(f"[red]unknown mode {mode!r}[/red] (expected local|vps|hybrid)")
        raise typer.Exit(1)
    cfg = Config(mode=mode)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(cfg.to_toml())
    console.print(f"[green]wrote[/green] {out} (mode={mode})")


@app.command()
def preflight(
    purpose: str = typer.Option(..., "--purpose", help="Legitimate purpose of this run"),
    observer: str = typer.Option(
        ..., "--observer", help="Strongest observer to defend against (ISP, VPS provider, target…)"
    ),
    mode: str = typer.Option("local", "--mode", help="local|vps|hybrid"),
    out: Path = typer.Option(Path("./runs"), "--out", help="Run directory"),
    identity_separation: bool = typer.Option(False, "--identity-separation"),
    network_verified: bool = typer.Option(False, "--network-verified"),
    dns_leak_checked: bool = typer.Option(False, "--dns-leak-checked"),
    webrtc_disabled: bool = typer.Option(False, "--webrtc-disabled"),
    inference_isolated: bool = typer.Option(False, "--inference-isolated"),
    storage_encrypted: bool = typer.Option(False, "--storage-encrypted"),
    retention_set: bool = typer.Option(False, "--retention-set"),
    kill_switch: bool = typer.Option(False, "--kill-switch"),
) -> None:
    """Issue a signed preflight.json for a run."""
    if mode not in {"local", "vps", "hybrid"}:
        console.print(f"[red]unknown mode {mode!r}[/red]")
        raise typer.Exit(1)

    pf = Preflight(
        purpose=purpose,
        observer=observer,
        deployment_mode=mode,
        identity_separation=identity_separation,
        network_path_verified=network_verified,
        dns_leak_test_passed=dns_leak_checked,
        webrtc_disabled=webrtc_disabled,
        inference_isolation=inference_isolated,
        storage_encrypted=storage_encrypted,
        retention_policy_set=retention_set,
        kill_switch_documented=kill_switch,
    )

    out.mkdir(parents=True, exist_ok=True)
    path = out / "preflight.json"
    path.write_text(json.dumps(PreflightGate().issue(pf), indent=2, default=str))

    unset = [
        name
        for name, ok in {
            "identity separation": identity_separation,
            "network path verified": network_verified,
            "DNS leak check": dns_leak_checked,
            "WebRTC disabled": webrtc_disabled,
            "inference isolation": inference_isolated,
            "storage encrypted": storage_encrypted,
            "retention policy set": retention_set,
            "kill switch documented": kill_switch,
        }.items()
        if not ok
    ]
    console.print(f"[green]issued[/green] {path}")
    console.print(f"  preflight_id: {pf.preflight_id}")
    console.print(f"  expires_at:   {pf.expires_at.isoformat()}")
    if unset:
        console.print(
            f"[yellow]note:[/yellow] these checks are unasserted and will gate collection "
            f"once Phase 11 enforces them: {', '.join(unset)}"
        )


@scope_app.command("create")
def scope_create(
    target: str = typer.Option(..., "--target", help="Seed target"),
    target_type: str = typer.Option("domain", "--type", help="domain|org|person|email|phone|ip"),
    purpose: str = typer.Option(..., "--purpose", help="Legitimate purpose"),
    observer: str = typer.Option("target", "--observer"),
    allow: Optional[list[str]] = typer.Option(None, "--allow", help="Allowed source (repeatable)"),
    deny: Optional[list[str]] = typer.Option(None, "--deny", help="Denied source (repeatable)"),
    active: bool = typer.Option(False, "--active", help="Authorize active collection"),
    out: Path = typer.Option(Path("./runs"), "--out", help="Run directory"),
) -> None:
    """Create a scope.json authorization file for a run."""
    scope = Scope(
        target=target,
        target_type=target_type,
        purpose=purpose,
        observer=observer,
        allowed_sources=list(allow) if allow else [],
        denied_sources=list(deny) if deny else [],
        active_authorized=active,
    )
    out.mkdir(parents=True, exist_ok=True)
    path = out / "scope.json"
    path.write_text(scope.model_dump_json(indent=2))
    console.print(f"[green]wrote[/green] {path}")
    console.print(f"  scope_id: {scope.scope_id}")
    console.print(f"  modes:    {[m.value for m in scope.allowed_modes]}")
    console.print(f"  active:   {'authorized' if active else 'blocked (passive by default)'}")


@scope_app.command("check")
def scope_check(
    source: str = typer.Argument(..., help="Source to authorize"),
    mode: str = typer.Argument("passive", help="passive|active"),
    run_dir: Path = typer.Option(Path("./runs"), "--run-dir"),
) -> None:
    """Authorize a source+mode against a scope file."""
    orch = Orchestrator(run_dir)
    try:
        scope = orch.require_scope()
    except PreflightError as exc:
        console.print(f"[red]blocked:[/red] {exc}")
        raise typer.Exit(1)
    decision = ScopeEngine(scope).authorize(source, CollectionMode(mode))
    if decision.allowed:
        console.print(f"[green]allowed[/green] {source} ({mode}) under {decision.scope_id}")
    else:
        console.print(f"[red]denied[/red] {source} ({mode}): {decision.reason}")
        raise typer.Exit(1)


@evidence_app.command("list")
def evidence_list(
    target: str = typer.Argument(..., help="Target id"),
    store: Path = typer.Option(Path("./data/evidence.sqlite3"), "--store"),
) -> None:
    """List evidence records for a target."""
    with open_store(store) as s:
        rows = s.list_by_target(target)
    if not rows:
        console.print(f"[yellow]no evidence for target {target!r}[/yellow]")
        raise typer.Exit(0)
    for e in rows:
        grade = f"{e.admiralty_source_grade.value}{e.admiralty_claim_grade.value}"
        console.print(f"[bold]{e.evidence_id}[/bold] {grade} {e.confidence.value} — {e.claim}")


@evidence_app.command("export")
def evidence_export(
    target: str = typer.Option(..., "--target", help="Target id"),
    store: Path = typer.Option(Path("./data/evidence.sqlite3"), "--store"),
    fmt: str = typer.Option("jsonl", "--format", help="jsonl|json|csv|md"),
    out: Path = typer.Option(Path("./reports"), "--out", help="Output directory"),
) -> None:
    """Export a target's evidence ledger as JSONL/JSON/CSV/Markdown."""
    from neesha.report import writer

    with open_store(store) as s:
        rows = s.list_by_target(target)
    if not rows:
        console.print(f"[yellow]no evidence for target {target!r}[/yellow]")
        raise typer.Exit(0)

    out.mkdir(parents=True, exist_ok=True)
    if fmt == "jsonl":
        writer.write_jsonl(out / f"{target}.jsonl", rows)
    elif fmt == "json":
        writer.write_json(out / f"{target}.json", rows)
    elif fmt == "csv":
        writer.write_csv(out / f"{target}.csv", rows)
    elif fmt == "md":
        writer.write_markdown(out / f"{target}.md", rows)
    else:
        console.print(f"[red]unknown format {fmt!r}[/red] (jsonl|json|csv|md)")
        raise typer.Exit(1)
    console.print(f"[green]exported[/green] {len(rows)} records -> {out}")


@app.command()
def target(
    seed: str = typer.Argument(..., help="Seed input: domain|org|person|email|phone|ip"),
    seed_type: str = typer.Option("domain", "--type", help="domain|org|person|email|phone|ip"),
    run_dir: Path = typer.Option(Path("./runs"), "--run-dir"),
) -> None:
    """Plan a collection run (collectors land in later phases)."""
    orch = Orchestrator(run_dir)
    try:
        pf = orch.require_preflight()
    except PreflightError as exc:
        console.print(f"[red]blocked:[/red] {exc}")
        raise typer.Exit(1)
    console.print(f"[green]preflight ok[/green] {pf.preflight_id}")
    console.print("planned DAG (collectors not yet implemented in Phase 0):")
    for step in orch.plan(seed, seed_type):
        console.print(f"  - {step}")


@app.command()
def posture(
    target: str = typer.Argument(..., help="Domain to assess"),
    grade: bool = typer.Option(False, "--grade", help="Print the A-F grade"),
    triggers: bool = typer.Option(False, "--triggers", help="Print sales triggers"),
    run_dir: Path = typer.Option(Path("./runs"), "--run-dir", help="Run directory with preflight.json + scope.json"),
    store: Path = typer.Option(Path("./data/evidence.sqlite3"), "--store"),
    out: Path = typer.Option(Path("./reports"), "--out", help="Brief output directory"),
) -> None:
    """Collect posture (DNS/SPF/DMARC/DKIM/TLS/headers) and write a Security Posture Brief."""
    orch = Orchestrator(run_dir)
    try:
        orch.require_preflight()
        scope = orch.require_scope(expected_target=normalize_domain(target))
    except PreflightError as exc:
        console.print(f"[red]blocked:[/red] {exc}")
        raise typer.Exit(1)

    audit = AuditLog(run_dir / "audit.jsonl")
    with open_store(store) as evidence_store:
        collector = PostureCollector(
            ScopeEngine(scope), evidence_store, target, audit=audit
        )
        try:
            evidences, brief = collector.run()
        except ScopeViolation as exc:
            console.print(f"[red]blocked by scope:[/red] {exc}")
            raise typer.Exit(1)

    domain = collector.target
    brief_dir = out / domain
    brief_dir.mkdir(parents=True, exist_ok=True)
    (brief_dir / "posture.md").write_text(brief.to_markdown())
    (brief_dir / "posture.json").write_text(brief.model_dump_json(indent=2))

    console.print(f"[green]collected[/green] {len(evidences)} evidence records -> {store}")
    if brief.flags:
        console.print(f"[yellow]flags:[/yellow] {', '.join(brief.flags)}")
    if grade:
        console.print(f"[bold]Overall: {brief.overall.letter}[/bold] ({brief.overall.score}/100)")
    if triggers and brief.triggers:
        console.print("triggers:")
        for t in brief.triggers:
            console.print(f"  - {t.signal} -> {t.offering}")

    guardrail_report = Guardrail.apply(evidences)
    (brief_dir / "guardrail.md").write_text(guardrail_report.to_markdown())
    (brief_dir / "guardrail.json").write_text(guardrail_report.model_dump_json(indent=2))
    console.print(
        f"[dim]guardrail: {guardrail_report.kept} kept, "
        f"{guardrail_report.downgraded} downgraded, {guardrail_report.dropped} dropped[/dim]"
    )
    console.print(f"brief -> {brief_dir / 'posture.md'} and {brief_dir / 'posture.json'}")


@app.command("collectors")
def collectors_list() -> None:
    """List known collectors and their cost tier."""
    from neesha.collectors.registry import DEFAULT_COLLECTORS, list_collectors

    label = {
        "A": "[green]A free[/green]",
        "B": "[yellow]B metered[/yellow]",
        "C": "[red]C authority-gated[/red]",
        "D": "[dim]D contract-gated (disabled)[/dim]",
    }
    for name, tier, description in list_collectors():
        default = " [dim](runs by default)[/dim]" if name in DEFAULT_COLLECTORS else ""
        console.print(f"[bold]{name}[/bold] {label.get(tier, tier)} — {description}{default}")


@app.command()
def passive(
    target: str = typer.Argument(..., help="Domain to collect on"),
    sources: Optional[str] = typer.Option(None, "--sources", help="Comma-separated collector names (default: all)"),
    run_dir: Path = typer.Option(Path("./runs"), "--run-dir", help="Run directory with preflight.json + scope.json"),
    store: Path = typer.Option(Path("./data/evidence.sqlite3"), "--store"),
    out: Path = typer.Option(Path("./reports"), "--out"),
) -> None:
    """Run passive OSINT collectors and write provenance-first evidence."""
    from neesha.collectors.registry import (
        DEFAULT_COLLECTORS,
        RUNNABLE_COLLECTORS,
        get_collector,
        is_metered,
    )
    from neesha.report import writer

    orch = Orchestrator(run_dir)
    try:
        orch.require_preflight()
        scope = orch.require_scope(expected_target=normalize_domain(target))
    except PreflightError as exc:
        console.print(f"[red]blocked:[/red] {exc}")
        raise typer.Exit(1)

    # A bare invocation runs free Tier A sources only. Metered adapters have
    # to be asked for by name: there is no budget ledger yet, so an implicit
    # default that spent money would be unbounded. AUDIT.md S1.
    names = (
        [n.strip() for n in sources.split(",") if n.strip()]
        if sources
        else list(DEFAULT_COLLECTORS)
    )
    unknown = [n for n in names if n not in RUNNABLE_COLLECTORS]
    if unknown:
        console.print(f"[red]unknown or disabled collectors: {', '.join(unknown)}[/red]")
        console.print(f"available: {', '.join(RUNNABLE_COLLECTORS)}")
        console.print("[dim]`neesha collectors` lists every collector and its tier[/dim]")
        raise typer.Exit(1)

    metered = [n for n in names if is_metered(n)]
    if metered:
        console.print(
            f"[yellow]metered:[/yellow] {', '.join(metered)} will call paid APIs. "
            "There is no budget ledger yet — spend is not capped."
        )

    domain = normalize_domain(target)
    audit = AuditLog(run_dir / "audit.jsonl")
    all_evidence = []
    with open_store(store) as evidence_store:
        engine = ScopeEngine(scope)
        for name in names:
            collector = get_collector(name)(engine, evidence_store, domain, audit=audit)
            try:
                evs = collector.run()
            except ScopeViolation as exc:
                console.print(f"[yellow]skipped {name}:[/yellow] {exc}")
                continue
            all_evidence.extend(evs)
            console.print(f"  {name}: {len(evs)} evidence record(s)")

    if not all_evidence:
        console.print("[yellow]no evidence collected[/yellow]")
        raise typer.Exit(0)

    result = Guardrail.apply(all_evidence)
    console.print(
        f"guardrail: [green]{result.kept} kept[/green], "
        f"[yellow]{result.downgraded} downgraded[/yellow], "
        f"[red]{result.dropped} dropped[/red]"
    )

    domain_dir = out / domain
    domain_dir.mkdir(parents=True, exist_ok=True)
    writer.write_jsonl(domain_dir / "osint.jsonl", all_evidence)
    (domain_dir / "guardrail.md").write_text(result.to_markdown())
    console.print(f"ledger -> {domain_dir / 'osint.jsonl'}")
    console.print(f"guardrail -> {domain_dir / 'guardrail.md'}")
    console.print(f"audit -> {audit.path}")


@app.command()
def resolve(
    target: str = typer.Argument(..., help="Seed domain to resolve"),
    store: Path = typer.Option(Path("./data/evidence.sqlite3"), "--store"),
    out: Path = typer.Option(Path("./reports"), "--out"),
) -> None:
    """Resolve entities and map relationships from collected evidence."""
    from neesha.resolve.mapper import NetworkMapper, to_mermaid
    from neesha.resolve.normalize import canonicalize_domain
    from neesha.resolve.resolver import EntityResolver

    with open_store(store) as s:
        evidence = s.list_by_target(target)
    if not evidence:
        console.print("[yellow]no evidence; run `neesha posture` or `neesha passive` first[/yellow]")
        raise typer.Exit(0)

    result = EntityResolver().resolve(target, evidence)
    relationships = NetworkMapper().map(result.entities, evidence, seed=target)

    domain = canonicalize_domain(target)
    domain_dir = out / domain
    domain_dir.mkdir(parents=True, exist_ok=True)
    (domain_dir / "entities.json").write_text(
        json.dumps([e.model_dump(mode="json") for e in result.entities], indent=2)
    )
    (domain_dir / "relationships.json").write_text(
        json.dumps([r.model_dump(mode="json") for r in relationships], indent=2)
    )
    (domain_dir / "graph.mmd").write_text(to_mermaid(result.entities, relationships))

    console.print(f"[green]{len(result.entities)} entities[/green], {len(relationships)} relationships")
    if result.flagged_merges:
        console.print(f"[yellow]{len(result.flagged_merges)} flagged merge(s) (not merged)[/yellow]")
        for flag in result.flagged_merges:
            console.print(f"  - {flag.entity_a_id[:8]} ~ {flag.entity_b_id[:8]} ({flag.similarity})")
    console.print(f"entities -> {domain_dir / 'entities.json'}")
    console.print(f"graph -> {domain_dir / 'graph.mmd'}")


@app.command()
def run(
    target: str = typer.Argument(..., help="Domain to run the full pipeline on"),
    sources: Optional[str] = typer.Option("crt.sh,otx,wayback,urlscan,hackertarget", "--sources", help="Passive collectors (comma-separated)"),
    data: Path = typer.Option(Path("./data"), "--data"),
    runs: Path = typer.Option(Path("./runs"), "--runs"),
    out: Path = typer.Option(Path("./reports"), "--out"),
) -> None:
    """Run the full local pipeline: preflight, scope, posture, passive, resolve."""
    from neesha.collectors.registry import get_collector
    from neesha.resolve.mapper import NetworkMapper, to_mermaid
    from neesha.resolve.resolver import EntityResolver

    domain = normalize_domain(target)
    run_dir = runs / domain
    out_dir = out / domain
    store_path = data / "evidence.sqlite3"

    # The gate is not self-service. This command used to mint its own
    # preflight, assert storage_encrypted=True without checking, sign it with
    # the gate's own key and then "verify" it — which made the gate
    # decorative on the tool's main path. AUDIT.md G1.
    orch = Orchestrator(run_dir)
    try:
        orch.require_preflight()
        scope = orch.require_scope(expected_target=domain)
    except PreflightError as exc:
        console.print(f"[red]blocked:[/red] {exc}")
        console.print("\n[bold]Authorize this run first:[/bold]")
        console.print(
            f"  neesha preflight --purpose '<why this target>' "
            f"--observer '<strongest observer>' --out {run_dir}"
        )
        console.print(
            f"  neesha scope create --target {domain} "
            f"--purpose '<why this target>' --out {run_dir}"
        )
        raise typer.Exit(1)

    out_dir.mkdir(parents=True, exist_ok=True)
    audit = AuditLog(run_dir / "audit.jsonl")
    engine = ScopeEngine(scope)
    with open_store(store_path) as evidence_store:
        posture_collector = PostureCollector(engine, evidence_store, domain, audit=audit)
        _, brief = posture_collector.run()
        (out_dir / "posture.md").write_text(brief.to_markdown())
        (out_dir / "posture.json").write_text(brief.model_dump_json(indent=2))

        for name in [s.strip() for s in sources.split(",") if s.strip()]:
            cls = get_collector(name)
            if cls is None:
                console.print(f"[yellow]skipping unknown collector {name}[/yellow]")
                continue
            evs = cls(engine, evidence_store, domain, audit=audit).run()
            console.print(f"  {name}: {len(evs)} evidence record(s)")

        evidence = evidence_store.list_by_target(domain)

    guardrail_report = Guardrail.apply(evidence)
    (out_dir / "guardrail.json").write_text(guardrail_report.model_dump_json(indent=2))
    (out_dir / "guardrail.md").write_text(guardrail_report.to_markdown())

    result = EntityResolver().resolve(domain, evidence)
    relationships = NetworkMapper().map(result.entities, evidence, seed=domain)
    (out_dir / "entities.json").write_text(json.dumps([e.model_dump(mode="json") for e in result.entities], indent=2))
    (out_dir / "relationships.json").write_text(json.dumps([r.model_dump(mode="json") for r in relationships], indent=2))
    (out_dir / "graph.mmd").write_text(to_mermaid(result.entities, relationships))

    console.print(
        f"[green]done[/green] {domain}: {len(evidence)} evidence, "
        f"{len(result.entities)} entities, {len(relationships)} relationships "
        f"(guardrail {guardrail_report.kept} kept / {guardrail_report.dropped} dropped)"
    )
    console.print(f"reports -> {out_dir}")


@app.command()
def serve(
    data: Path = typer.Option(Path("./data"), "--data"),
    reports: Path = typer.Option(Path("./reports"), "--reports"),
    host: str = typer.Option("127.0.0.1", "--host"),
    port: int = typer.Option(8765, "--port"),
) -> None:
    """Serve a local read-only console dashboard (loopback only)."""
    from neesha.web import serve as serve_web

    serve_web(data, reports, host, port)


@guardrail_app.command("verify")
def guardrail_verify(
    file: Optional[Path] = typer.Argument(None, help="Evidence JSON/JSONL export to verify"),
    store: Path = typer.Option(Path("./data/evidence.sqlite3"), "--store"),
    target: Optional[str] = typer.Option(None, "--target", help="Target id in the store"),
    admiralty: bool = typer.Option(False, "--admiralty", help="Show Admiralty grades"),
    strict: bool = typer.Option(False, "--strict", help="Drop weak single-source claims"),
) -> None:
    """Run the accuracy guardrail over evidence and report a verdict per claim."""
    evidence = _load_evidence(file, store, target)
    if not evidence:
        console.print("[yellow]no evidence to verify[/yellow]")
        raise typer.Exit(0)

    result = Guardrail.apply(evidence, strict=strict)
    console.print(
        f"guardrail: [bold]{result.total}[/bold] total, "
        f"[green]{result.kept} kept[/green], "
        f"[yellow]{result.downgraded} downgraded[/yellow], "
        f"[red]{result.dropped} dropped[/red] (strict={strict})"
    )
    action_color = {"keep": "green", "downgraded": "yellow", "dropped": "red"}
    for v in result.verdicts:
        grade = f" {v.grade}" if admiralty else ""
        flags = ",".join(v.flags) or "-"
        console.print(
            f"  [{action_color[v.action]}]{v.action:10}[/{action_color[v.action]}] "
            f"{v.evidence_id}{grade} conf={v.confidence.value} flags={flags} {v.claim[:64]}"
        )
    if strict and result.dropped:
        console.print(f"[red]strict gate failed:[/red] {result.dropped} claim(s) dropped")
        raise typer.Exit(1)


def _load_evidence(
    file: Optional[Path], store: Path, target: Optional[str]
) -> list[Evidence]:
    if file is not None:
        text = file.read_text()
        if file.suffix == ".jsonl":
            return [Evidence.model_validate(json.loads(line)) for line in text.splitlines() if line.strip()]
        if file.suffix == ".json":
            return [Evidence.model_validate(d) for d in json.loads(text)]
        console.print(f"[red]unsupported file {file}; use .jsonl/.json or --store --target[/red]")
        raise typer.Exit(1)
    if not target:
        console.print("[red]provide a file or --target[/red]")
        raise typer.Exit(1)
    with open_store(store) as s:
        return s.list_by_target(target)


@app.command()
def report(
    kind: str = typer.Argument(..., help="call-prep|power-map|vendor-landscape|signal-brief"),
    target: str = typer.Option(..., "--target"),
) -> None:
    """Analyst report generators — Phase 8."""
    console.print("[yellow]not implemented[/yellow] — analyst agents land in Phase 8")


if __name__ == "__main__":
    app()
