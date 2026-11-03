"""Find3r Intelligence Console — CLI entry point."""
from __future__ import annotations

from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table

from neesha import __version__
from neesha.cli.harness_cli import (
    budget_app,
    engagement_app,
    harness_app,
    harness_maltego_transform,
    harness_purge,
    harness_run,
    harness_serve,
)
from neesha.config import Config, DEFAULT_CONFIG_PATH

app = typer.Typer(
    help="Find3r — OSINT & External Attack Surface Intelligence Console.",
    no_args_is_help=True,
)
cloud_app = typer.Typer(help="Manage ephemeral Vultr Ubuntu 24.04 VPS nodes.", no_args_is_help=True)
console = Console()

app.add_typer(engagement_app, name="engagement")
app.add_typer(budget_app, name="budget")
app.add_typer(harness_app, name="harness")
app.add_typer(cloud_app, name="cloud")

app.command("run")(harness_run)
app.command("serve")(harness_serve)
app.command("purge")(harness_purge)
app.command("maltego-transform")(harness_maltego_transform)


@app.command()
def version() -> None:
    """Print the Find3r version."""
    console.print(f"Find3r [bold]{__version__}[/bold]")


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


@app.command("sources")
def sources_list() -> None:
    """List registered OSINT adapters, their cost tier, and availability."""
    from neesha.adapters import registry

    table = Table(box=None)
    for col in ("adapter", "tier", "status", "inputs", "reason"):
        table.add_column(col)
    for entry in registry.catalog():
        status = "[green]ready[/green]" if entry["available"] else "[yellow]unavailable[/yellow]"
        table.add_row(
            entry["name"],
            entry["tier"],
            status,
            ", ".join(entry["accepts"]),
            entry["reason"],
        )
    console.print(table)


@app.command("install-tools")
def install_tools_cmd(
    tool: str = typer.Argument("all", help="Tool name to install, or 'all' for all OSINT CLI tools"),
) -> None:
    """Auto-install external OSINT CLI tools (subfinder, amass, sherlock, holehe, socialscan, maigret, theHarvester)."""
    from neesha.adapters.tool_installer import install_tool

    console.print(f"[bold]Running OSINT tool installer for:[/bold] {tool}")
    res = install_tool(tool)
    if tool == "all":
        for item in res.get("results", []):
            mark = "[green]✓[/green]" if item.get("installed") else "[red]✗[/red]"
            console.print(f"  {mark} [bold]{item['tool']}[/bold]: {item.get('message', '')}")
        console.print(f"\n[bold]{res['installed_count']}/{res['total']} CLI tools installed and ready.[/bold]")
    else:
        mark = "[green]✓[/green]" if res.get("installed") else "[red]✗[/red]"
        console.print(f"  {mark} [bold]{res['tool']}[/bold]: {res.get('message', '')}")


@cloud_app.command("list")
def cloud_list() -> None:
    """List ephemeral Vultr Ubuntu VPS instances and active execution route."""
    from neesha.cloud.vultr import VultrManager

    mgr = VultrManager()
    info = mgr.list_nodes(sync_remote=mgr.is_configured())
    console.print(f"Active execution route: [bold]{info['active_node_id']}[/bold]")
    if not info["nodes"]:
        console.print("[dim]No active Vultr ephemeral nodes.[/dim]")
        return
    table = Table(box=None)
    for col in ("id", "label", "region", "ip", "status", "ssh"):
        table.add_column(col)
    for n in info["nodes"]:
        table.add_row(
            n["id"][:12],
            n["label"],
            n["region_name"],
            n["ip"] or "assigning…",
            n["status"],
            n["ssh_command"],
        )
    console.print(table)


@cloud_app.command("spinup")
def cloud_spinup(
    region: str = typer.Option("random", "--region", help="Vultr region ID (e.g. fra, ams, ewr) or 'random'"),
    plan: str = typer.Option("vc2-1c-2gb", "--plan", help="Vultr instance plan"),
) -> None:
    """Spin up an ephemeral Ubuntu 24.04 VPS in a randomized (or chosen) Vultr region."""
    from neesha.cloud.vultr import VultrError, VultrManager

    try:
        res = VultrManager().spin_up_node(region=region, plan=plan, auto_select=True)
    except VultrError as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(1)
    c = res["created"]
    console.print(f"[green]Provisioning Ubuntu 24.04 VPS[/green] {c['id']} ({c['label']}) in [bold]{c['region_name']}[/bold]")
    console.print(f"  SSH key: {res['cloud']['ssh_key_path']}")


@cloud_app.command("rotate")
def cloud_rotate(
    region: str = typer.Option("random", "--region", help="Vultr region ID or 'random'"),
) -> None:
    """Spin up a new random Ubuntu VPS and destroy previous ephemeral instance(s)."""
    from neesha.cloud.vultr import VultrError, VultrManager

    try:
        info = VultrManager().rotate_node(region=region)
    except VultrError as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(1)
    console.print(f"[green]Rotated ephemeral VPS.[/green] Active node: [bold]{info['active_node_id']}[/bold]")


@cloud_app.command("destroy")
def cloud_destroy(
    instance_id: str = typer.Argument("all", help="Vultr instance ID or 'all' to tear down all ephemeral nodes"),
) -> None:
    """Destroy an ephemeral Vultr Ubuntu VPS (or 'all')."""
    from neesha.cloud.vultr import VultrError, VultrManager

    try:
        res = VultrManager().destroy_node(instance_id)
    except VultrError as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(1)
    console.print(f"[green]Destroyed[/green] {len(res['destroyed'])} instance(s). Active route reset to local.")


@cloud_app.command("bootstrap-script")
def cloud_bootstrap_script() -> None:
    """Print the standalone Ubuntu 24.04 bootstrap script for provisioning any Ubuntu server."""
    from neesha.cloud.vultr import build_ubuntu_cloud_init

    print(build_ubuntu_cloud_init())


if __name__ == "__main__":
    app()
