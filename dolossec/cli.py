from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from pathlib import Path
from urllib.parse import urlparse

import typer
import yaml
from rich.console import Console
from rich.table import Table

from .agents.orchestrator import Orchestrator
from .config import settings
from .llm.deterministic import DeterministicPlanner
from .models import Authorization, PolicySpec, ScopeManifest, ScopeSpec, Target, TargetKind
from .policy import PolicyViolation, ScopePolicy, load_manifest

app = typer.Typer(help="DolosSec policy-gated autonomous application security agent")
console = Console()


def parse_target(value: str) -> Target:
    parsed = urlparse(value)
    if parsed.scheme in {"http", "https"}:
        return Target(kind=TargetKind.url, value=value)
    return Target(kind=TargetKind.local_path, value=str(Path(value).expanduser().resolve()))


def make_local_manifest(path: Path) -> ScopeManifest:
    return ScopeManifest(
        authorization=Authorization(
            owner="local-operator",
            ticket="LOCAL-SOURCE-REVIEW",
            purpose="Local source-code security review",
            expires_at=datetime.now(UTC) + timedelta(hours=24),
        ),
        scope=ScopeSpec(local_paths=[str(path.resolve())]),
        policy=PolicySpec(),
    )


def get_planner():
    if settings.llm_provider.lower() == "openai":
        from .llm.openai_provider import OpenAIPlanner
        return OpenAIPlanner(settings.model)
    return DeterministicPlanner()


@app.command()
def init(path: Path = typer.Argument(Path("scope.yaml"))) -> None:
    """Create a conservative scope-manifest template."""
    if path.exists():
        raise typer.BadParameter(f"refusing to overwrite existing file: {path}")
    template = {
        "authorization": {
            "owner": "security-team@example.com",
            "ticket": "APPSEC-0001",
            "purpose": "Authorized staging security assessment",
            "expires_at": (datetime.now(UTC) + timedelta(days=7)).isoformat(),
        },
        "scope": {"urls": ["https://staging.example.com"], "hosts": ["staging.example.com"], "cidrs": [], "local_paths": []},
        "policy": PolicySpec().model_dump(),
    }
    path.write_text(yaml.safe_dump(template, sort_keys=False), encoding="utf-8")
    console.print(f"[green]Created[/green] {path}")


@app.command()
def doctor() -> None:
    table = Table(title="DolosSec environment")
    table.add_column("Setting")
    table.add_column("Value")
    table.add_row("Planner", settings.llm_provider)
    table.add_row("Model", settings.model or "<not configured>")
    table.add_row("Max steps", str(settings.max_steps))
    table.add_row("Output directory", str(settings.output_dir))
    console.print(table)


@app.command()
def scan(
    target_value: str = typer.Argument(..., metavar="TARGET"),
    scope: Path | None = typer.Option(None, "--scope", help="Required for remote targets"),
    mode: str = typer.Option("standard", "--mode", help="quick, standard, or deep"),
) -> None:
    if mode not in {"quick", "standard", "deep"}:
        raise typer.BadParameter("mode must be quick, standard, or deep")
    target = parse_target(target_value)
    try:
        if target.kind == TargetKind.url:
            if scope is None:
                raise PolicyViolation("remote targets require --scope with an explicit authorization manifest")
            manifest = load_manifest(scope)
            policy = ScopePolicy(manifest)
            policy.validate_initial_target(target)
            scope_file = str(scope.resolve())
        else:
            path = Path(target.value)
            if not path.exists() or not path.is_dir():
                raise PolicyViolation(f"local target does not exist or is not a directory: {path}")
            if scope:
                manifest = load_manifest(scope)
            else:
                manifest = make_local_manifest(path)
            policy = ScopePolicy(manifest)
            policy.validate_initial_target(target)
            scope_file = str(scope.resolve()) if scope else None
    except (PolicyViolation, OSError, ValueError) as exc:
        console.print(f"[red]Policy error:[/red] {exc}")
        raise typer.Exit(2)

    planner = get_planner()
    record = asyncio.run(Orchestrator(target, planner, policy, mode, scope_file).run())
    console.print(f"[bold green]Completed[/bold green] run {record.run_id}")
    console.print(f"Findings: {record.findings_count}")
    console.print(f"Report: {record.output_dir / 'report.md'}")


@app.command()
def web(
    port: int = typer.Option(8787, "--port", min=1, max=65535, help="Local web UI port"),
    open_browser: bool = typer.Option(True, "--open-browser/--no-open-browser", help="Open the UI in the default browser"),
) -> None:
    """Run the local DolosSec web control plane."""
    import threading
    import webbrowser

    import uvicorn

    url = f"http://127.0.0.1:{port}"
    console.print(f"[green]DolosSec Web[/green] {url}")
    console.print("[dim]The UI is bound to loopback only. Remote browser access is intentionally disabled in this release.[/dim]")
    if open_browser:
        threading.Timer(0.8, lambda: webbrowser.open(url)).start()
    uvicorn.run("dolossec.web.app:app", host="127.0.0.1", port=port, log_level="warning")


if __name__ == "__main__":
    app()
