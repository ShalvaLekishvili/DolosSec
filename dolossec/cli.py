from __future__ import annotations

import asyncio
import platform
import shutil
import subprocess
from datetime import UTC, datetime, timedelta
from pathlib import Path
from urllib.parse import urlparse

import typer
import yaml
from rich.console import Console
from rich.table import Table

from .agents.orchestrator import Orchestrator
from .config import settings
from .llm.factory import create_planner
from .models import Authorization, PolicySpec, ScopeManifest, ScopeSpec, Target, TargetKind
from .policy import PolicyViolation, ScopePolicy, load_manifest

app = typer.Typer(help="DolosSec policy-gated autonomous application security agent")
ollama_app = typer.Typer(help="Inspect and configure the local Ollama AI backend")
app.add_typer(ollama_app, name="ollama")
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
    table.add_row("Ollama endpoint", settings.ollama_base_url)
    table.add_row("Remote Ollama allowed", str(settings.ollama_allow_remote))
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

    planner = create_planner()
    record = asyncio.run(Orchestrator(target, planner, policy, mode, scope_file).run())
    console.print(f"[bold green]Completed[/bold green] run {record.run_id}")
    console.print(f"Findings: {record.findings_count}")
    console.print(f"Report: {record.output_dir / 'report.md'}")


@ollama_app.command("status")
def ollama_status_cmd() -> None:
    """Check the local Ollama service and list installed models."""
    from .llm.ollama_provider import ollama_status

    status = asyncio.run(ollama_status())
    table = Table(title="DolosSec · Ollama")
    table.add_column("Setting")
    table.add_column("Value")
    table.add_row("Reachable", "yes" if status["reachable"] else "no")
    table.add_row("Base URL", str(status["base_url"]))
    table.add_row("Version", str(status.get("version") or "—"))
    table.add_row("Configured model", settings.model or "<not configured>")
    table.add_row("Installed models", str(len(status.get("models", []))))
    if status.get("error"):
        table.add_row("Error", str(status["error"]))
    console.print(table)
    if status.get("models"):
        models = Table(title="Local models")
        models.add_column("Model")
        models.add_column("Parameters")
        models.add_column("Quantization")
        for item in status["models"]:
            models.add_row(
                str(item.get("name") or "—"),
                str(item.get("parameter_size") or "—"),
                str(item.get("quantization_level") or "—"),
            )
        console.print(models)
    if not status["reachable"]:
        raise typer.Exit(1)


@ollama_app.command("pull")
def ollama_pull_cmd(model: str = typer.Argument("qwen3.5:9b")) -> None:
    """Download a local model using the installed Ollama CLI."""
    binary = shutil.which("ollama")
    if not binary:
        console.print("[red]Ollama CLI not found.[/red] Run `dolos ollama install-guide` first.")
        raise typer.Exit(1)
    console.print(f"[cyan]Pulling[/cyan] {model} using {binary}")
    result = subprocess.run([binary, "pull", model], check=False)
    if result.returncode:
        raise typer.Exit(result.returncode)


@ollama_app.command("test")
def ollama_test_cmd(model: str | None = typer.Option(None, "--model")) -> None:
    """Ask the configured local model for one typed DolosSec planning turn without executing tools."""
    from .llm.ollama_provider import OllamaPlanner

    selected = model or settings.model or "qwen3.5:9b"
    planner = OllamaPlanner(selected)
    target = Target(kind=TargetKind.local_path, value="/authorized/example")
    try:
        turn = asyncio.run(planner.next_turn(target, [], 0))
    except Exception as exc:
        console.print(f"[red]Ollama test failed:[/red] {exc}")
        raise typer.Exit(1)
    console.print(f"[green]Model responded:[/green] {selected}")
    console.print_json(turn.model_dump_json(indent=2))


@ollama_app.command("install-guide")
def ollama_install_guide() -> None:
    """Print concise official installation steps for this operating system."""
    system = platform.system().lower()
    if system == "linux":
        console.print("[bold]Linux / Kali / Debian / Ubuntu[/bold]")
        console.print("1. curl -fsSL https://ollama.com/install.sh | sh")
        console.print("2. ollama --version")
        console.print("3. ollama pull qwen3.5:9b")
    elif system == "darwin":
        console.print("[bold]macOS[/bold]")
        console.print("1. Install Ollama.app from the official Ollama download page and launch it once.")
        console.print("2. ollama --version")
        console.print("3. ollama pull qwen3.5:9b")
    elif system == "windows":
        console.print("[bold]Windows[/bold]")
        console.print("1. Install OllamaSetup.exe from the official Ollama download page.")
        console.print("2. Open a new PowerShell window and run: ollama --version")
        console.print("3. ollama pull qwen3.5:9b")
    else:
        console.print("See docs/OLLAMA.md for installation and configuration.")
    console.print("\nThen configure DolosSec in .env:")
    console.print("DOLOS_LLM_PROVIDER=ollama")
    console.print("DOLOS_MODEL=qwen3.5:9b")
    console.print("DOLOS_OLLAMA_BASE_URL=http://127.0.0.1:11434")
    console.print("\nVerify with: dolos ollama status && dolos ollama test")


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
