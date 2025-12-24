import os
import sys
import typer
from pathlib import Path
from typing import List, Optional
try:
    from importlib.metadata import version
except ImportError:
    from importlib_metadata import version

from .pack import create_bundle
from .verify import verify_bundle
from .util import (
    setup_logging, logging, init_console, 
    print_json, print_success, print_error
)
from . import util

app = typer.Typer(help="CI Evidence Pack Generator", add_completion=False)

def version_callback(value: bool):
    if value:
        try:
            v = version("ci-evidence-pack")
        except:
            v = "unknown"
        typer.echo(f"ci-evidence-pack v{v} - Made by OrygnsCode")
        raise typer.Exit()

@app.callback()
def main_callback(
    version: Optional[bool] = typer.Option(
        None, "--version", callback=version_callback, is_eager=True, help="Show version."
    )
):
    pass

@app.command()

def pack(
    repo: Path = typer.Option(Path("."), help="Path to repo root"),
    out: Path = typer.Option(Path("dist"), help="Output directory"),
    bundle_name: Optional[str] = typer.Option(None, help="Override bundle filename"),
    include: List[str] = typer.Option([], help="Files/dirs to include (relative to repo)"),
    sbom: str = typer.Option("auto", help="SBOM tool: cyclonedx, syft, none, auto"),
    collect_pip_freeze: bool = typer.Option(True, help="Collect pip freeze if python detected"),
    collect_git: bool = typer.Option(True, help="Collect git metadata"),
    
    # Deprecated aliases
    collection_git: Optional[str] = typer.Option(None, "--collection-git", hidden=True, help="Deprecated alias for --collect-git"),
    
    # Signing
    cosign_sign: bool = typer.Option(False, help="Sign with Cosign (requires OIDC/id-token)"),
    cosign_identity: Optional[str] = typer.Option(None),
    cosign_issuer: Optional[str] = typer.Option(None),
    
    # Modes
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Minimal output"),
    json_mode: bool = typer.Option(False, "--json", help="Output JSON only"),
    debug: bool = typer.Option(False, help="Enable debug logging")
):
    """
    Create an evidence bundle.
    """
    init_console(quiet=quiet, json_mode=json_mode)
    setup_logging(debug)
    
    rich_enabled = bool(util.console) and (not quiet) and (not json_mode)

    # Handle aliases
    if collection_git is not None:
        logging.warning("DEPRECATED: use --collect-git/--no-collect-git")
        val = collection_git.lower()
        if val in ["true", "1", "yes", "on", ""]:
             collect_git = True
        elif val in ["false", "0", "no", "off"]:
             collect_git = False
        else:
             logging.warning(f"Ignoring unrecognized value for deprecated flag: {val}. Defaulting to True.")
             collect_git = True
    
    if not bundle_name:
        sha = os.environ.get("GITHUB_SHA", "nosha")[:7]
        run_id = os.environ.get("GITHUB_RUN_ID", "local")
        repo_name = repo.resolve().name
        bundle_name = f"ci-evidence-pack_{repo_name}_{sha}_{run_id}.tar.gz"
        
    try:
        if rich_enabled and util.console:
            util.console.rule("[bold cyan]CI Evidence Pack - Generator[/bold cyan]")
            
        result = create_bundle(
            repo_root=repo,
            output_dir=out,
            bundle_name=bundle_name,
            includes=include,
            exclude_globs=[],
            sbom_format=sbom,
            collect_git=collect_git,
            collect_pip=collect_pip_freeze,
            cosign_sign=cosign_sign,
            cosign_identity=cosign_identity,
            cosign_issuer=cosign_issuer
        )
        
        if json_mode:
            print_json(result)
        elif quiet:
            print(result["bundle_path"])
        else:
            # Rich Output
            from rich.table import Table
            
            # Summary Table
            table = Table(title="Bundle Contents", show_header=True, header_style="bold magenta")
            table.add_column("Property", style="cyan")
            table.add_column("Value", style="green")
            
            table.add_row("Bundle Path", result["bundle_path"])
            table.add_row("Files Packed", str(result["file_count"]))
            table.add_row("SBOM Tool", result["sbom_tool"])
            table.add_row("Signed", "✅ Yes" if result["signed"] else "No")
            
            if rich_enabled and util.console:
                util.console.print(table)
            print_success(f"Bundle created: {result['bundle_path']}")
            
    except Exception as e:
        if json_mode:
            print_json({"error": str(e)})
            raise typer.Exit(code=1)
        print_error(str(e))
        raise typer.Exit(code=1)

@app.command()
def verify(
    bundle: Path = typer.Argument(..., help="Path to bundle .tar.gz"),
    sig: Optional[Path] = typer.Option(None, help="Path to .sig file"),
    cert: Optional[Path] = typer.Option(None, help="Path to .crt file"),
    identity: Optional[str] = typer.Option(None, help="Expected identity"),
    issuer: Optional[str] = typer.Option(None, help="Expected issuer"),
    
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Minimal output"),
    json_mode: bool = typer.Option(False, "--json", help="Output JSON only"),
    debug: bool = typer.Option(False, help="Enable debug logging")
):
    """
    Verify an evidence bundle.
    """
    init_console(quiet=quiet, json_mode=json_mode)
    setup_logging(debug)

    rich_enabled = bool(util.console) and (not quiet) and (not json_mode)
    
    try:
        # Explicit check for bundle existence to match strict requirements
        if not bundle.exists():
            msg = f"Bundle not found: {bundle}"
            if json_mode:
                print_json({"error": msg})
                raise typer.Exit(code=1)
            else:
                print_error(msg)
                raise typer.Exit(code=1)

        if rich_enabled and util.console:
            util.console.rule("[bold cyan]CI Evidence Pack - Verifier[/bold cyan]")
            
        result = verify_bundle(bundle, sig, cert, identity, issuer)
        
        if result.get("error"):
            # Logic failure (verification failed)
            if json_mode:
                # Still output JSON with error, then exit
                print_json(result)
                raise typer.Exit(code=2)
            elif quiet:
                # Quiet mode failure? Spec says "suppress non-error logs".
                # Errors should show.
                print_error(result["error"])
                raise typer.Exit(code=2)
            else:
                print_error(result["error"])
                raise typer.Exit(code=2)

        # Success path
        if json_mode:
            print_json(result)
        elif quiet:
            print("OK")
        else:
            from rich.panel import Panel
            
            if rich_enabled and util.console:
                util.console.print(Panel(f"[bold green]Bundle Verified Successfully[/bold green]\n\nPath: {result['bundle_path']}", title="Verification Result", border_style="green"))
            print_success("Verification Complete")

    except typer.Exit:
        raise
    except Exception as e:
        # Runtime/Unexpected failure
        if json_mode:
            print_json({"error": str(e)})
            raise typer.Exit(code=1)
        print_error(f"Runtime Error: {str(e)}")
        raise typer.Exit(code=1)

def main():
    app()

if __name__ == "__main__":
    main()
