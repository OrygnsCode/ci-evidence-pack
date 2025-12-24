import sys
import logging
import subprocess
import os
import json
import hashlib
from typing import List, Dict, Optional, Any
from pathlib import Path

# Try to import Rich, fail gracefully if not installed (though deps say it should be)
try:
    from rich.console import Console
    from rich.theme import Theme
except ImportError:
    Console = None
    
# Global console object
console: Optional["Console"] = None
_quiet_mode: bool = False
_json_mode: bool = False

def init_console(quiet: bool = False, json_mode: bool = False):
    """Initialize the global Rich console."""
    global console, _quiet_mode, _json_mode
    _quiet_mode = quiet
    _json_mode = json_mode
    
    if Console and not quiet and not json_mode:
        custom_theme = Theme({
            "info": "cyan",
            "warning": "yellow",
            "error": "bold red",
            "success": "bold green"
        })
        console = Console(theme=custom_theme, stderr=True)
    else:
        # No rich console in quiet/json or if missing
        console = None

def compute_file_sha256(path: Path) -> str:
    """Compute SHA256 hash of a file."""
    sha = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            sha.update(chunk)
    return sha.hexdigest()

def print_json(data: Any):
    """Print data as JSON to stdout."""
    print(json.dumps(data, indent=2, sort_keys=True))

def print_success(msg: str):
    """Print a success message."""
    if _quiet_mode or _json_mode:
        return
    if console:
        console.print(f"[success]✔ {msg}[/success]")
    else:
        print(f"✔ {msg}", file=sys.stderr)

def print_error(msg: str, hint: Optional[str] = None):
    """Print an error message."""
    # errors go to stderr unless we are strictly in json mode?
    # Spec says "On failure, still output JSON (with error populated) if --json is set"
    # So if json_mode, caller should handle printing JSON error. This helper might just log?
    # Actually, for standard errors routed here:
    if _json_mode:
        # If we are called, it might be a fatal error before we constructed the full JSON result.
        # We can try to print a minimal JSON error wrapper.
        pass # Let caller handle specific JSON structure if possible.
    elif _quiet_mode:
        pass # Quiet mode usually suppresses non-fatal? But fatal errors should be seen?
             # Spec: "suppress non-error logs". So error logs show.
        print(f"❌ {msg}", file=sys.stderr)
    else:
        if console:
            console.print(f"[error]❌ {msg}[/error]")
            if hint:
                console.print(f"[yellow]Hint: {hint}[/yellow]")
        else:
            print(f"❌ {msg}", file=sys.stderr)
            if hint:
                 print(f"Hint: {hint}", file=sys.stderr)

def setup_logging(debug: bool = False):
    """Configures logging for the CLI."""
    level = logging.DEBUG if debug else logging.INFO
    # If quiet or json, we suppress standard logging unless debug is ON?
    # Spec: "Keep existing logging for debug, but user-facing output should be Rich styled unless quiet/json."
    # If debug is True, we want logs.
    
    if _quiet_mode or _json_mode:
        if not debug:
            level = logging.CRITICAL + 1 # Suppress all
            
    logging.basicConfig(
        level=level,
        format="%(levelname)s: %(message)s",
        stream=sys.stderr
    )



def run_command(
    cmd: List[str], 
    cwd: Optional[Path] = None, 
    env: Optional[Dict[str, str]] = None,
    check: bool = True
) -> subprocess.CompletedProcess:
    """Run a subprocess command and return the result."""
    logging.debug(f"Running command: {' '.join(cmd)}")
    try:
        proc_env = os.environ.copy()
        if env:
            proc_env.update(env)

        return subprocess.run(
            cmd,
            cwd=cwd,
            env=proc_env,
            check=check,
            capture_output=True,
            text=True
        )
    except subprocess.CalledProcessError as e:
        logging.debug(f"Command failed with output: {e.stdout}")
        logging.debug(f"Command failed with stderr: {e.stderr}")
        if check:
            raise
        return e

def get_source_date_epoch() -> int:
    """Returns SOURCE_DATE_EPOCH as int, defaulting to 0."""
    val = os.environ.get("SOURCE_DATE_EPOCH", "0")
    try:
        return int(val)
    except ValueError:
        logging.warning(f"Invalid SOURCE_DATE_EPOCH '{val}', defaulting to 0")
        return 0

def stable_json_write(path: Path, data: Any):
    """Writes JSON to file deterministically (sorted keys, indent=2, utf-8, newline)."""
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, sort_keys=True, ensure_ascii=False)
        f.write("\n")
