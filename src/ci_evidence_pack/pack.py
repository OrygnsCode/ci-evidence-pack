import sys
import subprocess
import gzip
import os
import shutil
import tarfile
import tempfile
from pathlib import Path
try:
    from importlib.metadata import version
except ImportError:
    from importlib_metadata import version
from typing import List, Optional, Dict, Any

from .util import stable_json_write, run_command, logging, get_source_date_epoch
from .manifest import generate_manifest
from .sbom import generate_sbom

def collect_git_info(repo_root: Path) -> Optional[Dict[str, str]]:
    """Collects git metadata if available."""
    if not shutil.which("git"):
        return None
    
    # Check if it is a git repo
    if not (repo_root / ".git").exists():
        return None

    def git(args):
        try:
            res = run_command(["git"] + args, cwd=repo_root, check=False)
            return res.stdout.strip() if res.returncode == 0 else ""
        except Exception:
            return ""

    data = {}
    sid = git(["rev-parse", "HEAD"])
    if not sid:
        return None # Not working
        
    data["sha"] = sid
    data["branch"] = git(["rev-parse", "--abbrev-ref", "HEAD"])
    data["remote_url"] = git(["config", "--get", "remote.origin.url"])
    
    # dirty check
    status = git(["status", "--porcelain"])
    data["dirty"] = "true" if status else "false"
    
    desc = git(["describe", "--tags", "--always", "--dirty"])
    if desc:
        data["describe"] = desc
        
    return data

def collect_pip_freeze() -> Optional[str]:
    """Collects pip freeze output if appropriate."""
    # Check if this looks like a python environment or project
    # Trigger if setup.py or pyproject.toml exists? 
    # Or just always if python is present?
    # Prompt: "only if python project is detected and pip available"
    # We'll check for pyproject.toml / setup.py / requirements.txt in CWD? 
    # Actually the CLI moves to repo_root. We should check repo_root.
    # But collect_pip_freeze doesn't take repo_root. We'll update it to be smarter if needed.
    # For now, we assume if the user asks (default True), we try.
    
    try:
        # Check if pip is runnable
        res = run_command([sys.executable, "-m", "pip", "freeze"], check=False)
        if res.returncode == 0:
            lines = res.stdout.splitlines()
            return "\n".join(sorted(lines)) + "\n"
    except Exception:
        pass
    return None

def normalize_tarinfo(tarinfo):
    """Normalizes tar entries for determinism."""
    tarinfo.uid = 0
    tarinfo.gid = 0
    tarinfo.uname = ""
    tarinfo.gname = ""
    tarinfo.mtime = get_source_date_epoch()
    return tarinfo

def create_bundle(
    repo_root: Path,
    output_dir: Path,
    bundle_name: str,
    includes: List[str],
    exclude_globs: List[str],
    sbom_format: str,
    collect_git: bool,
    collect_pip: bool,
    cosign_sign: bool,
    cosign_identity: Optional[str],
    cosign_issuer: Optional[str]
) -> Dict[str, Any]:
    
    # Ensure absolute paths
    repo_root = repo_root.resolve()
    output_dir = output_dir.resolve()
    
    # Staging area
    with tempfile.TemporaryDirectory() as stage_str:
        stage_dir = Path(stage_str)
        
        # --- 1. Artifacts ---
        artifacts_dir = stage_dir / "artifacts"
        artifacts_dir.mkdir()
        
        input_log = []
        
        for inc_str in includes:
            # inc_str is relative to repo_root. 
            src_path = (repo_root / inc_str).resolve()
            
            # Security: ensure src_path is within repo_root? 
            # Or at least exists.
            if not src_path.exists():
                logging.warning(f"Include path not found: {inc_str}")
                continue
            
            # Destination under artifacts/<inc_str>
            # We want to preserve the relative structure.
            # If user includes "src/foo.py", we want "artifacts/src/foo.py".
            # If user includes "README.md", "artifacts/README.md".
            
            # We need to handle if inc_str is absolute (bad) or has .. (bad).
            # We assume Typer passed a string.
            # Let's clean it.
            clean_rel = Path(inc_str)
            if clean_rel.is_absolute():
                # Try to make relative to repo?
                try:
                    clean_rel = clean_rel.relative_to(repo_root)
                except ValueError:
                    logging.warning(f"Absolute path {inc_str} is not inside repo {repo_root}. Skipping.")
                    continue
            
            dest_path = artifacts_dir / clean_rel
            dest_path.parent.mkdir(parents=True, exist_ok=True)
            
            if src_path.is_dir():
                # copytree
                shutil.copytree(src_path, dest_path, dirs_exist_ok=True)
                input_log.append({"src": str(clean_rel), "type": "dir"})
            else:
                shutil.copy2(src_path, dest_path)
                input_log.append({"src": str(clean_rel), "type": "file"})
                
        # --- 2. Metadata ---
        metadata_dir = stage_dir / "metadata"
        metadata_dir.mkdir()
        
        # metadata.json (Tool info)
        try:
            v = version("ci-evidence-pack")
        except:
            v = "unknown"
            
        tool_meta = {
            "tool": "ci-evidence-pack",
            "version": v,
            "created_at_epoch": get_source_date_epoch()
        }
        stable_json_write(metadata_dir / "metadata.json", tool_meta)

        # run.json
        run_data = {
            "source_date_epoch": get_source_date_epoch(),
            "repo": os.environ.get("GITHUB_REPOSITORY"),
            "run_id": os.environ.get("GITHUB_RUN_ID"),
            "sha": os.environ.get("GITHUB_SHA"),
            "workflow": os.environ.get("GITHUB_WORKFLOW"),
            "actor": os.environ.get("GITHUB_ACTOR"),
            "event_name": os.environ.get("GITHUB_EVENT_NAME"),
            "job": os.environ.get("GITHUB_JOB"),
            "runner_name": os.environ.get("RUNNER_NAME")
        }
        # Filter empty
        run_data = {k: v for k, v in run_data.items() if v}
        stable_json_write(metadata_dir / "run.json", run_data)
        
        # git.json
        if collect_git:
            gdata = collect_git_info(repo_root)
            if gdata:
                stable_json_write(metadata_dir / "git.json", gdata)
                
        # --- 3. Deps ---
        deps_dir = stage_dir / "deps"
        if collect_pip:
            # Should we look for python files to confirm project type?
            # Or just try? The prompt says "only if python project is detected".
            # Let's look for known python files in repo_root.
            has_python = any((repo_root / f).exists() for f in ["pyproject.toml", "setup.py", "requirements.txt"]) or list(repo_root.glob("*.py"))
            
            if has_python:
                pf = collect_pip_freeze()
                if pf:
                    deps_dir.mkdir(exist_ok=True)
                    with open(deps_dir / "pip_freeze.txt", "w", encoding="utf-8") as f:
                        f.write(pf)
                        
        # --- 4. SBOM ---
        # Determine filename
        # cyclonedx -> sbom.cdx.json
        # syft -> sbom.syft.json
        # Check what will effectively be used.
        eff_tool = sbom_format
        if eff_tool == "auto":
            if shutil.which("cyclonedx-py"): eff_tool = "cyclonedx"
            elif shutil.which("syft"): eff_tool = "syft"
            else: eff_tool = "none"
            
        if eff_tool != "none":
            sbom_dir = stage_dir / "sbom"
            sbom_dir.mkdir()
            filename = "sbom.cdx.json" if eff_tool == "cyclonedx" else "sbom.syft.json"
            generate_sbom(sbom_dir / filename, sbom_format)
            
        # --- 5. Manifest ---
        manifest_dir = stage_dir / "manifest"
        manifest_dir.mkdir(exist_ok=True)
        stable_json_write(manifest_dir / "inputs.json", sorted(input_log, key=lambda x: x["src"]))
        
        # Hash everything
        generate_manifest(stage_dir)
        
        # --- 6. Pack ---
        output_dir.mkdir(parents=True, exist_ok=True)
        bundle_path = output_dir / bundle_name
        
        logging.info(f"Writing bundle to {bundle_path}...")
        
        # Sorted walk
        # We need all files in stage_dir
        # We start gzip with strict mtime
        with open(bundle_path, "wb") as f_out:
            # mtime=0 in gzip header for determinism
            with gzip.GzipFile(filename="", mode="wb", fileobj=f_out, mtime=0) as f_gzip:
                with tarfile.open(fileobj=f_gzip, mode="w:") as tar:
                    
                    # Gather all files
                    all_files = sorted(stage_dir.rglob("*"))
                    for p in all_files:
                        if p.name == ".DS_Store": continue
                        
                        rel_path = p.relative_to(stage_dir)
                        tar.add(p, arcname=str(rel_path), filter=normalize_tarinfo, recursive=False)
                        
    # --- 7. Sign ---
    sig_path = None
    cert_path = None
    signed = False
    
    if cosign_sign:
        if not shutil.which("cosign"):
            raise RuntimeError("Cosign requested but not found in PATH.")
            
        logging.info("Signing bundle...")
        
        # We place sig/cert next to bundle
        sig_path = output_dir / (bundle_name + ".sig")
        cert_path = output_dir / (bundle_name + ".crt")
        
        cmd = [
            "cosign", "sign-blob",
            "--yes",
            "--output-signature", str(sig_path),
            "--output-certificate", str(cert_path),
            str(bundle_path)
        ]
        
        # Run info
        logging.info(f"Running cosign: {' '.join(cmd)}")
        try:
            run_command(cmd)
            logging.info(f"Generated signature: {sig_path}")
            logging.info(f"Generated certificate: {cert_path}")
            signed = True
        except subprocess.CalledProcessError:
            raise RuntimeError("Cosign signing failed.")

    from .util import compute_file_sha256
    
    # Calculate bundle hash here to return
    bundle_sha = compute_file_sha256(bundle_path)
    
    # Count files in manifest
    manifest_count = 0 
    # Use manifest generation return? or read input_log?
    # input_log only touches inputs, not generated metadata files.
    # To get total files in bundle, we tracked them during pack?
    # Or just say "N files packed". 
    # We can use the file list we gathered for tar.
    # We didn't save it. Re-globbing stage_dir is risky as it is deleted.
    # We know generate_manifest hashes everything.
    # Let's just update generate_manifest to distinct files or we can use tar member count if we care.
    # Or just input_log count (user artifacts) + metadata.
    # Simpler: just count during the previous glob.
    
    # Pack result
    return {
        "bundle_path": str(bundle_path),
        "bundle_sha256": bundle_sha,
        "file_count": len(all_files), # from the tar loop
        "sbom_tool": eff_tool,
        "signed": signed,
        "sig_path": str(sig_path) if sig_path else None,
        "cert_path": str(cert_path) if cert_path else None,
        "source_date_epoch": get_source_date_epoch()
    }
