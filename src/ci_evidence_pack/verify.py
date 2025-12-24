import shutil
import tarfile
import tempfile
import logging
from pathlib import Path
from typing import Optional, Dict, Any
from .util import run_command
from .manifest import calculate_file_hash

def safe_extract(tar: tarfile.TarFile, path: Path):
    """
    Extracts tarfile member safely, preventing path traversal.
    """
    for member in tar.getmembers():
        member_path = Path(member.name)
        if member_path.is_absolute():
            raise Exception(f"Unsafe absolute path: {member.name}")
        if ".." in member_path.parts:
             raise Exception(f"Unsafe path traversal: {member.name}")
        
        # Check for symlinks pointing outside?
        if member.issym() or member.islnk():
             # Strict mode: block all symlinks/hardlinks
             raise Exception(f"Unsafe symlink/hardlink blocked: {member.name}")
             
        # Extract
        tar.extract(member, path=path, set_attrs=False) # set_attrs=False avoids permission issues

def verify_cosign(
    bundle_path: Path, 
    sig_path: Path, 
    cert_path: Path, 
    identity: Optional[str], 
    issuer: Optional[str]
) -> None:
    if not shutil.which("cosign"):
        logging.warning("Cosign not found; cannot verify signature.")
        # Fail or just warn? Prompt: "return exit code 0.. 2 on evidence invalid .. 1 on runtime".
        # If user PROVIDED sig+cert, they expect verification.
        raise RuntimeError("Cosign binary missing.")

    cmd = [
        "cosign", "verify-blob",
        "--certificate", str(cert_path),
        "--signature", str(sig_path),
        str(bundle_path)
    ]
    if identity:
        cmd.extend(["--certificate-identity", identity])
    if issuer:
        cmd.extend(["--certificate-oidc-issuer", issuer])

    try:
        run_command(cmd)
        logging.info("Signature Verified.")
    except Exception:
        logging.error("Signature verification failed.")
        raise RuntimeError("Signature INVALID.")

def verify_manifest(extracted_dir: Path) -> None:
    manifest_file = extracted_dir / "manifest" / "sha256sum.txt"
    if not manifest_file.exists():
        raise ValueError("Manifest file missing from bundle.")

    # 1. Load Expected
    expected = {}
    with open(manifest_file, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line: continue
            parts = line.split("  ", 1)
            if len(parts) != 2:
                continue
            h, p = parts
            expected[p] = h

    # 2. Check all expected files
    # Also check for UNEXPECTED files (strict mode)
    # Walk directory
    
    found_paths = set()
    
    # We walk relative
    for p in extracted_dir.rglob("*"):
        if not p.is_file(): continue
        if p.name == ".DS_Store": continue
        
        rel = p.relative_to(extracted_dir)
        rel_str = str(rel)
        
        # Ignore manifest file itself for hash check
        if rel_str == str(Path("manifest/sha256sum.txt")):
            continue
            
        found_paths.add(rel_str)
        
        if rel_str not in expected:
            # Found file not in manifest
            raise ValueError(f"Unexpected file in bundle: {rel_str}")
        
        # Check hash
        curr = calculate_file_hash(p)
        if curr != expected[rel_str]:
            raise ValueError(f"Hash mismatch for {rel_str}: expected {expected[rel_str]}, got {curr}")
            
    # 3. Check for missing
    for p in expected:
        if p not in found_paths:
             raise ValueError(f"Missing file declared in manifest: {p}")

    logging.info(f"Manifest verified: {len(expected)} files ok.")
    return True

def verify_bundle(
    bundle_path: Path,
    sig_path: Optional[Path],
    cert_path: Optional[Path],
    identity: Optional[str],
    issuer: Optional[str]
) -> Dict[str, Any]:
    
    result = {
        "bundle_path": str(bundle_path),
        "signature_verified": None,
        "manifest_verified": False,
        "strict": True,
        "error": None
    }

    if not bundle_path.exists():
        # Let's return error dict instead of fail() so CLI can handle format
        # But wait, fail() exits 1. 
        # If we return dict, CLI needs to inspect and exit.
        result["error"] = f"Bundle not found: {bundle_path}"
        return result

    # Sig verify
    if sig_path and cert_path:
        try:
            verify_cosign(bundle_path, sig_path, cert_path, identity, issuer)
            result["signature_verified"] = True
        except RuntimeError as e:
             # verify_cosign raises RuntimeError on failure
             result["signature_verified"] = False
             result["error"] = str(e)
             return result
             
    elif sig_path or cert_path:
        result["error"] = "Both --sig and --cert must be provided for verification."
        return result
        
    # Extract
    with tempfile.TemporaryDirectory() as tmp:
        td = Path(tmp)
        try:
            with tarfile.open(bundle_path, "r:gz") as tar:
                safe_extract(tar, td)
        except Exception as e:
            result["error"] = f"Failed to extract bundle: {e}"
            return result
            
        try:
            verify_manifest(td)
            result["manifest_verified"] = True
        except ValueError as e:
            result["manifest_verified"] = False
            result["error"] = str(e)
            return result

    return result
