import hashlib
import logging
from pathlib import Path
from typing import Dict

def calculate_file_hash(path: Path) -> str:
    """Calculates SHA256 hash of a file."""
    sha256 = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(65536)
            if not chunk:
                break
            sha256.update(chunk)
    return sha256.hexdigest()

def generate_manifest(bundle_root: Path) -> None:
    """
    Walks the bundle_root (excluding manifest/sha256sum.txt itself), 
    calculates hashes, and writes manifest/sha256sum.txt.
    """
    manifest_dir = bundle_root / "manifest"
    manifest_dir.mkdir(exist_ok=True, parents=True) 
    
    hashes: Dict[str, str] = {}
    
    # We walk relative paths to ensure identifying files correctly vs the root
    # Usage of sorted(rglob) ensures deterministic order of processing, 
    # though the dictionary keys sorting at the end is what matters for output.
    for p in sorted(bundle_root.rglob("*")):
        if not p.is_file():
            continue
        
        rel_path = p.relative_to(bundle_root)
        
        # Skip the manifest/sha256sum.txt file itself to avoid circular hashing.
        if rel_path.parts[0] == "manifest" and rel_path.name == "sha256sum.txt":
            continue
            
        hashes[str(rel_path)] = calculate_file_hash(p)
        
    # Write sha256sum.txt strictly sorted
    manifest_path = manifest_dir / "sha256sum.txt"
    with open(manifest_path, "w", encoding="utf-8") as f:
        for path in sorted(hashes.keys()):
            # Format: hash  path
            f.write(f"{hashes[path]}  {path}\n")
            
    logging.info(f"Generated manifest/sha256sum.txt with {len(hashes)} files.")
