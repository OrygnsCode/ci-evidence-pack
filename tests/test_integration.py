import os
import tarfile
import time
import pytest
import shutil
import hashlib
from pathlib import Path
from ci_evidence_pack.pack import create_bundle
from ci_evidence_pack.verify import verify_bundle, safe_extract

# Helpers
def create_random_files(root: Path):
    (root / "file1.txt").write_text("hello")
    # set random mtime
    os.utime(root / "file1.txt", (12345, 67890))
    
    (root / "subdir").mkdir()
    (root / "subdir" / "file2.txt").write_text("world")
    os.utime(root / "subdir" / "file2.txt", (11111, 22222))

def test_determinism(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    create_random_files(repo)
    
    out1 = tmp_path / "out1"
    out2 = tmp_path / "out2"
    
    # We set env var so get_source_date_epoch picks it up
    os.environ["SOURCE_DATE_EPOCH"] = "1700000000"
    
    try:
        res1 = create_bundle(
            repo_root=repo,
            output_dir=out1,
            bundle_name="bundle.tar.gz",
            includes=["file1.txt", "subdir"],
            exclude_globs=[],
            sbom_format="none",
            collect_git=False,
            collect_pip=False,
            cosign_sign=False,
            cosign_identity=None,
            cosign_issuer=None
        )
        b1 = Path(res1["bundle_path"])
        
        # Simulate time passage
        time.sleep(1.1)
        
        res2 = create_bundle(
            repo_root=repo,
            output_dir=out2,
            bundle_name="bundle.tar.gz",
            includes=["file1.txt", "subdir"],
            exclude_globs=[],
            sbom_format="none",
            collect_git=False,
            collect_pip=False,
            cosign_sign=False,
            cosign_identity=None,
            cosign_issuer=None
        )
        b2 = Path(res2["bundle_path"])
        
        # Binary compare
        assert b1.read_bytes() == b2.read_bytes()
        
        # SHA256 compare
        h1 = hashlib.sha256(b1.read_bytes()).hexdigest()
        h2 = hashlib.sha256(b2.read_bytes()).hexdigest()
        assert h1 == h2
        
    finally:
        del os.environ["SOURCE_DATE_EPOCH"]

def test_verify_manifest_tamper(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "data.txt").write_text("verifiable")
    
    out = tmp_path / "out"
    res = create_bundle(
        repo_root=repo,
        output_dir=out,
        bundle_name="bundle.tar.gz",
        includes=["data.txt"],
        exclude_globs=[],
        sbom_format="none",
        collect_git=False,
        collect_pip=False,
        cosign_sign=False,
        cosign_identity=None,
        cosign_issuer=None
    )
    bundle = Path(res["bundle_path"])
    
    # 1. Verify success
    vres = verify_bundle(bundle, None, None, None, None)
    assert vres["manifest_verified"] is True
    assert vres["error"] is None
    
    # 2. Tamper
    # Extract safely
    mod_dir = tmp_path / "mod"
    mod_dir.mkdir()
    with tarfile.open(bundle, "r:gz") as tar:
        safe_extract(tar, mod_dir)
        
    # Modify file content (hash mismatch)
    (mod_dir / "artifacts" / "data.txt").write_text("corrupted")
    
    # Repack meticulously to preserve structure so ONLY hash fails
    bad_bundle = out / "bad.tar.gz"
    
    # We must match the pack logic: mtime=0, gzip
    import gzip
    with open(bad_bundle, "wb") as f_out:
         with gzip.GzipFile(filename="", mode="wb", fileobj=f_out, mtime=0) as f_gzip:
             with tarfile.open(fileobj=f_gzip, mode="w:") as tar:
                 for p in sorted(mod_dir.rglob("*")):
                     rel = p.relative_to(mod_dir)
                     tar.add(p, arcname=str(rel), recursive=False)
                     
    # Verify should fail
    # Old logic: SystemExit(2)
    # New logic: returns dict with error
    vres_bad = verify_bundle(bad_bundle, None, None, None, None)
    assert vres_bad["manifest_verified"] is False
    assert vres_bad["error"] is not None
    assert "Hash mismatch" in vres_bad["error"]

def test_verify_extra_file(tmp_path):
    """Test strict mode: extra file in bundle causes failure."""
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "ok.txt").write_text("ok")
    
    out = tmp_path / "out"
    res = create_bundle(
        repo_root=repo,
        output_dir=out,
        bundle_name="bundle.tar.gz",
        includes=["ok.txt"],
        exclude_globs=[],
        sbom_format="none",
        collect_git=False,
        collect_pip=False,
        cosign_sign=False,
        cosign_identity=None,
        cosign_issuer=None
    )
    bundle = Path(res["bundle_path"])
    
    mod_dir = tmp_path / "mod_extra"
    mod_dir.mkdir()
    with tarfile.open(bundle, "r:gz") as tar:
        safe_extract(tar, mod_dir)
        
    # Add extra file
    (mod_dir / "extra_evil.txt").write_text("i am extra")
    
    bad_bundle = out / "bad_extra.tar.gz"
    import gzip
    with open(bad_bundle, "wb") as f_out:
         with gzip.GzipFile(filename="", mode="wb", fileobj=f_out, mtime=0) as f_gzip:
             with tarfile.open(fileobj=f_gzip, mode="w:") as tar:
                 for p in sorted(mod_dir.rglob("*")):
                     rel = p.relative_to(mod_dir)
                     tar.add(p, arcname=str(rel), recursive=False)
                     
    vres = verify_bundle(bad_bundle, None, None, None, None)
    assert vres["manifest_verified"] is False
    assert "Unexpected file" in vres["error"]

def test_verify_symlink_fail(tmp_path):
    """Test that valid tar with symlink is rejected by verify."""
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "data.txt").write_text("content")
    
    out = tmp_path / "out"
    res = create_bundle(
        repo_root=repo,
        output_dir=out,
        bundle_name="bundle.tar.gz",
        includes=["data.txt"],
        exclude_globs=[],
        sbom_format="none",
        collect_git=False,
        collect_pip=False,
        cosign_sign=False,
        cosign_identity=None,
        cosign_issuer=None
    )
    bundle = Path(res["bundle_path"])
    
    # Extract
    mod_dir = tmp_path / "mod_sym"
    mod_dir.mkdir()
    with tarfile.open(bundle, "r:gz") as tar:
         safe_extract(tar, mod_dir)
         
    # Add symlink
    (mod_dir / "bad_link").symlink_to("artifacts/data.txt")
    
    bad_bundle = out / "bad_sym.tar.gz"
    import gzip
    with open(bad_bundle, "wb") as f_out:
         with gzip.GzipFile(filename="", mode="wb", fileobj=f_out, mtime=0) as f_gzip:
             with tarfile.open(fileobj=f_gzip, mode="w:") as tar:
                 # Adding symlink to tar
                 for p in sorted(mod_dir.rglob("*")):
                     rel = p.relative_to(mod_dir)
                     tar.add(p, arcname=str(rel), recursive=False)
                     
    # Verify should fail with result dict error (no exit)
    vres = verify_bundle(bad_bundle, None, None, None, None)
    assert vres["error"] is not None
    assert "Failed to extract bundle" in vres["error"] or "Unsafe symlink" in vres["error"]
