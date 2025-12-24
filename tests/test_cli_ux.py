import json
import os
from typer.testing import CliRunner
from ci_evidence_pack.cli import app

runner = CliRunner()

def test_version_branding():
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert "Made by OrygnsCode" in result.stdout

def test_pack_quiet(tmp_path):
    with runner.isolated_filesystem(temp_dir=tmp_path):
        os.makedirs("repo")
        result = runner.invoke(app, ["pack", "--repo", "repo", "--quiet", "--sbom", "none", "--no-collect-git"])
        assert result.exit_code == 0
        lines = result.stdout.strip().splitlines()
        # Should be exactly one line with path
        assert len(lines) == 1
        assert lines[0].endswith(".tar.gz")
        assert "ci-evidence-pack_" in lines[0]

def test_pack_json(tmp_path):
    with runner.isolated_filesystem(temp_dir=tmp_path):
        os.makedirs("repo")
        result = runner.invoke(app, ["pack", "--repo", "repo", "--json", "--sbom", "none", "--no-collect-git"], catch_exceptions=False)
        assert result.exit_code == 0
        try:
            data = json.loads(result.stdout)
        except json.JSONDecodeError:
            print(f"DEBUG STDOUT: {result.stdout!r}")
            raise
        assert "bundle_path" in data
        assert "bundle_sha256" in data
        assert "file_count" in data
        assert data["signed"] is False

def test_verify_quiet(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "f.txt").write_text("content")
    
    from ci_evidence_pack.pack import create_bundle
    bundle = create_bundle(repo, tmp_path, "b.tar.gz", ["f.txt"], [], "none", False, False, False, None, None)["bundle_path"]
    
    result = runner.invoke(app, ["verify", str(bundle), "--quiet"], catch_exceptions=False)
    assert result.exit_code == 0
    assert result.stdout.strip() == "OK"

def test_verify_json(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    
    from ci_evidence_pack.pack import create_bundle
    # Note: create_bundle is not mocking logging, so it might log to stderr.
    # But logging should be suppressed by CLI init.
    (repo / "f.txt").write_text("content")
    bundle = create_bundle(repo, tmp_path, "b.tar.gz", ["f.txt"], [], "none", False, False, False, None, None)["bundle_path"]
    
    result = runner.invoke(app, ["verify", str(bundle), "--json"], catch_exceptions=False)
    assert result.exit_code == 0
    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError:
        print(f"DEBUG STDOUT: {result.stdout!r}")
        raise
    assert data["manifest_verified"] is True
    assert data["strict"] is True

def test_verify_error_json(tmp_path):
    # Verify missing file
    result = runner.invoke(app, ["verify", "missing.tar.gz", "--json"])
    assert result.exit_code != 0
    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError:
        print(f"DEBUG STDOUT: {result.stdout!r}")
        raise
    assert "error" in data
    assert "Bundle not found" in data["error"]
