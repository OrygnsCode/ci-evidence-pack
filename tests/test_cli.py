from typer.testing import CliRunner
from ci_evidence_pack.cli import app
import os
import shutil

runner = CliRunner()

import logging

def test_alias_logic_false(tmp_path, caplog):
    # Test --collection-git=false works and disables git.json
    with runner.isolated_filesystem(temp_dir=tmp_path):
        os.makedirs("repo")
        with caplog.at_level(logging.WARNING):
            result = runner.invoke(app, ["pack", "--repo", "repo", "--collection-git=false", "--sbom", "none"])
        assert result.exit_code == 0
        assert "DEPRECATED: use --collect-git/--no-collect-git" in caplog.text

def test_alias_logic_true(tmp_path, caplog):
    with runner.isolated_filesystem(temp_dir=tmp_path):
        os.makedirs("repo")
        with caplog.at_level(logging.WARNING):
            result = runner.invoke(app, ["pack", "--repo", "repo", "--collection-git=true", "--sbom", "none"])
        assert result.exit_code == 0
        assert "DEPRECATED: use --collect-git/--no-collect-git" in caplog.text
