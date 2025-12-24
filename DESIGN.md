# Design Document: CI Evidence Pack

## Overview
A tool to generate deterministic, read-only evidence bundles for compliance/audit, consisting of a Python CLI (`ci-evidence-pack`) and a Composite GitHub Action.

## Key Decisions

### 1. SBOM Strategy
- **Selected Approach**: Native Python generation using `cyclonedx-bom` library.
- **Reasoning**: avoids external binary dependencies (like `syft`) for the basic Python case, keeping the CLI portable. `syft` support can be added as a fallback via shell-out if strictly needed, but `cyclonedx-bom` satisfies the "prefer CycloneDX" requirement for Python projects.

### 2. Signing & Verification (Keyless)
- **Tool**: `cosign` (CLI) via subprocess.
- **Workflow**:
  - **Signing**: `cosign sign-blob --yes --output-certificate bundle.crt --output-signature bundle.sig bundle.tar.gz`
  - **Verification**: `cosign verify-blob --certificate bundle.crt --signature bundle.sig --certificate-identity <oidc-id> --certificate-oidc-issuer <oidc-iss> bundle.tar.gz`
- **Permissions**: The GitHub Action requires `id-token: write` to generate the OIDC token for Cosign.

### 3. Usage of `actions/upload-artifact` v4
- **Version**: v4
- **Inputs used**:
  - `name`: generic (e.g., `ci-evidence-pack`) or user-provided.
  - `path`: The bundle `.tar.gz` plus `.sig` and `.crt`.
  - `retention-days`: User configurable (default 30).
  - `if-no-files-found`: error.

### 4. Determinism Strategy
- **Archives**: Use Python `tarfile` with a custom filter to:
  - Reset `uid`/`gid` to 0.
  - Reset `uname`/`gname` to empty string.
  - Set `mtime` to `SOURCE_DATE_EPOCH` (or 0).
  - Sort file paths lexicographically before adding.
  - **Gzip**: Use `GzipFile` explicitly with `mtime=0` to ensure the gzip header is deterministic.
- **JSON**: Always `sort_keys=True`, `indent=2`.

## Project Structure
```text
.
├── pyproject.toml
├── src/
│   └── ci_evidence_pack/
│       ├── __init__.py
│       ├── cli.py        # Typer entrypoint
│       ├── pack.py       # Core packaging logic
│       ├── verify.py     # Verification logic
│       ├── sbom.py       # SBOM generation
│       ├── manifest.py   # Hashing and manifest creation
│       └── util.py       # Deterministic helpers
├── .github/
│   ├── actions/
│   │   └── ci-evidence-pack/
│   │       └── action.yml
│   └── workflows/
│       └── example.yml
└── README.md
```
