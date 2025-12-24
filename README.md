# CI Evidence Pack Generator

A production-quality tool to generate deterministic, read-only evidence bundles for compliance and audits. It collects source code context, build artifacts, dependencies, and SBOMs into a single signed tarball.

## Features

- **Deterministic**: Output bytes depend strictly on inputs (files, environment variables, time). If `SOURCE_DATE_EPOCH` and build environment (e.g. `GITHUB_RUN_ID`) are constant, output is bit-for-bit identical.
- **Secure**: Supports keyless signing via Sigstore Cosign (OIDC).
- **Comprehensive**: Bundles Git metadata, SBOM (CycloneDX), dependencies, and user-provided artifacts.
- **Verifiable**: CLI command to verify manifests and signatures.

## Installation

```bash
pip install ci-evidence-pack
```
*(Or install from source)*

## Quickstart (Local)

Run the pack command in your repository root:

```bash
# Basic usage
ci-evidence-pack pack 

# Control collection
ci-evidence-pack pack --no-collect-git --no-collect-pip-freeze

# Include specific build artifacts
ci-evidence-pack pack --include dist/app.bin --include configs/

# Output modes
ci-evidence-pack pack --quiet                      # Prints only the bundle path
ci-evidence-pack pack --json > evidence.json       # Output machine-readable JSON

# Verify immediately:
ci-evidence-pack verify dist/ci-evidence-pack_*.tar.gz
ci-evidence-pack verify bundle.tar.gz --quiet      # Prints "OK" only
```

## GitHub Actions Usage

Use the composite action in your workflow.

### Prerequisites for Signing
If `sign: true` is used, your workflow **must** have `id-token: write` permission to allow Cosign keyless signing.

```yaml
jobs:
  build:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      id-token: write # REQUIRED for signing
    
    steps:
      - uses: actions/checkout@v4
      
      # ... Your build steps ...

      - name: Generate Evidence
        if: always() # Run even if build fails
        uses: OrygnsCode/ci-evidence-pack@main
        with:
          upload-name: evidence-bundle
          sign: 'true'
          include: |
            dist/
            reports/coverage.xml
          retention-days: 30
```

## Development

To install in editable mode for testing changes locally:
```bash
pip install -e .
```

## Verification & Security

To verify a downloaded bundle locally:

```bash
# Verify internal manifest (sha256 sums) and strict structure
ci-evidence-pack verify bundle.tar.gz
```

The tool enforces strict security rules:
- **Hash Verification**: All files must match manifest SHA256.
- **Strict Mode**: Verification fails if the bundle contains extra files not in the manifest.
- **Safe Extraction**: Verification fails if the bundle contains absolute paths, path traversal (`..`), symlinks, or hardlinks.

### Signature Verification
To verify Cosign Keyless Signature, you need the `.sig` and `.crt` files:
```bash
ci-evidence-pack verify bundle.tar.gz \
  --sig bundle.sig \
  --cert bundle.crt \
  --identity "https://github.com/OrygnsCode/ci-evidence-pack/.github/workflows/example.yml@refs/heads/main" \
  --issuer "https://token.actions.githubusercontent.com"
```

## Output Bundle Schema

The generated `.tar.gz` contains:

- `metadata/`
  - `metadata.json`: Tool version and `SOURCE_DATE_EPOCH`.
  - `git.json`: Commit SHA, branch, remote URL, dirty status.
  - `run.json`: GitHub Actions run details (Run ID, Actor, Workflow).
- `deps/`
  - `pip_freeze.txt`: Python environment state (if Python detected).

- `sbom/`
  - `sbom.cdx.json`: CycloneDX SBOM of the environment.
- `artifacts/`
  - User-provided files (directory structure preserved).
- `manifest/`
  - `inputs.json`: Log of what was collected and from where.
  - `sha256sum.txt`: SHA256 hashes of all files in the bundle.
