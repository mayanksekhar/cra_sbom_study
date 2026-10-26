#!/usr/bin/env bash
set -u
export PATH="$PATH:$HOME/go/bin"
cd "$(dirname "$0")/.."
source .venv/bin/activate 2>/dev/null
out=tools/pinned_versions.txt
{
  echo "recorded: $(date -u +%Y%m%dT%H%M%SZ)"
  echo "syft: $(syft version | awk '/^Version/{print $2}')"
  echo "trivy: $(trivy --version | head -n 1)"
  echo "grype: $(grype version | awk '/^Version/{print $2}')"
  echo "cdxgen: $(head -n 1 tools/cdxgen_version.txt)"
  echo "osv_scanner: $(osv-scanner --version 2>&1 | head -n 1)"
  echo "govulncheck: $(govulncheck -version 2>&1 | head -n 3 | tr '\n' ' ')"
  echo "vexctl: $(vexctl version 2>&1 | grep -iE '^ *gitversion' | head -n 1)"
  echo "depscan: $(depscan --version 2>&1 | head -n 1)"
  echo "sbomqs: $(sbomqs version 2>&1 | grep -iE '^ *(git)?version' | head -n 1)"
  echo "go: $(go version)"
  echo "python: $(python3 --version)"
  echo "node: $(node --version)"
} | tee "$out"
