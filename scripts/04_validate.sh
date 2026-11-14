#!/usr/bin/env bash
# Validate every SBOM against its declared CycloneDX spec version with CycloneDX CLI.
set -uo pipefail
cd "$(dirname "$0")/.."
echo "tool,image,spec_version,valid,message" > results/validation.csv
for f in sboms/{syft,trivy,cdxgen}/*.cdx.json; do
  tool=$(basename "$(dirname "$f")"); img=$(basename "$f" .cdx.json)
  sv=$(jq -r '.specVersion // "unknown"' "$f" 2>/dev/null || echo unparseable)
  msg=$(cyclonedx validate --input-file "$f" --input-format json --input-version "v${sv/./_}" --fail-on-errors 2>&1)
  rc=$?; [[ $rc == 0 ]] && ok=yes || ok=no
  echo "$tool,$img,$sv,$ok,\"$(echo "$msg" | tr '\n",' ' ;;' | cut -c1-300)\"" >> results/validation.csv
done
column -s, -t results/validation.csv | cut -c1-140
