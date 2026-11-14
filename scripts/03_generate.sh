#!/usr/bin/env bash
# Generate CycloneDX JSON SBOMs with syft, trivy, cdxgen.
# Usage: scripts/03_generate.sh [run_id] [image ...]   (run_id r1 -> sboms/<tool>/, else sboms/_runs/<run_id>/<tool>/)
set -uo pipefail
cd "$(dirname "$0")/.."
RUN=${1:-r1}; shift || true
PLAT=linux/amd64
CDXGEN="$PWD/tools/node_modules/.bin/cdxgen"
now(){ perl -MTime::HiRes=time -e 'printf "%.3f\n", time'; }
[[ -f results/run_log.csv ]] || echo "run,tool,image,ref,exit,seconds,components,out" > results/run_log.csv

if [[ $# -gt 0 ]]; then IMAGES=("$@"); else IMAGES=($(tail -n +2 results/corpus.csv | cut -d, -f1)); fi

for img in "${IMAGES[@]}"; do
  ref=$(awk -F, -v n="$img" '$1==n{print $2}' results/corpus.csv)
  tar="$PWD/images/_tar/$img.tar"
  [[ -f $tar ]] || { mkdir -p images/_tar; docker save --platform $PLAT -o "$tar" "$ref"; }
  for tool in syft trivy cdxgen; do
    if [[ $RUN == r1 ]]; then d=sboms/$tool; else d=sboms/_runs/$RUN/$tool; fi
    mkdir -p "$d" results/logs/$RUN
    out="$d/$img.cdx.json"; log="results/logs/$RUN/$tool-$img.log"
    t0=$(now)
    case $tool in
      syft)   syft scan "docker-archive:$tar" -o "cyclonedx-json=$out" >"$log" 2>&1 ;;
      trivy)  trivy image --quiet --input "$tar" --format cyclonedx --output "$out" >"$log" 2>&1 ;;
      cdxgen) "$CDXGEN" -t docker --spec-version 1.6 -o "$out" "$tar" >"$log" 2>&1 ;;
    esac
    rc=$?; t1=$(now)
    n=$(jq '[.. | objects | select(has("bom-ref") and (.type=="library" or .type=="application" or .type=="framework"))] | length' "$out" 2>/dev/null || echo NA)
    secs=$(echo "$t1 - $t0" | bc)
    echo "$RUN,$tool,$img,$ref,$rc,$secs,$n,$out" | tee -a results/run_log.csv
  done
done
