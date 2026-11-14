#!/usr/bin/env bash
# Extract raw package-manager ground truth from inside images (linux/amd64).
# Output: ground_truth/raw/<image>/{os.txt,pip.json,npm-app.json,npm-global.json,maven-runtime.txt,jar-libs.txt}
set -euo pipefail
cd "$(dirname "$0")/.."
P="--platform linux/amd64"
run(){ docker run --rm $P --entrypoint "$2" "$1" "${@:3}"; }

dpkg_dump(){ run "$1" sh -c "dpkg-query -W -f='\${db:Status-Abbrev}\t\${Package}\t\${Version}\t\${Architecture}\t\${source:Package}\n' | awk -F'\t' '\$1 ~ /^ii/'"; }
apk_dump(){ run "$1" sh -c "apk info -v 2>/dev/null"; }

out(){ mkdir -p "ground_truth/raw/$1"; echo "ground_truth/raw/$1"; }
# walk installed node_modules: app root (if given), global modules, /opt/yarn*
npm_walk(){ docker run --rm $P -v "$PWD/scripts/gt_npm_walk.js:/w.js:ro" --entrypoint sh "$1" -c \
  "node /w.js $2 /usr/local/lib \$(ls -d /opt/yarn* 2>/dev/null)"; }

# --- self-built ---
o=$(out sb-java-springboot)
dpkg_dump sbom/sb-java-springboot:1.0 > $o/os.txt
docker build -q $P --target build -t sbom/sb-java-build:1.0 images/sb-java-springboot >/dev/null
run sbom/sb-java-build:1.0 cat /src/gt-maven-runtime.txt > $o/maven-runtime.txt
run sbom/sb-java-build:1.0 cat /src/gt-maven-all.txt     > $o/maven-all.txt
run sbom/sb-java-build:1.0 sh -c "cd /src/target && jar tf demo-1.0.0.jar | grep '^BOOT-INF/lib/.*\.jar$'" > $o/jar-libs.txt
# group:artifact:version for every nested jar, from its embedded META-INF/maven/<g>/<a>/pom.properties
run sbom/sb-java-build:1.0 bash -c 'cd /tmp && mkdir x && cd x && jar xf /src/target/demo-1.0.0.jar BOOT-INF/lib && \
  for j in BOOT-INF/lib/*.jar; do p=$(jar tf "$j" | grep -m1 "^META-INF/maven/.*/pom.properties$"); \
    if [ -n "$p" ]; then unzip -p "$j" "$p" 2>/dev/null || (mkdir -p t && cd t && jar xf "../$j" "$p" && cat "$p"); \
    else echo "#nometa $j"; fi | grep -E "^(groupId|artifactId|version)=|^#nometa" | tr "\n" " "; echo; done' > $o/jar-coords.txt

for img in sb-node-lock sb-node-nolock; do
  o=$(out $img)
  dpkg_dump sbom/$img:1.0 > $o/os.txt
  run sbom/$img:1.0 sh -c "cd /app && npm ls --all --json --omit=dev" > $o/npm-app.json || true
  run sbom/$img:1.0 sh -c "npm ls -g --all --json" > $o/npm-global.json || true
  npm_walk sbom/$img:1.0 /app > $o/npm-walk.jsonl
done

for img in sb-py-pinned sb-py-loose; do
  o=$(out $img)
  dpkg_dump sbom/$img:1.0 > $o/os.txt
  run sbom/$img:1.0 python -m pip list --format=json > $o/pip.json
done

# --- public images: OS layer ground truth where a package DB is queryable ---
for pair in "debian|debian:12.7-slim" "ubuntu|ubuntu:24.04" "python|python:3.12.7-slim-bookworm" \
            "node|node:22.11.0-bookworm-slim" "tomcat|tomcat:10.1.31-jre21-temurin-jammy"; do
  IFS='|' read -r n ref <<<"$pair"; o=$(out $n)
  dpkg_dump "$ref" > $o/os.txt
done
o=$(out python); run python:3.12.7-slim-bookworm python -m pip list --format=json > $o/pip.json
o=$(out node);   run node:22.11.0-bookworm-slim sh -c "npm ls -g --all --json" > $o/npm-global.json || true
npm_walk node:22.11.0-bookworm-slim "" > $o/npm-walk.jsonl
o=$(out alpine); apk_dump alpine:3.20.3 > $o/os.txt
# distroless has no shell: copy dpkg status.d out of a created container
o=$(out distroless)
cid=$(docker create $P gcr.io/distroless/base-debian12:latest /noop)
rm -rf $o/status.d; docker cp "$cid:/var/lib/dpkg/status.d" $o/status.d; docker rm "$cid" >/dev/null
echo "ground truth raw files:"; find ground_truth/raw -type f | sort
