#!/usr/bin/env bash
# Build self-built images and pull public images for linux/amd64; record digests in results/corpus.csv
set -euo pipefail
cd "$(dirname "$0")/.."
PLAT=linux/amd64
# name|ref|ecosystem|self_built|lock_file
CORPUS=(
 "sb-java-springboot|sbom/sb-java-springboot:1.0|java|yes|no(fat-jar)"
 "tomcat|tomcat:10.1.31-jre21-temurin-jammy|java|no|n/a"
 "sb-node-lock|sbom/sb-node-lock:1.0|node|yes|yes"
 "sb-node-nolock|sbom/sb-node-nolock:1.0|node|yes|no"
 "node|node:22.11.0-bookworm-slim|node|no|n/a"
 "sb-py-pinned|sbom/sb-py-pinned:1.0|python|yes|yes(pinned)"
 "sb-py-loose|sbom/sb-py-loose:1.0|python|yes|no(ranges)"
 "python|python:3.12.7-slim-bookworm|python|no|n/a"
 "debian|debian:12.7-slim|os|no|n/a"
 "ubuntu|ubuntu:24.04|os|no|n/a"
 "alpine|alpine:3.20.3|os|no|n/a"
 "distroless|gcr.io/distroless/base-debian12:latest|os|no|n/a"
)
echo "image,ref,digest,image_id,ecosystem,self_built,lock_file,size_mb" > results/corpus.csv
for row in "${CORPUS[@]}"; do
  IFS='|' read -r name ref eco self lock <<<"$row"
  if [[ $self == yes ]]; then
    docker build --platform $PLAT -t "$ref" "images/$name"
  else
    docker pull --platform $PLAT "$ref"
  fi
  id=$(docker image inspect "$ref" --format '{{.Id}}')
  digest=$(docker image inspect "$ref" --format '{{join .RepoDigests ","}}')
  [[ -z $digest ]] && digest="local:$id"
  size=$(docker image inspect "$ref" --format '{{.Size}}' | awk '{printf "%.1f",$1/1048576}')
  echo "$name,$ref,$digest,$id,$eco,$self,$lock,$size" >> results/corpus.csv
done
column -s, -t results/corpus.csv | cut -c1-200
