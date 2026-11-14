# Tool & Environment Versions

Recorded: 2026-10-25 (IST) / 2026-10-24 UTC

| Item | Version | Source |
|---|---|---|
| Host OS | macOS 26.2 (25C56), Apple Silicon arm64 | — |
| Docker Engine | 29.1.3 (Docker Desktop, linux/aarch64 VM) | docker.com |
| Target platform | **linux/amd64** for all pulls/builds/scans (emulated) | — |
| Syft | 1.55.0 (build 2026-10-19) | Homebrew core |
| Trivy | 0.76.1 | Homebrew core |
| cdxgen | 12.9.0 (local, `tools/node_modules`) | npm `@cyclonedx/cdxgen` |
| CycloneDX CLI | 0.33.1 | Homebrew core |
| Node.js / npm | 25.2.1 / 11.6.2 | host |
| Python | 3.13.9 (venv `.venv`) | host |
| Java / Maven (host) | 21.0.8 / 3.9.12 | host (images build Maven inside containers) |
| jq | 1.8.1 | host |
| Trivy Java DB | schema v1, UpdatedAt 2026-10-24 01:07 UTC, downloaded 2026-10-24 20:22 UTC | ghcr.io (auto-download on first jar scan) |

All three tools scan the same `docker save --platform linux/amd64` tarball (`images/_tar/<image>.tar`).
Syft: `docker-archive:` source; Trivy: `image --input`; cdxgen: `-t docker --spec-version 1.6`.
Output spec versions: Syft 1.7, Trivy 1.7, cdxgen 1.6 (pinned; its default is 1.7).

## Trivy supply-chain note
Official advisory **GHSA-69fq-xp46-6x23** ("Trivy ecosystem supply chain temporarily compromised",
CVE-2026-33634, March 19–22 2026) confirmed on github.com/aquasecurity/trivy/security/advisories.
Affected: v0.69.4 binary, v0.69.5/0.69.6 images, trivy-action / setup-trivy tags.
We use 0.76.1 (not in affected range). Trivy DB is not used for SBOM generation (`--format cyclonedx`, no vuln scan).
