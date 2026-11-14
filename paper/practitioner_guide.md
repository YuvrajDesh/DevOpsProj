# Practitioner Guide: Choosing an SBOM Generator for Container Images

Based on our measurements (Syft 1.55.0, Trivy 0.76.1, cdxgen 12.9.0; 12 linux/amd64 images; CycloneDX JSON).
Evidence for each row is in `results/` (file in brackets). This is a small study, so check results on your own images.

| # | Scenario | Recommended | Why (evidence) |
|---|---|---|---|
| 1 | OS base images (Debian/Ubuntu/Alpine/distroless) | **Syft or Trivy** | Both exact (P=R=1.0) on every OS package. cdxgen also lists source/origin packages as components (P=0.71 on Debian). [metrics_by_eco.csv, failure_patterns.csv F1] |
| 2 | Java fat/uber jars (Spring Boot), app servers (Tomcat) | **Trivy** | Resolves jars by SHA-1 through its Java DB, so it is exact even when jars have no `pom.properties` (17/37 here). Syft guesses group IDs/versions from MANIFEST (20 wrong coordinates). [failure_patterns.csv F3, jar_metadata.csv] |
| 3 | Air-gapped / offline CI with Java | **Syft** (+ manual review of Maven coordinates) | Trivy's Java accuracy needs a network-fetched Java DB. Without it, expect coordinate issues similar to Syft's. Mirror the DB if you can. [versions.md] |
| 4 | Installed Node.js apps (with or without package-lock) | **Any of the three** | All exact on installed `node_modules`. A lock file made no difference, and no tool reported the uninstalled devDependency. [metrics_gt.csv sb-node-*] |
| 5 | Python images built from a range-based `requirements.txt` | **Syft or Trivy** | cdxgen also reports the lower bounds of the ranges as versions (`pyyaml@5.1`), creating phantom components. [diffs.csv F2] |
| 6 | You need CPEs (e.g. NVD-based matching) | **Syft** | The only tool here that emits CPEs (100% of components). [fields_pooled.csv] |
| 7 | You need component hashes for integrity checks | **Trivy** (language pkgs) / **cdxgen** (OS pkgs) | Syft's CycloneDX output has no hashes. [fields_pooled.csv] |
| 8 | You also want language runtimes / binaries listed (node, python, openjdk) | **Syft** | Detects runtimes not registered with any package manager. [failure_patterns.csv P1] |
| 9 | Fastest CI scans | **Trivy** | Median 0.6 s/image, vs Syft 2.9 s and cdxgen 11.7 s (emulated amd64). [runtime_summary.csv] |
| 10 | Licence inventory | **Syft or Trivy** | Licences on >90% of components in every ecosystem. cdxgen rarely gives licences for OS/Maven packages. [fields_pooled.csv] |

## General rules
- **Pin the tool version and record its databases** (Trivy Java DB date). All three tools were deterministic run-to-run, but results change across versions and DB updates.
- **Verify tool provenance.** Trivy v0.69.4 binaries, the v0.69.5–0.69.6 images and the trivy-action tags were compromised in March 2026 (GHSA-69fq-xp46-6x23). Pin release digests or checksums, and pin GitHub Actions by commit SHA.
- **Scan the exact artifact you ship** (e.g. a `docker save` tarball) so SBOM and image cannot drift.
- **Don't merge SBOMs from different tools naively.** Component identity (Maven group IDs, Debian source vs binary packages) differs, so a union inflates counts.
