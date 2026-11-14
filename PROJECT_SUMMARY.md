# Project Summary — Work Done Till Now

**Project:** P16 — SBOM Generators Compared: Syft vs Trivy vs cdxgen on Container Images  
**Author:** Yuvraj Deshmukh  
**Institution:** International Institute of Information Technology Bangalore (IIITB)  
**Supervisor:** Prof. B. Thangaraju (CSE Project Elective)

---

## 1. Objective & Research Questions

We built a complete, reproducible empirical measurement study comparing three widely used open-source Software Bill of Materials (SBOM) generators—**Syft (v1.55.0)**, **Trivy (v0.76.1)**, and **cdxgen (v12.9.0)**—emitting **CycloneDX JSON** on `linux/amd64` container images.

The study addresses four core research questions:
- **RQ1 (Coverage & Accuracy):** Which tool finds the most real components per ecosystem (recall, precision, F1)?
- **RQ2 (Failure Modes):** Where and why does each tool miss or mislabel components?
- **RQ3 (Lock-File Impact):** Does the presence of a lock file or pinned manifest change tool accuracy on built container images?
- **RQ4 (Metadata Completeness & Operations):** How complete and consistent are version, PURL, license, CPE, supplier, and hash fields, as well as schema validity, run-to-run determinism, and scan runtime?

---

## 2. Container Image Corpus (12 `linux/amd64` Images)

We assembled and froze a 12-image corpus (`images/` and `results/corpus.csv`), pinned by SHA-256 digest and exported as `docker save` tarballs (`images/_tar/*.tar`) so all three tools scan the exact same bytes:

### Self-Built Images (5)
1. **`sb-java-springboot` (`sbom/sb-java-springboot:1.0`)**: Multi-stage Spring Boot 3.3.5 uber-jar on `eclipse-temurin:21-jre` (final image contains only the fat JAR + OS layer).
2. **`sb-node-lock` (`sbom/sb-node-lock:1.0`)**: Node.js 22 app built with `npm ci` from a `package-lock.json` (includes an uninstalled `devDependency`, `jest`, in the lockfile).
3. **`sb-node-nolock` (`sbom/sb-node-nolock:1.0`)**: Identical Node.js 22 app built with `npm install --no-package-lock` from caret ranges.
4. **`sb-py-pinned` (`sbom/sb-py-pinned:1.0`)**: Python 3.12 app installed from an exact `==` pinned `requirements.txt`.
5. **`sb-py-loose` (`sbom/sb-py-loose:1.0`)**: Python 3.12 app installed from a range-based `requirements.txt` (e.g., `django>=4.2,<5.0`), with `requirements.txt` retained in the image.

### Public / Official Images (7)
6. **`tomcat` (`tomcat:10.1.31-jre21-temurin-jammy`)**
7. **`node` (`node:22.11.0-bookworm-slim`)**
8. **`python` (`python:3.12.7-slim-bookworm`)**
9. **`debian` (`debian:12.7-slim`)**
10. **`ubuntu` (`ubuntu:24.04`)**
11. **`alpine` (`alpine:3.20.3`)**
12. **`distroless` (`gcr.io/distroless/base-debian12:latest`)**

---

## 3. Ground-Truth Engineering & Pitfalls Solved

We extracted **1,935 ground-truth components** (`ground_truth/*.csv` and `ground_truth/raw/`) directly from installed artifacts inside each container image:
- **OS Packages:** `dpkg-query` (status `ii` only) for Debian/Ubuntu, `apk info -v` for Alpine, and `/var/lib/dpkg/status.d` parsing for Distroless.
- **Python Packages:** `pip list --format=json` inside the container.
- **Key Pitfall 1 — npm Aliases & Out-of-Tree Global Packages:** `npm ls` reports aliased dependencies under their alias name (e.g., `string-width-cjs`) rather than the package's real identity (`string-width`) and misses `/opt/yarn*`. We wrote `scripts/gt_npm_walk.js` to walk all `node_modules` trees on disk and read every installed `package.json`.
- **Key Pitfall 2 — Spring Boot Fat-JAR Repackaging:** `mvn dependency:list` includes `spring-boot-starter-*` metadata POMs (absent from the final JAR) and omits `spring-boot-jarmode-tools` (injected by the Spring Boot repackager). We derived ground truth directly from the **37 nested JARs** inside `BOOT-INF/lib/` plus the application artifact (`edu.iiitb.sbom:demo`), mapped against resolved Maven build coordinates.

---

## 4. End-to-End Automated Pipeline (`Makefile` & `scripts/`)

The entire study is automated via `Makefile` so that `make analyze paper` regenerates all CSVs, figures, LaTeX tables, and number macros without requiring Docker:

| Script | What Was Implemented |
|---|---|
| `scripts/01_corpus.sh` | Builds the 5 self-built images and pulls the 7 public images (`--platform linux/amd64`), recording image digests and sizes in `results/corpus.csv`. |
| `scripts/02_ground_truth.sh` + `gt_npm_walk.js` | Extracts raw package lists from inside each image and compiles normalized ground-truth CSVs in `ground_truth/`. |
| `scripts/03_generate.sh` | Saves each image once via `docker save` and runs Syft, Trivy, and cdxgen on the identical tarball (`r1` main run on all 12 images + `r2–r4` determinism repeats on 3 images). Logs wall-clock runtime and exit codes to `results/run_log.csv`. |
| `scripts/04_validate.sh` | Validates all 36 main SBOMs with `cyclonedx validate` against their declared CycloneDX schema versions (`1.7` for Syft/Trivy, `1.6` for cdxgen) → `results/validation.csv`. |
| `scripts/normalize.py` | Parses PURLs into canonical `(eco, name, version)` tuples (PEP 503 normalization for PyPI, `group:artifact` for Maven, scope preservation for npm, Debian epoch stripping) → `results/normalized/`. |
| `scripts/measure.py` | Computes per-image and pooled micro-average Precision, Recall, and F1 (`results/metrics_gt.csv`, `results/metrics_by_eco.csv`), item-level diffs (`results/diffs.csv`), pairwise Jaccard similarity (`results/jaccard.csv`), exclusive tool overlaps (`results/overlap_counts.csv`), and field completeness (`results/fields_pooled.csv`). |
| `scripts/determinism.py` | Verifies run-to-run component-set equality across `r1–r4` (`results/determinism.csv`) and summarizes scan runtimes (`results/runtime_summary.csv`). |
| `scripts/failures.py` | Programmatically classifies every false positive, false negative, and cross-tool discrepancy into failure patterns `F1–F8` and `P1` (`results/failure_patterns.csv`, `results/jar_metadata.csv`). |
| `scripts/figures.py` | Generates publication-ready PDF and PNG plots in `figures/` (`fig1_recall_precision_by_eco`, `fig2_upset_overlap`, `fig3_f1_heatmap`). |
| `scripts/tables.py` | Generates LaTeX tables (`paper/tables/*.tex`) and 140+ LaTeX macros (`paper/numbers.tex`) so zero numbers are hardcoded in the paper prose. |

---

## 5. Key Empirical Findings

### 5.1 Pooled Accuracy by Ecosystem (`name+version` level)
| Ecosystem | Syft (P / R / F1) | Trivy (P / R / F1) | cdxgen (P / R / F1) | Key Takeaway |
|---|---|---|---|---|
| **Debian (`deb`)** | 1.000 / 1.000 / **1.000** | 1.000 / 1.000 / **1.000** | 0.707 / 1.000 / **0.828** | cdxgen emits 436 source packages alongside binary packages (`F1`). |
| **Alpine (`apk`)** | 1.000 / 1.000 / **1.000** | 1.000 / 1.000 / **1.000** | 0.824 / 1.000 / **0.903** | cdxgen emits 3 origin packages (`F1`). |
| **npm (`npm`)** | 1.000 / 1.000 / **1.000** | 1.000 / 1.000 / **1.000** | 1.000 / 1.000 / **1.000** | All three tools are exact on installed `node_modules`. |
| **PyPI (`pypi`)** | 1.000 / 1.000 / **1.000** | 1.000 / 1.000 / **1.000** | 0.865 / 1.000 / **0.928** | cdxgen emits 5 phantom version ranges from `requirements.txt` (`F2`). |
| **Maven (`maven`)** | 0.900 / 0.947 / **0.923** | 1.000 / 1.000 / **1.000** | 1.000 / 0.974 / **0.987** | Trivy resolves JARs via SHA-1 Java DB; Syft guesses coordinates when `pom.properties` is missing (`F3`). |

### 5.2 Cross-Tool Agreement
- Out of **2,458** distinct `(image, eco, name, version)` keys across all 12 images:
  - **1,953** are reported by all three tools.
  - **452** are reported only by **cdxgen** (driven by OS source/origin packages and range bounds).
  - **32** are reported only by **Syft** (guessed Maven coordinates, `jrt-fs`, runtime binaries).
  - **0** are reported only by **Trivy**.
- Mean pairwise Jaccard similarity across all 12 images:
  - **Syft–Trivy:** `0.978` (drops to `0.814` on `tomcat` due to Java JARs lacking `pom.properties`).
  - **cdxgen–Trivy:** `0.779`
  - **cdxgen–Syft:** `0.765`

### 5.3 Failure Pattern Taxonomy (RQ2)
- **F1 — OS source/origin package inflation (cdxgen: 439 entries):** Emits Debian source packages (`gcc-12`, `glibc`) and Alpine origin packages (`openssl`) as regular `library` components with no distinguishing filter property.
- **F2 — Manifest version ranges reported as versions (cdxgen: 5 entries):** On `sb-py-loose`, cdxgen parses `requirements.txt` ranges alongside `dist-info` metadata, creating phantom entries like `pyyaml@5.1` (from `>=5.1`).
- **F3 — Synthesized/incorrect Maven coordinates (Syft: 20 entries across `sb-java-springboot` and `tomcat`):** Because **17 of 37** nested JARs in the Spring Boot fat JAR lack `META-INF/maven/.../pom.properties`, Syft guesses coordinates from `MANIFEST.MF` (e.g., `checker-qual:checker-qual` instead of `org.checkerframework:checker-qual`, or `JarLauncher` as a groupId). Trivy achieves 100% accuracy by hashing JARs and querying its downloaded Java DB.
- **F4 — JDK internal JARs reported as Maven packages (Syft: 2 entries):** Reports JDK `lib/jrt-fs.jar` as `jrt-fs:jrt-fs`.
- **F5 — Missed nested JARs in fat JAR (Syft: 2, cdxgen: 1):** cdxgen misses `tomcat-embed-websocket`; Syft's 2 false negatives correspond to the mislabeled `F3` JARs.
- **F6 — Non-package artifacts without PURL (Syft: 18 entries):** Reports Windows `.exe` launchers bundled inside `pip`'s `distlib` as PURL-less `simple launcher` components.
- **F7 — Duplicate `(eco, name, version)` entries (Syft: 132, Trivy: 117, cdxgen: 56):** Mostly legitimate multi-path npm installs, plus cross-architecture Debian duplicates in cdxgen.
- **F8 — Uninstalled `devDependency` leak (All tools: 0):** None of the tools falsely reported `jest` from `package-lock.json`.
- **P1 — Unregistered language runtime binary detection (Syft: 8, cdxgen: 4, Trivy: 0):** Syft detects standalone `node`, `python`, and `openjdk` runtime binaries not registered in OS package managers.

### 5.4 Lock Files (RQ3), Field Completeness & Operational Metrics (RQ4)
- **Lock-file invariance on built images:** For Node.js (`sb-node-lock` vs `sb-node-nolock`), all three tools achieved `F1 = 1.000` regardless of lockfile presence. For Python, Syft and Trivy scored `1.000` on both `sb-py-pinned` and `sb-py-loose`, while cdxgen dropped from `1.000` to `0.848` on `sb-py-loose` because it mixed manifest range parsing (`F2`) with installed metadata.
- **Schema validity:** **36 / 36** SBOMs passed `cyclonedx validate`.
- **Determinism:** **9 / 9** tool × image cases produced 100% identical component sets across **4 repeated runs (`r1–r4`)**.
- **Scan runtime (median per image):** **Trivy `0.6 s`** (max `78.2 s` on first Java DB download), **Syft `2.9 s`**, **cdxgen `11.7 s`**.
- **Metadata fields:**
  - **CPEs:** Emitted **only by Syft** (`100%` of components).
  - **Hashes:** Trivy emits hashes for `100%` of language packages (`maven`, `npm`, `pypi`); cdxgen emits hashes for `69.3%` of OS packages; Syft emits `0%` hashes in CycloneDX output.
  - **Licenses:** High coverage in Syft (`91.5%–100%`) and Trivy (`93.5%–100%`); cdxgen covers npm (`99.1%`) but rarely OS (`1.1%`) or Maven (`4.0%`).

---

## 6. Deliverables Completed

1. **IEEE Conference Paper ([paper/main.tex](paper/main.tex) & [paper/main.pdf](paper/main.pdf)):**
   - Complete 9-section IEEEtran manuscript (`Abstract`, `Introduction`, `Background`, `Related Work`, `Methodology`, `Results`, `Failure Patterns`, `Discussion & Practitioner Guidance`, `Threats to Validity`, `Conclusion`, plus `Reproducibility`).
   - Backed by 15 citations in [paper/refs.bib](paper/refs.bib) (including EO 14028, EU CRA, Balliu et al. 2023, Zhou et al. 2025, Wang et al. 2026, Churakova et al. 2025, and the March 2026 Trivy supply-chain advisory GHSA-69fq-xp46-6x23).
   - Fully linked to auto-generated macros ([paper/numbers.tex](paper/numbers.tex)), LaTeX tables (`paper/tables/`), and vector PDF plots (`figures/`).
2. **Practitioner Decision Guide ([paper/practitioner_guide.md](paper/practitioner_guide.md)):**
   - 10-scenario lookup table mapping concrete use cases (OS base images, Java fat JARs, air-gapped CI, Node/Python builds, CPEs, hashes, runtime detection, CI speed, license compliance) to recommended tools and empirical evidence files.
3. **Environment & Provenance Record ([versions.md](versions.md)):**
   - Exact versions of all host tools, Trivy Java DB timestamp, and supply-chain security notes.
