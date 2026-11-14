# P16 — SBOM Generators Compared: Syft vs Trivy vs cdxgen

Comparative measurement study of SBOM coverage and accuracy on 12 `linux/amd64` container images
(IIIT Bangalore, CSE project elective, Prof. B. Thangaraju).

* Paper draft: [paper/main.tex](paper/main.tex) (IEEEtran) · Practitioner guide: [paper/practitioner_guide.md](paper/practitioner_guide.md)
* Tool/env versions: [versions.md](versions.md) · Corpus + digests: [results/corpus.csv](results/corpus.csv)

## Layout
```
images/<name>/            Dockerfiles + app sources for the 5 self-built images
images/_tar/              docker-save tarballs actually scanned (gitignored, regenerable)
ground_truth/raw/<img>/   raw extracts: dpkg/apk, pip list, npm walk, jar listing, mvn lists
ground_truth/<img>.csv    normalized ground truth (eco,name,version,layer)
sboms/<tool>/<img>.cdx.json         main run (r1)
sboms/_runs/<run>/<tool>/...        pilot + determinism repeats (r2–r4)
results/                  run_log, validation, normalized/, metrics_*, diffs, jaccard, failures, ...
figures/                  fig1–fig3 (pdf+png), produced by scripts/figures.py
paper/                    main.tex, refs.bib, numbers.tex + tables/ (auto-generated)
scripts/                  pipeline (below)
```

## Reproduce
Prerequisites (macOS, Homebrew; Apple Silicon works via emulation):
```bash
brew install syft trivy cyclonedx-cli jq tectonic        # Docker Desktop must be running
npm install --prefix tools @cyclonedx/cdxgen@12.9.0      # local, pinned
python3 -m venv .venv && .venv/bin/pip install pandas matplotlib seaborn packageurl-python
```
Full pipeline:
```bash
make corpus      # build/pull images, write results/corpus.csv (digests)
make gt          # extract ground truth from inside the images
make sboms       # syft/trivy/cdxgen on all images -> sboms/, results/run_log.csv
make repeats     # 3 extra runs on 3 images (determinism)
make validate    # cyclonedx validate -> results/validation.csv
make analyze     # normalize, metrics, determinism, failure patterns, figures, LaTeX tables/macros
make paper       # compile paper/main.tex
```
`make analyze paper` needs no Docker: it regenerates **every number, table and figure** from the saved
raw outputs. Paper numbers come only from `paper/numbers.tex` (written by `scripts/tables.py`).

## Pipeline scripts
| Script | Purpose |
|---|---|
| `01_corpus.sh` | build 5 images / pull 7, `--platform linux/amd64`, record digests |
| `02_ground_truth.sh` (+`gt_npm_walk.js`) | dpkg/apk/status.d, `pip list`, on-disk `package.json` walk, fat-jar `BOOT-INF/lib` listing |
| `03_generate.sh` | `docker save` once, then all 3 tools scan the same tarball; logs time + exit code |
| `04_validate.sh` | CycloneDX CLI schema validation per declared spec version |
| `normalize.py` | PURL → (eco, name, version); PEP 503, Maven `g:a`, deb epoch strip |
| `measure.py` | P/R/F1 vs GT, diffs, Jaccard, unique counts, field completeness |
| `determinism.py` | set equality across runs; runtime summary |
| `failures.py` | failure-pattern × tool counts |
| `figures.py`, `tables.py` | figures; LaTeX tables + number macros |

## Notes / decisions
* **Ground truth is artifact-level.** `npm ls` reports aliases (`string-width-cjs`) and `mvn dependency:list`
  doesn't match the repackaged jar, so the truth comes from on-disk `package.json` files and `BOOT-INF/lib`.
* Only ecosystems covered by an image's GT are scored; other components show up as `out_of_scope` in `results/diffs.csv`.
* Trivy's Java DB is fetched from the network on the first jar scan (version recorded in `versions.md`).
* Trivy supply-chain incident GHSA-69fq-xp46-6x23 (March 2026): we use 0.76.1, which is not affected.
