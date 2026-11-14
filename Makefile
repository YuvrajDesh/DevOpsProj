PY := .venv/bin/python
.PHONY: all corpus gt sboms repeats validate analyze paper clean-results

all: corpus gt sboms repeats validate analyze paper

corpus:      ## build/pull 12 images (linux/amd64), record digests
	./scripts/01_corpus.sh
gt:          ## extract raw ground truth from images
	./scripts/02_ground_truth.sh
sboms:       ## run syft/trivy/cdxgen on all images (run r1)
	./scripts/03_generate.sh r1
repeats:     ## determinism runs on 3 images
	for r in r2 r3 r4; do ./scripts/03_generate.sh $$r sb-java-springboot sb-node-lock sb-py-loose; done
validate:    ## CycloneDX schema validation
	./scripts/04_validate.sh
analyze:     ## everything downstream of raw outputs (no Docker needed)
	$(PY) scripts/normalize.py
	$(PY) scripts/measure.py
	$(PY) scripts/determinism.py
	$(PY) scripts/failures.py
	$(PY) scripts/figures.py
	$(PY) scripts/tables.py
paper:
	cd paper && tectonic main.tex
