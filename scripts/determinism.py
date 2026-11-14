#!/usr/bin/env python3
"""Determinism + runtime: compare normalized component sets across repeat runs (r1..r4)."""
import glob, os, sys
from pathlib import Path
import pandas as pd
sys.path.insert(0, str(Path(__file__).parent))
import normalize as N

ROOT = Path(__file__).resolve().parent.parent
rows = []
runs = {"r1": ROOT / "sboms"} | {os.path.basename(p): Path(p) for p in sorted(glob.glob(str(ROOT / "sboms/_runs/r*")))}
for img in ["sb-java-springboot", "sb-node-lock", "sb-py-loose"]:
    for tool in N.TOOLS:
        sets = {}
        for r, base in runs.items():
            f = base / tool / f"{img}.cdx.json"
            if f.exists():
                sets[r] = frozenset((x["eco"], x["name"], x["version"]) for x in N.parse_sbom(f))
        ref = sets.get("r1", frozenset())
        rows.append(dict(image=img, tool=tool, runs=len(sets), sizes="/".join(str(len(s)) for s in sets.values()),
                         identical=all(s == ref for s in sets.values()),
                         max_symdiff=max(len(s ^ ref) for s in sets.values())))
det = pd.DataFrame(rows); det.to_csv(ROOT / "results/determinism.csv", index=False); print(det.to_string())

log = pd.read_csv(ROOT / "results/run_log.csv")
log = log[log.run.str.match(r"r\d")]
rt = log.groupby("tool").seconds.agg(["count", "median", "mean", "min", "max"]).round(2)
rt.to_csv(ROOT / "results/runtime_summary.csv"); print(rt)
log.pivot_table(index="image", columns="tool", values="seconds", aggfunc="median").round(2) \
   .to_csv(ROOT / "results/runtime_per_image.csv")
