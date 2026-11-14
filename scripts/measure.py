#!/usr/bin/env python3
"""Compute all metrics from normalized SBOMs + ground truth. Every output is a CSV in results/.

Scoring scope: for each image, only ecosystems present in that image's ground truth are scored
(e.g. tomcat's GT covers deb only, so its jars are not scored). Tool components in other
ecosystems are counted as 'out_of_scope' and reported separately, never as FP.
"""
import csv, itertools
from collections import defaultdict
from pathlib import Path
import pandas as pd

ROOT = Path(__file__).resolve().parent.parent
R = ROOT / "results"
TOOLS = ["syft", "trivy", "cdxgen"]
OS_ECOS = {"deb", "apk", "rpm"}


def load_tool(tool, img, base=R / "normalized"):
    p = base / tool / f"{img}.csv"
    if not p.exists() or p.stat().st_size == 0:
        return None
    df = pd.read_csv(p, dtype=str, keep_default_na=False)
    return df if "name" in df else df.assign(name=[], version=[])


def load_gt(img):
    p = ROOT / "ground_truth" / f"{img}.csv"
    return pd.read_csv(p, dtype=str, keep_default_na=False) if p.exists() else None


def prf(tp, fp, fn):
    p = tp / (tp + fp) if tp + fp else float("nan")
    r = tp / (tp + fn) if tp + fn else float("nan")
    f = 2 * p * r / (p + r) if p == p and r == r and p + r else float("nan")
    return p, r, f


def keys(df, with_ver):
    return {(e, n, v) if with_ver else (e, n) for e, n, v in zip(df.eco, df.name, df.version)}


def main():
    corpus = pd.read_csv(R / "corpus.csv", dtype=str)
    images = list(corpus.image)
    eco_of = dict(zip(corpus.image, corpus.ecosystem))
    lock_of = dict(zip(corpus.image, corpus.lock_file))
    self_of = dict(zip(corpus.image, corpus.self_built))

    gt_rows, diff_rows, jac_rows, uniq_rows, field_rows = [], [], [], [], []
    for img in images:
        gt = load_gt(img)
        tdf = {t: load_tool(t, img) for t in TOOLS}
        # ---------- vs ground truth ----------
        if gt is not None and len(gt):
            scope = set(gt.eco)
            groups = {"all": scope, "os": scope & OS_ECOS, "lang": scope - OS_ECOS}
            for t, df in tdf.items():
                if df is None:
                    continue
                for gname, ecos in groups.items():
                    if not ecos:
                        continue
                    g = gt[gt.eco.isin(ecos)]; d = df[df.eco.isin(ecos)]
                    for level, wv in (("name", False), ("name+version", True)):
                        G, T = keys(g, wv), keys(d, wv)
                        tp, fp, fn = len(G & T), len(T - G), len(G - T)
                        p, r, f = prf(tp, fp, fn)
                        gt_rows.append(dict(image=img, ecosystem=eco_of[img], self_built=self_of[img],
                                            lock_file=lock_of[img], tool=t, scope=gname, level=level,
                                            gt_size=len(G), tool_size=len(T), tp=tp, fp=fp, fn=fn,
                                            precision=p, recall=r, f1=f))
                out_scope = df[~df.eco.isin(scope)]
                for e, n in out_scope.groupby("eco").size().items():
                    diff_rows.append(dict(image=img, tool=t, kind="out_of_scope", eco=e, name=f"<{n} comps>",
                                          gt_version="", tool_version=""))
                # missing / extra / version mismatch detail (name level within scope)
                d = df[df.eco.isin(scope)]
                gv = defaultdict(set); tv = defaultdict(set)
                for e, n, v in zip(gt.eco, gt.name, gt.version): gv[(e, n)].add(v)
                for e, n, v in zip(d.eco, d.name, d.version): tv[(e, n)].add(v)
                for k in gv.keys() - tv.keys():
                    diff_rows.append(dict(image=img, tool=t, kind="missing", eco=k[0], name=k[1],
                                          gt_version="|".join(sorted(gv[k])), tool_version=""))
                for k in tv.keys() - gv.keys():
                    diff_rows.append(dict(image=img, tool=t, kind="extra", eco=k[0], name=k[1],
                                          gt_version="", tool_version="|".join(sorted(tv[k]))))
                for k in gv.keys() & tv.keys():
                    if gv[k] != tv[k]:
                        diff_rows.append(dict(image=img, tool=t, kind="version_mismatch", eco=k[0], name=k[1],
                                              gt_version="|".join(sorted(gv[k])),
                                              tool_version="|".join(sorted(tv[k]))))
        # ---------- tool vs tool ----------
        avail = {t: keys(df[df.eco != "nopurl"], True) for t, df in tdf.items() if df is not None}
        for a, b in itertools.combinations(sorted(avail), 2):
            A, B = avail[a], avail[b]
            jac_rows.append(dict(image=img, ecosystem=eco_of[img], tool_a=a, tool_b=b, inter=len(A & B),
                                 union=len(A | B), jaccard=len(A & B) / len(A | B) if A | B else float("nan")))
        for t in avail:
            others = set().union(*[avail[o] for o in avail if o != t]) if len(avail) > 1 else set()
            uniq_rows.append(dict(image=img, ecosystem=eco_of[img], tool=t, total=len(avail[t]),
                                  unique=len(avail[t] - others)))
        # ---------- field completeness ----------
        for t, df in tdf.items():
            if df is None or not len(df):
                continue
            df = df.assign(group=df.eco.map(lambda e: "os" if e in OS_ECOS else ("nopurl" if e == "nopurl" else e)))
            for g, sub in df.groupby("group"):
                field_rows.append(dict(image=img, tool=t, eco=g, n=len(sub),
                                       **{c: sub[c].astype(int).mean() for c in
                                          ["has_purl", "purl_valid", "has_version", "has_license", "has_hash",
                                           "has_supplier", "has_cpe"]},
                                       duplicates=len(sub) - len(sub[["eco", "name", "version"]].drop_duplicates())))

    pd.DataFrame(gt_rows).to_csv(R / "metrics_gt.csv", index=False)
    pd.DataFrame(diff_rows).to_csv(R / "diffs.csv", index=False)
    pd.DataFrame(jac_rows).to_csv(R / "jaccard.csv", index=False)
    pd.DataFrame(uniq_rows).to_csv(R / "unique.csv", index=False)
    fr = pd.DataFrame(field_rows); fr.to_csv(R / "fields_per_image.csv", index=False)

    # pooled per tool x component ecosystem (micro-average over GT images)
    m = pd.DataFrame(gt_rows)
    pooled = []
    for img in images:
        gt = load_gt(img)
        if gt is None: continue
        for t in TOOLS:
            df = load_tool(t, img)
            if df is None: continue
            for e in set(gt.eco):
                for level, wv in (("name", False), ("name+version", True)):
                    G, T = keys(gt[gt.eco == e], wv), keys(df[df.eco == e], wv)
                    pooled.append(dict(tool=t, eco=e, level=level, tp=len(G & T), fp=len(T - G), fn=len(G - T)))
    pl = pd.DataFrame(pooled).groupby(["tool", "eco", "level"], as_index=False)[["tp", "fp", "fn"]].sum()
    pl[["precision", "recall", "f1"]] = pl.apply(lambda r: pd.Series(prf(r.tp, r.fp, r.fn)), axis=1)
    pl.to_csv(R / "metrics_by_eco.csv", index=False)

    # field completeness pooled (weighted by n)
    cols = ["has_purl", "purl_valid", "has_version", "has_license", "has_hash", "has_supplier", "has_cpe"]
    w = fr.copy()
    for c in cols: w[c] = w[c] * w.n
    fp_ = w.groupby(["tool", "eco"], as_index=False)[cols + ["n", "duplicates"]].sum()
    for c in cols: fp_[c] = (fp_[c] / fp_.n).round(3)
    fp_.to_csv(R / "fields_pooled.csv", index=False)
    print(pl.round(3).to_string())


if __name__ == "__main__":
    main()
