#!/usr/bin/env python3
"""Generate paper/numbers.tex (macros) and paper/tables/*.tex from results/*.csv.
Every number quoted in the paper comes from here."""
from pathlib import Path
import pandas as pd

ROOT = Path(__file__).resolve().parent.parent
R, P = ROOT / "results", ROOT / "paper"
(P / "tables").mkdir(parents=True, exist_ok=True)
TOOLS = ["syft", "trivy", "cdxgen"]
TN = {"syft": "Syft", "trivy": "Trivy", "cdxgen": "cdxgen"}
macros = {}


def mac(name, val):
    words = "Zero One Two Three Four Five Six Seven Eight Nine".split()
    macros["".join(words[int(ch)] if ch.isdigit() else ch for ch in name if ch.isalnum())] = val


def f3(x):
    return "--" if pd.isna(x) else f"{x:.3f}"


# ---------- corpus ----------
c = pd.read_csv(R / "corpus.csv")
mac("NImages", len(c)); mac("NSelfBuilt", int((c.self_built == "yes").sum()))
rows = []
for _, r in c.iterrows():
    dig = r.digest.split("@")[-1].replace("local:", "")[:19]
    rows.append(f"{r.image} & {r.ecosystem} & {r.self_built} & {r.lock_file} & {r.size_mb:.0f} & \\texttt{{{dig}}} \\\\")
(P / "tables/corpus.tex").write_text(
    "\\begin{table}[t]\\centering\\caption{Corpus (linux/amd64). Digest prefix shown; full digests in \\texttt{results/corpus.csv}.}\\label{tab:corpus}\n"
    "\\scriptsize\\begin{tabular}{lllllr}\\toprule\nImage & Eco & Self & Lock & MB & Digest \\\\\\midrule\n"
    .replace("lllllr", "llllrl") + "\n".join(rows).replace("_", "\\_").replace("\\texttt{sha256:", "\\texttt{") +
    "\n\\bottomrule\\end{tabular}\\end{table}\n")

# ---------- ground truth sizes ----------
gt_total = 0
for img in c.image:
    p = ROOT / "ground_truth" / f"{img}.csv"
    if p.exists():
        gt_total += len(pd.read_csv(p))
mac("NGTComponents", gt_total)

# ---------- pooled per-eco ----------
m = pd.read_csv(R / "metrics_by_eco.csv")
mv = m[m.level == "name+version"]
lines = []
for eco in ["deb", "apk", "pypi", "npm", "maven"]:
    cells = []
    for t in TOOLS:
        r = mv[(mv.tool == t) & (mv.eco == eco)].iloc[0]
        cells += [f3(r.precision), f3(r.recall), f3(r.f1)]
        key = f"{t.capitalize()}{eco.capitalize()}"
        mac(f"P{key}", f3(r.precision)); mac(f"R{key}", f3(r.recall)); mac(f"F{key}", f3(r.f1))
        mac(f"FP{key}", int(r.fp)); mac(f"FN{key}", int(r.fn))
    gtn = int(mv[(mv.tool == "syft") & (mv.eco == eco)].iloc[0][["tp", "fn"]].sum())
    lines.append(f"{eco} & {gtn} & " + " & ".join(cells) + " \\\\")
(P / "tables/by_eco.tex").write_text(
    "\\begin{table*}[t]\\centering\\caption{Precision / recall / F1 against ground truth, pooled over all images with ground truth, "
    "matched on (ecosystem, name, version). $|GT|$ = number of ground-truth components.}\\label{tab:byeco}\n"
    "\\small\\begin{tabular}{lr ccc ccc ccc}\\toprule\n & & \\multicolumn{3}{c}{Syft} & \\multicolumn{3}{c}{Trivy} & \\multicolumn{3}{c}{cdxgen}\\\\\n"
    "\\cmidrule(lr){3-5}\\cmidrule(lr){6-8}\\cmidrule(lr){9-11}\nEco & $|GT|$ & P & R & F1 & P & R & F1 & P & R & F1 \\\\\\midrule\n"
    + "\n".join(lines) + "\n\\bottomrule\\end{tabular}\\end{table*}\n")

# ---------- per-image F1 ----------
g = pd.read_csv(R / "metrics_gt.csv")
gl = g[(g.level == "name+version")]
piv = gl.pivot_table(index=["image", "scope"], columns="tool", values="f1")
lines = []
for (img, sc), r in piv.iterrows():
    if sc == "all":
        continue
    lines.append(f"{img} & {sc} & " + " & ".join(f3(r[t]) for t in TOOLS) + " \\\\")
(P / "tables/per_image.tex").write_text(
    "\\begin{table}[t]\\centering\\caption{Per-image F1 (name+version) by layer: OS packages vs.\\ language packages.}\\label{tab:perimage}\n"
    "\\scriptsize\\begin{tabular}{llccc}\\toprule\nImage & Layer & Syft & Trivy & cdxgen \\\\\\midrule\n"
    + "\n".join(lines).replace("_", "\\_") + "\n\\bottomrule\\end{tabular}\\end{table}\n")

# lock-file pairs (language layer)
for img in ["sb-node-lock", "sb-node-nolock", "sb-py-pinned", "sb-py-loose"]:
    for t in TOOLS:
        r = gl[(gl.image == img) & (gl.tool == t) & (gl.scope == "lang")].iloc[0]
        mac(f"F{t.capitalize()}{img.replace('sb-', '').replace('-', '').capitalize()}", f3(r.f1))

# ---------- jaccard / unique / overlap ----------
j = pd.read_csv(R / "jaccard.csv")
for (a, b), s in j.groupby(["tool_a", "tool_b"]):
    mac(f"J{a.capitalize()}{b.capitalize()}", f"{s.jaccard.mean():.3f}")
    mac(f"JMin{a.capitalize()}{b.capitalize()}", f"{s.jaccard.min():.3f}")
ov = pd.read_csv(R / "overlap_regions.csv").set_index("tools").exclusive_count
mac("OvAll", int(ov["syft+trivy+cdxgen"])); mac("OvCdxOnly", int(ov["cdxgen"]))
mac("OvSyftOnly", int(ov["syft"])); mac("OvTrivyOnly", int(ov["trivy"])); mac("OvUnion", int(ov.sum()))
jt = j[j.image == "tomcat"].set_index(["tool_a", "tool_b"]).jaccard
mac("JTomcatSyftTrivy", f"{jt[('syft', 'trivy')]:.3f}")

# ---------- failure patterns ----------
fp = pd.read_csv(R / "failure_patterns.csv")
pv = fp.pivot(index="pattern", columns="tool", values="count")[TOOLS]
lines = [f"{pat.split(' ', 1)[1]} & " + " & ".join(str(int(pv.loc[pat, t])) for t in TOOLS) + " \\\\" for pat in pv.index]
for pat in pv.index:
    for t in TOOLS:
        mac(f"Fail{pat.split(' ')[0]}{t.capitalize()}", int(pv.loc[pat, t]))
(P / "tables/failures.tex").write_text(
    "\\begin{table}[t]\\centering\\caption{Failure patterns $\\times$ tool (counts of affected component entries, all images). "
    "P1 is a capability beyond the ground truth, not a failure.}\\label{tab:failures}\n"
    "\\scriptsize\\begin{tabular}{p{4.6cm}rrr}\\toprule\nPattern & Syft & Trivy & cdxgen \\\\\\midrule\n"
    + "\n".join(lines).replace("_", "\\_").replace("#", "\\#") + "\n\\bottomrule\\end{tabular}\\end{table}\n")
jm = pd.read_csv(R / "jar_metadata.csv").iloc[0]
mac("NNestedJars", int(jm.nested_jars)); mac("NJarsNoMeta", int(jm.jars_without_pom_properties))

# ---------- fields ----------
fd = pd.read_csv(R / "fields_pooled.csv")
lines = []
for t in TOOLS:
    for _, r in fd[(fd.tool == t) & fd.eco.isin(["os", "npm", "pypi", "maven"])].iterrows():
        lines.append(f"{TN[t]} & {r.eco} & {int(r.n)} & " + " & ".join(f"{100*r[k]:.0f}" for k in
                     ["purl_valid", "has_version", "has_license", "has_hash", "has_supplier", "has_cpe"]) + " \\\\")
(P / "tables/fields.tex").write_text(
    "\\begin{table}[t]\\centering\\caption{Field completeness (\\% of component entries). os = deb+apk.}\\label{tab:fields}\n"
    "\\scriptsize\\setlength{\\tabcolsep}{3pt}\\begin{tabular}{llrrrrrrr}\\toprule\nTool & Eco & $n$ & PURL & Ver & Lic & Hash & Supp & CPE \\\\\\midrule\n"
    + "\n".join(lines) + "\n\\bottomrule\\end{tabular}\\end{table}\n")

# ---------- determinism / runtime / validation ----------
d = pd.read_csv(R / "determinism.csv")
mac("NDetCases", len(d)); mac("NDetIdentical", int(d.identical.sum())); mac("NDetRuns", int(d.runs.min()))
rt = pd.read_csv(R / "runtime_summary.csv").set_index("tool")
for t in TOOLS:
    mac(f"RtMed{t.capitalize()}", f"{rt.loc[t, 'median']:.1f}"); mac(f"RtMax{t.capitalize()}", f"{rt.loc[t, 'max']:.1f}")
v = pd.read_csv(R / "validation.csv")
mac("NSboms", len(v)); mac("NValid", int((v.valid == "yes").sum()))

out = "% AUTO-GENERATED by scripts/tables.py -- do not edit\n" + "\n".join(
    f"\\newcommand{{\\{k}}}{{{v}}}" for k, v in sorted(macros.items()))
(P / "numbers.tex").write_text(out + "\n")
print(f"{len(macros)} macros; tables:", sorted(x.name for x in (P / 'tables').iterdir()))
