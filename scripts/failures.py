#!/usr/bin/env python3
"""Failure-pattern x tool counts, computed from normalized SBOMs + diffs (no hand-entered numbers).
Output: results/failure_patterns.csv (pattern, tool, count, images, example)."""
import re, sys
from pathlib import Path
import pandas as pd
sys.path.insert(0, str(Path(__file__).parent))
import normalize as N
from measure import load_tool

ROOT = Path(__file__).resolve().parent.parent
R = ROOT / "results"
corpus = pd.read_csv(R / "corpus.csv", dtype=str)
diffs = pd.read_csv(R / "diffs.csv", dtype=str, keep_default_na=False)
rows = []


def add(pattern, tool, sub, example_col="name"):
    rows.append(dict(pattern=pattern, tool=tool, count=len(sub),
                     images=";".join(sorted(set(sub.image))) if len(sub) else "",
                     example=(f"{sub.iloc[0].image}: {sub.iloc[0][example_col]}" if len(sub) else "")))


def synth_group(purl, other_groups=None):
    """Maven namespace that is not a real groupId: missing, containing a Java class name, hyphen-suffixed
    (manifest-derived e.g. org.apache.tomcat-catalina), or equal to the artifact while another tool
    reports a different groupId for the same artifact+version (e.g. checker-qual:checker-qual)."""
    m = re.match(r"pkg:maven/([^/]+)/([^@]+)@([^?]*)", purl or "")
    if not m:
        return True
    g, a, v = m.groups()
    if re.search(r"[A-Z]", g) or re.search(r"\.[\w]+-[\w-]+$", g):
        return True
    return g == a and bool((other_groups or {}).get((a.lower(), v), set()) - {g.lower()})


allnorm = []
for t in N.TOOLS:
    for img in corpus.image:
        df = load_tool(t, img)
        if df is not None and len(df):
            allnorm.append(df.assign(tool=t, image=img))
A = pd.concat(allnorm)

for t in N.TOOLS:
    d = diffs[diffs.tool == t]
    a = A[A.tool == t]
    add("F1 OS source/origin package reported as installed package", t,
        d[(d.kind == "extra") & d.eco.isin(["deb", "apk"])])
    add("F2 manifest version range reported as version (requirements.txt)", t,
        d[(d.kind == "version_mismatch") & (d.eco == "pypi")])
    mv = a[a.eco == "maven"]
    others = {}
    for p in A[(A.tool != t) & (A.eco == "maven")].purl:
        m = re.match(r"pkg:maven/([^/]+)/([^@]+)@([^?]*)", p or "")
        if m: others.setdefault((m.group(2).lower(), m.group(3)), set()).add(m.group(1).lower())
    add("F3 synthesized/incorrect Maven groupId (jar lacks pom.properties)", t,
        mv[mv.purl.map(lambda p: synth_group(p, others)) & ~mv.name.str.endswith("jrt-fs")])
    add("F4 JDK-internal jar reported as Maven package (jrt-fs)", t, mv[mv.name.str.endswith("jrt-fs")])
    add("F5 nested jar inside fat jar missed", t, d[(d.kind == "missing") & (d.eco == "maven")])
    add("F6 non-package artifact without PURL (e.g. bundled .exe launchers)", t, a[a.eco == "nopurl"])
    add("F7 duplicate (eco,name,version) entries (mostly legitimate multiple install paths)", t,
        a[a.duplicated(["image", "eco", "name", "version"], keep="first")])
    add("F8 devDependency (in lock, not installed) reported", t, a[(a.eco == "npm") & (a.name == "jest")])
    add("P1 language runtime binary detected (node/python/openjdk) [beyond GT]", t, a[a.eco == "generic"])

fp = pd.DataFrame(rows)
fp.to_csv(R / "failure_patterns.csv", index=False)
print(fp.pivot(index="pattern", columns="tool", values="count")[N.TOOLS].to_string())

# jar metadata stat (explains F3)
jc = (ROOT / "ground_truth/raw/sb-java-springboot/jar-coords.txt").read_text().splitlines()
libs = [l for l in (ROOT / "ground_truth/raw/sb-java-springboot/jar-libs.txt").read_text().splitlines() if l.strip()]
nometa = sum(1 for l in jc if l.startswith("#nometa"))
pd.DataFrame([dict(image="sb-java-springboot", nested_jars=len(libs), jars_without_pom_properties=nometa)]) \
  .to_csv(R / "jar_metadata.csv", index=False)
print(f"nested jars {len(libs)}, without pom.properties {nometa}")
