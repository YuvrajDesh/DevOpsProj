#!/usr/bin/env python3
"""Normalize SBOMs and ground truth into a common (eco, name, version) schema.

Outputs
  results/normalized/<tool>/<image>.csv   one row per SBOM component (+ field-quality flags)
  ground_truth/<image>.csv                one row per ground-truth component
Keys: eco in {deb, apk, pypi, npm, maven, ...}; name/version normalized (see norm_*).
"""
import csv, glob, json, os, re, sys
from pathlib import Path
from packageurl import PackageURL

ROOT = Path(__file__).resolve().parent.parent
OUT_N = ROOT / "results" / "normalized"
TOOLS = ["syft", "trivy", "cdxgen"]
SKIP_TYPES = {"operating-system", "container", "file", "platform", "device", "firmware",
              "cryptographic-asset", "data", "machine-learning-model"}


# ---------------- normalization rules ----------------
def norm_name(eco, name, ns=None):
    name = (name or "").strip()
    if eco == "pypi":
        return re.sub(r"[-_.]+", "-", name).lower()
    if eco == "maven":
        return f"{(ns or '').lower()}:{name.lower()}" if ns else name.lower()
    if eco == "npm":
        return f"{ns}/{name}".lower() if ns else name.lower()
    return name.lower()


def norm_version(eco, v):
    v = (v or "").strip()
    if eco == "deb":
        v = re.sub(r"^\d+:", "", v)  # drop epoch (tools disagree on epoch placement)
    if eco == "pypi":
        v = v.lower()
    return v


def from_purl(p):
    try:
        u = PackageURL.from_string(p)
    except Exception:
        return None
    eco = u.type.lower()
    ns = u.namespace
    if eco in ("deb", "apk", "rpm"):
        ns = None  # distro namespace ignored
    return eco, norm_name(eco, u.name, ns), norm_version(eco, u.version)


# ---------------- SBOM parsing ----------------
def walk_components(comps):
    for c in comps or []:
        yield c
        yield from walk_components(c.get("components"))


def parse_sbom(path):
    d = json.load(open(path))
    rows = []
    for c in walk_components(d.get("components")):
        if c.get("type") in SKIP_TYPES:
            continue
        purl = c.get("purl") or ""
        parsed = from_purl(purl) if purl else None
        if parsed:
            eco, name, ver = parsed
            if not ver:
                ver = norm_version(eco, c.get("version"))
        else:
            eco, name, ver = "nopurl", (c.get("name") or "").lower(), c.get("version") or ""
        lic = c.get("licenses") or []
        rows.append(dict(
            eco=eco, name=name, version=ver, purl=purl,
            raw_name=c.get("name", ""), raw_version=c.get("version", ""), ctype=c.get("type", ""),
            has_purl=int(bool(purl)), purl_valid=int(parsed is not None),
            has_version=int(bool(c.get("version"))),
            has_license=int(bool(lic)),
            has_hash=int(bool(c.get("hashes"))),
            has_supplier=int(bool(c.get("supplier") or c.get("author") or c.get("publisher"))),
            has_cpe=int(bool(c.get("cpe"))),
        ))
    return rows


# ---------------- ground truth parsing ----------------
def gt_dpkg(p):
    out = []
    for line in open(p):
        f = line.rstrip("\n").split("\t")
        if len(f) >= 3 and f[1]:
            out.append(("deb", norm_name("deb", f[1]), norm_version("deb", f[2]), "os"))
    return out


def gt_apk(p):
    out = []
    for line in open(p):
        s = line.strip()
        m = re.match(r"^(.+)-([^-]+-r\d+)$", s)
        if m:
            out.append(("apk", m.group(1).lower(), m.group(2), "os"))
    return out


def gt_status_d(d):
    out = []
    for f in glob.glob(f"{d}/*"):
        if f.endswith(".md5sums"):
            continue
        txt = open(f, errors="ignore").read()
        n = re.search(r"^Package:\s*(\S+)", txt, re.M)
        v = re.search(r"^Version:\s*(\S+)", txt, re.M)
        if n and v:
            out.append(("deb", norm_name("deb", n.group(1)), norm_version("deb", v.group(1)), "os"))
    return out


def gt_pip(p):
    return [("pypi", norm_name("pypi", x["name"]), norm_version("pypi", x["version"]), "lang")
            for x in json.load(open(p))]


def gt_npm(p, layer):
    try:
        d = json.load(open(p))
    except Exception:
        return []
    out = []

    def rec(deps):
        for name, info in (deps or {}).items():
            v = info.get("version")
            if v:
                ns, _, nm = name.rpartition("/") if name.startswith("@") else (None, "", name)
                out.append(("npm", norm_name("npm", nm, ns or None), v, layer))
            rec(info.get("dependencies"))
    rec(d.get("dependencies"))
    return out


def gt_maven(p):
    out = []
    for line in open(p):
        m = re.match(r"^\s*([\w.\-]+):([\w.\-]+):(jar|pom|war)(?::[\w.\-]+)?:([\w.\-]+):(compile|runtime)", line)
        if m:
            out.append(("maven", f"{m.group(1).lower()}:{m.group(2).lower()}", m.group(4), "lang"))
    return out


def gt_npm_walk(p):
    out = []
    for line in open(p):
        line = line.strip()
        if not line.startswith("{"):
            continue
        x = json.loads(line)
        ns, _, nm = x["name"].rpartition("/") if x["name"].startswith("@") else (None, "", x["name"])
        out.append(("npm", norm_name("npm", nm, ns or None), x["version"], "self" if x.get("self") else "lang"))
    return out


def gt_jar_libs(libs, mvn_all):
    """Each BOOT-INF/lib/<artifact>-<version>.jar mapped to group via the build's resolved Maven list."""
    coords = {}
    for line in open(mvn_all):
        m = re.match(r"^\s*([\w.\-]+):([\w.\-]+):jar(?::[\w.\-]+)?:([\w.\-]+):\w+", line)
        if m:
            coords[f"{m.group(2)}-{m.group(3)}.jar"] = (m.group(1), m.group(2), m.group(3))
    # injected by spring-boot-maven-plugin repackage (not a declared dependency)
    INJECTED = {"spring-boot-jarmode-tools": "org.springframework.boot"}
    out = []
    for line in open(libs):
        fn = line.strip().rsplit("/", 1)[-1]
        if not fn:
            continue
        if fn in coords:
            g, a, v = coords[fn]
        else:
            m = re.match(r"^(.+?)-(\d[\w.\-]*)\.jar$", fn)
            a, v = m.group(1), m.group(2)
            g = INJECTED.get(a)
            if g is None:
                print(f"WARN unmapped jar {fn}", file=sys.stderr); continue
        out.append(("maven", f"{g.lower()}:{a.lower()}", v, "lang"))
    return out


def build_ground_truth():
    for d in sorted(glob.glob(str(ROOT / "ground_truth/raw/*"))):
        img = os.path.basename(d)
        rows = []
        if os.path.exists(f"{d}/os.txt"):
            first = open(f"{d}/os.txt").readline()
            rows += gt_dpkg(f"{d}/os.txt") if "\t" in first else gt_apk(f"{d}/os.txt")
        if os.path.isdir(f"{d}/status.d"):
            rows += gt_status_d(f"{d}/status.d")
        if os.path.exists(f"{d}/pip.json"):
            rows += gt_pip(f"{d}/pip.json")
        if os.path.exists(f"{d}/npm-walk.jsonl"):          # authoritative: on-disk package.json
            rows += gt_npm_walk(f"{d}/npm-walk.jsonl")
        if os.path.exists(f"{d}/jar-libs.txt"):            # authoritative: nested jars in fat jar
            rows += gt_jar_libs(f"{d}/jar-libs.txt", f"{d}/maven-all.txt")
            rows.append(("maven", "edu.iiitb.sbom:demo", "1.0.0", "self"))
        uniq = sorted(set(rows))
        with open(ROOT / f"ground_truth/{img}.csv", "w", newline="") as fh:
            w = csv.writer(fh); w.writerow(["eco", "name", "version", "layer"]); w.writerows(uniq)
        print(f"GT {img}: {len(uniq)} components")


def build_normalized(sbom_root=ROOT / "sboms", out_root=OUT_N):
    for tool in TOOLS:
        for p in sorted(glob.glob(str(sbom_root / tool / "*.cdx.json"))):
            img = os.path.basename(p).replace(".cdx.json", "")
            try:
                rows = parse_sbom(p)
            except Exception as e:
                print(f"PARSE-FAIL {tool} {img}: {e}", file=sys.stderr); continue
            (out_root / tool).mkdir(parents=True, exist_ok=True)
            with open(out_root / tool / f"{img}.csv", "w", newline="") as fh:
                w = csv.DictWriter(fh, fieldnames=list(rows[0].keys()) if rows else ["eco"])
                w.writeheader(); w.writerows(rows)
            print(f"NORM {tool:6s} {img}: {len(rows)} components")


if __name__ == "__main__":
    build_ground_truth()
    build_normalized()
