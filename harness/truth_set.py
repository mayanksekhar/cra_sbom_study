#!/usr/bin/env python3
import argparse, csv, datetime, json, os, re, subprocess, tomllib
from pathlib import Path

root = Path(__file__).resolve().parent.parent
ap = argparse.ArgumentParser()
ap.add_argument("--src", required=True)
ap.add_argument("--csv", required=True)
ap.add_argument("--out", required=True)
args = ap.parse_args()
src_root, gt_root = root / args.src, root / args.out

def sh(cmd, cwd, env=None, check=True):
    r = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, env={**os.environ, **(env or {})})
    if check and r.returncode != 0:
        raise RuntimeError(" ".join(cmd[:3]) + " failed: " + r.stderr.strip()[-300:])
    return r.stdout

def write(path, items):
    path.write_text("\n".join(sorted(set(items))) + "\n")

def truth_go(name, d, gt):
    mod = json.loads(sh(["go", "mod", "edit", "-json"], d))
    (gt / f"{name}_mainmodule.txt").write_text(mod["Module"]["Path"].lower() + "\n")
    write(gt / f"{name}_declared.txt", ["pkg:golang/%s@%s" % (r["Path"], r["Version"]) for r in mod.get("Require") or []])
    mg = []
    for l in sh(["go", "list", "-m", "all"], d).splitlines()[1:]:
        f = l.split()
        if len(f) >= 2:
            mg.append("pkg:golang/%s@%s" % (f[0], f[1]))
    write(gt / f"{name}_modgraph.txt", mg)
    fmt = "{{if and .Module (not .Module.Main)}}pkg:golang/{{.Module.Path}}@{{.Module.Version}}{{end}}"
    rt = []
    for plat in ("linux/amd64", "darwin/arm64", "windows/amd64"):
        goos, goarch = plat.split("/")
        out = sh(["go", "list", "-e", "-deps", "-f", fmt, "./..."], d, {"GOOS": goos, "GOARCH": goarch}, check=False)
        rt += [l for l in out.splitlines() if l.strip()]
    write(gt / f"{name}_runtime_multi.txt", rt)

def truth_maven(name, d, gt):
    ev = lambda e: sh(["mvn", "-B", "-q", "help:evaluate", "-Dexpression=" + e, "-DforceStdout"], d).strip()
    (gt / f"{name}_mainmodule.txt").write_text((ev("project.groupId") + "/" + ev("project.artifactId")).lower() + "\n")
    for kind, extra in (("all", []), ("shipped", ["-DincludeScope=runtime"])):
        tmp = Path("/tmp") / f"{name}_{kind}_mvn.txt"
        if tmp.exists():
            tmp.unlink()
        sh(["mvn", "-B", "-q", "dependency:list", "-Dsort=true", "-DoutputFile=" + str(tmp)] + extra, d)
        items = []
        for l in tmp.read_text().splitlines():
            p = l.strip().split(" -- ")[0].split(":")
            if len(p) == 5:
                g, a, v = p[0], p[1], p[3]
            elif len(p) == 6:
                g, a, v = p[0], p[1], p[4]
            elif len(p) > 6:
                g, a, v = p[0], p[1], p[-2]
            else:
                continue
            items.append("pkg:maven/%s/%s@%s" % (g, a, v))
        write(gt / f"{name}_{kind}.txt", items)

def npm_purls(lock, shipped):
    doc = json.loads(lock.read_text())
    if "packages" not in doc:
        raise RuntimeError("lockfile version 1 not supported: " + str(lock))
    out = set()
    for k, v in doc["packages"].items():
        if not k or not v.get("version"):
            continue
        if shipped and v.get("dev"):
            continue
        out.add("pkg:npm/" + k.split("node_modules/")[-1] + "@" + v["version"])
    return out

def truth_npm(name, d, gt):
    pj = json.loads((d / "package.json").read_text())
    (gt / f"{name}_mainmodule.txt").write_text(pj["name"].lower() + "\n")
    (gt / f"{name}_mainversion.txt").write_text(str(pj.get("version", "")).lower() + "\n")
    lock = d / "package-lock.json"
    committed = lock.exists()
    if not committed:
        sh(["npm", "install", "--package-lock-only", "--ignore-scripts", "--no-audit", "--no-fund"], d)
    (gt / f"{name}_lockfile.txt").write_text("committed\n" if committed else "generated\n")
    write(gt / f"{name}_all.txt", npm_purls(lock, False))
    write(gt / f"{name}_shipped.txt", npm_purls(lock, True))
    locks = [p for p in d.rglob("package-lock.json") if "node_modules" not in p.parts]
    write(gt / f"{name}_tree_all.txt", set().union(*[npm_purls(p, False) for p in locks]))
    write(gt / f"{name}_tree_shipped.txt", set().union(*[npm_purls(p, True) for p in locks]))

def lock_set(paths):
    s = set()
    for p in paths:
        for pk in tomllib.loads(p.read_text()).get("package", []):
            if "source" in pk:
                s.add("pkg:cargo/%s@%s" % (pk["name"], pk["version"]))
    return s

def truth_rust(name, d, gt):
    def tree(edges):
        return sh(["cargo", "tree", "--workspace", "--locked", "--target", "all", "--prefix", "none", "-f", "{p}", "-e", edges], d).splitlines()
    all_t, ship_t = tree("normal,build,dev"), tree("normal")
    local = sorted({l.split()[0].lower() for l in all_t if "(/" in l})
    (gt / f"{name}_mainmodule.txt").write_text("\n".join(local) + "\n")
    def parse(lines):
        out = []
        for l in lines:
            f = l.split()
            if "(/" in l or len(f) < 2 or f[0].startswith("[") or not re.match(r"v\d", f[1]):
                continue
            out.append("pkg:cargo/%s@%s" % (f[0], f[1][1:]))
        return out
    write(gt / f"{name}_all.txt", parse(all_t))
    write(gt / f"{name}_shipped.txt", parse(ship_t))
    write(gt / f"{name}_lock.txt", lock_set([d / "Cargo.lock"]))
    write(gt / f"{name}_tree_lock.txt", lock_set([p for p in d.rglob("Cargo.lock") if "target" not in p.parts]))


def pep503(n):
    return re.sub(r"[-_.]+", "-", n.lower())

def pypi_install(name, d, gt):
    venv = Path("/tmp") / ("cra_venv_" + name)
    sh(["rm", "-rf", str(venv)], d)
    sh(["python3", "-m", "venv", str(venv)], d)
    sh([str(venv / "bin/pip"), "install", "-q", "--disable-pip-version-check", "."], d)
    out = sh([str(venv / "bin/pip"), "freeze"], d)
    main = (gt / f"{name}_mainmodule.txt").read_text().strip()
    items = []
    for l in out.splitlines():
        if "==" in l:
            n, v = l.split("==", 1)
            if pep503(n) != main:
                items.append("pkg:pypi/%s@%s" % (pep503(n), v.strip()))
    write(gt / f"{name}_install.txt", items)

def poetry_lock_closure(d, groups):
    pj = tomllib.loads((d / "pyproject.toml").read_text())
    tp = pj["tool"]["poetry"]
    roots = set(pep503(k) for k in tp.get("dependencies", {}) if k.lower() != "python")
    lock = tomllib.loads((d / "poetry.lock").read_text())
    pk = {pep503(p["name"]): p for p in lock["package"]}
    seen, stack = set(), list(roots)
    while stack:
        n = stack.pop()
        if n in seen or n not in pk:
            continue
        seen.add(n)
        for dep in (pk[n].get("dependencies") or {}):
            stack.append(pep503(dep))
    return {"pkg:pypi/%s@%s" % (n, pk[n]["version"]) for n in seen}, {"pkg:pypi/%s@%s" % (n, p["version"]) for n, p in pk.items()}

def truth_pypi(name, d, gt):
    pj = tomllib.loads((d / "pyproject.toml").read_text())
    pname = (pj.get("project", {}).get("name") or pj.get("tool", {}).get("poetry", {}).get("name"))
    if not pname:
        m = re.search(r"name\s*=\s*[\'\"]([A-Za-z0-9_.-]+)[\'\"]", (d / "setup.py").read_text()) if (d / "setup.py").exists() else None
        pname = m.group(1) if m else name
    (gt / f"{name}_mainmodule.txt").write_text(pep503(pname) + "\n")
    if (d / "poetry.lock").exists():
        shipped, alltxt = poetry_lock_closure(d, None)
        write(gt / f"{name}_lock.txt", shipped)
        write(gt / f"{name}_all.txt", alltxt)
        (gt / f"{name}_lockfile.txt").write_text("poetry.lock\n")
    elif (d / ".config/requirements-lock.txt").exists():
        items = []
        for l in (d / ".config/requirements-lock.txt").read_text().splitlines():
            m = re.match(r"^([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?==([A-Za-z0-9._!+-]+)", l.strip())
            if m:
                items.append("pkg:pypi/%s@%s" % (pep503(m.group(1)), m.group(2)))
        write(gt / f"{name}_lock.txt", items)
        (gt / f"{name}_lockfile.txt").write_text("pip-compile requirements-lock.txt\n")
    else:
        (gt / f"{name}_lockfile.txt").write_text("none\n")
    pypi_install(name, d, gt)
    write(gt / f"{name}_shipped.txt", (gt / f"{name}_lock.txt").read_text().split() if (gt / f"{name}_lock.txt").exists() else (gt / f"{name}_install.txt").read_text().split())

BUILDERS = {"go": truth_go, "maven": truth_maven, "npm": truth_npm, "rust": truth_rust, "pypi": truth_pypi}
print(f"{'project':<16}{'eco':<7}status")
for r in csv.DictReader(open(root / args.csv)):
    name, eco = r["name"], r["ecosystem"]
    gt = gt_root / eco
    gt.mkdir(parents=True, exist_ok=True)
    try:
        if eco not in BUILDERS:
            raise RuntimeError("ecosystem not supported yet: " + eco)
        BUILDERS[eco](name, src_root / name, gt)
        (gt / f"{name}_resolved_at.txt").write_text(datetime.datetime.now(datetime.UTC).strftime("%Y%m%dT%H%M%SZ") + "\n")
        status = "ok"
    except Exception as e:
        status = "FAILED " + str(e).replace("\n", " ")[:220]
    print(f"{name:<16}{eco:<7}{status}")

tools = []
for c in (["go", "version"], ["mvn", "-version"], ["cargo", "--version"], ["rustc", "--version"], ["node", "--version"], ["npm", "--version"]):
    try:
        tools.append(subprocess.run(c, capture_output=True, text=True).stdout.splitlines()[0])
    except Exception:
        pass
(gt_root / "_tooling.txt").write_text("\n".join(tools) + "\n")
print("\nfile line counts")
for p in sorted(gt_root.rglob("*.txt")):
    if p.name.startswith("_tooling") or re.search(r"_(mainmodule|mainversion|resolved_at|lockfile)\.txt$", p.name):
        continue
    print(f"{str(p.relative_to(root)):<58}{len(p.read_text().split()):>6}")
