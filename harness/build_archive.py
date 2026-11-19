"""Build the sanitised data archive of the untracked files under results*/.
Usage (repository root): python3 -I harness/build_archive.py OUTDIR STAMP
Replaces the author address, consumer mailbox addresses (domain kept), every other personal address (role, example and version forms kept), the home path, the user name and the host name of the
machine that runs it, verifies that no trace is left and that every JSON file still parses, then writes
OUTDIR/cra_data_STAMP.tar.gz (sorted, fixed times, no owner) and its .sha256. Nothing is written if a check fails."""
import glob, gzip, hashlib, json, os, re, socket, subprocess, sys, tarfile
from pathlib import Path
out = Path(sys.argv[1]); stamp = sys.argv[2]
home = os.path.expanduser("~"); user = os.path.basename(home); host = socket.gethostname()
email = subprocess.run(["git", "config", "user.email"], capture_output=True, text=True).stdout.strip()
tracked = set(subprocess.run(["git", "ls-files", "-z"], capture_output=True, text=True).stdout.split("\0"))
consumer = re.compile(r"[A-Za-z0-9._%+-]+@((?:gmail|qq|outlook|hotmail|yahoo|163)\.com)")
ROLE = {"redacted", "security-advisories", "nvd", "package-announce", "disclosure", "security", "report", "cna", "cve",
        "vulnerability", "secalert", "noreply", "no-reply", "token", "git", "pass", "user", "n", "a", "foo", "u003cc", "psirt",
        "product-security", "security-reports", "oss-security", "announce", "bugs", "support", "info", "abuse"}
NAMES = ("evil.com", "victim.com", "target.com", "good-corp.com", "company.com", "xn--company-pka.com",
         "planetexpress.com", "spy.net", "attacker.com")
ANY = re.compile(r"(?<![A-Za-z0-9._%+-])([A-Za-z0-9._%+-]+)@([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,})\b")
def is_kept(local, dom):
    d, l = dom.lower(), local.lower()
    if l in ROLE: return True
    if re.fullmatch(r"[0-9][0-9a-z.\-]*", d): return True
    if d.startswith(("pytest.", "example.")) or d.endswith((".example", ".test", ".invalid")): return True
    if d == "openssh.com": return True
    return any(n in d for n in NAMES)
removed_personal = [0]
def personal(m):
    if is_kept(m.group(1), m.group(2)): return m.group(0)
    removed_personal[0] += 1; return "redacted@redacted.invalid"
rules = []
if email: rules.append(("author address", re.compile(re.escape(email)), "author@example.invalid"))
rules += [("consumer address", consumer, r"redacted@\1"),
          ("personal address", ANY, personal),
          ("home path", re.compile(re.escape(home) + "/"), "~/"),
          ("home path bare", re.compile(re.escape(home)), "~"),
          ("user name", re.compile(re.escape(user)), "author")]
if len(host) > 2: rules.append(("host name", re.compile(re.escape(host)), "host"))
VERIFY = {"consumer address": re.compile(r"(?<![A-Za-z0-9._%+-])(?!redacted@)" + consumer.pattern)}
OTHER = re.compile(r"(?<![A-Za-z0-9._%+-])(?!redacted@|author@example)[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}\b")
other, other_files = set(), 0
stage = out / "stage"
import shutil; shutil.rmtree(stage, ignore_errors=True); stage.mkdir(parents=True)
counts = {n: 0 for n, _, _ in rules}; files = changed = binary = 0
for d in sorted(glob.glob("results*")):
    for root, _, names in os.walk(d, followlinks=True):
        for nm in names:
            rel = os.path.normpath(os.path.join(root, nm))
            if rel in tracked: continue
            raw = Path(rel).read_bytes(); files += 1
            try: text = raw.decode("utf-8")
            except UnicodeDecodeError:
                binary += 1; data = raw
            else:
                new = text
                for n, rx, rep in rules:
                    new, k = rx.subn(rep, new); counts[n] += k
                if new != text: changed += 1
                data = new.encode("utf-8")
            dst = stage / rel; dst.parent.mkdir(parents=True, exist_ok=True); dst.write_bytes(data)
bad = 0
for p in sorted(stage.rglob("*")):
    if not p.is_file(): continue
    try: text = p.read_text(encoding="utf-8")
    except UnicodeDecodeError: continue
    for n, rx, _ in rules:
        if n in ("home path bare",) : continue
        if n == "personal address":
            if any(not is_kept(m.group(1), m.group(2)) for m in ANY.finditer(text)): print("RESIDUE", n, p.relative_to(stage)); bad += 1
            continue
        if VERIFY.get(n, rx).search(text): print("RESIDUE", n, p.relative_to(stage)); bad += 1
    found = OTHER.findall(text)
    if found: other |= set(found); other_files += 1
    if p.suffix == ".json" and p.stat().st_size:
        try: json.loads(text)
        except Exception as e: print("JSON BROKEN", p.relative_to(stage), str(e)[:60]); bad += 1
print(f"files collected {files}, text files changed {changed}, binary {binary}")
counts["personal address"] = removed_personal[0]
for n, k in counts.items(): print(f"  replacements {n}: {k}")
print(f"role, example and version forms left on purpose: {len(other)} distinct in {other_files} files")
if bad:
    print("STOP: checks failed, no archive written"); sys.exit(1)
arc = out / f"cra_data_{stamp}.tar.gz"
with open(arc, "wb") as fh, gzip.GzipFile(filename="", mode="wb", fileobj=fh, mtime=0) as gz, tarfile.open(fileobj=gz, mode="w") as tf:
    for p in sorted(stage.rglob("*")):
        if not p.is_file(): continue
        ti = tarfile.TarInfo(str(p.relative_to(stage))); ti.size = p.stat().st_size; ti.mtime = 1763337600
        ti.uid = ti.gid = 0; ti.uname = ti.gname = ""; ti.mode = 0o644
        with open(p, "rb") as f: tf.addfile(ti, f)
h = hashlib.sha256(arc.read_bytes()).hexdigest()
(out / f"cra_data_{stamp}.tar.gz.sha256").write_text(f"{h}  {arc.name}\n")
print("archive", arc.name, arc.stat().st_size, "bytes; sha256", h)
