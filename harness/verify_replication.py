import csv, sys
DOC = "docs/draft_front_back.md"
fails = []
def need(cond, msg):
    if not cond:
        fails.append(msg)
tot = {}
for v in ("11.11.0", "10.11.0"):
    rows = list(csv.DictReader(open(f"results_replication/replication_cdxgen_{v}.csv")))
    need(len(rows) == 11, f"{v}: {len(rows)} rows, expected 11")
    need(sum(r["eco"] == "npm" for r in rows) == 3, f"{v}: npm rows")
    need(sum(r["eco"] == "rust" for r in rows) == 8, f"{v}: rust rows")
    for r in rows:
        a, b, c = int(r["pinned_12.9.0"]), int(r["old_" + v]), int(r["common"])
        need(a == b == c, f"{v} {r['project']}: {a} {b} {c}")
        need(r["only_pinned"] == "0" and r["only_old"] == "0", f"{v} {r['project']}: differing purls")
        need(r["old_spec"] == "1.6", f"{v} {r['project']}: spec {r['old_spec']}")
    tot[v] = sum(int(r["pinned_12.9.0"]) for r in rows)
need(tot["11.11.0"] == tot["10.11.0"], "pinned totals differ between the two files")
text = open(DOC).read()
for phrase in ("cdxgen 10.11.0 and 11.11.0", "identical purl sets in all 11 projects"):
    need(phrase in text, f"missing in {DOC}: {phrase}")
g = {}
for v in ("0.88.0", "0.90.0", "0.95.0", "0.100.0"):
    rows = list(csv.DictReader(open(f"results_replication/replication_grype_{v}.csv")))
    need(len(rows) == 76, f"grype {v}: {len(rows)} rows, expected 76")
    need(sum(r["kind"] == "reference" for r in rows) == 19, f"grype {v}: reference rows")
    need(all(r["only_pinned"] == "0" and r["only_old"] == "0" for r in rows if r["kind"] == "reference"), f"grype {v}: reference sboms differ")
    g[v] = rows
def differs(r):
    return r["only_pinned"] != "0" or r["only_old"] != "0"
for v in ("0.95.0", "0.100.0"):
    need(not any(differs(r) for r in g[v]), f"grype {v}: differs from 0.114.0")
    need(sum(int(r["pinned_0.114.0"]) for r in g[v]) == 3061, f"grype {v}: pinned pair total")
r90 = g["0.90.0"]
need(sum(differs(r) for r in r90) == 15, "grype 0.90.0: expected 15 differing sboms")
need(sum(int(r["only_old"]) for r in r90) == 402, "grype 0.90.0: only_old total")
need(sum(int(r["only_pinned"]) for r in r90) == 89, "grype 0.90.0: only_pinned total")
need(all(r["sbom"].endswith(("_cdxgen", "_trivy")) for r in r90 if differs(r) and r["eco"] == "npm"), "grype 0.90.0: a differing npm sbom is not group style")
need(all(r["sbom"] == "starship_syft" for r in r90 if differs(r) and r["eco"] == "rust"), "grype 0.90.0: rust difference outside starship_syft")
sc = list(csv.DictReader(open("results_replication/replication_grype_scores_0.88.0.csv")))
need(all(r["pinned_fn_scanner_miss"] == "0" for r in sc), "scores: pinned scanner misses not 0")
miss = [r for r in sc if r["old_fn_scanner_miss"] != "0"]
need(len(miss) == 2 and all(r["project"] == "uptime-kuma" and r["scanner"] == "grype" and r["generator"] in ("cdxgen", "trivy") and r["old_fn_scanner_miss"] == "6" for r in miss), "scores: 0.88.0 scanner misses are not the two uptime-kuma rows")
for phrase in ("Grype 0.88.0, 0.90.0, 0.95.0 and 0.100.0 were rerun",):
    need(phrase in text, f"missing in {DOC}: {phrase}")
gc = open("results_replication/grype_group_control_uptime_kuma.txt").read()
for line in ("reference findings lost, as generated: 6 | after merging group into name: 0",
             "only_old pairs, as generated: 26 | after: 0",
             "total only_old 26 of which artifact name has no scope slash while the purl has %40: 26",
             "trivy   0.90.0   lost 6  only_old 26  only_pinned 6",
             "trivy   0.95.0   lost 0  only_old 0  only_pinned 0",
             "cdxgen  0.90.0   lost 6  only_old 32  only_pinned 11",
             "cdxgen  0.95.0   lost 0  only_old 0  only_pinned 0"):
    need(line in gc, f"group control record: missing line: {line}")
tc = open("results_replication/trivy_license_control_nest.txt").read()
for line in ("trivy: Version: 0.69.3",
             "license lists changed in the control copy: 1",
             "nest_unmodified: components 151, walk errors 1, language specific files 1, truth components found 150 of 188, missing 38",
             "nest_control: components 332, walk errors 0, language specific files 2, truth components found 188 of 188, missing 0"):
    need(line in tc, f"trivy license control record: missing line: {line}")
st = list(csv.DictReader(open("results_replication/replication_syft_trivy.csv")))
need(len(st) == 38, f"syft trivy: {len(st)} rows, expected 38")
need(sum(r["ecosystem"] == "npm" for r in st) == 22 and sum(r["ecosystem"] == "rust" for r in st) == 16, "syft trivy: ecosystem rows")
need(sum(r["tool"] == "syft" for r in st) == 19 and sum(r["tool"] == "trivy" for r in st) == 19, "syft trivy: tool rows")
need(sum(r["identical"] == "1" for r in st) == 34, "syft trivy: identical pairs")
need(all(int(r["n_old"]) > 0 for r in st if (r["project"], r["tool"]) != ("TypeScript", "trivy")), "syft trivy: an old output is empty")
need(all(r["n_old"] == r["n_new"] == "0" for r in st if (r["project"], r["tool"]) == ("TypeScript", "trivy")), "syft trivy: TypeScript trivy")
need(all(r["only_old"] == "0" and r["only_new"] == "0" and r["n_old"] == r["n_new"] for r in st if r["identical"] == "1"), "syft trivy: identical rows differ")
got = {(r["project"], r["tool"]): (r["n_old"], r["n_new"], r["only_old"], r["only_new"]) for r in st if r["identical"] == "0"}
want = {("nest", "trivy"): ("198", "150", "48", "0"), ("socket.io", "syft"): ("1647", "1626", "21", "0"), ("eza", "syft"): ("216", "219", "0", "3"), ("just", "trivy"): ("150", "157", "0", "7")}
need(got == want, f"syft trivy: differing pairs {got}")
sr = open("results_replication/syft_trivy_replication_record.txt").read()
for line in ("old Syft 1.33.0", "old Trivy 0.66.0", "source commit 7bcb181268893fdd69ef4582588c040bb1036c33", "pinned Syft 1.45.1", "pinned Trivy 0.69.3",
             "17 /examples/basic-crud-application/vue-client/yarn.lock", "17 /examples/create-react-app-example/yarn.lock", "3 /snap/snapcraft.yaml",
             "== nest trivy, components only in the old output: 48", "== just trivy, components only in the new output: 7", "== socket.io syft, components only in the old output: 34"):
    need(line in sr, f"syft trivy record: missing line: {line}")
for phrase in ("34 of 38 project and tool pairs", "replication_syft_trivy.csv", "6 of 8 (node-red differs in one purl only by a vcs_url qualifier"):
    need(phrase in text, f"missing in {DOC}: {phrase}")
need("the same Rust lists in 7 of 8 projects" not in text, "old Rust sentence still in the draft")
for v in ("11.11.0", "10.11.0"):
    c2 = list(csv.DictReader(open(f"results_replication/replication_cdxgen_npm2_{v}.csv")))
    need(len(c2) == 8 and all(r["eco"] == "npm" for r in c2), f"cdxgen npm2 {v}: rows")
    need(all(r["old_spec"] == "1.6" for r in c2), f"cdxgen npm2 {v}: spec")
    d2 = {r["project"]: (r["pinned_12.9.0"], r["old_" + v], r["common"], r["only_pinned"], r["only_old"]) for r in c2 if not (r["only_pinned"] == "0" and r["only_old"] == "0")}
    need(d2 == {"node-red": ("939", "939", "938", "1", "1"), "socket.io": ("1810", "364", "363", "1447", "1")}, f"cdxgen npm2 {v}: differing rows {d2}")
cr = open("results_replication/cdxgen_npm2_record.txt").read()
for line in ("cdxgen 10.11.0 (npm package", "cdxgen 11.11.0 (npm package)", "pinned CycloneDX Generator 12.9.0",
             "== node-red, cdxgen 10.11.0 against the pinned 12.9.0: only pinned 1, only old 1",
             "== node-red, cdxgen 11.11.0 against the pinned 12.9.0: only pinned 1, only old 1",
             "== socket.io, cdxgen 10.11.0 against the pinned 12.9.0: only pinned 1447, only old 1",
             "== socket.io, cdxgen 11.11.0 against the pinned 12.9.0: only pinned 1447, only old 1",
             "1037 examples/create-react-app-example/yarn.lock", "409 examples/basic-crud-application/vue-client/yarn.lock",
             "?vcs_url=git%2Bssh", "?vcs_url=git%2Bhttps"):
    need(line in cr, f"cdxgen npm2 record: missing line: {line}")
need("cdxgen was not rerun on the eight npm projects added later" not in text, "old cdxgen scope sentence still in the draft")
g3 = list(csv.DictReader(open("results_replication/replication_syft_trivy_go_mvn_py.csv")))
need(len(g3) == 52, f"go mvn py: {len(g3)} rows, expected 52")
need(sum(r["ecosystem"] == "go" for r in g3) == 20 and sum(r["ecosystem"] == "maven" for r in g3) == 16 and sum(r["ecosystem"] == "pypi" for r in g3) == 16, "go mvn py: ecosystem rows")
need(sum(r["identical"] == "1" for r in g3) == 41, "go mvn py: identical pairs")
zero = {("fastapi", "trivy"), ("pip", "trivy")}
need(all(int(r["n_old"]) > 0 for r in g3 if (r["project"], r["tool"]) not in zero), "go mvn py: an old output is empty")
need(all(r["n_old"] == r["n_new"] == "0" for r in g3 if (r["project"], r["tool"]) in zero), "go mvn py: the two zero rows")
gosyft = [r for r in g3 if r["ecosystem"] == "go" and r["tool"] == "syft"]
need(len(gosyft) == 10 and all(r["identical"] == "0" and r["n_old"] == r["n_new"] and r["only_old"] == r["only_new"] for r in gosyft), "go mvn py: go syft rows")
need(sum(int(r["only_old"]) for r in gosyft) == 251, "go mvn py: 251 go purls")
need({(r["project"], r["tool"]) for r in g3 if r["identical"] == "0"} == {(r["project"], "syft") for r in gosyft} | {("spring-petclinic-rest", "trivy")}, "go mvn py: differing pairs")
sp = [r for r in g3 if r["project"] == "spring-petclinic-rest" and r["tool"] == "trivy"][0]
need((sp["n_old"], sp["n_new"], sp["only_old"], sp["only_new"]) == ("101", "101", "2", "2"), "go mvn py: spring-petclinic-rest trivy")
gg = list(csv.DictReader(open("results_replication/replication_syft_go_grype.csv")))
need(len(gg) == 10 and all(r["only_old"] == "0" and r["only_new"] == "0" and r["old"] == r["new"] and r["new_equals_committed"] == "1" for r in gg), "go grype: rows")
gm = open("results_replication/syft_trivy_go_mvn_py_record.txt").read()
for line in ("pinned Syft 1.45.1", "Grype 0.114.0",
             "run 1 old  purls 101 | swagger jakarta: versioned 0 unversioned 2", "run 2 new  purls 101 | swagger jakarta: versioned 2 unversioned 0",
             "run 3 new  purls 101 | swagger jakarta: versioned 2 unversioned 0", "run 4 old  purls 101 | swagger jakarta: versioned 0 unversioned 2",
             "total only_old 251, with subpath 251, mapped one to one 251, unmapped 0", "rows 10 | old equals new in 10 | new equals committed in 10"):
    need(line in gm, f"go mvn py record: missing line: {line}")
for phrase in ("41 of 52 pairs", "replication_syft_trivy_go_mvn_py.csv", "6 of 8 (node-red differs in one purl only by a vcs_url qualifier"):
    need(phrase in text, f"missing in {DOC}: {phrase}")
need("Go, Maven, PyPI and the container set were not rerun with other versions of any tool" not in text, "old scope sentence still in the draft")
def grows(v):
    return list(csv.DictReader(open(f"results_replication/replication_grype_go_mvn_py_{v}.csv")))
gv = {v: grows(v) for v in ("0.95.0", "0.100.0", "0.90.0", "0.88.0")}
for v, rs in gv.items():
    need(len(rs) == 104 and sum(r["eco"] == "go" for r in rs) == 40 and sum(r["eco"] == "maven" for r in rs) == 32 and sum(r["eco"] == "pypi" for r in rs) == 32, f"grype go mvn py {v}: rows")
    need(all(r["only_pinned"] == "0" and r["only_old"] == "0" for r in rs if r["eco"] == "maven"), f"grype go mvn py {v}: maven differs")
need(all(r["only_pinned"] == "0" and r["only_old"] == "0" for r in gv["0.100.0"]), "grype 0.100.0 go mvn py: differs")
d95 = {r["sbom"]: (r["only_pinned"], r["only_old"]) for r in gv["0.95.0"] if r["only_pinned"] != "0" or r["only_old"] != "0"}
need(d95 == {"django_cdxgen": ("0", "18"), "pip_cdxgen": ("0", "5"), "poetry_cdxgen": ("0", "8"), "requests_cdxgen": ("0", "2")}, f"grype 0.95.0 go mvn py: differing sboms {d95}")
k = lambda rs: [(r["sbom"], r["kind"], r["pinned_0.114.0"], r["common"], r["only_pinned"], r["only_old"]) for r in rs]
need(k(gv["0.90.0"]) == k(gv["0.88.0"]), "grype 0.88.0 and 0.90.0 go mvn py differ from each other")
d90 = [r for r in gv["0.90.0"] if r["only_pinned"] != "0" or r["only_old"] != "0"]
need(len(d90) == 44, f"grype 0.90.0 go mvn py: {len(d90)} differing sboms")
need(sum(int(r["only_pinned"]) for r in d90 if r["eco"] == "go") == 271 and sum(int(r["only_old"]) for r in d90 if r["eco"] == "go") == 1, "grype 0.90.0 go: 271 lost and 1 gained")
need(sum(int(r["only_pinned"]) for r in d90 if r["eco"] == "pypi") == 237 and sum(int(r["only_old"]) for r in d90 if r["eco"] == "pypi") == 0, "grype 0.90.0 pypi: 237 lost")
gr = open("results_replication/grype_go_mvn_py_record.txt").read()
for line in ("Grype 0.114.0 with the frozen database snapshot 20261030", "descriptor version in the outputs ['0.88.0']", "descriptor version in the outputs ['0.90.0']",
             "descriptor version in the outputs ['0.95.0']", "descriptor version in the outputs ['0.100.0']",
             "sboms with any difference: 44 of 104", "sboms with any difference: 4 of 104", "sboms with any difference: 0 of 104",
             "GHSA  pinned  1694 lost   181 gained   1", "GO    pinned   980 lost    90 gained   0", "CVE   pinned     8 lost     0 gained   0",
             "0.90.0: lost on versioned purls 3, on unversioned 234 | extra on versioned 0, on unversioned 0",
             "0.95.0: lost on versioned purls 0, on unversioned 0 | extra on versioned 0, on unversioned 33",
             "pinned 0.114.0: 234 of 994 pairs are on unversioned purls",
             "   cdxgen     495     234     434", "   syft       262       0     189", "   trivy      157       0     103"):
    need(line in gr, f"grype go mvn py record: missing line: {line}")
for phrase in ("234 of the 434 false positives of cdxgen with Grype on PyPI (54 percent)", "cdxgen was not rerun on the Go, Maven and PyPI sets", "replication_grype_go_mvn_py_*.csv"):
    need(phrase in text, f"missing in {DOC}: {phrase}")
need("cdxgen and Grype were not rerun on the Go, Maven and PyPI sets" not in text, "old Grype scope sentence still in the draft")
if fails:
    print("FAILED"); [print(" ", f) for f in fails]; sys.exit(1)
print("replication ok: 2 versions x 11 projects identical to 12.9.0, %d purls compared per version" % tot["11.11.0"])
print("grype replication ok: 0.95.0 and 0.100.0 identical to 0.114.0 on 76 sboms; 0.90.0 differs on 15; 0.88.0 shows 6 scanner misses in two uptime-kuma rows")
print("trivy license control ok: nest, unmodified copy finds 150 of 188 truth components, copy with one license list converted finds 188 of 188")
print("syft and trivy replication ok: 19 projects, 34 of 38 pairs identical, the 4 differences are the recorded ones")
print("cdxgen npm2 replication ok: 8 projects x 2 versions, 6 identical, node-red differs by a purl qualifier, socket.io by two yarn.lock files")
print("go maven pypi replication ok: 26 projects, 41 of 52 pairs identical, 251 go purls differ in form only, pinned Grype findings identical on 10 of 10")
print("grype go maven pypi replication ok: 4 versions x 104 sboms; 0.100.0 identical, maven identical in all, 0.95.0 differs on 4 pypi cdxgen sboms, 0.88.0 and 0.90.0 on 44")
