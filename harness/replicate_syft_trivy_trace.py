import json, sys
from collections import Counter
from pathlib import Path
out = Path(sys.argv[1])  # usage: replicate_syft_trivy_trace.py OUT
def comps(p):
    r = []
    def walk(cs):
        for c in cs or []:
            r.append(c); walk(c.get("components"))
    walk(json.loads(p.read_text()).get("components")); return r
for name, eco, tool, side in [("socket.io","npm","syft","old"),("eza","rust","syft","new"),("nest","npm","trivy","old"),("just","rust","trivy","new")]:
    o = comps(out/"old"/tool/eco/f"{name}.cdx.json"); n = comps(out/"new"/tool/eco/f"{name}.cdx.json")
    po = {(c.get("purl") or "").lower() for c in o}; pn = {(c.get("purl") or "").lower() for c in n}
    diff = (po - pn) if side == "old" else (pn - po)
    cnt = Counter()
    for c in (o if side == "old" else n):
        if (c.get("purl") or "").lower() in diff:
            paths = sorted({p["value"] for p in c.get("properties", []) if any(k in p["name"].lower() for k in ("path", "location"))})
            cnt[paths[0] if paths else "NO PATH PROPERTY"] += 1
    print(f"== {name} {tool}, components only in the {side} output: {sum(cnt.values())}")
    for k, v in cnt.most_common(8): print("  ", v, k)
