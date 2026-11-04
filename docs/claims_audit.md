# Claims audit (2026-10-30). A claim enters the paper only when its status is verified twice.

| Claim | Source | Status | Missing check |
|---|---|---|---|
| Reachability removes 59 percent (356 of 608) of findings on 10 Go apps | harness/reach_set.py, results_go/reach.json | single oracle (govulncheck) | manual labels (label_sample.csv), lexical check covered only 20 not called findings |
| Trivy applies product scoped VEX only with a purl on the root and every component on the path, Grype ignores it | harness/vex_set.py, vex_chain.py, vex_bisect.py | verified, Trivy 0.69.3 and Grype 0.114.0, Go only | other Trivy and Grype versions, other ecosystems |
| 42 of 230 called findings are covered by another project's module scoped file | harness/vex_cross.py | verified, prediction matched scans | more varied project set, shared dependencies inflate it |
| Missing root version makes 55 of 108 findings on the product's own name | harness/go_checks.py | verified | the 53 remaining findings not checked individually |
| Trivy misses 17 findings that Grype reports (caddy 3 not called, cli 3, helm 5, hugo 1, k9s 5 called), 14 of 230 reachable findings | harness/trace_residue.py | verified for this snapshot (OSV confirmed the first 12) | mechanism unknown, k9s 5 not checked in OSV, other snapshots |
| cdxgen 12.9.0 writes CycloneDX 1.7 and Grype and Trivy reject it | pilot scans | verified | none |
| Syft SBOM crashes OSV Scanner 2.7.0 (GitHub Actions components) | scan_set.sh strip workaround | verified on 5 SBOMs, root cause unknown | minimal reproduction |
| Syft over reports modules not shipped (precision 0.60 to 1.00 on Go set) | harness/score.py | verified | none (descriptive) |
| Lockfile dependence (empty SBOM without a lockfile) | pilot | replicates Mind the Gap | cite, not a contribution |
| Database drift: 19 to 22 reference findings in 4 days | pilot snapshots 20261026, 20261030 | verified | none |

Rule: re-run the producing script from a clean checkout before the number goes in the paper.
