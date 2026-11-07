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
| Syft recovers about a fifth of the real findings on Maven (43 of 201), all of them in Go and on the older pins | harness/score_findings.py, results_mvn, results_go, results_old | verified in 3 sets, every miss traced to the SBOM (120 component absent, 38 no version) | only 3 Maven projects hold 180 of 201 findings, no second Maven generator version |
| Syft on Maven lists the dependencies declared in the root pom (component count 1 to 3 above the declared count in 8 of 8 projects) | inline script (pom regex count) | verified as a pattern, regex count is rough | the 1 to 3 extra components unexplained |
| Maven profile behaviour: Trivy ignores profile dependencies, Syft lists all (even flag only), cdxgen follows Maven | harness/control_profiles.sh (reproduced 2026-11-05), swagger-petstore, petclinic | verified, two minimal controls and two real projects | one version per tool, two minimal poms |
| Maven shipped truth error about 3 of 237 components (artifact naming), dependency:list is more complete than dependency:tree | results_mvn, groundtruth_mvn | verified for 8 projects | jakarta.activation naming case open |
| Optional dependencies: Trivy omits them, jedis shipped set 16 vs 5 for a consumer | groundtruth_mvn shipped_nonopt | verified for jedis, other 7 projects not tested against the pom | parser assumption (every optional marked in tree output) |
| Reference findings in Maven: 201 across 8 projects, Grype and Trivy identical | results_mvn | verified | 3 projects dominate |
| Go set: 608 vs 610 reference findings depending on the counting unit | reach.json vs findings_vs_reference.csv | open | paper must fix one unit (finding per advisory and package, or per merged alias set) |
| Go set: 53 findings on the product's own module at its pinned version, 52 confirmed by Grype, Trivy and OSV, 52 with a Go DB record, 18 high or critical | harness/product_findings.py, results_go/product_findings.csv | verified in 10 Go applications, one snapshot | exploitability not assessed, why 4 projects have none |

Rule: re-run the producing script from a clean checkout before the number goes in the paper.
