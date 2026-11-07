# Draft, sections 3 to 6 (2026-11-07). Status in brackets: V verified in this repo, P partial, O open. Source files in braces. Numbers come from CSVs or logs, not from memory; run harness/verify_draft_numbers.py.

## 3 Method

Tools and versions. Syft 1.45.1, Trivy 0.69.3, Grype 0.114.0, cdxgen 12.9.0 (run at CycloneDX 1.6, because Grype and Trivy reject its default 1.7), OSV Scanner 2.7.0, govulncheck 1.9.0 against a local copy of the Go vulnerability database (4,712 entries, last modified 2026-10-27). Go 1.26.8, Maven 3.9.11 on JDK 25, Python 3.14.7, Node 24.18.0. {tools/pinned_versions.txt, tools/dbsnap_*.txt, tools/govuln_20261030.sha256}

Vulnerability data is frozen. Snapshot 20261030 (Grype database built 2026-10-30 06:23 UTC, Trivy database updated 07:16 UTC, OSV databases downloaded the same day) is used for every table. Snapshot 20261026 was used for the pilot's first scans and for the drift measurement. Checksums are recorded.

Projects. Pilot at default branch HEAD, 10 projects in five ecosystems. Older pins, 6 projects at tags from 2024. Go set, 10 applications at tags from February to October 2024 (lazygit excluded, it vendors its dependencies). Maven set, 8 projects (WebGoat dropped, no root pom at the pinned commit). PyPI set, 8 projects at tags from May to October 2024. Pins are in dataset/*_pinned.csv.

Truth. Per ecosystem, from the package manager of the project: Go declared, module graph and runtime on three platforms; Maven all, shipped (runtime scope) and shipped without optional dependencies; npm and Rust all, shipped and whole tree; PyPI lock where a lock exists, else a fresh install (install truth reflects resolution on 2026-11-07, so lockless projects are scored by name only).

Reference and error attribution. A reference SBOM is built from the shipped truth. A generator's findings are compared with the same scanner's findings on the reference, so database differences cancel. Every missed finding is attributed to: component absent, component without a version, wrong version, or scanner miss. Unit: one finding per component and issue (alias cluster). {harness/score_findings.py, harness/count_units.py}

Reachability oracle: govulncheck, Go only. VEX forms: A (product is the application, subcomponent is the vulnerable module) and B (product is the module).

Threats noted here: one version per tool; popular projects with shared dependencies; truth for Maven has up to 3 of 237 components in doubt; for PyPI install truth drifts from the pinned lock (28 of 37 poetry packages, 29 of 33 ansible-lint packages resolve to other versions).

## 4 SBOM scope and identity

4.1 Lockfile dependence. Express without a lockfile: Syft 0 components, Trivy 0, cdxgen 368 [V, pilot]. On five lockless PyPI projects the runtime sets total 24 components; cdxgen finds all 24, Syft and Trivy 0 of 24 and report 15 to 18 components each from docs and test requirement files [V]. {results_py/metrics.csv}

4.2 Scope policy. Maven, 8 projects, component level, name level. Against all scope truth: cdxgen P 1.00 R 1.00, Syft P 0.96 R 0.28, Trivy P 1.00 R 0.48. Against shipped without optional dependencies: cdxgen P 0.48 R 1.00, Syft P 0.54 R 0.33, Trivy P 0.98 R 0.99 [V]. No generator wins under both definitions. {results_mvn/metrics.csv}

4.3 Syft on Maven reads the dependencies declared in the root pom [P]. Components against a rough count of <dependency> entries: swagger-petstore 18 and 17, jpetstore-6 21 and 20, spring-petclinic-rest 26 and 24, spring-framework-petclinic 40 and 38, commons-lang 9 and 8, commons-io 12 and 10, jackson-databind 11 and 10, jedis 18 and 17. The 1 to 3 extra components are not explained.

4.4 Maven profiles [P, two minimal controls and two real projects]. A minimal pom with a plain dependency, an activeByDefault profile, a JDK 11 or later profile and a flag only profile: Maven resolves the plain and the JDK profile dependency (an active JDK profile deactivates activeByDefault ones); cdxgen matches Maven; Syft lists all four; Trivy lists only the plain one. A second control without the JDK profile: Maven resolves the plain and the activeByDefault dependency, Trivy still lists only the plain one. Real cases: swagger-petstore jaxb-osgi (profile jdk11+) and spring-framework-petclinic h2 (profile H2, activeByDefault, the only active profile) are in the resolved set and missing from Trivy's SBOM. {harness/control_profiles.sh}

4.5 Identity [V for Go, P elsewhere]. A root purl without a version made scanners match every advisory of the module: findings on the product's own name fell from 108 to 53 when the tag was added (10 Go applications, cdxgen SBOMs). A private docs package named axios at version 1.0.0, nested under the root in cdxgen's SBOM, gave 31 findings in Grype and none in Trivy; with the same component at top level both report 31. Trivy reads Python requirements only from a file named like requirements.txt (ansible-lint: 0 PyPI components from .config/requirements-lock.txt, 33 once copied to requirements.txt; one project, one rename [P]). {harness/control_trivy_layout.sh}

## 5 Scanner consumption

5.1 Every missed finding traces to the SBOM [V]. 959 reference findings over five sets, scanner misses 0 in all 15 generator rows. Findings recovered: pilot, cdxgen 22 of 22, Syft 5 of 22 (16 component absent, 1 no version), Trivy 22 of 22; older pins 48 of 48 for all three; Go, cdxgen 606 of 608 (2 absent, both in fzf), Syft and Trivy 608; Maven, cdxgen and Trivy 201 of 201, Syft 43 of 201 (120 absent, 38 no version); PyPI, cdxgen 61 of 80 (19 wrong version: it resolved newer versions than the pinned lock), Syft 73 of 80 (7 absent), Trivy 54 of 80 (26 absent). {docs/table_findings.md}

5.2 Scanner difference on identical input [V, one snapshot]. Trivy reports none of 17 findings that Grype reports on 5 of the 10 Go projects (caddy 3, cli 3, helm 5, hugo 1, k9s 5). 14 of them are reachable findings (6 percent of 230 reachable). Trivy's database was built after Grype's, so staleness does not explain it. OSV confirmed the first 12; the k9s 5 were not checked. Mechanism unknown. For dependency findings only; for the product itself the three scanners agree (5.3).

5.3 Findings on the product itself [V]. 53 findings on the 10 Go applications' own module at the pinned tag; 52 are confirmed by Grype, Trivy and OSV, 52 have a record in the Go database for the module path, 18 are high or critical in Grype. Generators exclude the root from the component list, so these are outside the inventory. Three of the four projects with none have no database record at all. {results_go/product_findings.csv}

5.4 Database drift [P]. Reference findings in the pilot grew from 19 to 22 between snapshots four days apart.

5.5 Compatibility [V]. cdxgen 12.9.0 writes CycloneDX 1.7 by default, which Grype and Trivy reject. Syft SBOMs for five npm and PyPI projects crash OSV Scanner 2.7.0 (unsupported ecosystem GitHub Actions, then a nil pointer); copies without the GitHub Actions components scan.

## 6 VEX and reachability

6.1 Reachability on Go [P, single oracle, labels pending]. 608 findings on the reference SBOMs of 10 applications: 230 called, 356 not called, 22 without a verdict (16 have no Go database record). Reachability would remove 356 of 608. A name search for the vulnerable symbols in 20 sampled not called findings found no plausible missed call in the 18 testable cases (weak test: no reflection or interface dispatch). Manual labels: 0 of 40. {results_go/reach.json, labels/label_sample.csv}

6.2 Product scoped VEX [V for Go, one version per tool]. For each project, statements marking the 356 not called findings not_affected. Trivy with form A: 353 of 353 not called findings removed, 0 of 216 called removed. Grype with form A: 0 of 356 removed. Grype with form B: 356 of 356 removed. No called finding removed from the product it was analysed for. {results_go/vex_set.csv}

6.3 What Trivy needs [V on node_exporter v1.9.1, 34 not called findings]. One intermediate component between a purl root and all modules: library with purl removes 34, library without purl 0, application without purl 0, file without purl 0. Depth 1 to 4 all remove 34. On the generators' own SBOMs form A removes 0 or 1 of 34. Syft and Trivy SBOMs need both a purl on the root and edges from the root; cdxgen needs the edges only. Grype removed 0 of 34 in every variant (cause not examined).

6.4 Cross project suppression [V]. A module scoped statement from project P suppresses reachable findings in project Q when both contain the same module version and advisory. 5 of 90 ordered pairs overlap; 42 of 230 called findings are exposed; the static prediction matched the scans of all 5 pairs in both scanners (13 or 14 called findings removed in the four large pairs, 2 in the fifth). Product scoped form A removed none. Exposure depends on shared module versions in this set. {harness/vex_cross.py}

6.5 Limits. Reachability and VEX results are Go only (no oracle for Java or Python). Hand built SBOMs in the favourable shape were used for the set wide VEX test. One version per tool.
