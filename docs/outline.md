# Paper outline (working draft, 2026-11-07)

Working title: From SBOM to finding: where correctness is lost in vulnerability handling under the CRA
Target: arXiv preprint first, then a workshop. Novelty is not verified beyond two full reads (Mind the Gap, Hidden Dependencies) and search snippets.
Status key: V verified in this repo, P partial (one check or one set), M missing evidence. Rows refer to docs/claims_audit.md.

## 1 Introduction
Context: CRA obligations (vulnerability reporting from 11 Sep 2026, main obligations 11 Dec 2027). Prior work: generators differ (Mind the Gap), lockfiles fix component accuracy (Reality Check), VEX handling differs on a synthetic Java case (Hidden Dependencies).
Question: is an accurate SBOM enough for correct findings and correct VEX?
Contributions to confirm: (1) multi level truth and error attribution from component to finding, (2) measured failure modes in Go and Maven, with pilot data for npm, Rust and PyPI, (3) VEX behaviour of two scanners with controls and a Go reachability rate, (4) what an evidence grade pipeline must declare.

## 2 Related work (docs/literature.md)
Mind the Gap 2609.19920, Reality Check 2511.20313, Python studies 2409.06390 and 2409.01214, Maven studies (FSE 2023, TUM), Hidden Dependencies 2604.21278, VEX-Bench 2609.08040, Vexed by VEX 2503.14388.
M: read Reality Check and VEX-Bench in full; repeat the search for work after Oct 2026.

## 3 Method
Tools and pinned versions, frozen databases (snapshots 20261026 and 20261030 with checksums), sets (pilot 10 at HEAD, older pins 6, Go 10, Maven 8), truth levels (declared, resolved, shipped, tree), reference SBOM per project, error attribution (absent, no version, wrong version, scanner), reachability oracle (govulncheck, Go only), VEX forms A and B, controls.
P: one version per tool. Counting unit decided: one finding per alias cluster per component (Go reference 608, scorer still counts pairs, 610).

## Results status update (2026-11-07)
Five sets on one counting unit (alias cluster), 959 reference findings (docs/table_findings.md, generated). No scanner miss in any set (every missed finding traces to the SBOM). PyPI added: cdxgen loses 19 findings by resolving newer versions than the pinned lock, Trivy reads Python requirements only from requirements.txt style names (one project, one rename). Concentration caveat: Go holds 608 of 959, PyPI findings come from two lockfile projects.

## Drafting status (2026-11-07)
docs/draft.md has sections 3 to 6 as a status marked skeleton (V, P, O next to each statement, source files named, headline numbers checked by harness/verify_draft_numbers.py). docs/cra_mapping.md maps results to Annex I Part II point (1) and BSI TR-03183-2, but the regulation's primary text was NOT read in this session (EUR-Lex fetch returned only the page header): rows rest on secondary sources. Not yet verified: Annex I Part II points beyond (1), Article 13 and 14 content and time limits, any wording on VEX.

## 4 SBOM scope and identity
1. Scope policy differs by tool and changes the ranking (pilot, older pins, Maven). P, replicates Mind the Gap for JS and Rust.
2. Syft on Maven lists only declared pom dependencies. P, 8 of 8 projects, regex count is rough.
3. Maven profiles and optional dependencies (Trivy ignores profiles, Syft lists all, cdxgen follows Maven). P, two controls plus two projects.
4. Nested and placeholder components give phantom findings (axios 1.0.0, requests latest). P, two examples.
5. Missing root version creates phantom findings in Go (55 of 108). V. The remaining 53 findings on the product itself are robust across three scanners (52 of 53) and sit outside the SBOM inventory because generators exclude the root. V for this set, exploitability not assessed.

## 5 Scanner consumption
1. Every finding missed against the same scanner's reference result traces to the SBOM, none to the scanner (4 sets). V. Wording must say per scanner.
2. Trivy misses 17 findings Grype reports (14 reachable, 6 percent of reachable). V for this snapshot. M: mechanism, k9s 5 in OSV.
3. Database drift (19 to 22 reference findings in 4 days). P, one measurement.
4. Compatibility: cdxgen 1.7 rejected by Grype and Trivy, Syft SBOM crashes OSV Scanner. V. M: minimal reproduction, upstream report.

## 6 VEX and reachability
1. Reachability removes 59 percent of Go findings (356 of 608). P, single oracle. M: 40 manual labels (labels/label_sample.csv).
2. Trivy applies product scoped VEX only with a purl on the root and on every component on the path, Grype ignores it, Syft and Trivy generated SBOMs cannot carry it. V on Go, 10 projects, one version per tool. M: cdxgen partial fit.
3. Module scoped VEX from one product suppresses reachable findings in another (42 of 230 exposed). P, depends on shared module versions.
4. No reachability oracle outside Go. State as a limit.

## 7 What an evidence grade pipeline must declare
Scope, product purl with version, connected graph, product scoped statements, profile handling. Derived from sections 4 to 6.
CRA text mapped from the EUR-Lex consolidated English text (docs/cra_mapping.md). M: BSI TR-03183-2 primary text (rows are secondary), ENISA and Commission guidance, any implementing act under Art. 13(24).

## 8 Threats to validity
Single reachability oracle, Go only; one snapshot and one version per tool; popular projects with shared dependencies; my own method errors found and corrected during the work (listed in docs/pilot_findings.md), so every table must be regenerated from a clean checkout.

## 9 Artifacts
Harness, truth files, pinned project lists, snapshot checksums. M: licences of vulnerability databases, FOSSA terms (FOSSA, dep scan and sbomqs were never run).

## Decisions for the author (defaults apply if not decided)
1. Containers: default is out of paper 1, future work.
2. FOSSA, dep scan, sbomqs: default is out, mention as not evaluated.
3. Python: default is pilot only, no set.
4. Counting unit: alias cluster (decided, count_units.py reconciled 610 vs 608).
