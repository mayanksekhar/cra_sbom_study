# Literature check (search snippets only, 2026-10-30). Read the full papers before citing.

Closest to RQ1:
1. Mind the Gap: SBOM specification ambiguities, Syft/Trivy/cdxgen on JS and Rust, lockfile reference, arXiv 2609.19920. Plans a benchmark. Scoop risk.
2. A Reality Check on SBOM-based Vulnerability Management, CODASPY 2026, arXiv 2511.20313. 2,414 repos. Lockfiles give accurate SBOMs. Grype and Trivy agree. Go reachability cut false positives by 74.4 percent (31 of 121).
3. Impact of SBOM Generators on Vulnerability Assessment in Python, arXiv 2409.06390. SBOM Generation Tools in the Python Ecosystem, arXiv 2409.01214.
4. Assessing SBOM Generators for Java Maven (TUM, 100 repos). SCA for Java projects, FSE 2023 (21,130 Maven modules).
5. Beyond Compliance: GitHub SBOMs, arXiv 2607.04614. Poking Around in the Dark, arXiv 2606.02442 (ground truth methods).
6. Accuracy Evaluation of SBOM Tools, ARES 2024. SBOM landscape study, arXiv 2402.11151.

Closest to RQ2 and RQ3:
1. Vexed by VEX tools, arXiv 2503.14388 (container scanners incl. OSV, DepScan, Jaccard consistency).
2. Ground-Truth-Based Evaluation of Vulnerability Detection, arXiv 2604.21111 (identical inputs, different assignments).
3. Hidden Dependencies and Component Variants, arXiv 2604.21278 (VEX suppression can add false negatives). Closest to false suppression.
4. VEX-Bench, arXiv 2609.08040 (govulncheck 19 of 30, reachability does not close the gap).
5. SLR, arXiv 2506.03507 (cites Trivy over 7x Grype on 1,151 SBOMs).

CRA: agentic RAG for CRA assurance cases, arXiv 2608.19509 (relevant to the LLM gap benchmark idea). Commercial: Anchore CRA, CRA Evidence.

Our results that replicate prior work: lockfile dependence, Syft and Trivy agreement, cdxgen scope, scanner divergence.
Possibly new, unverified: nested and placeholder name phantom findings, miss attribution (0 scanner misses), measured DB drift, OSV feed coverage, OSV crash on Syft npm and PyPI SBOMs, cdxgen 1.7 rejection.
Direction: an accurate SBOM is not sufficient for correct vulnerability handling.
Next: read Mind the Gap, Reality Check, Hidden Dependencies and VEX-Bench in full, then add a container image set.

## Full reads (2026-10-30)

Mind the Gap (arXiv 2609.19920, Inria and ANSSI): 3,000+ JS and Rust projects, lockfile baseline that keeps dev and test dependencies, generation only, no vulnerability scanning. Covers scope policy, cdxgen directory exclusions, symlink and workspace placeholder components, aliasing. Plans an edge case benchmark and Python and Java extension. Tool versions Syft 1.38.2, Trivy 0.68.2, cdxgen 12.0.0. Our npm and Rust RQ1 results are replication.

Hidden Dependencies (arXiv 2604.21278): Java, synthetic, one vulnerability. With VEX applied, Grype and CVE-Bin-Tool suppress nothing, Trivy suppresses everything including reachable cases (false suppression). Cloned components not detected in CycloneDX by any tool. Measures consistency, not accuracy. Same Trivy version (0.69.3) as our setup.

Revised direction: From SBOM to finding, where correctness is lost. Layers: SBOM scope and identity (extend to Go, Maven, Python), scanner consumption (phantom matches, versionless components, feed coverage, drift, crashes), VEX application on real findings. CRA discussion: what an evidence grade pipeline must declare.

## Read in full 2026-11-10 (arXiv HTML and PDF)
Zhou, Dacier, Konstantinou, A Reality Check on SBOM-based Vulnerability Management, CODASPY 2026, arXiv 2511.20313, doi 10.1145/3800506.3803490. 2,414 repositories in Python (Poetry), Rust, Ruby, PHP. Syft 1.33.0 and Trivy 0.66.0 identical and 100 percent accurate from lock files (Jaccard 1.0); both empty for package-lock.json at those versions. Manual check of 16 repositories, 113 reported, 9 confirmed (92.0 percent false positive rate), coverage check removes 61.9 percent. An earlier version quoted 97.5 and 63.3 percent in a search summary. Go: 12 projects at 2025 release versions, 121 reported, 31 with listed symbols present in the compiled binary's symbol table (74.4 percent reduction), symbols from the Go vulnerability database; no call graph, no govulncheck. States that VEX is a communication format, not an analysis engine. Threats: fixed environment, manual verification limited, static analysis only, vendoring not addressed.
Shi et al., VEX-Bench, arXiv 2609.08040. 75 expert labelled cases, Go 30, Java 25, Python 20; Fleiss kappa 0.667 on 15 calibration cases; 70.7 percent not affected, code_not_reachable 38 of 75. Table 3: OSV-Scanner F1 40.5, Trivy 36.1 (n 75); Go subset: OSV detect F1 38.9, OSV reachability 42.9 (precision 28.6, recall 85.7), govulncheck coverage 63.3 percent (19 of 30, needs a successful build), precision 22.2, recall 28.6, F1 25.0. Affected predicted if a tool reports the target CVE. Reachability does not imply exploitability.
Read only as abstract, html summary or poster: Churakova, Ekstedt, Schmid, Vexed by VEX tools, arXiv 2503.14388 (seven tools, Jaccard and Tversky, highest pairwise Jaccard about 0.69 Trivy against Grype, 88 percent correlation with database overlap).
Seen as titles only, to read: A Practical Solution to Systematically Monitor Inconsistencies in SBOM-based Vulnerability Scanners (arXiv listing, 2025-12); LUCID, a framework for reducing false positives and inconsistencies among container scanning tools; and works cited by Reality Check: Yu et al. DSN 2024 (metadata based SBOM correctness), O'Donoghue et al. 2023 and 2024, Rabbi et al. SAC 2024 (npm), Benedetti et al. arXiv 2409.06390 (Python), Balliu et al. 2023 (Java), Cofano et al. TrustCom 2024 (Python), Zhao et al. ISSRE 2024 (CovSBOM), Pashchenko et al. TSE 2022 (Vuln4Real), Imtiaz et al. ESEM 2021.
govulncheck documentation (go.googlesource.com, doc.go, seen as a snippet): binary mode uses the binary's symbol information to find mentions of vulnerable functions and may report false positives for code that is in the binary but unreachable; govulncheck can emit OpenVEX. Our mechanical check is close to that mode. Binary mode might fit in memory for k9s (untested).
