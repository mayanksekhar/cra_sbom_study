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
