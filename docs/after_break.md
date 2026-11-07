# Status at quarter mark (2026-10-30)

Done: pinned toolchain, frozen Grype, Trivy, OSV and Go vuln databases (snapshot 20261030), multi level truth for 10 pilot projects, scorers, reference SBOMs, miss attribution, literature check, direction revised.

Next, in order:
1. VEX experiment on node_exporter: govulncheck shows 3 findings in required modules and 0 called. Generate OpenVEX with vexctl, test Grype, Trivy and OSV for suppression and scope (global or path).
2. Fetch the six older pins in dataset/pilot_old.csv, generate truth, SBOMs, scans, rescore.
3. Add OSV to the findings scorer. Use results/raw_osvstrip copies (OSV crashes on Syft npm and PyPI SBOMs with GitHub Actions components).
4. Look up RUSTSEC-2026-0204 and RUSTSEC-2026-0173 on fd, and the OSV matches on UNKNOWN versions in petclinic via Syft.
5. sbomqs completeness, dep scan, FOSSA terms check, container image set, container pipeline.

Open: axios 1.0.0 is a nested docs package (Grype 31 findings, Trivy and OSV 0). cdxgen must run at spec 1.6 for Grype and Trivy.

Update 2026-10-30: step 1 (VEX experiment on node_exporter) done, see docs/pilot_findings.md. Next is step 2, older pins.

Update 2026-10-30 evening: VEX line has a method and a result (see docs/pilot_findings.md). Next: explain Trivy anchor case, then scale the oracle (more Go projects at older pins) to get rates.

Update 2026-10-30 night: VEX has 10 project rate, cross project suppression measured. Remaining: second ecosystem at scale, manual labelling of a finding sample, containers, write up. Roughly half done by my weights.

Next after labelling: (1) fill results_go/label_sample.csv (40 rows, independent verdict first, then compare to govulncheck), (2) second ecosystem at scale for the SBOM to finding layer (Maven or Python), (3) container images, (4) trace the 3 Trivy missing findings and the 22 findings without a govulncheck verdict, (5) outline the paper.

## Status 2026-11-07 (end of session)
About 75 percent by my own weights (estimates). Pushed head: baf9e71 or later. Done this session: PyPI set (8 projects), five sets on one counting unit (alias cluster, 959 reference findings, docs/table_findings.md generated), draft of sections 3 to 6 with harness/verify_draft_numbers.py (16 phrase checks, sections 3, 4 and 5.2 to 5.5 not covered by it), CRA mapping read from the EUR-Lex consolidated English text (Annex I, Articles 3, 13, 14, 64, 69, 71), Go product findings classified, profile and Trivy layout controls as scripts, outline and claims audit updated.
Not in the repo yet: harness/label_cli.py (the labelling tool exists only in chat, rerun its Command 1 to write it).
Open, in order: (1) 15 labels with the tool, then python3 harness/label_cli.py --report, paste the confusion matrix, (2) copy vulndb archives and .sha256 files off the laptop, (3) container images (new truth method, fresh session), (4) draft section 7 and an introduction from docs/cra_mapping.md, (5) BSI TR-03183-2 primary text (rows in cra_mapping.md are secondary), (6) a second reader for docs/draft.md.
Known weak points: single reachability oracle (govulncheck, Go only, 0 of 40 labels); Go holds 608 of 959 reference findings; PyPI findings come from two lockfile projects; one version per tool; Maven truth has up to 3 of 237 components in doubt; Trivy 17 missed findings mechanism unknown; Grype ignores product scoped VEX, cause unknown.
