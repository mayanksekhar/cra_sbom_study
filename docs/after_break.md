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
