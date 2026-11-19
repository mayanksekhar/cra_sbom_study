# Security policy

This repository holds an empirical research study, its measurement code and its results. It is not a product and runs no service.

## Reporting a problem

Please use GitHub private vulnerability reporting: open the Security tab of this repository and choose "Report a vulnerability". Please do not open a public issue for a security problem.

In scope: code in harness/ that handles untrusted input unsafely, personal data or a secret in the repository or in the data archive, and any way to tamper with the verification (the pinned archive hash, the checks, the workflow).

Out of scope: vulnerabilities in the open source projects that the study measured. Those findings are public advisories and belong to the projects concerned. Errors in the numbers of the study are welcome as normal issues, with the failing check or the recomputation attached.

## Response

This is a one person research project. I aim to answer within 7 days and to record every confirmed fix in docs/pilot_findings.md.
