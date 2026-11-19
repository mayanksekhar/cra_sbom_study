# Contributing

Corrections, replications and new measurements are welcome.

## Before you open a pull request

1. Fetch the data archive and run all checks: bash harness/fetch_data.sh, then python3 harness/check_all.py --strict. Every check must pass and none may be skipped.
2. Say which claim your change touches (docs/claims_audit.md) and label it verified, partial or open.
3. Add no personal data: no addresses of people, no home paths, no tokens. harness/build_archive.py redacts the archive and stops if a personal address survives.

## Closed for now

The manual labelling of the reachability sample (40 cards) is closed until the second labeller has finished. Please do not submit labels. See the labelling protocol in the README.

## Review

Every change goes through a pull request that the maintainer approves, and the verify workflow must pass.
