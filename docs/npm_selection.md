# Selection rule for the second npm set

Fixed on 2026-11-13, before any SBOM generator or scanner was run on the candidates.

1. The candidates are listed in dataset/npm_candidates.csv in a fixed order. The application or library label is the author's own knowledge and was not checked.
2. For each candidate the version is the highest stable semver tag (x.y.z, with or without a leading v) of its GitHub repository on the day of the probe.
3. A candidate qualifies if package-lock.json is committed at the repository root at that tag.
4. The first 8 qualifying candidates in list order form the new set.
5. A candidate is skipped only for these reasons: no stable tag, no committed package-lock.json, clone failure. No candidate is replaced or dropped for anything a generator or scanner reports.
6. The three projects of the first npm set (mocha, TypeScript, pm2) stay as they are.

The probe is harness/probe_npm_candidates.sh. Its output is kept as results_npm/probe.csv.

## Amendment of 2026-11-13, made after the first probe and before any generator or scanner ran on the candidates

The first probe output is kept as results_npm/probe_v1.csv. It showed two defects of the probe, found by reading the table against this rule and not from any tool result on the candidates.

1. Rule 2 says the highest stable tag with or without a leading v. The probe sorted tags with sort -V, which ranks a v prefixed tag above a plain one (mongoose v4.11.13, puppeteer v19.2.2 and node-red v0.2.0 were stale picks). The probe now strips the prefix before sorting. The rule is unchanged.
2. Rule 3 is amended: a candidate qualifies if package-lock.json is committed at the root with lockfileVersion 2 or 3, because harness/truth_npm.sh reads the packages map that version 1 lock files do not have. The probe now records lockfile_version.

The first 8 qualifying candidates in list order are still taken without reordering. The result of the second probe is kept as results_npm/probe.csv.

