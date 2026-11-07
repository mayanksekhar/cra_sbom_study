# CRA and BSI mapping (2026-11-07)

Verification status. The EUR-Lex fetch returned only the page header, so the regulation text was NOT read in primary form in this session. Rows below rest on secondary sources that quote the same sentence for Annex I Part II point (1) (Cybeats, FOSSA, cra-decoded, governance docs, several others) and on descriptions of BSI TR-03183-2 v2.1.0 (CycloneDX 1.6 or higher or SPDX 3.0.1 or higher, JSON or XML; one SBOM per product version; recursive dependency resolution down to the first component outside the scope of delivery; exact version, not a range; purl listed as an additional field, mandatory when available). Read the primary texts before any of this goes into a paper.

| Requirement (source, status) | What our results say | Status |
|---|---|---|
| Annex I Part II point (1): identify and document vulnerabilities and components, including an SBOM in a commonly used machine readable format covering at the very least the top level dependencies (secondary sources, identical wording) | Syft on Maven lists roughly the dependencies declared in the root pom (8 of 8 projects, counts 1 to 3 above a rough declared count), which is close to the CRA floor, and recovers 43 of 201 real findings. Meeting the floor does not mean the vulnerabilities of the product are visible. | P, floor wording secondary, "top level" undefined in the regulation per secondary sources |
| BSI TR-03183-2: recursive dependency resolution (secondary sources) | Only generators that resolve transitive dependencies recover the Maven findings (cdxgen, Trivy 201 of 201). Syft does not. | P |
| BSI: component version is exact, not a range (secondary sources) | 38 of the 158 Maven findings Syft misses are on components present without a version. In the pilot 25 of 28 Syft Maven components in spring_petclinic had no version. | V for our data, requirement wording secondary |
| BSI: CycloneDX 1.6 or higher (secondary sources) | cdxgen 12.9.0 writes CycloneDX 1.7 by default. 1.7 satisfies "1.6 or higher", yet Grype 0.114.0 and Trivy 0.69.3 both reject it. A guideline compliant SBOM can be unreadable by two scanners. | V for the rejection, guideline wording secondary |
| BSI: product is a logical component with name and version, purl additional when available (secondary sources) | Without a versioned root purl, Grype (not Trivy or OSV Scanner, see the version control) matched every advisory of the module: 55 of 108 findings on the product name were phantoms (Go, cdxgen SBOMs). Trivy applies a product scoped VEX statement only when the root and every component on the path to the vulnerable module have a purl. A purl being additional, not required, leaves this gap open. | V for Go, requirement wording secondary |
| CRA does not define scope of "components" (cra-decoded, secondary) | Scope policy flips the generator ranking: against Maven all scope truth cdxgen scores P 1.00 R 1.00 and Trivy R 0.48, against shipped_nonopt cdxgen P 0.48 R 1.00 and Trivy P 0.98 R 0.99. BSI "scope of delivery" favours the shipped definition. | V for our data |
| One SBOM per product version (BSI, secondary) | Database drift: reference findings grew from 19 to 22 over four days with no change in the projects (pilot). A per version SBOM needs a dated vulnerability snapshot to be reproducible. | P, one measurement |
| Annex I Part II vulnerability handling points beyond (1), Article 14 reporting timelines (24 hours early warning, 72 hours notification, final report), Article 13 due diligence on third party components and support period | NOT VERIFIED in this session. A vendor page from an earlier search mentioned the 24 and 72 hour windows. Application dates seen in secondary sources: reporting obligations 11 September 2026, main obligations 11 December 2027. | O |
| VEX in the CRA text | NOT VERIFIED. Searches returned no CRA wording on VEX or exploitability. Do not claim the CRA mentions or omits VEX until Annex I and Article 14 are read. | O |

Implication to test in the paper (not yet supported): an evidence grade pipeline needs scope declared, a versioned product purl, a connected dependency graph, exact versions on every component, product scoped statements, a dated vulnerability snapshot.

## Update 2026-11-07: partial primary reading
Source: cyberresilienceact.eu/fr/regulation.html, a third party French reproduction of Articles 1 to 39 of Regulation (EU) 2024/2847 (not EUR-Lex; my translations; cut off mid Article 39; annexes, Article 40 onward and Article 71 NOT read). This supersedes the earlier "NOT VERIFIED" rows for Article 13 and 14 below.

Verified in that text:
1. Art. 3(39) SBOM: an official document with the details and the supply chain relationships of the components used to build a product.
2. Art. 3(41) exploitable vulnerability: one that an adversary could effectively use in actual operating conditions. Art. 3(42) actively exploited: reliable evidence of exploitation by a malicious actor without the system owner's authorisation.
3. Art. 13(8): during the support period vulnerabilities of the product, including its components, are managed effectively under Annex I Part II. Support period at least five years, or the expected use time if shorter.
4. Art. 13(6): a vulnerability found in an integrated component is reported to its maintainer and addressed under Annex I Part II.
5. Art. 13(24): the Commission may specify SBOM format and elements by implementing act. Art. 13(25): market surveillance authorities may request SBOMs for dependency assessments.
6. Art. 14(1) and (2): actively exploited vulnerability, early warning within 24 hours of becoming aware, notification within 72 hours, final report within 14 days after a fix or mitigation is available, through the single reporting platform (Art. 16). Severe incidents: 24 hours, 72 hours, final report within one month of the notification.
7. Art. 14(8): users informed of an actively exploited vulnerability and mitigations, in a structured machine readable format where appropriate. VEX is not named.
8. The term VEX does not appear in Articles 1 to 39.
Reporting obligations apply from 11 September 2026 (site annotation and earlier secondary sources, Article 71 not read).

Observations for the paper (not yet claims):
1. The SBOM floor (top level dependencies, Annex I Part II point 1, secondary sources) is narrower than the duty to manage vulnerabilities of components (Art. 13(8)). Maven: Syft, which approximates the top level, recovers 43 of 201 real findings.
2. Art. 3(41) defines exploitable vulnerability. Reachability and VEX approximate it, the regulation prescribes no method.
3. Secondary sources number the same duties inconsistently (Art. 13(6) called SBOM maintenance, Art. 13(10) and 13(1)(b) cited for duties the text places in 13(8)). Use verified numbers only.
Still unread: Annex I (all of it), Annex II, VII, Article 71. Unverified recollection: Annex I Part I point 2(a) refers to products without known exploitable vulnerabilities.

## Update 2026-11-07 (later): primary text read
Source: EUR-Lex consolidated English text of Regulation (EU) 2024/2847 (02024R2847-20241120, includes corrigenda C1 to C3), supplied by the author as a PDF. The document states it has no legal effect, the authentic text is the Official Journal version. Read, not text searched: "not found" below means I did not see it while reading. This supersedes the French reproduction notes and the secondary source rows for the items below. BSI TR-03183-2 rows remain secondary (the PDF is only the regulation).

Verified:
1. Annex I Part II point (1): identify and document vulnerabilities and components, including by drawing up a software bill of materials in a commonly used and machine readable format covering at the very least the top level dependencies of the products. Article 3 defines neither dependency nor top level dependencies. Art. 3(6): component means software or hardware intended for integration into an electronic information system.
2. Annex I Part I point 2(a): products to be made available on the market without known exploitable vulnerabilities, on the basis of the cybersecurity risk assessment and where applicable. Art. 3(40) vulnerability, Art. 3(41) exploitable vulnerability (potential to be effectively used by an adversary under practical operational conditions), Art. 3(42) actively exploited vulnerability.
3. Annex I Part II points 2 to 8: remediate vulnerabilities without delay in relation to the risks posed (2), effective and regular security tests (3), disclose information about fixed vulnerabilities (4), coordinated vulnerability disclosure policy (5), measures to share information about potential vulnerabilities in the product and in third party components, with a contact address (6), secure update distribution (7), updates disseminated without delay, free of charge, with advisory messages (8).
4. SBOM disclosure: Annex VII points 2(b) and 8 put the SBOM in the technical documentation, provided to a market surveillance authority on reasoned request where necessary to check compliance. Annex II point 9: only if the manufacturer decides to make the SBOM available to users, information on where it can be accessed. Art. 13(24) and 13(25) as before.
5. Dates: Art. 71 applies the regulation from 11 December 2027, Article 14 from 11 September 2026, Chapter IV (Articles 35 to 51) from 11 June 2026. Art. 69(3): Article 14 applies to all products in scope including those placed on the market before 11 December 2027. Art. 69(2): other requirements apply to earlier products only after a substantial modification.
6. Art. 64(2): fines up to EUR 15 000 000 or 2.5 percent of worldwide annual turnover for non compliance with Annex I and Articles 13 and 14. Art. 64(10): no fines for micro and small enterprises for missing the 24 hour deadline of Art. 14(2)(a) and 14(4)(a), none for open source software stewards.
7. VEX, vulnerability exploitability exchange, advisory formats: not named in the text I read. Machine readable formats are mentioned in Art. 13(6) and Art. 14(8) only.

Observations for the paper (not claims, no legal interpretation, not legal advice):
1. The text separates vulnerability (3(40)) from exploitable vulnerability (3(41)) and phrases Annex I Part I 2(a) with the latter. Reachability analysis and VEX approximate that definition, the regulation prescribes no method. A tool that wrongly suppresses a reachable finding bears on that wording. How it applies to component vulnerabilities is a question for lawyers.
2. The SBOM floor (Annex I Part II point 1, top level dependencies) is narrower than the duty to manage vulnerabilities of the product including its components (Art. 13(8)) and to share information about potential vulnerabilities in third party components (Annex I Part II point 6).
3. SBOMs reach authorities on reasoned request (Annex VII point 8) and users only if the manufacturer chooses (Annex II point 9). Errors in an SBOM would mostly surface through an authority request.
4. Article 14 reporting has applied since 11 September 2026, ahead of the main obligations, and covers older products.

## Update 2026-11-07 (BSI): TR-03183-2 v2.1.0 read
Source: full text of BSI TR-03183-2 v2.1.0 (2025-08-20) from a third party mirror (ibf-solutions.com). BSI's own PDF fetch returned only a landing page blurb, so check against bsi.bund.de before citing. Section numbers are the guideline's.

Verified:
1. Section 4: JSON or XML, CycloneDX 1.6 or higher or SPDX 3.0.1 or higher, officially released versions only.
2. Section 3.1 and 8.1.14: a separate SBOM per software version, updated only for added information or error corrections. An SBOM MUST NOT contain vulnerability information, a document with both does not conform. CSAF recommended, VEX as a profile.
3. Introduction: an SBOM does not state vulnerabilities or exploitability. Whether a vulnerable component affects the product needs an analysis of how the product uses it, done as part of vulnerability handling, result provided to users as a security advisory or VEX.
4. Section 3.2.1: compiled code, the component used in the linker run MUST be listed. Interpreted code, exact required version MUST be listed if the component is part of the delivery item, otherwise the minimum required version SHOULD be listed. The primary component is the root of the dependency tree and is a component.
5. Section 5.1: recursive dependency resolution MUST reach, on each path, the first component outside the scope of delivery. Section 8.1.11: scope of delivery means parts delivered with the product, not parts to be acquired separately. Section 8.3.1: top level SBOM is the primary component plus direct dependencies.
6. Table 3 required per component: creator, name, version (file modification date if no version assigned), filename, dependencies with completeness clearly indicated, distribution licences, SHA-512 hash of the deployable component, executable, archive and structured properties. Table 2 required for the SBOM: creator (email or URL), timestamp. Table 5 additional, MUST if it exists: source code URI, URI of the deployable form, other unique identifiers (CPE or purl), original licences. CycloneDX mapping: components without dependencies are declared as empty elements in the dependency graph, completeness through compositions.
7. Section 5.1 and 8.4.3: the SBOM must hold the information available during the build, a build SBOM follows the linker run for translated code.
8. Section 7: the most recent guideline version MUST be used, the previous one for up to six months after a new one.

Corrections to the secondary source rows above:
1. "Exact version, not a range" is too simple: exact required version is a MUST for interpreted code in the delivery item, minimum required version a SHOULD outside it. Version is a required field for every component (Table 3), so the Syft versionless Maven components (38 of 158 missed findings) break a required field.
2. cdxgen's default CycloneDX 1.7 meets "1.6 or higher". Not checked: whether 1.7 is an officially released version.

Observations (not claims):
1. Our Go shipped truth (linker run, three platforms) matches BSI's rule for compiled code, the declared and module graph definitions do not.
2. CRA floor (top level dependencies) corresponds to BSI's top level SBOM, BSI's own minimum (5.1) goes deeper.
3. Syft and Trivy primary components without a version (Go pilot) conflict with the required version field. Probe: harness/bsi_probe.py.
4. Library projects: scope of delivery may exclude separately acquired dependencies, so BSI might need only the first level identified. Interpretation, unverified. Our shipped truth for libraries is the consumer's runtime closure.
Not measured by us: creator, filename, SHA-512 hash, executable, archive, structured properties, licences.

## BSI probe results (2026-11-07, harness/bsi_probe.py, 43 SBOMs per generator over five sets, all CycloneDX 1.6)
Primary component has a version: cdxgen 29, Syft 0, Trivy 0. Has a purl: cdxgen 43, Syft 0, Trivy 0. Has outgoing dependency edges: cdxgen 41, Syft 0, Trivy 40. Vulnerability data embedded: 0 for all three. compositions present: 0 for all three. Packages (components with a purl) without a version field: cdxgen 68 of 6162, Syft 0 of 3560, Trivy 15 of 2570.
Inferred, not checked per file: cdxgen's 14 SBOMs without a root version equal the number of Go SBOMs (2 pilot, 2 older pins, 10 Go set).
Reading against BSI (Table 3, 5.1, CycloneDX mapping): Syft's primary component enumerates no direct dependencies in any SBOM, no generator states completeness through compositions. No generator embeds vulnerability data (my earlier guess about Trivy was wrong).
Caveats: scans were of temporary copies so the root name is a local path; source name and version flags of Syft and Trivy not tested, so the missing root version is the default behaviour of a directory scan, not a proven limitation. The probe covers 6 of the 10 required component fields, not creator, filename, SHA-512 hash, executable, archive, structured.
CORRECTION to the earlier BSI observation: the claim that Syft's versionless Maven components break the required version field is not supported by the probe, because Syft's version field is filled for all 3560 packages. What lacks a version is the purl of some components. The content of the version field for those components is still to be checked. Same open question for Trivy's 15 and cdxgen's 68 packages without a version field.

## Version field contents (2026-11-07, harness/bsi_probe.py plus an inline listing over 43 SBOMs per generator)
Packages whose purl has no version: Syft 85 (golang 14, maven 64, github 7), Trivy 15 (golang), cdxgen 68 (pypi).
Version field: Syft holds the string UNKNOWN in 79 (14 Go product modules, 64 Maven dependencies such as jmh-core, and by subtraction 1 GitHub component) and a branch name in 6 GitHub Actions components (main 4, master 2). Trivy: null in all 15 (the product's own module, 2 pilot, 2 older pins, 11 in the Go set whose 10 projects imply one SBOM with two such components, unexplained). cdxgen: empty string in all 68 (unpinned requirement lines such as pytest-cov, trustme, wheel, and a component named "." with purl pkg:pypi/.).
Reading against BSI Table 3 (version required for every component, file modification date if no version is assigned): all three generators emit components without a usable version. The earlier withdrawal of the Syft claim is itself withdrawn: Syft fills the field with a placeholder, which is not a version identifier as I read the text.
CORRECTION to the 2026-11-05 entry on Go product findings: I wrote that Trivy lists the product as an ordinary component "with a purl and a version". It does not: the purl has no version and the version field is absent in all 15 Go SBOMs.
Hypothesis, untested: a scanner treats version UNKNOWN as matching nothing and an absent version as matching every advisory (Syft 0 product findings, Trivy and cdxgen 91 each). Control: harness/control_version.py.
