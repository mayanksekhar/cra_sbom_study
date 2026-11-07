# CRA and BSI mapping (2026-11-07)

Verification status. The EUR-Lex fetch returned only the page header, so the regulation text was NOT read in primary form in this session. Rows below rest on secondary sources that quote the same sentence for Annex I Part II point (1) (Cybeats, FOSSA, cra-decoded, governance docs, several others) and on descriptions of BSI TR-03183-2 v2.1.0 (CycloneDX 1.6 or higher or SPDX 3.0.1 or higher, JSON or XML; one SBOM per product version; recursive dependency resolution down to the first component outside the scope of delivery; exact version, not a range; purl listed as an additional field, mandatory when available). Read the primary texts before any of this goes into a paper.

| Requirement (source, status) | What our results say | Status |
|---|---|---|
| Annex I Part II point (1): identify and document vulnerabilities and components, including an SBOM in a commonly used machine readable format covering at the very least the top level dependencies (secondary sources, identical wording) | Syft on Maven lists roughly the dependencies declared in the root pom (8 of 8 projects, counts 1 to 3 above a rough declared count), which is close to the CRA floor, and recovers 43 of 201 real findings. Meeting the floor does not mean the vulnerabilities of the product are visible. | P, floor wording secondary, "top level" undefined in the regulation per secondary sources |
| BSI TR-03183-2: recursive dependency resolution (secondary sources) | Only generators that resolve transitive dependencies recover the Maven findings (cdxgen, Trivy 201 of 201). Syft does not. | P |
| BSI: component version is exact, not a range (secondary sources) | 38 of the 158 Maven findings Syft misses are on components present without a version. In the pilot 25 of 28 Syft Maven components in spring_petclinic had no version. | V for our data, requirement wording secondary |
| BSI: CycloneDX 1.6 or higher (secondary sources) | cdxgen 12.9.0 writes CycloneDX 1.7 by default. 1.7 satisfies "1.6 or higher", yet Grype 0.114.0 and Trivy 0.69.3 both reject it. A guideline compliant SBOM can be unreadable by two scanners. | V for the rejection, guideline wording secondary |
| BSI: product is a logical component with name and version, purl additional when available (secondary sources) | Without a versioned root purl, scanners matched every advisory of the module: 55 of 108 findings on the product name were phantoms (Go, cdxgen SBOMs). Trivy applies a product scoped VEX statement only when the root and every component on the path to the vulnerable module have a purl. A purl being additional, not required, leaves this gap open. | V for Go, requirement wording secondary |
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
