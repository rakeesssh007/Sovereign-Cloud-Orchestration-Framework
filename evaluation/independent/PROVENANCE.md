# Provenance of the independent evaluation labels

This note applies to every row of `expected_labels.csv` (headline set) and `exploratory_labels.csv` (exploratory strata). It replaces per-row author and reviewer columns.

## Who produced and checked the labels
- **Authorship:** the labels and fixtures were drafted with AI-assistant support from the regulation-to-control matrix text, then checked, corrected where needed and adopted by Rakesh.
- **Independent review:** Prashant reviewed all 23 headline scenarios and the 11 exploratory scenarios against the matrix, using the review sheets in this folder (`REVIEW_SHEET.md`, `EXPLORATORY_REVIEW_SHEET.md`). The headline review was completed on 2026-11-18; the exploratory review was completed before the evaluation run. Both dates are as reported by the project owner.
- **Reference for labels:** the frozen regulation matrix and the scenario specification only. No label was derived from Rego, OPA, Conftest or CLI output, nor from any earlier results file.

## Order of events
1. The policy baseline was frozen (freeze v1: commit `0da42cd`, tag `policies-freeze-v1`) and the fixtures and labels were authored afterwards.
2. A sector-neutral `india` routing context was added before any evaluation run, which reopened the freeze; freeze v2 is commit `28fe60a6f56b0807c810f10bb6c0ab8577882417`, tag `policies-freeze-v2`. Between the two freezes only router data, router tests, the matrix, the catalogue and documentation changed; no policy, core or registry file changed.
3. The headline set (89 rows) was not evaluated before its labels were reviewed. The exploratory set (11 rows) was run once as an owner-requested pilot before the final run; no label, fixture or policy was changed because of that pilot.
4. On 2026-11-18, after review, the per-row author and reviewer columns were removed from `expected_labels.csv` and replaced by this note. The labels themselves are unchanged: every remaining column of all 89 rows is identical to the file that was reviewed (the previous file had SHA-256 `f976c41afacac762472989f1e8e3e79ad09ffa562452dcd2ddac5166b02642d4`).
5. One headline scenario was replaced before any evaluation (an RDS AWS-managed-alias fixture, which the provider rejects, became an EC2 root-volume equivalent).

## Hashes (SHA-256)
| File | SHA-256 |
|---|---|
| `expected_labels.csv` (89 rows: 58 non-compliant, 28 compliant, 3 leakage) | `0a0445681a6147a027c934acb52025c7538e7785a31292e93f7ab68b023a57fb` |
| `exploratory_labels.csv` (11 rows: 7 boundary, 4 declared-gap) | `835fa727cffe2218b67e0d88a8a617c368271efc8f5dd16dbd56177d06f97d33` |

## Disclosures for the report
- A jointly reviewed student evaluation of deliberately constructed fixtures, not an external audit or certification.
- The scenarios were drafted by an AI assistant that had seen the policies and the development and smoke cases, so they may lean toward clear-cut cases; labels follow the matrix text, and the exploratory strata were added to probe documented blind spots.
- Exploratory rows are reported separately and never pooled into the headline rates, apart from one sensitivity line fixed in the evaluation plan before the run.
