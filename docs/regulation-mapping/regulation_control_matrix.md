# Regulation-to-Control Matrix (SCOF)

Last updated: 2026-10-02. Verification was done by web search only.

Status labels:
- VERIFIED-PRIMARY: read at the issuing authority's own page.
- VERIFIED-SECONDARY: confirmed through secondary summaries; primary text still to be read (TO CONFIRM).
- INTERPRETATION: our technical reading. No verified legal text requires this exact control.
- NOT VERIFIED: do not rely on it.

## Sources

| ID | Source | Status | Notes |
|----|--------|--------|-------|
| S1 | RBI circular: [DPSS.CO.OD.No 2785/06.08.005/2017-2018, 6 April 2018](https://www.rbi.org.in/Scripts/NotificationUser.aspx?Id=11244&Mode=0),<br>FAQ :["Storage of Payment System Data"](https://www.rbi.org.in/Scripts/FAQView.aspx?Id=130)  | VERIFIED-PRIMARY | “Storage of Payment System Data.” Paragraph 1 requires system providers to store the entire data relating to payment systems operated by them only in India, including full end-to-end transaction details/information. For the foreign leg of a transaction, the data may also be stored in the foreign country if required. RBI FAQ clarifies applicability to payment system providers authorised/approved by RBI under the Payment and Settlement Systems Act, 2007, including banks and relevant payment-ecosystem entities. |
| S2 | [DPDP Rules 2025, G.S.R. 846(E)](https://www.meity.gov.in/static/uploads/2025/11/53450e6e5dc0bfa85ebd78686cadad39.pdf), notified 13 Nov 2025 (some secondary sources say 14 Nov), Rule 6 "Reasonable security safeguards" | VERIFIED-PRIMARY |  Rule 1 specifies commencement: Rules 1, 2 and 17–21 come into force on publication; Rule 4 after one year; Rules 3, 5–16, 22 and 23 after eighteen months. Rule 6, “Reasonable security safeguards,” requires reasonable security safeguards to prevent personal data breach and specifies minimum measures including encryption/obfuscation/masking/virtual tokens, access control, logging/monitoring/review, backups/continued-processing measures, specified retention of logs and personal data, processor-contract provisions, and technical/organisational measures. Rule 15, “Transfer of personal data outside the territory of India,” permits transfer outside India subject to requirements specified by the Central Government concerning making such data available to a foreign State or persons/entities under its control. |
| S3 | [DPDP Act 2023](https://www.meity.gov.in/static/uploads/2024/02/Digital-Personal-Data-Protection-Act-2023.pdf?), obligation to take reasonable security safeguards | VERIFIED-PRIMARY | Digital Personal Data Protection Act, 2023. Section 8(5) requires a Data Fiduciary to protect personal data in its possession or control by taking reasonable security safeguards to prevent personal data breach. Section 8(4) separately requires appropriate technical and organisational measures for effective observance of the Act and Rules. The penalty associated with breach of the Section 8(5) security-safeguard obligation is specified separately in Schedule Entry 1, read with Section 33(1), and may extend to ₹250 crore. Commencement: Section 8 falls within clause (c) of commencement notification G.S.R. 843(E), dated 13 November 2025, and comes into force eighteen months after Gazette publication (13 May 2027). As of 2 October 2026, Section 8(5) is therefore not yet in force. |
| S4 | [DPDP Act](https://www.meity.gov.in/static/uploads/2024/02/Digital-Personal-Data-Protection-Act-2023.pdf?) Section 16 and [Rules](https://www.meity.gov.in/static/uploads/2025/11/53450e6e5dc0bfa85ebd78686cadad39.pdf?) Rule 15, cross-border transfer | VERIFIED-PRIMARY | DPDP Act, 2023, Section 16 (“Processing of personal data outside India”): Section 16(1) permits the Central Government to restrict, by notification, transfer of personal data by a Data Fiduciary for processing to specified countries or territories outside India. Section 16(2) preserves other Indian laws imposing a higher degree of protection or restriction on such transfers. DPDP Rules, 2025, Rule 15 (“Transfer of personal data outside the territory of India”): personal data processed under the Act may be transferred outside India, subject to requirements that the Central Government may specify concerning making such data available to a foreign State or persons/entities under its control or an agency of such State. Neither Section 16 nor Rule 15 establishes a blanket India-only storage requirement. We do NOT claim DPDP requires India-only storage. |
| S5 | [GDPR EUR-Lex (Regulation (EU) 2016/679)](https://eur-lex.europa.eu/eli/reg/2016/679) Article 32, Security of processing | VERIFIED-PRIMARY | GDPR (Regulation (EU) 2016/679), Article 32(1), “Security of processing.” Requires controllers and processors to implement appropriate technical and organisational measures to ensure a level of security appropriate to the risk, taking into account the state of the art, implementation costs, and the nature, scope, context and purposes of processing. Article 32(1)(a) expressly includes pseudonymisation and encryption of personal data; points (b)–(d) address confidentiality/integrity/availability/resilience, restoration after incidents, and regular testing and evaluation of security measures. |
| S6 | [GDPR EUR-Lex (Regulation (EU) 2016/679)](https://eur-lex.europa.eu/eli/reg/2016/679) Article 44, general principle for transfers | VERIFIED-PRIMARY | GDPR (Regulation (EU) 2016/679), Articles 44–46. Article 44 (“General principle for transfers”) requires transfers of personal data to third countries or international organisations to comply with the conditions of Chapter V and ensures that the level of protection guaranteed by the GDPR is not undermined. Article 45 (“Transfers on the basis of an adequacy decision”) permits transfers where the European Commission has determined that an adequate level of protection is provided. Article 46 (“Transfers subject to appropriate safeguards”) permits transfers in the absence of an Article 45 adequacy decision where appropriate safeguards are provided and enforceable data-subject rights and effective legal remedies are available. These provisions do not establish a blanket EU-only storage requirement. It does not forbid storage outside the EU. |

## Controls (chain: Source -> Requirement -> Control -> Terraform attribute -> Rego rule -> Fixture)

Control IDs are context-neutral and name the technical check. One control has one Rego rule. Which controls apply, and with which parameters, is decided by the routing context (see Routing contexts). The legal basis can differ per context and is recorded under each control.

### REGION-RESTRICTION
- Check: the AWS provider region must be in the allowed list supplied by the routing context. One Rego rule; the router passes the list.
- Terraform attribute: configuration.provider_config.aws.expressions.region.constant_value (literal region, D-013).
- Rego rule: PLANNED policies/region.rego . 
- Allowed lists (parameters; store as data, do not hardcode in Rego):
  - india-finance: ap-south-1, ap-south-2. Based on [AWS's documented region geographies.](https://docs.aws.amazon.com/global-infrastructure/latest/regions/aws-availability-zones.html#zones-asia-pacific)
  - eu: eu-central-1, eu-west-1, eu-west-3, eu-north-1, eu-south-1, eu-south-2. Excludes eu-west-2 (United Kingdom) and eu-central-2 (Switzerland), based on [AWS's documented region geographies.](https://docs.aws.amazon.com/global-infrastructure/latest/regions/aws-availability-zones.html#zones-europe)
- Legal basis per context:
  - india-finance: S1 (RBI). Legal content (as verified): payment system data to be stored in systems located only in India (scope: RBI-authorised payment system providers; payment data). Our interpretation: AWS resources of an India finance workload that holds payment data must be deployed in India regions. Caveats: covers payment data only, not all financial data. RBI also allows the foreign leg of a cross-border transaction to be stored abroad; this rule does not model that exception, so it is stricter than the circular. Backups, replication and global services are not modelled. DPDP is not the source of this control (S4: no blanket India-only storage requirement).
  - eu: S6 (GDPR Art 44), S5 context. Legal content (as verified): transfers to third countries are allowed only if Chapter V conditions are met. Our interpretation (conservative, INTERPRETATION): for an EU deployment context, deploy only in EU regions so that no third-country transfer arises. Caveats: GDPR does not require EU-only storage; adequacy decisions and safeguards (Arts 45-46) are not modelled.
  - india without a sector: no region restriction; no verified source provides one (S4).
- Fixtures: india-finance PASS s3_kms_cmk_india, rds_encrypted_cmk_india, ec2_encrypted_cmk_india, kms_rotation_enabled_india, iam_least_privilege_india; FAIL s3_wrong_region, rds_wrong_region. eu PASS s3_kms_cmk_eu. Cross-context check (India fixtures under eu must FAIL) is planned.

### DATA-ENCRYPTION
- Basis (all contexts): S2 Rule 6 and S5 Art 32.
- Legal content (as verified): reasonable or appropriate security measures, with encryption named as one example. Neither text names KMS or any AWS service. DPDP Rule 6 commences 18 months after notification (about 13 May 2027, per Rule 1), so that basis is not yet in force; GDPR Art 32 is in force.
- Our interpretation: persistent storage must be encrypted with AWS KMS. SSE-S3 (AES256) is still encryption, so the fixture s3_no_kms_encryption violates our stricter KMS control, not necessarily the law.
- Check: S3 sse_algorithm is aws:kms; RDS storage_encrypted is true; EC2 root_block_device encrypted is true.
- Terraform attributes: aws_s3_bucket_server_side_encryption_configuration (rule.apply_server_side_encryption_by_default.sse_algorithm); aws_db_instance.storage_encrypted; aws_instance.root_block_device[].encrypted.
- Rego rule: PLANNED policies/encryption.rego .
- Fixtures: FAIL s3_no_kms_encryption, rds_unencrypted, ec2_unencrypted_ebs. PASS the compliant set.

### KEY-OWNERSHIP
- Basis: none verified. INTERPRETATION.
- Rationale: control over the key lifecycle supports "appropriate technical measures"; no verified text requires customer-managed keys.
- Check: referenced KMS keys must be customer-managed (an aws_kms_key resource or a CMK ARN), not an AWS-managed alias (alias/aws/*).
- Terraform attributes: kms_master_key_id (S3), kms_key_id (RDS, EBS). References to keys created in the same plan are unknown at plan time, so read configuration.root_module.resources[].expressions.<attr>.references.
- Rego rule: PLANNED policies/key_ownership.rego .
- Fixtures: FAIL s3_aws_managed_key.
- Paper note: present as a defence-in-depth control, not as a legal mandate.

### KEY-ROTATION
- Basis: none verified. INTERPRETATION (security best practice).
- Check: aws_kms_key.enable_key_rotation is true.
- Rego rule: PLANNED policies/key_ownership.rego or policies/kms.rego .
- Fixtures: FAIL kms_rotation_disabled. All compliant fixtures with keys set rotation to true.
- Paper note: this extends the three violation categories named in hypothesis H1; record that in the methodology.

### IAM-NO-WILDCARD-ADMIN
- Basis: S2 Rule 6 (access control is among the minimum safeguards), VERIFIED-PRIMARY. The wildcard-admin rule is our INTERPRETATION of "access control"; Rule 6 does not mention IAM or wildcards. Rule 6 commences about 13 May 2027 (Rule 1), so the DPDP basis is not yet in force.
- Check: no IAM policy statement may Allow Action "*" on Resource "*".
- Terraform attribute: aws_iam_policy.policy (JSON string, parse with json.unmarshal in Rego).
- Rego rule: PLANNED policies/iam.rego .
- Fixtures: FAIL iam_wildcard_admin. PASS iam_least_privilege_india.

## Control basis summary

| Control | Legal basis verified | Basis in force (as of 2026-10-02) | Control strictness vs law |
|---------|----------------------|-----------------------------------|---------------------------|
| REGION-RESTRICTION (india-finance) | S1 RBI circular (payment data, India only) | Yes (since 2018) | Stricter: ignores foreign-leg exception, applies by deployment context |
| REGION-RESTRICTION (eu) | S6 GDPR Art 44 (conditions on transfers) | Yes | INTERPRETATION: GDPR allows transfers under Arts 45-46; EU-only is conservative |
| DATA-ENCRYPTION | S2 Rule 6, S5 Art 32 (encryption named) | GDPR yes; DPDP Rule 6 about 13 May 2027 | Stricter: law requires encryption, we require KMS |
| KEY-OWNERSHIP | None | n/a | INTERPRETATION (defence in depth) |
| KEY-ROTATION | None | n/a | INTERPRETATION (security best practice) |
| IAM-NO-WILDCARD-ADMIN | S2 Rule 6 (access control named) | DPDP Rule 6 about 13 May 2027 | INTERPRETATION: wildcard-admin is our reading of "access control" |

Commencement of DPDP Act section 8(5): see S3 (not yet in force as of 2026-10-02).

Candidate future controls from Rule 6 (logging, monitoring, backups, log retention) are out of the MVP scope unless explicitly approved.

## Routing contexts
DPDP and GDPR are both sector-neutral. Only the RBI circular is sector-specific, so the india-finance region list is the only part that depends on sector.

| Layer | Applies when | Controls (parameters) |
|-------|--------------|-----------------------|
| Base | always | DATA-ENCRYPTION, KEY-OWNERSHIP, KEY-ROTATION, IAM-NO-WILDCARD-ADMIN |
| Jurisdiction | jurisdiction = EU | REGION-RESTRICTION (eu list) |
| Sector overlay | jurisdiction = India and sector = finance | REGION-RESTRICTION (india-finance list) |

Evaluated contexts: india-finance (base + REGION-RESTRICTION with the India list) and eu (base + REGION-RESTRICTION with the EU list). India without a sector has base controls only; no verified source gives it a region rule.
healthcare: NO verified source yet. Deferred; do not invent requirements. The MVP demonstrates routing with two contexts, which satisfies the two-context requirement. Healthcare is a documented limitation and future-work item, not part of the evaluated system.
## Verification status
Completed: RBI circular and FAQ, DPDP Rules 2025 (Rules 1, 6, 15), DPDP Act (ss.8, 16, Schedule), GDPR Arts 32 and 44-46 on EUR-Lex.

Region allow-lists (CTL-01a, CTL-01b) checked against AWS region documentation on 2026-10-02. AWS adds regions over time, so re-check before the final artifact.

Still open:
1. Healthcare context has no verified source; deferred (pending verified sourcing).