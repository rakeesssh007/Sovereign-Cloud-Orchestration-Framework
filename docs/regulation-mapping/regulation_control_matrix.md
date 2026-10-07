# Regulation-to-Control Matrix (SCOF)

Last updated: 2026-10-05. Verification was done by web search and, where noted, by reading the primary text.

Status labels:
- VERIFIED-PRIMARY: read at the issuing authority's own page.
- VERIFIED-SECONDARY: confirmed through secondary summaries; primary text still to be read (TO CONFIRM).
- INTERPRETATION: our technical reading. No verified legal text requires this exact control.
- NOT VERIFIED: do not rely on it.

## Sources

| ID | Source | Status | Notes |
|----|--------|--------|-------|
| S1 | RBI circular: [DPSS.CO.OD.No 2785/06.08.005/2017-2018, 6 April 2018](https://www.rbi.org.in/Scripts/NotificationUser.aspx?Id=11244&Mode=0),<br>FAQ :["Storage of Payment System Data"](https://www.rbi.org.in/Scripts/FAQView.aspx?Id=130)  | VERIFIED-PRIMARY | “Storage of Payment System Data.” Paragraph 1 requires system providers to store the entire data relating to payment systems operated by them only in India, including full end-to-end transaction details/information. For the foreign leg of a transaction, the data may also be stored in the foreign country if required. RBI FAQ clarifies applicability to payment system providers authorised/approved by RBI under the Payment and Settlement Systems Act, 2007, including banks and relevant payment-ecosystem entities. |
| S2 | [DPDP Rules 2025, G.S.R. 846(E)](https://www.meity.gov.in/static/uploads/2025/11/53450e6e5dc0bfa85ebd78686cadad39.pdf), notified 13 Nov 2025 (the Gazette itself is dated 13 November 2025; some secondary sources say 14 Nov), Rule 6 "Reasonable security safeguards" | VERIFIED-PRIMARY |  Rule 1 specifies commencement: Rules 1, 2 and 17–21 come into force on publication; Rule 4 after one year; Rules 3, 5–16, 22 and 23 after eighteen months. Rule 6, “Reasonable security safeguards,” requires reasonable security safeguards to prevent personal data breach and specifies minimum measures including encryption/obfuscation/masking/virtual tokens, access control, logging/monitoring/review, backups/continued-processing measures, specified retention of logs and personal data, processor-contract provisions, and technical/organisational measures. Rule 15, “Transfer of personal data outside the territory of India,” permits transfer outside India subject to requirements specified by the Central Government concerning making such data available to a foreign State or persons/entities under its control. |
| S3 | [DPDP Act 2023](https://www.meity.gov.in/static/uploads/2024/02/Digital-Personal-Data-Protection-Act-2023.pdf), obligation to take reasonable security safeguards | VERIFIED-PRIMARY | Digital Personal Data Protection Act, 2023. Section 8(5) requires a Data Fiduciary to protect personal data in its possession or control by taking reasonable security safeguards to prevent personal data breach. Section 8(4) separately requires appropriate technical and organisational measures for effective observance of the Act and Rules. The penalty associated with breach of the Section 8(5) security-safeguard obligation is specified separately in Schedule Entry 1, read with Section 33(1), and may extend to ₹250 crore. Commencement: Section 8 falls within clause (c) of commencement notification G.S.R. 843(E), dated 13 November 2025, and comes into force eighteen months after Gazette publication (13 May 2027). As of 2 October 2026, Section 8(5) is therefore not yet in force. |
| S4 | [DPDP Act](https://www.meity.gov.in/static/uploads/2024/02/Digital-Personal-Data-Protection-Act-2023.pdf) Section 16 and [Rules](https://www.meity.gov.in/static/uploads/2025/11/53450e6e5dc0bfa85ebd78686cadad39.pdf?) Rule 15, cross-border transfer | VERIFIED-PRIMARY | DPDP Act, 2023, Section 16 (“Processing of personal data outside India”): Section 16(1) permits the Central Government to restrict, by notification, transfer of personal data by a Data Fiduciary for processing to specified countries or territories outside India. Section 16(2) preserves other Indian laws imposing a higher degree of protection or restriction on such transfers. DPDP Rules, 2025, Rule 15 (“Transfer of personal data outside the territory of India”): personal data processed under the Act may be transferred outside India, subject to requirements that the Central Government may specify concerning making such data available to a foreign State or persons/entities under its control or an agency of such State. Neither Section 16 nor Rule 15 establishes a blanket India-only storage requirement. We do NOT claim DPDP requires India-only storage. |
| S5 | [GDPR EUR-Lex (Regulation (EU) 2016/679)](https://eur-lex.europa.eu/eli/reg/2016/679) Article 32, Security of processing | VERIFIED-PRIMARY | GDPR (Regulation (EU) 2016/679), Article 32(1), “Security of processing.” Requires controllers and processors to implement appropriate technical and organisational measures to ensure a level of security appropriate to the risk, taking into account the state of the art, implementation costs, and the nature, scope, context and purposes of processing. Article 32(1)(a) expressly includes pseudonymisation and encryption of personal data; points (b)–(d) address confidentiality/integrity/availability/resilience, restoration after incidents, and regular testing and evaluation of security measures. |
| S6 | [GDPR EUR-Lex (Regulation (EU) 2016/679)](https://eur-lex.europa.eu/eli/reg/2016/679) Article 44, general principle for transfers | VERIFIED-PRIMARY | GDPR (Regulation (EU) 2016/679), Articles 44–46. Article 44 (“General principle for transfers”) requires transfers of personal data to third countries or international organisations to comply with the conditions of Chapter V and ensures that the level of protection guaranteed by the GDPR is not undermined. Article 45 (“Transfers on the basis of an adequacy decision”) permits transfers where the European Commission has determined that an adequate level of protection is provided. Article 46 (“Transfers subject to appropriate safeguards”) permits transfers in the absence of an Article 45 adequacy decision where appropriate safeguards are provided and enforceable data-subject rights and effective legal remedies are available. These provisions do not establish a blanket EU-only storage requirement. It does not forbid storage outside the EU. |
| S7 | [GDPR EUR-Lex (Regulation (EU) 2016/679)](https://eur-lex.europa.eu/eli/reg/2016/679) Article 5(1)(f), integrity and confidentiality | VERIFIED-PRIMARY | Article 5(1)(f) requires personal data to be processed in a manner that ensures appropriate security, including protection against unauthorised or unlawful processing and against accidental loss, destruction or damage, using appropriate technical or organisational measures (“integrity and confidentiality”). Used only as supporting basis for ACCESS-EXPOSURE. The control itself remains an INTERPRETATION because Article 5(1)(f) does not specifically require blocking public S3 or RDS exposure. |
| S8 | [Reserve Bank of India (Information Technology Governance, Risk, Controls and Assurance Practices) Directions, 2023](https://www.rbi.org.in/Scripts/NotificationUser.aspx?Id=12562), Master Direction RBI/2023-24/107, DoS.CO.CSITEG/SEC.7/31.01.015/2023-24, 7 November 2023, paragraph 29(e) | VERIFIED-PRIMARY | Read on the RBI website on 2026-10-05. Paragraph 29 ("Disaster Recovery Management", Chapter V), sub-clause (e): a regulated entity must back up data and periodically restore the backed-up data to check that it is usable, while preserving the integrity of the backups and protecting them from unauthorised access (paraphrased). It names no retention period, no restore frequency and no technology. In force from 1 April 2024 (paragraph 1(c)). Applicability (paragraph 2(a)): commercial banks (banking companies, corresponding new banks and the State Bank of India, including small finance banks, payments banks and foreign banks in India), NBFCs in the Top, Upper and Middle Layers, Credit Information Companies, and EXIM Bank, NABARD, NaBFID, NHB and SIDBI. Not applicable (paragraph 2(b)): Local Area Banks and NBFC-Core Investment Companies. Foreign banks operating through branches follow a comply-or-explain approach (paragraph 2(c)). The Directions apply in addition to other laws (paragraph 31). They are not a requirement for every organisation in India. |

## DPDP Rule 6 sub-clauses used (paraphrase of S2; text re-read and confirmed against the Gazette PDF on 2026-10-05)

| Sub-clause | Content (paraphrased, not verbatim) | Used by |
|------------|-------------------------------------|---------|
| Rule 6(1)(a) | Appropriate data security measures, such as encryption, obfuscation, masking or virtual tokens. | DATA-ENCRYPTION |
| Rule 6(1)(b) | Appropriate measures to control access to the computer resources used by the Data Fiduciary or its Data Processor, wherever applicable. | IAM-NO-WILDCARD-ADMIN, ACCESS-EXPOSURE |
| Rule 6(1)(c) | Visibility on access to personal data through appropriate logs, monitoring and review, to detect unauthorised access, investigate it and prevent recurrence. | LOG-RETENTION |
| Rule 6(1)(d) | Reasonable measures for continued processing if the confidentiality, integrity or availability of personal data is compromised, such as by way of data-backups. | BACKUP-RESILIENCE |
| Rule 6(1)(e) | For the same purposes, retain such logs and personal data for a period of one year, unless compliance with any law for the time being in force requires otherwise. | LOG-RETENTION |
| Rule 6(1)(f), (g) | Processor-contract provisions; appropriate technical and organisational measures. | Not modelled |
| Rule 8(3) | Separate minimum one-year retention of personal data, associated traffic data and logs, for purposes in the Seventh Schedule; its illustration says "at least one year". | Context for LOG-RETENTION only |

Rules 5 to 16 come into force eighteen months after publication (Rule 1(4)), about 13 May 2027.

## Controls (chain: Source -> Requirement -> Control -> Terraform attribute -> Rego rule -> Fixture)

Control IDs are context-neutral and name the technical check. One control has one Rego rule. Which controls apply, and with which parameters, is decided by the routing context (see Routing contexts). The legal basis can differ per context and is recorded under each control.

### REGION-RESTRICTION
- Check: the AWS provider region must be in the allowed list supplied by the routing context. One Rego rule; the router passes the list.
- Terraform attribute: configuration.provider_config.aws.expressions.region.constant_value (literal region).
- Rego rule: policies/region.rego (implemented).
- Allowed lists (parameters; store as data, do not hardcode in Rego):
  - india-finance: ap-south-1, ap-south-2. Based on [AWS's documented region geographies.](https://docs.aws.amazon.com/global-infrastructure/latest/regions/aws-availability-zones.html#zones-asia-pacific)
  - eu: eu-central-1, eu-west-1, eu-west-3, eu-north-1, eu-south-1, eu-south-2. Excludes eu-west-2 (United Kingdom) and eu-central-2 (Switzerland), based on [AWS's documented region geographies.](https://docs.aws.amazon.com/global-infrastructure/latest/regions/aws-availability-zones.html#zones-europe)
- Legal basis per context:
  - india-finance: S1 (RBI). Legal content (as verified): payment system data to be stored in systems located only in India (scope: RBI-authorised payment system providers; payment data). SCOF interpretation: AWS resources of an India finance workload that holds payment data must be deployed in India regions. Caveats: covers payment data only, not all financial data. RBI also allows the foreign leg of a cross-border transaction to be stored abroad; this rule does not model that exception, so it is stricter than the circular. Backups, replication and global services are not modelled. DPDP is not the source of this control (S4: no blanket India-only storage requirement).
  - eu: S6 (GDPR Art 44), S5 context. Legal content (as verified): transfers to third countries are allowed only if Chapter V conditions are met. SCOF interpretation (conservative): for an EU deployment context, deploy only in EU regions so that no third-country transfer arises. Caveats: GDPR does not require EU-only storage; adequacy decisions and safeguards (Arts 45-46) are not modelled.
  - india without a sector: no region restriction; no verified source provides one (S4).
- Fixtures: india-finance PASS s3_kms_cmk_india, rds_encrypted_cmk_india, ec2_encrypted_cmk_india, kms_rotation_enabled_india, iam_least_privilege_india; FAIL s3_wrong_region, rds_wrong_region. eu PASS s3_kms_cmk_eu. 
- Cross-context check: India fixtures evaluated under the eu context fail REGION-RESTRICTION as expected.

### DATA-ENCRYPTION
- Basis (all contexts): S2 Rule 6 and S5 Art 32.
- Legal content (as verified): reasonable or appropriate security measures, with encryption named as one example. Neither text names KMS or any AWS service. DPDP Rule 6 commences 18 months after notification (about 13 May 2027, per Rule 1), so that basis is not yet in force; GDPR Art 32 is in force.
- SCOF interpretation: persistent storage must be encrypted with AWS KMS. SSE-S3 (AES256) is still encryption, so the fixture s3_no_kms_encryption violates our stricter KMS control, not necessarily the law.
- Check: S3 sse_algorithm is aws:kms; RDS storage_encrypted is true; EC2 root_block_device encrypted is true.
- Terraform attributes: aws_s3_bucket_server_side_encryption_configuration (rule.apply_server_side_encryption_by_default.sse_algorithm); aws_db_instance.storage_encrypted; aws_instance.root_block_device[].encrypted.
- Rego rule: policies/encryption.rego (implemented).
- Fixtures: FAIL s3_no_kms_encryption, rds_unencrypted, ec2_unencrypted_ebs. PASS the compliant set.

### KEY-OWNERSHIP
- Basis: none verified. INTERPRETATION.
- Rationale: control over the key lifecycle supports "appropriate technical measures"; no verified text requires customer-managed keys.
- Check: referenced KMS keys must be customer-managed (an aws_kms_key resource or a CMK ARN), not an AWS-managed alias (alias/aws/*).
- Terraform attributes: kms_master_key_id (S3), kms_key_id (RDS, EBS). References to keys created in the same plan are unknown at plan time, so read configuration.root_module.resources[].expressions.<attr>.references.
- Rego rule: policies/key_ownership.rego (implemented).
- Fixtures: FAIL s3_aws_managed_key.

### KEY-ROTATION
- Basis: none verified. INTERPRETATION (security best practice).
- Check: aws_kms_key.enable_key_rotation is true.
- Rego rule: policies/key_rotation.rego (implemented).
- Fixtures: FAIL kms_rotation_disabled. All compliant fixtures with keys set rotation to true.

### IAM-NO-WILDCARD-ADMIN
- Basis: S2 Rule 6 (access control is among the minimum safeguards), VERIFIED-PRIMARY. The wildcard-admin rule is our INTERPRETATION of "access control"; Rule 6 does not mention IAM or wildcards. Rule 6 commences about 13 May 2027 (Rule 1), so the DPDP basis is not yet in force.
- Check: no IAM policy statement may Allow Action "*" on Resource "*".
- Terraform attribute: aws_iam_policy.policy (JSON string, parse with json.unmarshal in Rego).
- Rego rule: policies/iam.rego (implemented).
- Fixtures: FAIL iam_wildcard_admin. PASS iam_least_privilege_india.

### LOG-RETENTION
- Status: INTERPRETATION — The security objective is supported, but the one-year requirement is applied to all CloudWatch log groups for implementation purposes.
- Basis: S2 Rule 6(1)(c) and 6(1)(e), VERIFIED-PRIMARY. DPDP only. No verified EU source requires one-year log retention, so the control is not enabled in the eu context.
- Legal content (as verified, paraphrased): Rule 6(1)(c) requires visibility on access to personal data through appropriate logs, monitoring and review. Rule 6(1)(e) requires such logs and personal data to be retained for one year, unless another law in force requires otherwise. Rule 8(3) separately describes a minimum of one year for its own purposes. Rule 6 commences about 13 May 2027, so this basis is not yet in force.
- SCOF interpretation : one year is read as a floor, not an exact period. The check is applied to every CloudWatch log group in the plan, because the plan does not show which log groups hold access logs for personal data.
- Check: aws_cloudwatch_log_group.retention_in_days must be at least 365. An absent value or 0 (never expires) passes.
- Terraform attribute: aws_cloudwatch_log_group.retention_in_days.
- Rego rule: policies/log_retention.rego (implemented).
- Applies to contexts: india, india-finance. Not enabled in eu.
- Limits: broader than the rule (all log groups, not only access logs for personal data). Not modelled: the other-law exception, S3 access logs, CloudTrail, logs kept outside CloudWatch, retention of the personal data itself, and any conflict between never-expire logs and erasure duties.
- Fixtures: FAIL log_group_short_retention_india (30 days, india-finance). PASS log_group_retention_365_india (365 days, india-finance) and log_group_short_retention_eu (30 days, eu: the control is not enabled there). The plan of log_group_short_retention_india evaluated under eu reports REGION-RESTRICTION only, with no LOG-RETENTION finding.

### ACCESS-EXPOSURE
- Status: INTERPRETATION — The security objective is supported, but “no public S3/RDS” is an implementation interpretation.
- Basis: S2 Rule 6(1)(b), VERIFIED-PRIMARY, not yet in force. GDPR Art 32(1) (S5), in force. GDPR Art 5(1)(f) (S7) is TO CONFIRM and is not relied on.
- Legal content (as verified, paraphrased): Rule 6(1)(b) requires appropriate measures to control access to the computer resources used by the Data Fiduciary or its Data Processor. Art 32(1) requires technical and organisational measures appropriate to the risk, including confidentiality (see S5). Neither text mentions public access, S3 or RDS.
- SCOF interpretation : explicit public exposure of a data store is a failure to control access.
- Check: no aws_s3_bucket_public_access_block has any of block_public_acls, block_public_policy, ignore_public_acls or restrict_public_buckets set to false, and no aws_db_instance has publicly_accessible set to true.
- Terraform attributes: aws_s3_bucket_public_access_block (the four flags); aws_db_instance.publicly_accessible.
- Rego rule: policies/access_exposure.rego (implemented).
- Applies to contexts: all (base control set).
- Limits: only explicit exposure is detected. A bucket with no public-access-block resource, public bucket policies or ACLs, security groups and account-level block settings are not modelled, so false negatives are accepted for the MVP.
- Fixtures: FAIL s3_public_access_block_open_india (block_public_policy false) and rds_publicly_accessible_india (publicly_accessible true), both under india-finance. PASS s3_public_access_block_all_india. The existing compliant RDS fixtures set no publicly_accessible and plan it as false, so they pass without changes.

### BACKUP-RESILIENCE
- Status: INTERPRETATION — The resilience objective is supported, but “RDS automated backups of at least 1 day” is a SCOF technical baseline.
- Basis: S8 RBI IT Governance Directions 2023, paragraph 29(e), VERIFIED-PRIMARY, in force since 1 April 2024, for RBI regulated entities (india-finance context). S2 Rule 6(1)(d), VERIFIED-PRIMARY, not yet in force. GDPR Art 32(1)(c) (S5), in force.
- Legal content (as verified, paraphrased): Rule 6(1)(d) requires reasonable measures for continued processing if the confidentiality, integrity or availability of personal data is compromised, naming data-backups as an example. Art 32(1)(c) concerns the ability to restore availability of and access to personal data in a timely manner after an incident (see S5). RBI paragraph 29(e) (S8) requires a regulated entity to back up data and periodically restore it to check that it is usable, while preserving the integrity of the backups and protecting them from unauthorised access. None of the three texts requires automated backups, RDS, or a number of days.
- SCOF interpretation : enabled RDS automated backups are a reasonable technical measure toward the backup obligations in S8, Rule 6(1)(d) and Art 32(1)(c). The threshold of at least 1 day is SCOF's technical implementation baseline for ensuring that automated RDS backups are enabled, not a numeric requirement of any of those texts.
- Check: aws_db_instance.backup_retention_period must be set explicitly to at least 1. A value below 1 is denied. An omitted value is denied too: the plan reports it as unknown until apply, and the AWS provider documents a default of 0, which disables automated backups ([provider documentation, read 2026-10-05](https://github.com/hashicorp/terraform-provider-aws/blob/main/website/docs/r/db_instance.html.markdown)).
- Terraform attribute: aws_db_instance.backup_retention_period.
- Rego rule: policies/backup_resilience.rego (implemented).
- Applies to contexts: all (base control set).
- Basis of the threshold : at least 1 day is the SCOF technical baseline for ensuring that automated RDS backups are enabled. It is not a numeric requirement of RBI paragraph 29(e), DPDP Rule 6(1)(d) or GDPR Art 32(1)(c): none of them names a number of days, and S8 names no retention period. An explicit value is required: a value below 1 is denied, and so is an omitted value (see Check).
- Applicability of the RBI basis (S8): the RBI Directions apply only to the regulated entities listed in paragraph 2(a) of S8 (see the S8 row), not to every organisation in India. The RBI basis therefore applies to the india-finance context, which assumes the deployment belongs to such an entity; SCOF does not check whether a given deployment is in scope. In the other contexts the control rests on S2 Rule 6(1)(d) and S5 Art 32(1)(c).
- Limits: RDS aws_db_instance only. Enabled automated backups do not show that backups are periodically restored and verified, that their integrity is preserved, or that access to them is restricted (S8 paragraph 29(e)); none of that is modelled. S3 versioning, EBS snapshots, Aurora clusters and cross-region copies (which could also interact with REGION-RESTRICTION) are not modelled either.
- Fixtures: FAIL rds_no_backup_india (backup_retention_period = 0) and rds_backup_not_set_india (attribute omitted, unknown at plan time), both under india-finance. PASS rds_encrypted_cmk_india, which now sets backup_retention_period = 7 explicitly. The other RDS fixtures and the terraform/rds reference configuration also set it explicitly, so that each keeps its single intended violation.

## Control basis summary

| Control | Legal basis verified | Basis in force (as of 2026-10-05) | Control strictness vs law |
|---------|----------------------|-----------------------------------|---------------------------|
| REGION-RESTRICTION (india-finance) | S1 RBI circular (payment data, India only) | Yes (since 2018) | Stricter: ignores foreign-leg exception, applies by deployment context |
| REGION-RESTRICTION (eu) | S6 GDPR Art 44 (conditions on transfers) | Yes | INTERPRETATION: GDPR allows transfers under Arts 45-46; EU-only is conservative |
| DATA-ENCRYPTION | S2 Rule 6, S5 Art 32 (encryption named) | GDPR yes; DPDP Rule 6 about 13 May 2027 | Stricter: law requires encryption, we require KMS |
| KEY-OWNERSHIP | None | n/a | INTERPRETATION (defence in depth) |
| KEY-ROTATION | None | n/a | INTERPRETATION (security best practice) |
| IAM-NO-WILDCARD-ADMIN | S2 Rule 6 (access control named) | DPDP Rule 6 about 13 May 2027 | INTERPRETATION: wildcard-admin is our reading of "access control" |
| LOG-RETENTION (india, india-finance) | S2 Rule 6(1)(c), 6(1)(e) | DPDP Rule 6 about 13 May 2027 | INTERPRETATION: one year read as a floor; applied to all log groups, broader than the rule |
| ACCESS-EXPOSURE | S2 Rule 6(1)(b), S5 Art 32(1) | GDPR yes; DPDP Rule 6 about 13 May 2027 | INTERPRETATION: explicit public exposure only |
| BACKUP-RESILIENCE | S8 RBI para 29(e) (india-finance, RBI regulated entities), S2 Rule 6(1)(d), S5 Art 32(1)(c) | RBI yes (since 1 April 2024); GDPR yes; DPDP Rule 6 about 13 May 2027 | INTERPRETATION: automated backups of at least 1 day; no text names a number |

Commencement of DPDP Act section 8(5): see S3 (not yet in force as of 2026-10-05).

LOG-RETENTION, ACCESS-EXPOSURE and BACKUP-RESILIENCE were INTERPRETED (see their sections). Rule 6(1)(c) monitoring and review, Rule 6(1)(f) processor contracts and Rule 6(1)(g) organisational measures are not modelled.

## Routing contexts
DPDP and GDPR are both sector-neutral. The RBI sources (S1 and S8) are sector-specific. S1 changes behaviour only through the india-finance region list. S8 is an additional legal basis for BACKUP-RESILIENCE, which is enabled in every context, so the set of enforced controls still differs by sector only through the region control.

| Layer | Applies when | Controls (parameters) |
|-------|--------------|-----------------------|
| Base | always | DATA-ENCRYPTION, KEY-OWNERSHIP, KEY-ROTATION, IAM-NO-WILDCARD-ADMIN, ACCESS-EXPOSURE, BACKUP-RESILIENCE |
| Jurisdiction | jurisdiction = EU | REGION-RESTRICTION (eu list) |
| Jurisdiction | jurisdiction = India | LOG-RETENTION |
| Sector overlay | jurisdiction = India and sector = finance | REGION-RESTRICTION (india-finance list) |

Evaluated contexts (control sets are implemented by router/policy-routing/control_sets.json):
- india-finance: base + LOG-RETENTION + REGION-RESTRICTION (India list).
- eu: base + REGION-RESTRICTION (EU list). LOG-RETENTION is not enabled.
- india (test-only, never emitted by the router): base + LOG-RETENTION, no region rule; no verified source gives it a region rule.
healthcare: NO verified source yet. Deferred; do not invent requirements. The MVP demonstrates routing with two contexts, which satisfies the two-context requirement. Healthcare is a documented limitation and future-work item, not part of the evaluated system.
## Verification status
Completed: RBI circular and FAQ, DPDP Rules 2025 (Rules 1, 6, 8(3), 15), RBI IT Governance Directions 2023 (paragraphs 1, 2, 29(e)), DPDP Act (ss.8, 16, Schedule), GDPR Arts 32 and 44-46 on EUR-Lex.

Region allow-lists  checked against AWS region documentation on 2026-10-05. AWS adds regions over time, so re-check before the final artifact.

Still open:
1. Healthcare context has no verified source; deferred (pending verified sourcing).