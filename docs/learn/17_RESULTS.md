# 17. Results

**What you'll learn:** every headline number in one place, with its label and where it comes from.

**Read this after:** [16_HOW_TO_RUN](16_HOW_TO_RUN.md)

All numbers are printed by the code on the seeded synthetic data (as of 2026-10-31) and checked in CI.
**measured** = counted by the code; **SIMULATED** = from an assumption in the code; nothing is a vendor figure.

| Area | Result | Label | Source |
|---|---|---|---|
| Tests | see README "N tests" line (checked by CI) | measured | `scripts/count_tests.py` |
| Findings | 73 after de-duplication across code, secrets, DAST, dependencies and pentest | measured | `findings` |
| CVE ranking | v2 coverage 47.4% / efficiency 75.0% vs CVSS-only 15.8% / 25.0% (top 12, 19 labelled exploited) | measured on synthetic labels | `rank` |
| Exposure | company 376 / 1000; 7d -6, 30d -24, 90d -72 | measured (trend synthetic) | `exposure` |
| Attack paths | 10 paths; top choke point closes 4 | measured | `paths` |
| Toxic combinations | 13 open across 9 of 10 rules | measured | `paths` |
| CTEM | 3 closed after rescan, 1 reopened; fix validation 75.0% | SIMULATED rescan | `ctem` |
| Vulnerability SLA | 52 of 72 open findings inside SLA (72.2%) | measured | `kpis` |
| Devices | 5 of 30 fully compliant (16.7%); EDR 93.3% | measured | `devices` |
| Browser | 3 of 8 extensions high risk; 66.7% of sessions on the managed browser | measured | `browser` |
| Access review | 16 issues, 10 revoked by reviewers, 100% complete | measured | `access` |
| Questionnaire | 21 questions, 15 drafted, accuracy 86.7%, auto-answer 61.9%, 1 rejected, 1 edited | measured | `questionnaire` |
| Trust Center | 7 requests, 85.7% decided by rules, 1 to a person; 6 KEV updates, 0 emails sent | measured | `trust` |
| Trust analytics | 1,420 visits, $515,000 pipeline influenced | **SIMULATED** | `trust-metrics` |
| Vendor risk | V-03 7 met / 12; V-04 7 / 7; V-09 4 / 12 with 7 inconclusive | measured | `tprm` |
| Purchase gate | 2 of 5 requests blocked | measured | `purchases` |
| Identity | 3 of 10 Tier 0 checks pass; drill RTO 23.5 h | measured / **SIMULATED** RTO | `identity` |
| SOC | auto-triage 75.0%; 2 undos; 1 rubber-stamp flag; MTTR per phase only | measured | `soc` |
| Human risk | click 7.7%, report 65.4%; insurance readiness 60.0% | measured | `human` |
| Validation | 2 urgent proven, 2 unproven dropped, 1 unsafe test refused; zero-disruption 87.5% | SIMULATED | `validate` |
| Pentest assistant | 3 accepted (pending sign-off), 3 rejected, 1 flagged | measured | `pentest` |
| MSP | 8 tenants, 56 cross-tenant queries refused, 0 canary leaks; roadmap $140,000 | measured / **SIMULATED** cost | `msp` |
| Mock audit | 6 sampled, 4 pass | measured | `audit` |
| Frameworks | 12 frameworks, 110 requirements, 109 mapped, 1 gap, all approximate | measured | `coverage` |
| Controls | 12 pass, 11 partial, 7 fail of 30 | measured | `controls` |
| AI governance | monitoring 89.5%, override 10.0%, regulatory readiness 51.9%, outage drill fail | measured | `ai-gov` |
| AI ROI | 28.4 net hours, ratio 2.99 | **SYNTHETIC inputs** | `ai_governance.roi` |

Toxic count source:

<!-- run: python -c "from secprog import attack_paths as a;c=a.toxic_counts();print(sum(c.values()),'open,',sum(v>0 for v in c.values()),'of',len(c),'rules matched')" -->
```text
13 open, 9 of 10 rules matched
```
<!-- /run -->

---

**Next:** [18_LIMITATIONS](18_LIMITATIONS.md)
