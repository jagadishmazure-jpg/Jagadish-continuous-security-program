# Implementation guide

How to turn this model into a real program, in order. Each step keeps the approval gate.

| Step | Replace | Keep | Done when |
|---|---|---|---|
| 1 | `secprog/data.py` assets and owners with your CMDB export | Asset ids, business units, crown-jewel flags | Every finding resolves to an owner |
| 2 | Synthetic scans with real SARIF, ZAP, dependency and secrets exports | The importers, de-duplication and the unredacted-secret refusal | Import success above 99% |
| 3 | Synthetic EPSS/KEV with the public EPSS and CISA KEV files, downloaded on a schedule | `cve_rank` and its evaluation | Re-measure coverage on your own exploited history |
| 4 | Device and browser data with your MDM and managed-browser exports | The 10 device checks and extension scoring | Weekly compliance trend |
| 5 | Directory data for access reviews and Tier 0 checks | Campaigns, reviewer sign-off, two-person recovery steps | First quarterly campaign closed |
| 6 | Questionnaire knowledge base with your approved answers and evidence | Citations, expert approve/edit/reject, sign-off by a person | Accuracy measured on 50+ real questions |
| 7 | Static Trust Center with your hosting, behind your own access rules | The gating rules and the review path | Requests decided within SLA |
| 8 | Report preview job with your scheduler | Preview-first; add a reviewed transport, an allow-list and an approval step | Leadership receives approved reports only |

## Cloud option (not built)

On Azure: a Container Apps job builds the previews, a Microsoft Foundry agent writes the summary paragraph, a Logic
App waits for approval and sends through SendGrid or Office 365 with the key in Key Vault. Estimate cost and get
approval before creating any resource.

## What to measure first

Exposure trend, SLA adherence, fix validation rate, questionnaire turnaround and accuracy, approval delay and
rubber-stamp flags. Re-measure every number this repo shows; do not reuse its synthetic results.
