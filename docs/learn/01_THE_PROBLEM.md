# 01. The problem

**What you'll learn:** why a small security team falls behind, and what "continuous" means here.

**Read this after:** [00_START_HERE](00_START_HERE.md)

A growing fintech like Brightwater Ledger has a few security people and a long list of jobs:

- Scanners (code, secrets, dependencies, web apps) each produce their own list. The same issue shows up twice.
- There are hundreds of CVEs. CVSS alone says most of them are "high", so people fix the wrong ones first.
- Nobody knows the single fix that blocks the most attack paths to the payment ledger.
- Laptops drift out of policy. Leavers keep access. Vulnerabilities pass their due date.
- Sales needs a 200-question security questionnaire answered by Friday.
- Customers ask for the SOC 2 report; someone has to check the NDA before sending it.
- Every new vendor needs a risk review, but some purchases are approved before security sees them.
- Leadership wants one page each week with real numbers.

AI agents can draft a lot of this work. They also bring new risks: they can make things up, act without
permission, leak one customer's data to another, or quietly stop working.

## What this repo does about it

1. **One findings list.** Every scanner feeds one model with de-duplication.
2. **Rank by threat, not by CVSS.** Known-exploited (KEV) and likely-exploited (EPSS) CVEs on important assets
   come first. Every rank has a one-line reason.
3. **Exposure score and attack paths.** A published formula you can recompute, plus "fix X closes N paths".
4. **Continuous checks** on devices, access and SLAs, turned into evidence for audits.
5. **Agents draft; people decide.** Questionnaire answers, vendor grades, Trust Center posts and recovery steps
   are drafts until a named person approves.
6. **Govern the agents themselves.** Every agent has an owner, a heartbeat, allowed tools and a KPI that says when
   it is failing.

"Continuous" means the checks run on every build of the data, not once a year before the audit.

---

**Next:** [02_CONCEPTS](02_CONCEPTS.md)
