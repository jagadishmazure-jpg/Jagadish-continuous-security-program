# 00. Start here

**What you'll learn:** what this repo is, the order to read it in, and the three commands that show it working.

**Read this after:** nothing; this is the first page.

This repo runs a **continuous security program** for a fictional payments and lending company, **Brightwater
Ledger** (`brightwater-ledger.example`). It has 19 small agents and a coordinator. They import scan results, rank
CVEs, score exposure, find attack-path choke points, check devices and access, answer customer security
questionnaires, run a Trust Center, assess vendors, plan identity recovery, govern their own AI use, and write daily
and weekly leadership reports.

The one rule behind every page: **agents propose, people approve.** No agent can approve, publish, send, decide a
risk, or run a destructive step. Tests prove it.

**Everything is synthetic and offline.** Every number on these pages is printed by a real run of the code on
seeded synthetic data and re-checked in CI (`scripts/render_docs.py --check`). Numbers marked **SIMULATED** come
from stated assumptions, not measurement. Nothing is sent, deployed or billed.

## Reading order

| # | Page | One line |
|---:|---|---|
| 00 | [Start here](00_START_HERE.md) | Map of the docs |
| 01 | [The problem](01_THE_PROBLEM.md) | Why security programs fall behind |
| 02 | [Concepts](02_CONCEPTS.md) | Findings, exposure, evidence, readiness, approvals |
| 03 | [Architecture](03_ARCHITECTURE.md) | Modules and data flow |
| 04 | [Agents](04_AGENTS.md) | The coordinator, 19 agents, the gate and the trust ladder |
| 05 | [Workflows](05_WORKFLOWS.md) | Which flows run and where people step in |
| 06 | [Exposure and findings](06_EXPOSURE_AND_FINDINGS.md) | Scans, CVE ranking, exposure score, attack paths, CTEM |
| 07 | [Devices, access and SLAs](07_POSTURE_AND_ACCESS.md) | Device posture, access reviews, vulnerability SLAs |
| 08 | [Trust Center and questionnaires](08_TRUST_AND_QUESTIONNAIRES.md) | Cited answers, expert review, gated documents |
| 09 | [Vendor risk](09_VENDOR_RISK.md) | TPRM assessments and the purchase gate |
| 10 | [Identity, SOC and human risk](10_IDENTITY_SOC_HUMAN.md) | Tier 0, recovery drill, SOC authority, phishing |
| 11 | [MSP and vCISO](11_MSP_AND_VCISO.md) | Eight tenants, roadmap, mock audit |
| 12 | [Frameworks and readiness](12_FRAMEWORKS_AND_READINESS.md) | 12 crosswalks and readiness rings |
| 13 | [AI governance](13_AI_GOVERNANCE.md) | The 12 AI governance KPIs, ROI, vendor concentration |
| 14 | [Executive reporting](14_EXECUTIVE_REPORTING.md) | Daily and weekly previews and schedulers |
| 15 | [Use cases](15_USE_CASES.md) | 29 stories, each with one command |
| 16 | [How to run](16_HOW_TO_RUN.md) | Commands |
| 17 | [Results](17_RESULTS.md) | Measured numbers in one place |
| 18 | [Limitations](18_LIMITATIONS.md) | What this is not |

After the sequence, read [PRESENTATION_GUIDE.md](../../PRESENTATION_GUIDE.md) to present the project.

## See it work in three commands

```bash
pip install -r requirements-dev.txt
python -m pytest -q                        # every test, offline, about 2 seconds
python -m secprog five                     # today's top 5 fixes
```

<!-- run: python -m secprog five -->
```text
1. Cut app-identity -> dc01 (kerberoastable service account)  [closes 4 of 10 attack paths]
2. Cut internet -> loan-portal (exploit public-facing app (SQLi))  [closes 4 of 10 attack paths]
3. Cut dc01 -> kyc-bucket (admin can grant bucket access)  [closes 3 of 10 attack paths]
4. Fix corporate-db-31 (TOX-06)  [Sitting duck: internet-facing, no owner, open findings]
5. Fix dc01 (TOX-07)  [Identity store with a high finding]
```
<!-- /run -->

```mermaid
flowchart LR
  P[01 Problem] --> C[02 Concepts] --> A[03 Architecture] --> AG[04 Agents] --> W[05 Workflows]
  W --> E[06 Exposure] --> D[07 Devices and access] --> T[08 Trust] --> V[09 Vendors]
  V --> I[10 Identity and SOC] --> M[11 MSP] --> F[12 Frameworks] --> AI[13 AI governance]
  AI --> R[14 Reports] --> U[15 Use cases] --> H[16 How to run] --> RS[17 Results] --> L[18 Limitations]
```

---

**Next:** [01_THE_PROBLEM](01_THE_PROBLEM.md)
