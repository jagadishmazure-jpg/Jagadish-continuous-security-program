# Presentation guide

How to present this repo in 5 or 15 minutes, the commands to demo, likely questions and a one-card summary.
All numbers below are printed by the code on synthetic data; say "synthetic" or "simulated" when you quote them.

## 5-minute script

| Minute | Say | Show |
|---|---|---|
| 0:00 | "Security programs fall behind because work arrives from twenty places and nobody can say what to fix first. This is a model of a continuous program for a fictional fintech, Brightwater Ledger." | README top |
| 0:45 | "One rule: agents propose, people approve. No agent can approve, send, publish or accept risk; tests prove it." | `python -m secprog coordinator` |
| 1:30 | "Prioritization: ranking with EPSS, KEV and reachability catches 47.4% of the exploited CVEs in the top 12, versus 15.8% for CVSS alone, on synthetic labels." | `python -m secprog rank` |
| 2:15 | "Attack paths: one service account sits on 4 of 10 paths to crown jewels, so it is fix number one." | `python -m secprog five` |
| 3:00 | "Trust: the AI drafts questionnaire answers with citations; an expert rejected one wrong draft. Accuracy 86.7%, measured on our 15 drafts." | `python -m secprog questionnaire` |
| 3:45 | "Leadership gets daily and weekly reports as previews. Sending needs config, an allow-list, a vault key, an approval flag and a transport, and the repo ships no transport." | open `out/reports/weekly.html` |
| 4:30 | "Every number in the docs is re-run in CI, and weak results stay visible: device compliance is 16.7%." | `docs/learn/17_RESULTS.md` |

## 15-minute script

1. **Problem (2 min).** [01_THE_PROBLEM](docs/learn/01_THE_PROBLEM.md): too many findings, slow questionnaires, AI
   used without oversight.
2. **Architecture (2 min).** [03_ARCHITECTURE](docs/learn/03_ARCHITECTURE.md): inputs -> findings -> ranking ->
   controls -> frameworks and trust -> reports; the coordinator and the gate.
3. **Exposure (3 min).** `rank`, `exposure`, `paths`, `ctem`. Point out the fix validation (75.0%) and the one
   reopened finding.
4. **Posture (2 min).** `devices`, `browser`, `access`. The sideloaded extension scored 75 and the infostealer
   replay: revoke needs one approval, an org-wide block needs two.
5. **Trust and vendors (2 min).** `questionnaire`, `trust`, `tprm`, `purchases` (2 of 5 purchases blocked for
   skipping security review).
6. **Identity, SOC, AI governance (2 min).** `identity` (3 of 10 Tier 0 checks pass), `soc` (rubber-stamp flag),
   `ai-gov` (outage drill fails: one workflow has no fallback).
7. **Frameworks and reporting (1 min).** `coverage`: 12 frameworks, 110 requirements, 1 honest gap. `report`.
8. **Limits (1 min).** [18_LIMITATIONS](docs/learn/18_LIMITATIONS.md): synthetic, no model calls, approximate
   mappings.

## Demo commands

```bash
python -m pytest -q
python -m secprog five
python -m secprog rank
python -m secprog questionnaire
python -m secprog browser
python -m secprog coverage
python -m secprog report --kind weekly --out out && ls out/reports
python -m secprog copilot "which vendors are overdue?"
```

## Likely questions

| Question | Answer |
|---|---|
| Is any of this real data? | No. Seeded synthetic data for a fictional company. Real ids (CVE format, framework clause ids) are used for shape only. |
| Does it call an LLM? | No. Drafting and grading are deterministic stand-ins so tests are repeatable. The point is the controls around AI. |
| How do you know the numbers are honest? | `render_docs.py --check` re-runs every documented command in CI and fails on drift; each number is labelled. |
| Why can't agents approve? | Accountability. The gate raises an error when an agent identity tries; tests cover every gate. |
| Isn't 47.4% coverage low? | It is on a hard synthetic set (12 slots, 19 exploited). The comparison matters: 3x CVSS-only at the same workload. |
| Are the framework mappings audited? | No. They are approximate crosswalks; the type is recorded per framework. |
| How would you deploy it? | See the implementation guide: real importers, keep the gate, add a reviewed transport, re-measure. |

## Cheat card

- **Company:** Brightwater Ledger (fictional) · **Agents:** coordinator + 19 · **Tests:** see README
- **Rule:** agents propose, people approve; 2 people for destructive steps
- **Ranking:** 47.4% coverage / 75.0% efficiency vs CVSS 15.8% / 25.0% (synthetic)
- **Exposure:** 376 / 1000, down 72 in 90 days (synthetic trend)
- **Questionnaire:** 21 questions, accuracy 86.7%, 1 rejected draft
- **Frameworks:** 12 · 110 requirements · 109 mapped · 1 gap · approximate
- **Weak spots shown:** devices 16.7% compliant, Tier 0 3/10, AI drill fail
- **Nothing sent, nothing deployed, nothing billed.**
