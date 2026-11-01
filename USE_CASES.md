# Use cases

29 stories, each with one command you can run offline and the module that does the work. Generated from
`secprog/usecases.py`; a test checks every command exists. For the story versions, see
[docs/learn/15_USE_CASES.md](docs/learn/15_USE_CASES.md).

<!-- run-md: python -m secprog usecases -->
| ID | Use case | Command | Module |
|---|---|---|---|
| UC-01 | Pick today's top 5 fixes | `python -m secprog five` | `secprog.ctem.five_minute_list` |
| UC-02 | Rank dependency CVEs better than CVSS-only | `python -m secprog rank` | `secprog.cve_rank.evaluate` |
| UC-03 | Exposure score per asset, business unit and company | `python -m secprog exposure` | `secprog.exposure.scores` |
| UC-04 | Find attack-path choke points and toxic combinations | `python -m secprog paths` | `secprog.attack_paths` |
| UC-05 | Close a ticket only after a rescan passes (CTEM) | `python -m secprog ctem` | `secprog.ctem.Cycle` |
| UC-06 | Import code, secrets and DAST scans into one findings list | `python -m secprog findings` | `secprog.findings` |
| UC-07 | Device posture, AV exclusions and exposed ports | `python -m secprog devices` | `secprog.devices` |
| UC-08 | Access review with human decisions | `python -m secprog access` | `secprog.access_review` |
| UC-09 | Answer a security questionnaire with citations and expert review | `python -m secprog questionnaire` | `secprog.questionnaire` |
| UC-10 | Trust Center with NDA rules, AI disclosures and a KEV playbook | `python -m secprog trust` | `secprog.trust_center` |
| UC-11 | Vendor risk assessment with human residual-risk decision | `python -m secprog tprm` | `secprog.tprm` |
| UC-12 | Block spend approved before security review | `python -m secprog purchases` | `secprog.tprm.purchase_gate` |
| UC-13 | Tier 0 identity checks and a clean-room recovery drill | `python -m secprog identity` | `secprog.identity_recovery` |
| UC-14 | SOC authority registry and per-phase MTTR | `python -m secprog soc` | `secprog.soc_authority` |
| UC-15 | Phishing training, insurance readiness and a consensus gate | `python -m secprog human` | `secprog.endpoint_human` |
| UC-16 | Exposure validation with a safety reviewer | `python -m secprog validate` | `secprog.exposure_validation` |
| UC-17 | Reject phantom pentest findings | `python -m secprog pentest` | `secprog.pentest_agent` |
| UC-18 | MSP view: tenant isolation, roadmap, tiers, oversharing | `python -m secprog msp` | `secprog.msp` |
| UC-19 | Framework readiness rings and coverage summary | `python -m secprog frameworks` | `secprog.frameworks` |
| UC-20 | The 12 AI governance KPIs | `python -m secprog ai-gov` | `secprog.ai_governance` |
| UC-21 | Govern our own agents (shadow -> recommend -> enforce) | `python -m secprog governance` | `secprog.governance` |
| UC-22 | Daily and weekly report previews (never sent) | `python -m secprog report --kind weekly --out out` | `secprog.reports` |
| UC-23 | Trust Dashboard HTML | `python -m secprog dashboard --out out` | `secprog.dashboard` |
| UC-24 | GRC Copilot (12 questions) | `python -m secprog copilot q01` | `secprog.copilot` |
| UC-25 | Read-only MCP server for exposure data | `python -m secprog mcp-demo` | `secprog.mcp_server` |
| UC-26 | vCISO queue and mock audit | `python -m secprog audit` | `secprog.vciso` |
| UC-27 | AI exposure discovery, register and outage drill | `python -m secprog ai-exposure` | `secprog.ai_exposure` |
| UC-28 | Coordinator week: plans, gates and approvals | `python -m secprog coordinator` | `secprog.coordinator` |
| UC-29 | Score browser extensions, gate unmanaged browsers, replay an infostealer case | `python -m secprog browser` | `secprog.browser` |
<!-- /run-md -->
