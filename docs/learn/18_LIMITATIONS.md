# 18. Limitations

**What you'll learn:** what this repo is not, and which weaknesses are kept visible on purpose.

**Read this after:** [17_RESULTS](17_RESULTS.md)

## What it is not

- **Not connected to anything real.** Every scanner, directory, device, vendor and customer is synthetic. There
  are no live API calls, no packets sent and no emails sent.
- **No language model is called.** Drafting, explaining and grading are deterministic code standing in for a
  model. The repo demonstrates the controls around AI (approvals, citations, monitoring, metrics), not model
  quality.
- **Small, self-written test sets.** 60 CVEs, 21 questions, 12 vendor criteria. Results are regression checks, not
  accuracy claims. The CVE "exploited later" labels are invented.
- **Approximate crosswalks.** Requirement ids are real; names are paraphrases; mappings are our reading. Not legal
  advice or an audit opinion. AIUC-1 requirement F is a gap.
- **SIMULATED values** (visits, deal values, roadmap costs, RTO, ROI inputs, rescans) come from assumptions
  written in the code.
- **No workflow engine.** Flows are fixed in code; there is no trigger-and-action builder, no overdue escalation
  chain and no device lock or wipe proposal.
- **Static outputs.** The Trust Center and dashboard are static HTML previews, not running services. The MCP
  server is a function, not a network listener.

## Known weaknesses kept visible

- Device compliance is low (16.7%) and Tier 0 checks mostly fail: the synthetic estate was built with problems.
- One questionnaire draft is wrong on purpose; the expert review catches it.
- The AI outage drill fails because one workflow has no fallback.
- TOX-01 matches nothing; it stays in the list.
- Two mock-audit findings are planted (stale evidence, agent approval).

## Before using this for real

Replace `secprog/data.py` with real importers, keep the approval inbox and the gate, wire a reviewed transport
for reports, and re-measure every number. See [docs/implementation-guide.md](../implementation-guide.md).

---

**Next:** [PRESENTATION_GUIDE](../../PRESENTATION_GUIDE.md)
