# Interview points

Short answers, each backed by something you can run.

1. **"How do you prioritize vulnerabilities?"** Exploit likelihood (EPSS), known exploitation (KEV), reachability
   and asset value, then measure it: top-12 coverage 47.4% vs 15.8% for CVSS-only on synthetic labels
   (`python -m secprog rank`).
2. **"How do you stop AI agents doing damage?"** Propose-only autonomy, a single gate, two people for destructive
   steps, decision rights per agent, and rubber-stamp detection (`python -m secprog coordinator`, `soc`).
3. **"How do you keep AI questionnaire answers honest?"** Cite or route to an expert; the expert can approve, edit
   or reject; measure accuracy (86.7% on 15 drafts) and keep the rejected draft visible.
4. **"What is CTEM to you?"** A loop: scope, discover, prioritize, validate, mobilize; and a fix only counts after
   a rescan (75.0% fix validation, 1 reopened) (`python -m secprog ctem`).
5. **"How do you report to leadership?"** Same numbers daily and weekly, labelled, as previews; sending needs
   approval (`python -m secprog report`).
6. **"How do you handle framework sprawl?"** 30 controls crosswalked to 12 frameworks; one honest gap; mapping
   type recorded (`python -m secprog coverage`).
7. **"What would you do differently in production?"** Real importers, re-measured numbers, a reviewed transport,
   and a workflow engine for escalations; see [implementation-guide.md](implementation-guide.md).
