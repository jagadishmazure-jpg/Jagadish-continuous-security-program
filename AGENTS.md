# AGENTS.md

The agents in this repo, what each is accountable for, the metric that shows it is working, when it counts as
failing, the person accountable and how much autonomy it has. Generated from `secprog/agents.py`.

<!-- run-md: python -m secprog agents-md -->
# AGENTS.md scorecard (generated)

| Agent | Outcome | Metric | Fails when | Accountable human | Autonomy |
|---|---|---|---|---|---|
| scan-importer | Every scan imported and de-duplicated | import success rate | < 99% | maria.secops | act_with_approval |
| dependency-ranker | Exploited CVEs fixed first | coverage at top 12 | < 40% | maria.secops | suggest |
| dast-surface | No unknown internet-facing assets | unowned hosts | > 0 for 7 days | maria.secops | suggest |
| device-posture | Devices meet the baseline | compliant devices | < 80% | omar.it | suggest |
| access-review | Quarterly review completed | campaign completion | < 100% by due date | rina.manager | act_with_approval |
| vuln-sla | Findings fixed within SLA | SLA adherence | < 85% | maria.secops | suggest |
| exposure | Exposure score trending down | org score 30-day change | > 0 (rising) | maria.secops | suggest |
| trust-center | Customers self-serve security answers | self-service rate | < 50% | tess.trust | suggest |
| questionnaire | Questionnaires returned within SLA | turnaround days | > 5 | tess.trust | suggest |
| tprm | Critical vendors assessed on cadence | critical vendors overdue | > 0 | paul.procurement | suggest |
| vciso | Roadmap approved each quarter | roadmap items on track | < 70% | vic.vciso | suggest |
| reporter | Reports on time with real numbers | report build success | < 100% | maria.secops | suggest |
| copilot | Answers cite their source | answers with citations | < 100% | maria.secops | suggest |
| recovery-runbook | Safe, ordered recovery plan | destructive steps with 2 approvals | < 100% | ian.identity | suggest |
| post-action-verifier | No unverified fix counted as done | verified fixes | < 100% of closed | maria.secops | suggest |
| exposure-validator | Only proven exposures reach the queue | unproven findings dropped | n/a | maria.secops | suggest |
| safety-reviewer | No unsafe probe runs | unsafe probes run | > 0 | maria.secops | suggest |
| ai-exposure | Every AI tool registered | unregistered AI tools | > 0 for 14 days | dana.ai | suggest |
| pentest-triage | No phantom findings | phantom findings accepted | > 0 | maria.secops | suggest |
<!-- /run-md -->

## Rules every agent follows

1. **Propose, never approve.** Approving, publishing, sending, accepting risk and destructive steps need a named
   person. The gate raises `ApprovalError` / `PermissionError` when an agent tries.
2. **Two people for destructive steps** (for example an org-wide extension block or a Tier 0 password reset).
3. **Cite or route.** An answer without a source goes to a subject expert, not to the customer.
4. **Log everything** to the hash-chained log; a broken chain fails the run.
5. **Least data.** Browser events keep metadata and a content hash, never content. Secrets are never imported
   unredacted.
6. **Stay in your lane.** Each agent has decision rights in the registry; anything outside them is refused.
7. **Synthetic only** here: no network calls, no sends, no cloud resources.

See [docs/learn/04_AGENTS.md](docs/learn/04_AGENTS.md) for the coordinator, the trust ladder and policies POL-01..06.
