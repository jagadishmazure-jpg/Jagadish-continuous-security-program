# 11. MSP and vCISO

**What you'll learn:** how one team serves eight fictional clients without leaking data between them, how a
costed roadmap is approved, and what the vCISO queue and mock audit do.

**Read this after:** [10_IDENTITY_SOC_HUMAN](10_IDENTITY_SOC_HUMAN.md)

## Tenant isolation with canaries

Each of the 8 clients holds a secret canary string. Every query is scoped to one tenant. The test asks every
tenant for every other tenant's data (8 x 7 = 56 cross-tenant queries); all 56 are refused and no canary ever
appears in a result. QBR packs are HTML previews and are checked for other tenants' canaries too.

<!-- run: python -m secprog msp -->
```text
{
  "canary_leaks": 0,
  "cross_tenant_refused": 56,
  "passed": true,
  "tenants": 8
}
Brightwater Ledger          advanced   94.0%
Kestrel Community Bank      regulated  100.0%
Fernhill Credit Union       regulated  92.9%
Oakmere Legal LLP           advanced   91.7%
Redwing Precision Parts     essential  100.0%
Lumen Ridge Clinic          advanced   93.6%
Saltmarsh Wealth Advisors   regulated  98.0%
Briar Lane Nonprofit        essential  98.2%
```
<!-- /run -->

The table is SLA tracking per client and service tier (Essential, Advanced, Regulated).

## Costed roadmap

Assessment gaps are scored on value, effort, risk, feasibility and readiness, then placed into a 12-month plan.
Items that do not fit in 12 months move to next year. The total is **$140,000 (SIMULATED costs)**. A vCISO must
approve the roadmap before a client sees it; an agent or a non-vCISO role raises `PermissionError`.

## Other MSP checks

- **Copilot / M365 oversharing:** 3 confidential or restricted sites (Finance-Board, HR-Salaries, IT-Runbooks)
  are shared org-wide or by link. The agent proposes "restrict to members and exclude from Copilot until reviewed";
  a person approves.
- **Co-managed RACI:** exactly one Accountable party per activity; the shipped RACI passes.
- **Outcome tracker:** 21 hours a month saved, $1,995 (SIMULATED).

## vCISO decision queue

Risk acceptances, roadmap approvals, vendor residual risk, autonomy promotions and policy exceptions all land in
one queue, ordered overdue first, then by severity, then by due date: VQ-05, VQ-03, VQ-01, VQ-02, VQ-04. Only a vCISO decides. A risk
acceptance must expire within 1 to 90 days and needs a reason.

## Mock audit

The mock auditor samples evidence and checks it like an auditor would: fresh, hashed, mapped to a control, from a
known source, and approved by a person.

<!-- run: python -m secprog audit -->
```text
sampled 6, passed 4
 - Firewall review 2025 | stale: 425 days old (limit 90); unknown source 'legacy-share'
 - Change CH-09 approval | approval recorded by an agent, not a person
```
<!-- /run -->

Both findings are planted on purpose so the audit has something to catch: a stale file from an unknown share,
and a change approved by an agent.

---

**Next:** [12_FRAMEWORKS_AND_READINESS](12_FRAMEWORKS_AND_READINESS.md)
