# 13. AI governance

**What you'll learn:** the 12 AI governance KPIs, how AI ROI is computed honestly, how AI vendor concentration
and an outage drill are measured, and how shadow AI is found.

**Read this after:** [12_FRAMEWORKS_AND_READINESS](12_FRAMEWORKS_AND_READINESS.md)

## Why this matters (context only)

A 2026 CEO survey published by Dataiku (*Global AI Confessions: CEO Edition*) **claims** that most CEOs believe
employees use AI without approval, worry about legal exposure from AI agents, and feel over-exposed to too few AI
vendors. These are **Dataiku's self-reported survey claims**, not facts measured here. No code, test or report in
this repo uses them; they only explain why the KPIs below exist. The exact survey figures are listed, labelled,
in [SOURCE_COVERAGE.md](../SOURCE_COVERAGE.md).

## The 12 KPIs, measured on synthetic data

<!-- run: python -m secprog ai-gov -->
```text
{
  "agent_legal_risk_blocked": 3,
  "ai_regulatory_readiness_pct": 51.9,
  "ai_roi": 2.99,
  "ai_vendor_concentration": {
    "hhi": 0.556,
    "top1_share_pct": 66.7
  },
  "approval_sla_pct": 88.9,
  "autonomy_mix": {
    "act_then_notify": 0,
    "act_with_approval": 2,
    "suggest": 17
  },
  "basis": "computed from synthetic data",
  "decision_audit_pass_pct": 100.0,
  "decision_rights_coverage_pct": 100.0,
  "explainability_rate_pct": 100.0,
  "monitoring_coverage_pct": 89.5,
  "override_rate_pct": 10.0,
  "resilience_test": "fail",
  "shadow_ai_exposure": {
    "unapproved_tools": 2,
    "users": 3
  }
}
```
<!-- /run -->

| KPI | What it means here |
|---|---|
| explainability_rate_pct | Questionnaire drafts, top-12 CVE ranks and vendor grades that carry a citation or reason |
| decision_audit_pass_pct | Six integrity checks: three hash-chained logs verify, every approval by a person, no self-approval, every rejection has a reason |
| monitoring_coverage_pct | Agents with a heartbeat in the last 24 hours (17 of 19) |
| approval_sla_pct | SOC approvals decided inside the approval SLA |
| override_rate_pct | Share of agent proposals that people rejected or changed |
| decision_rights_coverage_pct | Agents with an owner, an approver and an escalation path |
| ai_regulatory_readiness_pct | Mean readiness of the AI frameworks (ISO/IEC 42001, AIUC-1, EU AI Act, NIST AI RMF) |
| agent_legal_risk_blocked | Agent actions the gate blocked plus unregistered tool use caught by drift detection |
| ai_roi | Net value / AI cost (see below) |
| ai_vendor_concentration | Herfindahl index and top provider share across AI workflows |
| autonomy_mix | How many agents suggest, act with approval, or act then notify |
| shadow_ai_exposure | Unapproved AI tools in use and how many people use them |

`resilience_test: fail` is the result of the last AI outage drill (below).

## AI ROI, with review time subtracted

<!-- run: python -c "import json;from secprog import ai_governance;print(json.dumps(ai_governance.roi(),indent=2))" -->
```text
{
  "hours_saved_gross": 36.0,
  "review_hours": 7.7,
  "hours_saved_net": 28.4,
  "value_per_month": 2693.25,
  "ai_cost_per_month": 900.0,
  "roi_ratio": 2.99,
  "basis": "SYNTHETIC inputs; review time by people is subtracted"
}
```
<!-- /run -->

Gross hours saved minus the hours people spend reviewing AI drafts gives **28.4 net hours**. All inputs are
**SYNTHETIC**. Tests check that a cheaper AI raises the ratio and a much more expensive one lowers it.

## Concentration and the outage drill

<!-- run: python -m secprog ai-exposure -->
```text
{
  "concentration": {
    "ai_workflows": 6,
    "hhi": 0.556,
    "top1_share_pct": 66.7,
    "top2_share_pct": 100.0,
    "vendors_on_provider_a": 3,
    "with_fallback_pct": 66.7
  },
  "drill": {
    "affected": 4,
    "date": "2026-10-25",
    "degraded_to_fallback": [
      "WF-support-answers",
      "WF-questionnaire-drafts",
      "WF-copilot"
    ],
    "provider": "model-provider-a",
    "result": "fail",
    "stopped": [
      "WF-trust-drafts"
    ]
  }
}
```
<!-- /run -->

Two thirds of AI workflows sit on one provider. In the drill, that provider "went down": three workflows fell
back, one (Trust Center drafts) stopped. Because one stopped, the drill **fails**, and the dashboard says so.

## Shadow AI and the AI inventory

Discovery reads synthetic package manifests, browser-extension lists, proxy logs and cloud resources. Every AI
tool found lands in a register as approved, unapproved or embedded. Approving a tool is a review-board decision by
a person. The Trust Center publishes a "How we use AI" section and an AI feature table for customers.

---

**Next:** [14_EXECUTIVE_REPORTING](14_EXECUTIVE_REPORTING.md)
