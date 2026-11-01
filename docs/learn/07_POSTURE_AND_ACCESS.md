# 07. Devices, access and SLAs

**What you'll learn:** the continuous checks on laptops and servers, user access and vulnerability due dates, and
how each becomes audit evidence.

**Read this after:** [06_EXPOSURE_AND_FINDINGS](06_EXPOSURE_AND_FINDINGS.md)

## Device posture

Ten checks per device, MDM-style: disk encryption, screen lock, firewall, EDR running, AV healthy, patched in 30
days, checked in within 7 days, no risky AV exclusions (for example `*.ps1`, `*.exe` or a Temp folder excluded from
Defender-style scanning), no risky open ports (SSH 22, SMB 445, RDP 3389, VNC 5900) and no plaintext credentials on disk.

<!-- run: python -m secprog devices -->
```text
{
  "compliant": 5,
  "compliant_pct": 16.7,
  "devices": 30,
  "edr_coverage_by_os": {
    "linux": 90.0,
    "macos": 100.0,
    "windows": 90.0
  },
  "exposed_ports": 15,
  "pass_pct_by_check": {
    "av_healthy": 100.0,
    "checked_in_7d": 83.3,
    "disk_encrypted": 93.3,
    "edr_running": 93.3,
    "firewall_on": 96.7,
    "no_plaintext_credentials": 86.7,
    "no_risky_av_exclusions": 93.3,
    "no_risky_open_ports": 50.0,
    "patched_30d": 33.3,
    "screen_lock": 93.3
  },
  "plaintext_creds": 4,
  "risky_exclusions": 2,
  "stale_agents": 5
}
```
<!-- /run -->

Only 5 of 30 devices pass all ten checks. The weakest checks are patching (33.3%) and open ports (50.0%). The
synthetic fleet was built to have these problems so the reports have something to show.

## Managed browser and extensions

Work happens in the browser, so the browser is a control point too (`secprog/browser.py`, synthetic telemetry):

- **Extension risk** comes from manifest permissions (`<all_urls>`, `cookies`, `clipboardRead`, `webRequest`,
  `downloads`), plus 20 points if the extension is sideloaded. The agent recommends allow, review or block; an
  owner decides each one, and an agent identity cannot.
- **Posture with degraded access:** a device that fails a soft check (old browser, no disk encryption) is not
  hard-blocked. The recommendation is "governed browser only, no download, no paste". A rooted device or one not
  on the managed browser is recommended for denial. A person approves either.
- **Metadata only:** browser events keep who, app, action, verdict and a SHA-256 of the content, never the content.
- **Infostealer scenario:** malicious extension -> stolen session cookie -> impossible-travel sign-in -> session
  revocation (one approval) -> org-wide extension block (two approvals). Simulated; nothing is revoked for real.

<!-- run: python -m secprog browser -->
```text
EXT-06 Session Sync (sideloaded)    risk  75  block
EXT-03 Coupon Finder Plus           risk  70  block
EXT-04 AI Writing Buddy             risk  50  block
EXT-07 Grammar Checker Lite         risk  31  review
EXT-08 Screen Recorder              risk  15  allow
EXT-02 PDF Quick Viewer             risk  11  allow
EXT-01 Ledger Password Helper       risk   6  allow
EXT-05 Tab Organizer                risk   6  allow
D-001    full
D-002    degraded: governed browser only, no download, no paste (recommend)  browser_current
BYOD-01  degraded: governed browser only, no download, no paste (recommend)  disk_encrypted
BYOD-02  deny (recommend)  os_supported,not_rooted,disk_encrypted,screen_lock,managed_browser_enrolled
CTR-01   full
CTR-02   deny (recommend)  managed_browser_enrolled
{
  "infostealer": {
    "approvals": {
      "REQ-0001": "approved",
      "REQ-0002": "approved"
    },
    "basis": "simulated scenario on synthetic telemetry",
    "log_ok": true,
    "time_to_block_min": 67,
    "time_to_revoke_min": 9,
    "timeline": [
      [
        "T+0m",
        "agent:ext-risk",
        "EXT-06 'Session Sync (sideloaded)' installed; risk 75 (cookies + all sites + not store listed)"
      ],
      [
        "T+42m",
        "agent:soc-triage",
        "sign-in for user07 from a second country 9 minutes after a local sign-in (impossible travel) with the same session cookie"
      ],
      [
        "T+44m",
        "agent:soc-triage",
        "proposed revoke_sessions for user07 (REQ-0001)"
      ],
      [
        "T+51m",
        "lee.soc",
        "approved session revocation (simulated)"
      ],
      [
        "T+53m",
        "agent:ext-risk",
        "proposed org-wide block of EXT-06 (REQ-0002); needs two people"
      ],
      [
        "T+67m",
        "omar.it",
        "second approval; EXT-06 blocked org-wide (simulated)"
      ]
    ]
  },
  "kpis": {
    "basis": "synthetic browser telemetry",
    "degraded_access_recommended": 2,
    "deny_recommended": 2,
    "extensions": 8,
    "high_risk_extensions": 3,
    "high_risk_pct": 37.5,
    "sessions_on_managed_browser_pct": 66.7,
    "unmanaged_device_sessions": 4
  }
}
```
<!-- /run -->

## Access review

The agent finds dormant, orphaned and terminated-but-active accounts, privileged accounts without MFA and toxic
privilege pairs. It **proposes** revocations; a named reviewer decides each one. The campaign record becomes
access-review evidence.

<!-- run: python -m secprog access -->
```text
{
  "by_type": {
    "dormant": 10,
    "orphaned": 1,
    "privileged_without_mfa": 1,
    "terminated_but_active": 2,
    "toxic_privileges": 2
  },
  "completion_pct": 100.0,
  "issues": 16,
  "log_ok": true,
  "revoked": 10
}
```
<!-- /run -->

## Vulnerability SLA

Due dates depend on severity and asset criticality (a critical on a crown jewel is due sooner than a critical on
a test box). Of 72 open findings, 52 are inside their SLA: **72.2% adherence** (KPI 8 below). MTTR is
reported per severity band as a median and a 90th percentile, never as one blended number.

## The 16 exposure-management KPIs

<!-- run: python -m secprog kpis -->
```text
{
  "exposure_16": {
    "10_unknown_external_assets": 3,
    "11_expiring_certs_30d": 3,
    "12_scan_coverage_pct": 93.0,
    "13_ai_inventory": {
      "tools_seen": 5,
      "unapproved": 2
    },
    "14_identity_exposure": {
      "privileged_without_mfa": 1,
      "tier0_checks_failing": 7
    },
    "15_ctem_cycle_health": {
      "log_ok": true,
      "stage": "done"
    },
    "16_agent_accountability": {
      "agents": 19,
      "decision_rights_pct": 100.0,
      "monitored_pct": 89.5
    },
    "1_exposure_score": {
      "org": 376,
      "trend": {
        "30d": -24,
        "7d": -6,
        "90d": -72
      }
    },
    "2_top_contributors": [
      [
        "payments",
        3955
      ],
      [
        "lending",
        3580
      ],
      [
        "platform",
        3270
      ]
    ],
    "3_crown_jewel_paths": {
      "open_choke_points": 5,
      "paths": 10,
      "top_choke": "app-identity -> dc01"
    },
    "4_toxic_combinations_open": 13,
    "5_kev_exposure": 6,
    "6_prioritization": {
      "coverage_pct": 47.4,
      "efficiency_pct": 75.0,
      "workload_pct": 20.0
    },
    "7_mttr_by_band": {
      "critical": {
        "median_h": 70.0,
        "p90_h": 166.0
      },
      "high": {
        "median_h": 330.0,
        "p90_h": 750.0
      },
      "low": {
        "median_h": 3050.0,
        "p90_h": 3890.0
      },
      "medium": {
        "median_h": 1500.0,
        "p90_h": 2380.0
      }
    },
    "8_sla_adherence_pct": 72.2,
    "9_fix_validation": {
      "pass_pct": 75.0,
      "reopened": 1
    }
  },
  "program": {
    "basis": "measured from synthetic workflows; visits, self-service and revenue are SIMULATED",
    "efficiency": {
      "auto_answer_rate_pct": 61.9,
      "questionnaire_turnaround_days": 3,
      "self_service_pct": 58.0,
      "within_2_5_day_sla": true
    },
    "risk": {
      "time_to_first_vuln_update_h": 4.0,
      "vendor_coverage_pct": 30.0,
      "vendors_overdue_or_triggered": 3
    },
    "trust": {
      "ai_accuracy_pct": 86.7,
      "engagement_visits_30d": 1420,
      "revenue_influenced": 515000
    }
  }
}
```
<!-- /run -->

---

**Next:** [08_TRUST_AND_QUESTIONNAIRES](08_TRUST_AND_QUESTIONNAIRES.md)
