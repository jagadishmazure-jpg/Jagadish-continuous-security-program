# 03. Architecture

**What you'll learn:** the modules, how data flows between them, and why it is all standard-library Python.

**Read this after:** [02_CONCEPTS](02_CONCEPTS.md)

```mermaid
flowchart TB
  subgraph Data["Synthetic estate (secprog/data.py, fixed seed)"]
    AS[40 assets] --- CV[60 CVEs] --- DV[30 devices] --- AC[26 accounts] --- VN[10 vendors] --- CL[8 MSP clients]
  end
  subgraph Detect["Find and rank"]
    FI[findings.py] --> CR[cve_rank.py] --> EX[exposure.py] --> AP[attack_paths.py] --> CT[ctem.py]
    DE[devices.py]; AR[access_review.py]; SL[vuln_sla.py]; EV[exposure_validation.py]; PT[pentest_agent.py]
  end
  subgraph Trust["Trust and vendors"]
    KB[knowledge.py] --> QN[questionnaire.py]
    KB --> TC[trust_center.py]
    TP[tprm.py]
  end
  subgraph Gov["Govern"]
    CO[coordinator.py] --> GA[governance.py gate]
    GA --> IN[core.py approval inbox + hash log]
    AG[agents.py 19 agents]
    AIG[ai_governance.py]; AIX[ai_exposure.py]
  end
  subgraph Report["Report"]
    CTL[controls.py 30 tests] --> FW[frameworks.py 12 crosswalks]
    KP[kpis.py] --> RP[reports.py previews] ; KP --> DB[dashboard.py] ; KP --> CP[copilot.py]
    MCP[mcp_server.py read-only]
  end
  Data --> Detect --> Report
  Data --> Trust --> Report
  Gov --> Detect
  Gov --> Trust
```

## Design choices

- **Standard library only.** No runtime dependencies (`dependencies = []`). The PDF writer (`minipdf.py`) and the
  charts (`svgchart.py`) are small and deterministic, so the same input gives the same bytes.
- **No model calls.** Where a real product would call a language model (drafting answers, explaining a rank), this
  repo uses deterministic code and labels it. The governance, approvals and metrics around the AI are the point.
- **One fixed "today".** `TODAY = 2026-10-31`, so ages and due dates never change between runs.
- **Same evidence fields as the companion repo.** `core.Evidence` copies the record format of
  [Jagadish-arc-ampe-compliance-automation](https://github.com/jagadishmazure-jpg/Jagadish-arc-ampe-compliance-automation)
  so files can be read by either tool. There is no import between the repos.

## Module sizes (real)

<!-- run: python -c "import pathlib;fs=sorted(pathlib.Path('secprog').glob('*.py'));print(len(fs),'modules,',sum(len(f.read_text().splitlines()) for f in fs),'lines')" -->
```text
39 modules, 5417 lines
```
<!-- /run -->

---

**Next:** [04_AGENTS](04_AGENTS.md)
