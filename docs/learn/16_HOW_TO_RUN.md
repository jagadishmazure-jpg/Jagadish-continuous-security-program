# 16. How to run

**What you'll learn:** how to install, test and run every command, offline.

**Read this after:** [15_USE_CASES](15_USE_CASES.md)

## Requirements

Python 3.11 or newer. The package has **no runtime dependencies**. Tests need `pytest`; linting needs `ruff`
(both pinned in `requirements-dev.txt`).

```bash
git clone https://github.com/jagadishmazure-jpg/Jagadish-continuous-security-program.git
cd Jagadish-continuous-security-program
python -m venv .venv && . .venv/bin/activate
pip install -r requirements-dev.txt
python -m pytest -q
python scripts/count_tests.py
```

## Commands

```bash
python -m secprog <command> [question] [--out DIR] [--kind daily|weekly]
```

<!-- run: python -c "from secprog.__main__ import COMMANDS;print(' '.join(sorted(COMMANDS)))" -->
```text
access agents-md ai-exposure ai-gov audit browser coordinator copilot coverage ctem dashboard devices exposure findings five frameworks governance human identity kpis mcp-demo msp paths pentest purchases questionnaire rank report schedule soc tprm trust trust-metrics usecases validate
```
<!-- /run -->

Commands that write files (`report`, `dashboard`) write only under `--out` (default `out/`, which git ignores).

## Checks that CI runs

```bash
ruff check .
python -m pytest -q
python scripts/count_tests.py           # must match "N tests" in README.md
python scripts/render_docs.py --check   # every documented output matches a fresh run
python scripts/check_brands.py          # no real company names in tracked files
```

CI also runs gitleaks over the full history and CodeQL (Python and Actions, security-and-quality queries).

## Optional cloud

There is none to run. The Microsoft Foundry / Logic Apps example in
[14_EXECUTIVE_REPORTING](14_EXECUTIVE_REPORTING.md) is a disabled design sketch.

---

**Next:** [17_RESULTS](17_RESULTS.md)
