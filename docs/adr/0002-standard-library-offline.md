# ADR 0002: Standard library only, offline, synthetic data

**Status:** accepted · **Date:** 2026-10-31

**Context.** A portfolio repo must run anywhere, fast, with no keys and no cost.

**Decision.** No runtime dependencies. Seeded synthetic data. PDFs and charts are written by small built-in
modules (`minipdf`, `svgchart`). Drafting is deterministic code standing in for a model.

**Consequences.** Repeatable tests and numbers; no claims about model quality.
