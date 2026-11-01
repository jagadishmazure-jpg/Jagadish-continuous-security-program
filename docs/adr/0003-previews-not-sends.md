# ADR 0003: Reports are previews; sending needs six conditions

**Status:** accepted · **Date:** 2026-10-31

**Context.** Leadership reports are useful on a schedule, but an accidental send leaks data and a repo must never
email anyone.

**Decision.** Reports are written to `out/` as HTML, PDF, CSV and `.eml` marked `[PREVIEW - NOT SENT]`. `send()`
requires an enabled config, allowed recipients, no secrets in config, `approved=True` and a caller transport. The
repo ships no transport.

**Consequences.** Safe by default; a real deployment must add and review its own transport.
