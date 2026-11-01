# ADR 0001: Agents propose, people approve

**Status:** accepted · **Date:** 2026-10-31

**Context.** The program uses many agents. Security and trust decisions (accepting risk, publishing an answer,
blocking an extension, sending a report) need an accountable person.

**Decision.** Agents may only propose. A single approval gate records who approved, when and why. Destructive or
org-wide steps need two people. Agent identities that try to approve raise an error.

**Consequences.** Slower than full autonomy, but every action has an owner. Approval delay and rubber-stamping are
measured so the human step stays meaningful.
