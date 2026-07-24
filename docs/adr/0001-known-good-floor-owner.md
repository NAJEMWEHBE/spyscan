# ADR 0001 — allowlist.py owns every known-good floor

- **Status:** Accepted — 2026-07-13
- **Branch:** `refactor/owned-record-finding` (owned-record candidate #04)
- **Relates to / brushes:** DESIGN-DECISIONS.md Decision 3 ("all three detection layers combined into **one score**")

## Context

The scanner floors a benign entity toward `INFO` (suppresses a false positive) through
two separate mechanisms that express the *same* policy shape —
`if not known_bad and (<entity is known-good>): return INFO`:

1. **User allowlist** (`allowlist.py`). Data-driven: signer / path-glob / sha256 / entity-key
   rules the user edits, visible via `spyscan allowlist`. The pipeline matches a fact against
   it, sets `attrs["allowlisted"]` + `allowlist_reason`, and `score.py` applies the floor.
2. **Hardcoded Microsoft-signed floor** (`score.py`, `score_fact`). Inline logic:
   `trusted_ms OR (verified AND "microsoft" in signer)` returns `INFO` directly.
   **Invisible** to `spyscan allowlist` — a user auditing "what is being trusted?" cannot see it.

Two homes for one policy ("which known-good floors exist?") means no single answer location,
and the Microsoft floor is un-inspectable. This is the exact ownerless-policy smell the
`refactor/owned-record-finding` branch exists to remove.

### The load-bearing detail

`trusted_ms` and the `verified AND microsoft` clause are **not** redundant across collectors:

- Authenticode-enriched facts (process/autostart, second pass) get `trusted_ms`
  (`enrich/signature.py`: `trusted_ms = signed AND "microsoft" in signer`).
- **autoruns** facts set `verified` + `signer` at collection time but never `trusted_ms`/`signed`,
  so they floor **only** via the second clause.

A faithful fold must replicate the whole condition, and it must stay **verified-gated**: a naive
"signer contains microsoft" allowlist rule would floor an **unverified** fact whose signer string
merely claims Microsoft — a detection bypass (spoofed/invalid signature walks free). The current
`Allowlist` signer rule is an un-gated substring match, so it cannot be reused as-is.

## Decision

Fold the Microsoft-signed floor into `allowlist.py` as an **always-active, verified-gated
built-in rule**. `allowlist.py` becomes the single owner of every known-good floor; `score.py`
keeps exactly one known-good branch (`if not known_bad and allowlisted: return INFO`) and no
longer knows the word "Microsoft".

- `Allowlist.matches()` gains a built-in clause that returns
  `(True, "allowlisted: Microsoft-signed")` when `trusted_ms OR (verified AND microsoft-in-signer)`.
- The built-in is **unconditional** — active even for an empty/missing allowlist file — so it
  preserves today's unconditional floor (the missing-file fallback must not lose it).
- The built-in is **enumerable** (`Allowlist.builtin_rules()`), so `spyscan allowlist` and the
  app's allowlist note can finally show it. That inspectability is the point.

## Why this does NOT violate Decision 3 (the "brush", resolved)

Decision 3 fuses all detection into one score, and `score.py` owns that fusion. This fold keeps
that intact: `score.py` still **applies** the floor and still owns the numeric score. Only the
known-good **signal** (the rule that decides "this is Microsoft-and-verified") relocates — which
is *exactly* how the user allowlist has always coexisted with Decision 3: the pipeline computes
`allowlisted`, `score.py` honors it. We are making the Microsoft floor consistent with a pattern
Decision 3 already tolerates, not splitting the score across modules. The score stays fused.

The floor also remains a **non-security gate**: `score.py` applies it only `if not known_bad`, so
a `defender_hit` / `ioc_procname_hit` / `canary_tripped` signal still overrides it. The allowlist —
built-in Microsoft rule included — can never silence real malware.

## Alternatives considered

- **Document the split, don't merge.** Leave both floors, add cross-reference comments. Zero risk,
  but keeps two homes and leaves the Microsoft floor invisible to the allowlist CLI. Rejected: it
  documents the smell instead of removing it, and forfeits the inspectability win.
- **Reject the fold — keep the guardrails deliberately distinct.** The Hard Principles list
  "signature/publisher reputation checks" and "user-editable allowlist" as separate guardrails.
  Rejected: they are separate *inputs*, but both express one *floor policy*; unifying the policy's
  owner does not merge the inputs (signature enrichment still produces the signer facts). The
  verified-gating keeps the signature semantics honest.

## Consequences

- One owner for the known-good floor; `spyscan allowlist` shows the Microsoft built-in.
- `Allowlist` is now signature-aware for its one built-in rule (reads `trusted_ms`/`verified`/`signer`).
  Acceptable: it stays a non-security gate (known-bad overrides).
- Behavior is preserved end-to-end (autoruns MS facts floor in pass 1; enriched process MS facts
  floor in pass 2 after signature enrichment; non-candidate processes were never MS-floored and
  still aren't). Guarded by a regression test: an **unverified** Microsoft-signer fact must NOT floor.
- `score_fact` alone no longer floors a raw `trusted_ms` fact — it requires `allowlisted` (set by the
  pipeline). Unit tests that hand-built Microsoft facts and expected `score_fact` to floor them are
  relocated to the allowlist/pipeline level, where the behavior now lives.
