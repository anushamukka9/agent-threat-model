# Contributing to agent-threat-model

Thanks for considering a contribution. This is a small, focused tool
and we want to keep it that way.

## What fits here

- New threat rules with tests: show the spec that must trigger the
  rule alongside the mitigated spec that must not.
- Scorecard checks that can be explained in one short label.
- Docs, examples, and benchmark cases with honest expected results.

## What does not fit

- Runtime tracing, network calls, or anything that runs the agent
  being modeled. Analysis is static and spec-based on purpose.
- Dependencies in the core. It is stdlib-only and it should stay
  that way.
- Guessing. A control that is not in the spec is treated as absent.
  If a rule cannot point at the spec fields that triggered it, it
  does not belong in the catalog.

## How to contribute

1. Fork the repo and create a branch: `git checkout -b fix/short-desc`.
2. Add your change plus tests. Rule work needs paired tests: the
   triggering spec and the mitigated variant that stays clean.
3. Run the gates: `pytest` and `ruff check` / `ruff format --check`.
   Both must be clean. The benchmark must still report precision
   and recall of 1.00 against the labeled cases.
4. Write your feature's limitations honestly. Every part of this
   tool documents what it cannot do. That is a requirement, not a
   suggestion.
5. Open a PR with a short description: what it does, why, and the
   test evidence. Keep the human voice: plain sentences, no hype.

## Style

- Python 3.10+, `src/` layout, type hints on public APIs.
- Line length 100, ruff-enforced.
- No em-dashes anywhere. This is a hard rule for this repo.
- Commit messages in imperative mood: `fix: scope ATM-016 to payment tools`,
  not `fixed ATM-016 scoping`.
