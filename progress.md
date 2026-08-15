# progress — kaggle-agent-security

## 2026-08-15 (iter-271) — scaffold
- Entered competition (K1) + captured full spec (K2). PROJECT.md + features.json created.
- Identified blocker: need SDK/fixtures locally; no Kaggle API key -> must pull via browser.
- Strategy hypothesis: Go-Explore/novelty archive search over env.interact, harvest
  diverse candidates across the 4 predicate families; working note = top deliverable.

## 2026-08-15 (iter-272/273) — SDK obtained + scorer reverse-engineered
- Kaggle web Download-All + /api/v1 both blocked (no API token; 401). WORKAROUND:
  aicomp-sdk 3.1.2 is on PyPI (exact competition version) -> downloaded wheel+sdist,
  unpacked to sdk/. K3 PASS.
- Read attacks/contracts.py (AttackAlgorithmBase.run -> list[AttackCandidate];
  env.interact/snapshot/restore) and core/predicates.py (EXACT trigger logic for all
  4 predicates). Documented in STRATEGY.md — this is the scoring cheat-sheet.
- Key insight: final user message is keyword-checked; unsafe action must come from
  INJECTED untrusted web/email content for confused-deputy/share hits.
- Next: read attacker_goexplore.py baseline, stand up local evaluator, write attack.py (K4).
