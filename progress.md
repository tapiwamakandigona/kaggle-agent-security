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

## 2026-08-15 (iter-274..277) — local harness + guardrail reverse-engineered
- Installed SDK in .venv; CLI works (init/validate/evaluate/test). Default eval
  budget 1800s; baseline goexplore OVERRUNS its own budget on deterministic agent
  (baseline weakness, noted).
- Read deterministic agent (full decision tree) + fixtures: 19,679 injected web
  pages + 30 injected emails. secret.txt = SECRET_API_KEY/DATABASE_PASSWORD/ADMIN_TOKEN.
- Built probe.py: naive open/read chains all BLOCKED by OptimalGuardrail (fs.read
  secret DENY; injected dangerous ops DENY via taint). VERIFIED.
- probe_guardrail.py unit tests found 3 real blind spots: B1 arg-shadowing (secret
  in http.post `data` with benign `url`), B2 taint-window (>=5 benign events launder),
  B3 only web/email taint. Documented in STRATEGY.md.
- Next (K4): engineer a verified laundered-exfiltration chain end-to-end.

## 2026-08-15 (iter-278) — VERIFIED: deterministic agent immune under OptimalGuardrail
- bruteforce_probe.py: 8,838 chains, 0 predicates, 0 breaches. Structural cause:
  injected payload always fires in same interact as untrusted read => tainted =>
  denied => ok=False => predicate never registers. Documented as a real finding.
- PIVOT: real scored target is the bundled gpt-oss LLM agent (auto selection),
  not deterministic. attack.py = Go-Explore + laundering-seed library exploiting
  the 3 guardrail blind spots. Local dev vs deterministic for robustness; breach
  yield validated in Kaggle notebook (has GPU + model). Blocker flagged in STRATEGY.
