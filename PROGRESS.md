# NetGuard: progress log

## Review 3 (2026-10-26)

| Item | Status | Evidence |
|---|---|---|
| **P1-a** Scan-based redundancy and optimizer (no per-rule recompilation) | Done | `core/src/analysis.c` (`scan_redundant`), `core/src/optimize.c` (kept-set scan, one equivalence proof at the end); the old versions are kept as `analysis_redundancy_equiv_check` and `optimize_keep_equiv` for the differential test `scan_equiv` (500 random policies, 5,375 checks). Review-2 example outputs are byte-identical (text and JSON). |
| Limits raised to 2,048 rules / 400,000 NFA / 200,000 DFA states | Done | `core/include/ir.h`; `RuleSet` widened to 2,048 bits (`bitset.h`) |
| **P1-b** ClassBench import + examples | Done | `tools/import_classbench.py`, `datasets/classbench/README.md`, `examples/classbench_{fw1_100,acl1_200,ipc1_200,fw1_631,acl1_2048}.ng` |
| Benchmark with before/after | Done | `tools/bench.py`, `outputs/bench.md` (all numbers measured) |
| **P1-c** `netguard equiv ORIGINAL SUGGESTED` | Done | `core/src/compare.c`, C test `compare` (equivalent, non-equivalent, parse error, action reordering, field mismatch) |
| `/api/ai-merge` with Gemini, counterexample-guided retry, demo cache | Done | `web/ai.py`, `web/app.py`, `examples/ai_cache/*.json`: **real gemini-3.5-flash replies** for 8 examples, plus one labelled hand-written rejection demo (`ai_demo_rejection.fw`); `tests_py/test_ai.py` (no network). Live call through the web app verified (56 s, accepted). |
| UI: AI-merge card (timeline, counts, diff, "Use AI policy", LIVE / RECORDED / DEMO pill, "Replay recorded reply" option) | Done | `web/static/` section 8 |
| UI: ClassBench provenance note, grouped example picker (P3) | Done | `web/static/app.js` |
| **P2** UCI import and replay | Done (real data) | `log2.csv` (65,532 records) downloaded from UCI; `examples/uci_induced.ng` (115 rules, optimizer 86); `outputs/uci_replay.md`: 95.65 % agreement with the logged actions, oracle 65,532/65,532 |
| P3 screenshots | Not done | |
| Render deployment | Done | `Dockerfile` (compiles `bin/netguard` for Linux in the image), `.dockerignore`, `render.yaml` (free plan, `GEMINI_API_KEY` with `sync: false`), `web/requirements.txt`; memory cap `NETGUARD_MAX_TRANS_CELLS` and timeout `NETGUARD_TIMEOUT` are now configurable |

### Test status (last run)

- `make`: 0 warnings
- `make test`: 427,165 checks, 0 failures
- `make debug` (ASan + UBSan): 427,165 checks, 0 failures
- `pytest tests_py`: 37 passed. The oracle test now also covers the three smaller ClassBench policies (5,000 packets each).
- macOS `leaks`: 0 leaks for compile, `equiv` (equivalent / not equivalent / parse error) and classify-batch.

### Still to do

1. Take screenshots for `outputs/screenshots/` (P3).
2. Rotate the Gemini API key after the review: it was shared in chat. It is not stored in any project file.

### Notes

- `gemini-2.5-flash` returns HTTP 404 for new API keys, so the default model is `gemini-3.5-flash` (override with `GEMINI_MODEL`).
- There is no `SPEC.md` in the project. The grammars used in the AI prompt are the ones in `README.md`.

## Review 2

Compiler pipeline (lexer, parsers, partition, Thompson NFA, subset construction, Hopcroft), analysis, optimizer, equivalence, classification, DOT/JSON, CLI, Flask, UI, tests. See `README.md`.
