# AI-assisted rule merging (Gemini proposes, NetGuard proves)

Generated 2026-10-26 by `tools/ai_merge_report.py`. A proposal is accepted only if `netguard equiv` proves it equivalent to the ORIGINAL policy (product automaton over the partition of both policies) **and** it has fewer rules than NetGuard's optimizer. Rejected attempts get a counterexample packet back (max 3 attempts). *Recorded real Gemini reply* = a real gemini-3.5-flash response saved by tools/make_ai_cache.py and re-proven by NetGuard when this report was generated.

| example | mode | original rules | optimizer rules | AI rules (proven) | attempts | accepted | verdict |
|---|---|---|---|---|---|---|---|
| ai_demo_rejection.fw | HAND-WRITTEN demo | 10 | 5 | 4 | ❌ → ✅ | yes | accepted: proven equivalent to the original and 4 < 5 rules |
| ai_trap.fw | recorded real Gemini reply | 13 | 12 | 10 | ✅ | yes | accepted: proven equivalent to the original and 10 < 12 rules |
| classbench_acl1_200.ng | recorded real Gemini reply | 200 | 127 | 127 | ✅ | no | rejected: proven equivalent, but 127 rules is not fewer than the optimizer's 127; the optimizer's policy is kept |
| classbench_fw1_100.ng | recorded real Gemini reply | 100 | 67 | 66 | ✅ | yes | accepted: proven equivalent to the original and 66 < 67 rules |
| classbench_ipc1_200.ng | recorded real Gemini reply | 200 | 130 | — | ❌ | no | rejected: no attempt was proven equivalent; the optimizer's policy is kept |
| firewall_anomalies.fw | recorded real Gemini reply | 10 | 5 | 4 | ✅ | yes | accepted: proven equivalent to the original and 4 < 5 rules |
| firewall_basic.fw | recorded real Gemini reply | 4 | 2 | 2 | ✅ | no | rejected: proven equivalent, but 2 rules is not fewer than the optimizer's 2; the optimizer's policy is kept |
| tax.ng | recorded real Gemini reply | 5 | 4 | 4 | ✅ | no | rejected: proven equivalent, but 4 rules is not fewer than the optimizer's 4; the optimizer's policy is kept |
| uci_induced.ng | recorded real Gemini reply | 115 | 86 | 83 | ✅ | yes | accepted: proven equivalent to the original and 83 < 86 rules |

## ai_demo_rejection.fw (HAND-WRITTEN demo)

*Cache provenance:* HAND-WRITTEN demo response (no GEMINI_API_KEY was available when this cache was created). It imitates the kind of output a model produces; it is NOT a real Gemini reply. Regenerate with tools/make_ai_cache.py when a key is available.

*Note:* Attempt 1 widens R10's 172.16.0.0/24 to /16 (a typical over-merge) and must be rejected with a counterexample; attempt 2 merges R5+R6 (ports 80-89 and 90-100) correctly.

- attempt 1: **NOT EQUIVALENT**: counterexample `proto=TCP src_ip=0.0.0.0 dst_ip=172.16.1.0 dst_port=8000` -- original DENY (DEFAULT), AI policy ALLOW (R4)
- attempt 2: **EQUIVALENT** (4 rules, 17 product state pairs explored)

## ai_trap.fw (recorded real Gemini reply)

*Cache provenance:* REAL Gemini reply: model gemini-3.5-flash, recorded 2026-10-26 by tools/make_ai_cache.py

*Note:* attempt 1: equivalent

- attempt 1: **EQUIVALENT** (10 rules, 25 product state pairs explored)

## classbench_acl1_200.ng (recorded real Gemini reply)

*Cache provenance:* REAL Gemini reply: model gemini-3.5-flash, recorded 2026-10-26 by tools/make_ai_cache.py

*Note:* attempt 1: equivalent

- attempt 1: **EQUIVALENT** (127 rules, 152 product state pairs explored)

## classbench_fw1_100.ng (recorded real Gemini reply)

*Cache provenance:* REAL Gemini reply: model gemini-3.5-flash, recorded 2026-10-26 by tools/make_ai_cache.py

*Note:* attempt 1: equivalent

- attempt 1: **EQUIVALENT** (66 rules, 109 product state pairs explored)

## classbench_ipc1_200.ng (recorded real Gemini reply)

*Cache provenance:* REAL Gemini reply: model gemini-3.5-flash, recorded 2026-10-26 by tools/make_ai_cache.py

*Note:* attempt 1: does not parse (the reply was cut off and garbled after rule r80; NetGuard reported line:col diagnostics). The automatic retry did not complete within that run. A second, separate recording on the same day returned a correct 130-rule policy (proven equivalent, but not fewer than the optimizer's 130).

- attempt 1: **does not parse**: 64:43 expected 'in' or '==' but found 'sing'; 65:40 unexpected '.'; 66:17 unexpected 'Output' at the start of a statement; 66:39 unexpected '.'

## firewall_anomalies.fw (recorded real Gemini reply)

*Cache provenance:* REAL Gemini reply: model gemini-3.5-flash, recorded 2026-10-26 by tools/make_ai_cache.py

*Note:* attempt 1: equivalent

- attempt 1: **EQUIVALENT** (4 rules, 17 product state pairs explored)

## firewall_basic.fw (recorded real Gemini reply)

*Cache provenance:* REAL Gemini reply: model gemini-3.5-flash, recorded 2026-10-26 by tools/make_ai_cache.py

*Note:* attempt 1: equivalent

- attempt 1: **EQUIVALENT** (2 rules, 13 product state pairs explored)

## tax.ng (recorded real Gemini reply)

*Cache provenance:* REAL Gemini reply: model gemini-3.5-flash, recorded 2026-10-26 by tools/make_ai_cache.py

*Note:* attempt 1: equivalent

- attempt 1: **EQUIVALENT** (4 rules, 11 product state pairs explored)

## uci_induced.ng (recorded real Gemini reply)

*Cache provenance:* REAL Gemini reply: model gemini-3.5-flash, recorded 2026-10-26 by tools/make_ai_cache.py

*Note:* attempt 1: equivalent

- attempt 1: **EQUIVALENT** (83 rules, 6 product state pairs explored)
