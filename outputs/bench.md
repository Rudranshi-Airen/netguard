# NetGuard on ClassBench filter sets

Measured on 2026-10-26 with `bin/netguard compile --json`; every number below is read from the compiler's own JSON (`stats.phase_ms` is `clock()` CPU time per phase; *wall* is the measured process time). Policies are the first N rules of `datasets/classbench/rules/1k_1/<series>_seed_1.rules` imported by `tools/import_classbench.py` (actions assigned with seed 7, P(DENY)=0.3, default DENY: ClassBench has no actions).

| series | rules | cells | symbols | NFA | DFA | Min DFA | shadowed | redundant | optimized rules | lex ms | parse ms | partition ms | nfa ms | dfa ms | minimize ms | analysis ms | optimize ms | equivalence ms | dot ms | total ms | wall s |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| fw1 | 25 | 1134000 | 108 | 341 | 129 | 40 | 0 | 11 | 14 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.2 | 0.1 | 0.0 | 0.1 | 0.7 | 1.3 | 0.00 |
| fw1 | 50 | 5600000 | 149 | 1175 | 446 | 72 | 0 | 19 | 31 | 0.0 | 0.0 | 0.0 | 0.0 | 0.4 | 1.1 | 0.1 | 0.1 | 0.4 | 1.1 | 3.3 | 0.01 |
| fw1 | 100 | 42300864 | 236 | 4643 | 1847 | 109 | 0 | 33 | 67 | 0.1 | 0.1 | 0.0 | 0.1 | 7.1 | 8.0 | 0.4 | 0.8 | 6.6 | 1.6 | 24.7 | 0.03 |
| fw1 | 200 | 133183440 | 351 | 18497 | 8049 | 163 | 0 | 71 | 129 | 0.1 | 0.2 | 0.0 | 0.2 | 119.2 | 49.9 | 2.4 | 11.6 | 75.2 | 3.0 | 261.8 | 0.29 |
| fw1 | 400 | 224910000 | 399 | 54743 | 12984 | 298 | 5 | 125 | 271 | 0.1 | 0.4 | 0.1 | 0.5 | 486.9 | 77.4 | 6.0 | 25.1 | 305.1 | 4.0 | 905.6 | 0.91 |
| fw1 | 800 | 589918329 | 497 | 254503 | 116295 | 1426 | 14 | 100 | 690 | 0.2 | 1.0 | 0.1 | 2.6 | 29856.9 | 1032.6 | 94.2 | 250.8 | 25638.3 | 8.5 | 56885.3 | 57.08 |
| acl1 | 25 | 108360 | 106 | 251 | 95 | 45 | 0 | 11 | 14 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.1 | 0.1 | 0.0 | 0.1 | 0.6 | 1.0 | 0.00 |
| acl1 | 50 | 286440 | 149 | 501 | 154 | 63 | 0 | 19 | 31 | 0.0 | 0.0 | 0.0 | 0.0 | 0.1 | 0.3 | 0.1 | 0.1 | 0.1 | 1.1 | 1.9 | 0.00 |
| acl1 | 100 | 1718280 | 244 | 1001 | 292 | 101 | 0 | 33 | 67 | 0.0 | 0.1 | 0.0 | 0.0 | 0.3 | 0.8 | 0.3 | 0.2 | 0.5 | 1.4 | 3.5 | 0.01 |
| acl1 | 200 | 3146780 | 317 | 2001 | 470 | 152 | 2 | 73 | 127 | 0.1 | 0.2 | 0.0 | 0.1 | 0.9 | 2.3 | 0.6 | 0.5 | 1.0 | 2.4 | 8.1 | 0.01 |
| acl1 | 400 | 8522550 | 462 | 4005 | 875 | 235 | 6 | 138 | 261 | 0.1 | 0.4 | 0.1 | 0.1 | 4.2 | 6.3 | 1.4 | 1.8 | 3.5 | 3.6 | 21.5 | 0.03 |
| acl1 | 800 | 44545914 | 770 | 60329 | 25321 | 370 | 18 | 324 | 464 | 0.2 | 1.0 | 0.1 | 0.6 | 318.4 | 239.7 | 23.4 | 208.2 | 277.7 | 7.6 | 1076.9 | 1.09 |
| ipc1 | 25 | 2389725 | 125 | 743 | 337 | 42 | 0 | 11 | 14 | 0.0 | 0.0 | 0.0 | 0.0 | 0.2 | 0.6 | 0.1 | 0.0 | 0.3 | 0.6 | 1.9 | 0.00 |
| ipc1 | 50 | 12380940 | 197 | 1723 | 769 | 69 | 0 | 19 | 31 | 0.0 | 0.0 | 0.0 | 0.0 | 1.2 | 2.5 | 0.1 | 0.1 | 0.9 | 1.1 | 6.0 | 0.01 |
| ipc1 | 100 | 31100160 | 267 | 3559 | 1410 | 98 | 0 | 33 | 67 | 0.0 | 0.1 | 0.0 | 0.0 | 6.1 | 6.2 | 0.4 | 0.3 | 3.8 | 1.4 | 18.3 | 0.02 |
| ipc1 | 200 | 218972650 | 438 | 12727 | 5485 | 159 | 0 | 70 | 130 | 0.1 | 0.2 | 0.0 | 0.1 | 103.9 | 41.1 | 1.6 | 4.0 | 57.7 | 3.0 | 211.7 | 0.22 |
| ipc1 | 400 | 2035584000 | 801 | 48887 | 22466 | 283 | 0 | 133 | 267 | 0.1 | 0.4 | 0.1 | 0.5 | 1466.6 | 501.1 | 10.5 | 39.6 | 756.1 | 4.3 | 2779.2 | 2.79 |
| ipc1 | 800 | **failed:** the subset construction exceeded 200000 DFA states | | | | | | | | | | | | | | | | | | | | 7.53 |

## Speed-up of the scan-based analysis/optimizer (P1-a)

*Before* = `bin/netguard-review2` (one full recompile + equivalence check per rule in analysis and in the optimizer; its limits were 256 rules / 20,000 NFA / 50,000 DFA states). *After* = current build (exact scan of the unminimized DFA, one equivalence proof at the end). Same input files.

| series | rules | before analysis+optimize ms | after analysis+optimize ms | before total ms | after total ms | speed-up (total) | same result |
|---|---|---|---|---|---|---|---|
| fw1 | 25 | 7.3 | 0.1 | 8.5 | 1.3 | 6.7x | yes |
| fw1 | 50 | 105.0 | 0.2 | 108.5 | 3.3 | 33.3x | yes |
| fw1 | 100 | 2479.0 | 1.2 | 2502.8 | 24.7 | 101.2x | yes |
| fw1 | 200 | 49605.7 | 14.1 | 49828.3 | 261.8 | 190.3x | yes |
| fw1 | 400 | before failed: too many rules (the limit is 256) | | | | | |
| acl1 | 25 | 4.8 | 0.1 | 5.7 | 1.0 | 5.7x | yes |
| acl1 | 50 | 22.0 | 0.2 | 23.7 | 1.9 | 12.7x | yes |
| acl1 | 100 | 141.0 | 0.4 | 144.1 | 3.5 | 40.6x | yes |
| acl1 | 200 | 839.4 | 1.1 | 846.3 | 8.1 | 104.9x | yes |
| acl1 | 400 | before failed: too many rules (the limit is 256) | | | | | |
| ipc1 | 25 | 25.7 | 0.1 | 27.4 | 1.9 | 14.8x | yes |
| ipc1 | 50 | 271.0 | 0.2 | 276.7 | 6.0 | 46.2x | yes |
| ipc1 | 100 | 2082.9 | 0.6 | 2100.8 | 18.3 | 114.9x | yes |
| ipc1 | 200 | 51293.3 | 5.6 | 51496.5 | 211.7 | 243.3x | yes |
| ipc1 | 400 | before failed: too many rules (the limit is 256) | | | | | |
