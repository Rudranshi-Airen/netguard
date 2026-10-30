# Real-traffic replay: UCI Internet Firewall Data through NetGuard

Measured 2026-10-26. Log: `datasets/uci/log2.csv` (65532 real firewall records). Policy: `examples/uci_induced.ng` (induced by tools/import_uci.py). Each record is classified by the compiled minimized DFA via `bin/netguard classify-batch`.

| metric | value |
|---|---|
| records replayed | 65532 |
| NetGuard decision == logged action | 62682 (95.65 %) |
| decided by DEFAULT | 6798 (10.37 %) |
| automaton == linear oracle (`oracle_agrees`) | 65532 / 65532 |
| classify-batch wall time | 1.63 s (24.9 µs / packet) |

## Confusion table (rows: logged action, columns: NetGuard decision)

| logged \ NetGuard | ALLOW | DENY | DROP | RESET | total |
|---|---|---|---|---|---|
| ALLOW | 37414 | 226 | 0 | 0 | 37640 |
| DENY | 2530 | 12417 | 40 | 0 | 14987 |
| DROP | 0 | 0 | 12851 | 0 | 12851 |
| RESET | 53 | 1 | 0 | 0 | 54 |

Disagreements are expected: the induced policy sees only the destination port, while the real firewall's decisions also depended on addresses, connection state and NAT.
