# NetGuard: Compiler-Assisted Firewall Policy Optimization and Explainable Rule Analysis

NetGuard compiles firewall policies, written in a small rule language, into finite automata. It then:

- finds shadowed and redundant rules,
- proposes an optimized policy,
- proves the optimized policy is equivalent to the original, and
- explains every classification decision.

It is a third-year Compiler Design project and an **educational tool only**. It never configures a real firewall and never touches network traffic.

All compiler and automata logic is written in **C11** using only the standard library (no flex/bison, regex, automata or JSON libraries). Python/Flask is a thin web layer that runs the binary and returns its JSON unchanged. The browser UI only renders that JSON.

---

## Build

### Linux / WSL / macOS

```bash
make                 # builds bin/netguard   (gcc or clang, -std=c11 -Wall -Wextra -O2, zero warnings)
make test            # builds and runs the C unit tests
make debug           # -g -fsanitize=address,undefined build; runs the C tests under the sanitizers
```

`make debug` produces `bin/netguard-debug` and `bin/netguard_tests-debug`. On Linux/WSL, LeakSanitizer is part of ASan, so leaks fail the run. Apple Silicon macOS has no LeakSanitizer; use `leaks --atExit -- bin/netguard ...` there instead.

### Windows (MinGW-w64)

```bash
mingw32-make
```

This works from `cmd.exe`/PowerShell and from an MSYS shell, and produces `bin\netguard.exe`. MinGW has no sanitizers, so use WSL for `make debug`.

### Python side

```bash
pip install flask pytest
```

## Run

```bash
make && python web/app.py
```

Then open http://127.0.0.1:5000.

> **macOS note:** on macOS 12 and later, port 5000 is usually taken by AirPlay Receiver. Use another port:
> ```bash
> PORT=5050 python web/app.py
> ```

The server finds `bin/netguard` or `bin/netguard.exe` automatically. If the binary has not been built, every API call returns a clear error asking you to run `make`.

## Tests

```bash
make test                    # C: lexer, parser, partition, automata, analysis, scan-vs-equivalence, equiv command (~427k checks)
make debug                   # same tests under AddressSanitizer + UndefinedBehaviorSanitizer
python -m pytest -q tests_py # Python: API, AI-merge (no network) and independent-oracle differential tests
```

- `tests_py/test_oracle.py` has its **own** `.fw`/`.ng` parsers and its own first-match evaluator. For every valid example it generates 5,000 random packets, biased toward rule boundaries ±1, and checks that `classify-batch` gives the same decision **and** the same deciding rule.
- The C automata tests do three things:
  - check hand-computed NFA/DFA/min-DFA state counts on tiny policies;
  - check that Hopcroft's result has the same size as an independent naive Moore minimization;
  - check that, on 300 random policies of up to 6 rules, the minimized DFA, the unminimized DFA and the oracle agree on both ends of every partition cell.

---

## CLI

```bash
netguard compile  FILE [--syntax fw|ng] [--json] [--min-by action|rule]
netguard classify FILE --packet "proto=TCP src_ip=10.1.2.3 dst_ip=8.8.8.8 dst_port=22" [--json]
netguard classify-batch FILE < packets.txt        # one packet per line -> one JSON result per line
netguard verify   FILE [--n 10000] [--seed 42]    # random packets: min-DFA vs oracle, optimized vs original
netguard dot      FILE --stage nfa|dfa|min [--min-by action|rule]
netguard equiv    ORIGINAL SUGGESTED [--syntax fw|ng] [--json]   # prove two policies equivalent, or get a counterexample
```

Exit codes:

| Code | Meaning |
|---|---|
| 0 | Success |
| 1 | Compile errors (the JSON still contains the diagnostics) |
| 2 | Usage error (bad option, unreadable file, malformed packet) |
| 3 | `equiv` only: the two policies are NOT equivalent (the output has the counterexample) |

The syntax is chosen from the file extension (`.ng` means generic, anything else means firewall) unless `--syntax` is given.

### Real output

```
$ bin/netguard compile examples/firewall_basic.fw
NetGuard  policy 'firewall'  (4 rules, 4 fields, default DENY)
Partition: proto=5 src_ip=3 dst_ip=1 dst_port=7  -> 105 cells, alphabet 16 symbols
Automata:  NFA 51 (eps 34, sym 22) -> DFA 21 (final 5) -> Min 13 (by rule: 15)
Analysis:  ok=3 shadowed=1 partial=0 redundant=0
  R1    ok                                             none
  R2    shadowed  single-rule shadow, conflicting      high
  R3    ok                                             none
  R4    ok                                             none
Optimization: 4 -> 2 rules
  1. remove R2    Fully shadowed (single-rule shadow, conflicting): R1 contains it, so it never decides a packet; its packets are decided by R1 (DENY).
  2. remove R1    Became removable after earlier deletions (it was needed in the original policy: deleting it alone would let R2 (ALLOW) decide proto=TCP src_ip=10.0.0.0 dst_ip=0.0.0.0 dst_port=22). Now that R2 has been removed, the packets it decided fall through to DEFAULT DENY, the same action (DENY).
Equivalence (optimized vs original): EQUIVALENT
Optimized policy:
# Optimized by NetGuard: 2 of 4 rules kept (equivalent to the original)
ALLOW TCP FROM ANY TO ANY PORT 443                       # R1 (original R3)
ALLOW UDP FROM ANY TO ANY PORT 53                        # R2 (original R4)
DEFAULT DENY
```

```
$ bin/netguard classify examples/firewall_anomalies.fw --packet "proto=TCP src_ip=192.168.1.7 dst_ip=8.8.8.8 dst_port=92"
Packet:   proto=TCP src_ip=192.168.1.7 dst_ip=8.8.8.8 dst_port=92
Decision: ALLOW  (by R6)
Matched:  R6, R7
  R1: dst_port 92 ∉ [22,22]
  R2: src_ip 192.168.1.7 ∉ [10.0.0.0,10.255.255.255]
  R3: dst_port 92 ∉ [443,443]
  R4: proto 6 (TCP) ∉ [17,17]
  R5: dst_port 92 ∉ [80,89]
Trace (min-DFA states):
  proto     6 (TCP)          sym 3   [6,6]                        M0 -> M2
  src_ip    192.168.1.7      sym 4   [192.168.1.0,192.168.1.255]  M2 -> M7
  dst_ip    8.8.8.8          sym 0   [0.0.0.0,172.15.255.255]     M7 -> M12
  dst_port  92               sym 7   [90,95]                      M12 -> M16
Oracle:   ALLOW (R6)
```

```
$ bin/netguard verify examples/firewall_anomalies.fw --n 10000 --seed 42
{"ok":true,"n":10000,"seed":42,"mismatches":[],"min_dfa_vs_oracle":{"agree":10000,"disagree":0},"dfa_vs_oracle":{"agree":10000,"disagree":0},"optimized_vs_original":{"agree":10000,"disagree":0},"optimized_min_dfa_vs_original":{"agree":10000,"disagree":0},"all_agree":true,"original_rules":10,"optimized_rules":5}
```

```
$ echo "proto=UDP src_ip=1.2.3.4 dst_ip=8.8.8.8 dst_port=53" | bin/netguard classify-batch examples/firewall_basic.fw
{"ok":true,"input":"proto=UDP src_ip=1.2.3.4 dst_ip=8.8.8.8 dst_port=53","packet":{...},"decision":"ALLOW","decided_by":"R4",...}
```

```
$ bin/netguard compile examples/errors.fw
examples/errors.fw:2:16: error: octet 300 in '300.0.0.1' is greater than 255  [hint: each IPv4 octet must be between 0 and 255]
examples/errors.fw:3:16: error: CIDR prefix /33 in '10.0.0.0/33' is greater than 32  [hint: an IPv4 prefix length must be between 0 and 32]
examples/errors.fw:4:16: warning: CIDR '10.1.2.3/8' has host bits set; normalized to 10.0.0.0/8  [hint: ...]
examples/errors.fw:5:32: error: port range 100-50 is empty (low end > high end)  [hint: write the lower port first]
... (10 errors and 2 warnings in total, one per broken line)
```

`compile --json` returns a single document with these top-level keys:

`ok, diagnostics, tokens, policy, partition, nfa, dfa, min_dfa, min_dfa_modes, analysis, optimization, equivalence, stats`

---

## Input languages

### Firewall policy (`.fw`)

```
policy       := { stmt NEWLINE }
stmt         := rule | default_decl | ε
default_decl := 'DEFAULT' action                     (optional, default DENY, at most once)
rule         := action proto 'FROM' addr 'TO' addr [ 'PORT' portspec ]
action       := 'ALLOW' | 'DENY'
proto        := 'TCP' | 'UDP' | 'ICMP' | 'ANY' | INT  (6, 17, 1, 0..255)
addr         := 'ANY' | IPV4 | CIDR | IPV4 '-' IPV4
portspec     := 'ANY' | INT | INT '-' INT             (0..65535, omitted = ANY)
```

- Keywords are case-insensitive.
- `#` starts a comment, which can be a whole line or the end of a line.
- The packet model is the vector `(proto, src_ip, dst_ip, dst_port)`.
- Rules are numbered R1, R2, … and the **first match wins**.

### Generic rules (`.ng`)

```
ruleset IDENT ;
field IDENT : INT .. INT ;                 (1..8 fields)
default IDENT ;
rule IDENT : IDENT when cond { and cond } ;
cond := IDENT in INT .. INT  |  IDENT == INT
```

A field that a rule does not mention matches its whole domain. Both front ends produce the same IR (`core/include/ir.h`).

---

## Architecture

```
                    .fw source                         .ng source
                        |                                   |
             lexer.c (DFA scanner)              parser_ng.c (scanner + RD parser)
                        |                                   |
          parser_fw.c (recursive descent)                   |
                        |                                   |
             sema.c (checks, lowering)                      |
                        +-----------------+-----------------+
                                          |
                              Policy IR (ir.h): ranges per field
                                          |
                        partition.c  -- sweep-line intervals = alphabet symbols
                                          |
                        nfa.c        -- Thompson ε-NFA (one fragment per rule)
                                          |
                        dfa.c        -- subset construction, layered + SINK, matched/winner/output
                          |                 |                                   |
            minimize.c (Hopcroft)    analysis.c (separate pass over the       classify.c
            by action / by rule      UNMINIMIZED DFA: shadowed / partial /    (min DFA decides,
                          |          redundant)                                unminimized DFA explains,
                          |                 |                                  oracle.c cross-checks)
                          |          optimize.c (remove rules; each removal
                          |          validated by equiv.c)
                          |                 |
                          +---- equiv.c: product-automaton BFS, counterexample packet
                                          |
             dot.c (Graphviz) + json.c (writer) + pipeline.c (driver, phase timing) + main.c (CLI)
                                          |
                     bin/netguard  <--subprocess--  web/app.py (Flask)  <--fetch--  web/static (UI)
```

Each algorithm file starts with a block comment that explains:

- the algorithm,
- its complexity, and
- the compiler-design concept it demonstrates.

### Files

| Path | Contents |
|---|---|
| `core/src/*.c`, `core/include/*.h` | The whole compiler (C11) |
| `core/tests/*.c` | C tests with a tiny assertion framework (`test.h`) |
| `core/Makefile` | Builds `bin/netguard[.exe]`; targets `all`, `debug`, `test`, `clean`. The root `Makefile` delegates to it. |
| `web/app.py` | Flask: `POST /api/compile`, `/api/classify`, `/api/verify`, `/api/ai-merge`, `GET /api/examples`. Each call runs the binary with a 30 s timeout. |
| `web/ai.py` | Gemini call (stdlib `urllib` only), prompts, counterexample-guided retry, demo cache. No analysis logic. |
| `tools/` | `import_classbench.py`, `bench.py`, `import_uci.py`, `replay_uci.py`, `ai_merge_report.py`, `make_ai_cache.py` |
| `outputs/` | Generated reports: `bench.md`, `ai_merge.md` (and `uci_replay.md` once the UCI log is present) |
| `web/static/` | UI: plain JavaScript, Viz.js 3.11.0 pinned from jsDelivr |
| `examples/` | `firewall_basic.fw`, `firewall_anomalies.fw`, `errors.fw`, `tax.ng`, five `classbench_*.ng` policies, `ai_cache/` (demo AI responses) |
| `tests_py/` | `test_api.py`, `test_oracle.py`, `test_ai.py` (pytest) |

### Limits

Exceeding a limit produces a diagnostic, never a crash:

- 2,048 rules
- 8 fields
- 16 actions
- 400,000 NFA states
- 200,000 DFA states
- 60 million DFA transition-table cells (memory cap)

---

## Expected results (asserted by the tests)

### `firewall_anomalies.fw`

| Rule | Status |
|---|---|
| R2 | shadowed, single-rule shadow by R1, conflicting, high severity |
| R7 | shadowed, union shadow by R5 + R6, same action |
| R8 | redundant: DEFAULT DENY already decides its packets |
| R9 | redundant: R10 decides its packets with the same action |
| R1, R3, R4, R5, R6, R10 | ok |

R10 is ok even though R9 takes some of its packets first. R9 is redundant, so that overlap changes no decision. R9 is still listed in R10's `beaten_by`.

**Optimization** removes, in order:

1. R2 (shadowed)
2. R7 (shadowed)
3. R9 (redundant)
4. R8 (redundant)
5. R1

R1 becomes removable only after R2 is gone, because DEFAULT DENY then covers TCP/22. The removal log says so.

The result is R3, R4, R5, R6, R10 + DEFAULT DENY, and the equivalence check says **equivalent**.

### `tax.ng`

- **t5** is shadowed. It is single-rule contained in t3, and its DFA-derived covering set is {t2, t3}. It is conflicting because t2 (SLAB_0) decides part of it.
- **t2** is partially overlapped by t1.

---

## Review 3: real datasets, scaling, AI-assisted merging

### Datasets

| Data | What it is | In this repo |
|---|---|---|
| **ClassBench** | Packet-classification benchmark (D. E. Taylor and J. S. Turner, *ClassBench: A Packet Classification Benchmark*, IEEE INFOCOM 2005). Filter sets are generated from seed files taken from **real firewalls (fw), ACLs (acl) and IP chains (ipc)**. | `examples/classbench_*.ng`, made by `tools/import_classbench.py`; source and regeneration steps in `datasets/classbench/README.md` (the dataset itself is not committed) |
| **UCI Internet Firewall Data** | 65,532 real firewall log records from a university firewall (https://archive.ics.uci.edu/dataset/542/internet+firewall+data) | `examples/uci_induced.ng` (made by `tools/import_uci.py` from `datasets/uci/log2.csv`, not committed); replay report in `outputs/uci_replay.md` |

**ClassBench rules have no actions.** The importer assigns DENY with probability 0.3 (else ALLOW) using the fixed seed 7, and the default is DENY. The rule geometry (prefixes, port ranges, protocols) is ClassBench's; the shadowed/redundant counts depend on these assigned actions. The UI shows this note whenever a ClassBench example is loaded.

```bash
git clone --depth 1 https://github.com/sorrachai/PartitonSort datasets/classbench/PartitonSort
mkdir -p datasets/classbench/rules
tar xzf datasets/classbench/PartitonSort/Rulesets/1k_2k_4k_8k.tar.gz -C datasets/classbench/rules
python3 tools/bench.py --before bin/netguard-review2     # writes outputs/bench.md (--before is optional)
```

### Real traffic: UCI firewall log (P2)

`tools/import_uci.py` turns the log into a policy over `src_port` and `dst_port`:

- one rule per destination port seen at least 20 times, with that port's majority logged action;
- the default is the overall majority action.

On the real log this gives **115 rules** (default ALLOW, actions ALLOW/DENY/DROP). NetGuard's optimizer reduces them to **86**: 29 rules only repeat the default, and the result is proven equivalent.

`tools/replay_uci.py` then classifies **all 65,532 records** with the compiled automaton (`outputs/uci_replay.md`):

| Measure | Result |
|---|---|
| NetGuard decision = logged action | **95.65%** (62,682 / 65,532) |
| Automaton = linear oracle | 65,532 / 65,532 |
| Replay time | 1.63 s (24.9 µs per packet) |

The remaining 4.35% differ because the induced policy only sees the destination port, while the real firewall also used addresses, connection state and NAT.

```bash
curl -L -o datasets/uci/uci.zip "https://archive.ics.uci.edu/static/public/542/internet+firewall+data.zip"
unzip datasets/uci/uci.zip -d datasets/uci
python3 tools/import_uci.py && python3 tools/replay_uci.py
```

### Scaling (P1-a)

Analysis and optimization used to recompile the whole policy once per rule. They now scan the unminimized DFA's final states once:

- **Redundancy:** rule *i* is redundant iff, in every final state that *i* wins, the next matching rule (or the DEFAULT) has the same action.
- **Optimizer:** keeps a kept-set *K*. Rule *i* is removed iff the lowest rule of `matched(s) ∩ (K \ {i})` (or the DEFAULT) gives the original decision in every final state.
- **One proof at the end:** the product-automaton equivalence check runs once, on the final optimized policy.

A C test checks, on 500 random policies, that the scan-based redundancy and optimizer give exactly the same results as the old equivalence-per-rule versions. Example outputs are byte-identical to Review 2.

Measured with `tools/bench.py` (`outputs/bench.md` has every column); *before* is the Review-2 binary on the same files:

| ClassBench, first 200 rules | before (total) | after (total) | speed-up | same result |
|---|---|---|---|---|
| fw1 | 49,828 ms | 262 ms | 190× | yes |
| acl1 | 846 ms | 8.1 ms | 105× | yes |
| ipc1 | 51,497 ms | 212 ms | 243× | yes |

Larger policies (`outputs/bench.md`, `examples/`):

- **fw1:** 800 rules compile in 57 s; the subset construction dominates.
- **acl1:** 2,048 rules (the rule limit) compile in 0.7 s.
- **fw1 from the 8k set:** the largest prefix that compiles is 631 rules (7.9 s). At 637 rules the subset construction passes the 200,000 DFA-state limit, so the cutoff is set by that limit, not by time.

### AI-assisted rule merging (Gemini proposes, NetGuard proves)

NetGuard's optimizer only *removes* rules. Merging (for example `PORT 80-89` + `PORT 90-100` into `PORT 80-100`) is proposed by Gemini through `POST /api/ai-merge` (UI section 8, **AI merge (Gemini)**):

1. NetGuard compiles the policy; its optimized policy is sent to Gemini with the language grammar and the first-match-wins rule.
2. The reply (fences stripped) is checked with `netguard equiv ORIGINAL REPLY`, always against the **original** policy. The check is a product-automaton proof over the partition of both policies.
3. If the reply does not parse or is not equivalent, the diagnostics or the **counterexample packet** with both decisions go back to Gemini, which gets up to 3 attempts in total.
4. The reply is **accepted only if it is proven equivalent and has fewer rules** than the optimizer's result. Otherwise the optimizer's policy stays.

```bash
export GEMINI_API_KEY=...            # never hard-coded or logged; read from the environment only
export GEMINI_MODEL=gemini-3.5-flash # optional (the default). gemini-2.5-flash now returns 404 for new keys
export GEMINI_TIMEOUT=60             # optional: seconds per API call (one retry on 429/5xx/timeout)
export GEMINI_BUDGET=150             # optional: seconds for a whole AI-merge run, then demo fallback
PORT=5050 python web/app.py
```

**Recorded replies and demo mode.** Live calls are slow: 7 s to 3 min per policy in our runs, because Gemini's latency varies a lot. So the UI has a **"Replay recorded reply (instant)"** checkbox, on by default. It replays the saved response for that example from `examples/ai_cache/` and re-proves it with NetGuard on the spot. Untick it to call Gemini live.

Without a key, or if a live call fails or times out, the saved response is used automatically. The pill shows:
- **LIVE GEMINI** for a live call;
- **RECORDED GEMINI REPLY** for a saved real reply;
- **DEMO CACHE** for a hand-written example.

Record new replies with:

```bash
GEMINI_API_KEY=... python3 tools/make_ai_cache.py EXAMPLE...
```

**Real results** (gemini-3.5-flash, recorded 2026-10-26, each reply proven by `netguard equiv`; full log in `outputs/ai_merge.md`):

| Policy | Original | NetGuard optimizer | Gemini, proven | Accepted |
|---|---|---|---|---|
| `firewall_anomalies.fw` | 10 | 5 | **4** (merged ports 80-89 + 90-100) | yes |
| `ai_trap.fw` (merges that look safe but aren't) | 13 | 12 | **10** | yes |
| `uci_induced.ng` (real UCI traffic) | 115 | 86 | **83** | yes |
| `classbench_fw1_100.ng` | 100 | 67 | **66** | yes |
| `classbench_acl1_200.ng` | 200 | 127 | 127 | no (not fewer) |
| `tax.ng` | 5 | 4 | 4 | no (not fewer) |
| `firewall_basic.fw` | 4 | 2 | 2 | no (not fewer) |
| `classbench_ipc1_200.ng` | 200 | 130 | — | no: the reply was cut off and garbled after rule r80, and NetGuard rejected it with line:col diagnostics (e.g. `64:43 expected 'in' or '==' but found 'sing'`) |

Gemini never produced a policy that parsed but was wrong, so no real counterexample rejection happened. To demonstrate that path, `ai_demo_rejection.fw` (the same rules as `firewall_anomalies.fw`) has a **hand-written** cache, labelled as such:
- attempt 1 widens `172.16.0.0/24` to `/16` and is rejected with the counterexample `proto=TCP src_ip=0.0.0.0 dst_ip=172.16.1.0 dst_port=8000` (original DENY, AI ALLOW);
- attempt 2 is the corrected merge and is accepted.

The ClassBench numbers show that the AI adds little after NetGuard's own optimizer: the optimizer already removes almost everything removable, and AI merging helps only where same-action ranges sit next to each other.

---

## Formal model and its limits

- **Fixed-order field vector.** The automaton reads a packet as a fixed-order vector of fields, `proto, src_ip, dst_ip, dst_port` (or the declared `.ng` fields). Each field value is mapped to one alphabet symbol (its partition interval), so a packet is a word of exactly `nfields` symbols. A field the policy does not mention still costs one symbol.
- **Priority through `winner`.** The NFA accepts a word with every rule tag that matches. The subset construction keeps all of them in `matched`. Priority is restored in each final DFA state by `winner` = the lowest rule index in `matched`, which is exactly first-match-wins. The decision is `actions[winner]`, or the DEFAULT when nothing matches.
- **Shadowing and redundancy are a separate analysis.** They are computed by their own pass over the **unminimized** DFA's final states (redundancy too: rule *i* is redundant iff, in every final state it wins, the next matching rule or the DEFAULT has the same action). They are not a by-product of minimization. Within this model the analysis is exact, not heuristic:
  - every reachable final state stands for at least one real packet, and
  - every packet reaches exactly one final state,

  so "never wins" means "never decides any packet".
- **Optimization only removes rules.** It never merges, splits, reorders or rewrites a rule. A removal is accepted only if every final DFA state keeps its original decision, and the final optimized policy is then proved equivalent to the original by the product automaton.
- **Rule merging is proposed by an AI, never trusted.** `/api/ai-merge` lets Gemini rewrite the policy; the rewrite is used only if `netguard equiv` proves it equivalent to the original and it has fewer rules.
- **Only the listed fields are modeled.** There is no stateful or connection tracking (no SYN/ESTABLISHED, no NAT, no rate limits, no interface or direction). There are no source ports, ICMP types or other header fields unless they are declared as `.ng` fields. The results hold for this model only, not for a real firewall's full semantics.

---

## Notes

- Viz.js is loaded from `https://cdn.jsdelivr.net/npm/@viz-js/viz@3.11.0/lib/viz-standalone.js`. Offline, the UI shows the DOT text instead of the drawn graph.
- Graphs with more than 200 nodes are not exported in the JSON (`too_large: true`). Use `netguard dot FILE --stage ...` to get the complete graph.
