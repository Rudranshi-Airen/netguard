# ClassBench filter sets (source of the `examples/classbench_*.ng` files)

ClassBench (D. E. Taylor and J. S. Turner, "ClassBench: A Packet Classification
Benchmark", IEEE INFOCOM 2005) is the standard packet-classification benchmark.
Its filter sets are *generated from seed parameter files extracted from real
firewalls (fw), access control lists (acl) and IP chains (ipc)*.

The filter sets used here come from the PartitionSort repository
(the repo name is spelled "PartitonSort"):

    git clone --depth 1 https://github.com/sorrachai/PartitonSort datasets/classbench/PartitonSort
    mkdir -p datasets/classbench/rules
    tar xzf datasets/classbench/PartitonSort/Rulesets/1k_2k_4k_8k.tar.gz -C datasets/classbench/rules

The full dataset is NOT committed (it is in .gitignore). Only the generated
policies in `examples/` are kept:

| example | source file | rules |
|---|---|---|
| classbench_fw1_100.ng   | rules/1k_1/fw1_seed_1.rules  | first 100 |
| classbench_acl1_200.ng  | rules/1k_1/acl1_seed_1.rules | first 200 |
| classbench_ipc1_200.ng  | rules/1k_1/ipc1_seed_1.rules | first 200 |
| classbench_fw1_631.ng   | rules/8k_1/fw1_seed_1.rules  | first 631 (largest fw1 prefix that compiles: at 637 rules the subset construction exceeds the 200,000 DFA-state limit) |
| classbench_acl1_2048.ng | rules/8k_1/acl1_seed_1.rules | first 2048 (the NG_MAX_RULES limit; compiles in under 1 s) |

**Actions are not real.** ClassBench rules have no actions. `tools/import_classbench.py`
assigns DENY with probability 0.3, else ALLOW, using the fixed seed 7, and the
default is DENY. Shadowing/redundancy counts therefore depend on these assigned
actions; the rule *geometry* (prefixes, port ranges, protocols) is ClassBench's.

Regenerate, e.g.:

    python3 tools/import_classbench.py datasets/classbench/rules/1k_1/fw1_seed_1.rules 100 > examples/classbench_fw1_100.ng
