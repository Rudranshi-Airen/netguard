#!/usr/bin/env python3
"""Replay the real UCI firewall log through NetGuard and report agreement.

Every record of log2.csv becomes one packet (src_port, dst_port) for
`bin/netguard classify-batch`; the decision of the compiled automaton is
compared with the action the real firewall logged.  Writes
outputs/uci_replay.md with the agreement rate and a confusion table.

The induced policy only looks at the destination port, while the real firewall
also used addresses, state and NAT, so 100 % agreement is not expected; the
point is a real-traffic replay of the compiled classifier, with the oracle
cross-check (`oracle_agrees`) on every single packet.

usage: python3 tools/replay_uci.py [datasets/uci/log2.csv] [--policy examples/uci_induced.ng]
"""
import argparse
import collections
import json
import os
import subprocess
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "tools"))
from import_uci import read_log  # noqa: E402


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("csv", nargs="?", default=os.path.join(ROOT, "datasets", "uci", "log2.csv"))
    ap.add_argument("--policy", default=os.path.join(ROOT, "examples", "uci_induced.ng"))
    ap.add_argument("--out", default=os.path.join(ROOT, "outputs", "uci_replay.md"))
    a = ap.parse_args()
    if not os.path.isfile(a.csv) or not os.path.isfile(a.policy):
        sys.exit("need %s and %s (run tools/import_uci.py first)" % (a.csv, a.policy))
    binary = os.path.join(ROOT, "bin", "netguard.exe" if os.name == "nt" else "netguard")
    records = list(read_log(a.csv))
    packets = "".join("src_port=%d dst_port=%d\n" % (s, d) for s, d, _ in records)
    t0 = time.perf_counter()
    p = subprocess.run([binary, "classify-batch", a.policy, "--syntax", "ng"], input=packets,
                       capture_output=True, text=True, timeout=600)
    wall = time.perf_counter() - t0
    if p.returncode != 0:
        sys.exit("classify-batch failed: %s" % p.stderr[:500])
    results = [json.loads(line) for line in p.stdout.splitlines()]
    assert len(results) == len(records), (len(results), len(records))

    confusion = collections.Counter()
    agree = oracle_ok = by_default = 0
    for (_, _, logged), r in zip(records, results):
        confusion[(logged, r["decision"])] += 1
        agree += logged == r["decision"]
        oracle_ok += bool(r["oracle_agrees"])
        by_default += r["decided_by"] == "DEFAULT"
    n = len(records)
    acts = sorted({k[0] for k in confusion} | {k[1] for k in confusion})
    out = ["# Real-traffic replay: UCI Internet Firewall Data through NetGuard\n",
           "Measured %s. Log: `%s` (%d real firewall records). Policy: `%s` (induced by tools/import_uci.py). "
           "Each record is classified by the compiled minimized DFA via `bin/netguard classify-batch`.\n"
           % (time.strftime("%Y-%m-%d"), os.path.relpath(a.csv, ROOT), n, os.path.relpath(a.policy, ROOT)),
           "| metric | value |", "|---|---|",
           "| records replayed | %d |" % n,
           "| NetGuard decision == logged action | %d (%.2f %%) |" % (agree, 100.0 * agree / n),
           "| decided by DEFAULT | %d (%.2f %%) |" % (by_default, 100.0 * by_default / n),
           "| automaton == linear oracle (`oracle_agrees`) | %d / %d |" % (oracle_ok, n),
           "| classify-batch wall time | %.2f s (%.1f µs / packet) |" % (wall, 1e6 * wall / n),
           "\n## Confusion table (rows: logged action, columns: NetGuard decision)\n",
           "| logged \\ NetGuard | " + " | ".join(acts) + " | total |",
           "|---|" + "---|" * (len(acts) + 1)]
    for la in acts:
        row = [confusion[(la, na)] for na in acts]
        out.append("| %s | %s | %d |" % (la, " | ".join(str(x) for x in row), sum(row)))
    out.append("\nDisagreements are expected: the induced policy sees only the destination port, while the real "
               "firewall's decisions also depended on addresses, connection state and NAT.")
    os.makedirs(os.path.dirname(a.out), exist_ok=True)
    with open(a.out, "w", encoding="utf-8") as f:
        f.write("\n".join(out) + "\n")
    print("agreement %.2f %% (%d/%d), oracle %d/%d -> %s" % (100.0 * agree / n, agree, n, oracle_ok, n,
                                                             os.path.relpath(a.out, ROOT)))


if __name__ == "__main__":
    main()
