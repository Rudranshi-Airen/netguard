#!/usr/bin/env python3
"""Induce a NetGuard .ng policy from the UCI "Internet Firewall Data" log.

Dataset: https://archive.ics.uci.edu/dataset/542/internet+firewall+data
(log2.csv: 65,532 records of a real university firewall; columns
Source Port, Destination Port, NAT Source Port, NAT Destination Port, Action,
Bytes, ...; Action is allow / deny / drop / reset-both).

Policy induction (deliberately simple, so it is easy to explain):
  * fields: src_port 0..65535, dst_port 0..65535
  * one rule per destination port seen at least --min-count times (default 20),
    action = that port's majority logged action (ties: alphabetical);
  * default = the overall majority action.
The policy therefore has hundreds of exact-port rules: a realistic input for the
analysis (rules equal to the default are redundant) and for AI rule merging.

Also writes datasets/uci/packets.txt (one "src_port=.. dst_port=.." per record)
for `netguard classify-batch`.

usage: python3 tools/import_uci.py [datasets/uci/log2.csv] [--min-count 20]
"""
import argparse
import collections
import csv
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ACTIONS = {"allow": "ALLOW", "deny": "DENY", "drop": "DROP", "reset-both": "RESET"}
MAX_RULES = 2048


def read_log(path):
    """Yield (src_port, dst_port, ACTION) for every record."""
    with open(path, newline="", encoding="utf-8-sig") as f:
        for row in csv.DictReader(f):
            row = {k.strip(): v for k, v in row.items()}
            yield int(row["Source Port"]), int(row["Destination Port"]), ACTIONS[row["Action"].strip().lower()]


def majority(counter):
    return sorted(counter.items(), key=lambda kv: (-kv[1], kv[0]))[0][0]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("csv", nargs="?", default=os.path.join(ROOT, "datasets", "uci", "log2.csv"))
    ap.add_argument("--min-count", type=int, default=20)
    ap.add_argument("--out", default=os.path.join(ROOT, "examples", "uci_induced.ng"))
    ap.add_argument("--packets", default=os.path.join(ROOT, "datasets", "uci", "packets.txt"))
    a = ap.parse_args()
    if not os.path.isfile(a.csv):
        sys.exit("%s not found: download log2.csv from https://archive.ics.uci.edu/dataset/542/internet+firewall+data "
                 "into datasets/uci/" % a.csv)
    records = list(read_log(a.csv))
    overall = collections.Counter(act for _, _, act in records)
    per_port = collections.defaultdict(collections.Counter)
    for _, dport, act in records:
        per_port[dport][act] += 1
    ports = [p for p, c in per_port.items() if sum(c.values()) >= a.min_count]
    dropped = 0
    if len(ports) > MAX_RULES:          # keep the most frequent ports (NG_MAX_RULES)
        ports.sort(key=lambda p: -sum(per_port[p].values()))
        dropped = len(ports) - MAX_RULES
        ports = ports[:MAX_RULES]
    ports.sort()
    default = majority(overall)
    actions_used = sorted({majority(per_port[p]) for p in ports} | {default})

    lines = [
        "# Induced from the UCI Internet Firewall Data log (%s): %d real records." % (os.path.basename(a.csv), len(records)),
        "# One rule per destination port seen >= %d times; action = the port's majority logged action;" % a.min_count,
        "# default = overall majority action. Logged actions: %s." % ", ".join("%s=%d" % kv for kv in sorted(overall.items())),
    ]
    if dropped:
        lines.append("# %d less frequent qualifying ports were left out (rule limit %d)." % (dropped, MAX_RULES))
    lines += ["ruleset uci_firewall;", "field src_port : 0 .. 65535;", "field dst_port : 0 .. 65535;",
              "default %s;" % default]
    for p in ports:
        lines.append("rule p%d : %s when dst_port == %d;   # %d records" % (p, majority(per_port[p]), p, sum(per_port[p].values())))
    with open(a.out, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    os.makedirs(os.path.dirname(a.packets), exist_ok=True)
    with open(a.packets, "w", encoding="utf-8") as f:
        for s, d, _ in records:
            f.write("src_port=%d dst_port=%d\n" % (s, d))
    print("records %d, rules %d, default %s, actions %s -> %s, %s" % (
        len(records), len(ports), default, actions_used, os.path.relpath(a.out, ROOT), os.path.relpath(a.packets, ROOT)))


if __name__ == "__main__":
    main()
