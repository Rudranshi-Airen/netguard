#!/usr/bin/env python3
"""Convert a ClassBench filter set into a NetGuard .ng policy.

ClassBench (Taylor & Turner, IEEE INFOCOM 2005) is the standard packet-
classification benchmark; its filter sets are generated from seeds taken from
real firewalls (fw*), ACLs (acl*) and IP chains (ipc*).  Each line is
    @src/len  dst/len  sport_lo : sport_hi  dport_lo : dport_hi  proto/mask  flags
ClassBench rules carry NO action, so an action is assigned with a fixed random
seed (DENY with probability --deny, else ALLOW).  State this in the report.

usage: import_classbench.py RULES_FILE N [--deny 0.3] [--seed 7] > out.ng
"""
import argparse
import random

FIELDS = [("proto", 255), ("src_ip", 4294967295), ("dst_ip", 4294967295),
          ("src_port", 65535), ("dst_port", 65535)]


def prefix(s):
    ip, plen = s.split("/")
    plen = int(plen)
    a = [int(x) for x in ip.split(".")]
    v = (a[0] << 24) | (a[1] << 16) | (a[2] << 8) | a[3]
    mask = (0xFFFFFFFF << (32 - plen)) & 0xFFFFFFFF if plen else 0
    return v & mask, (v & mask) | (~mask & 0xFFFFFFFF)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("rules")
    ap.add_argument("n", type=int)
    ap.add_argument("--deny", type=float, default=0.3)
    ap.add_argument("--seed", type=int, default=7)
    a = ap.parse_args()
    rnd = random.Random(a.seed)
    print(f"# ClassBench import: {a.rules}, first {a.n} rules, actions assigned (seed {a.seed}, deny {a.deny})")
    print("ruleset classbench;")
    for name, hi in FIELDS:
        print(f"field {name} : 0 .. {hi};")
    print("default DENY;")
    k = 0
    for line in open(a.rules):
        f = line.lstrip("@").split("\t")
        if len(f) < 5:
            continue
        val, mask = (int(x, 16) for x in f[4].split("/"))
        conds = [f"proto == {val}"] if mask else []
        parts = [("src_ip", prefix(f[0])), ("dst_ip", prefix(f[1])),
                 ("src_port", tuple(int(x) for x in f[2].split(":"))),
                 ("dst_port", tuple(int(x) for x in f[3].split(":")))]
        for name, (lo, hi) in parts:
            full = 4294967295 if name.endswith("ip") else 65535
            if (lo, hi) != (0, full):
                conds.append(f"{name} in {lo} .. {hi}")
        k += 1
        act = "DENY" if rnd.random() < a.deny else "ALLOW"
        print(f"rule r{k} : {act} when {' and '.join(conds) if conds else 'proto in 0 .. 255'};")
        if k >= a.n:
            break


if __name__ == "__main__":
    main()
