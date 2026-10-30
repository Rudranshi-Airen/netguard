"""Differential test: the C automata vs an independent Python oracle.

This file has its own small parsers for .fw and .ng and its own linear
first-match evaluator; it shares no code with the C compiler.  For every
valid example it generates 5,000 random packets (biased toward rule
boundaries +-1), classifies them all with `netguard classify-batch`, and
requires the decision AND the deciding rule to match exactly.
"""

import ipaddress
import json
import os
import random
import re
import subprocess

import pytest

from conftest import EXAMPLES, binary_path

N_PACKETS = 5000
U32 = 2**32 - 1
PROTOS = {"TCP": 6, "UDP": 17, "ICMP": 1}


# ---------------------------------------------------------------- parsers
def ip_range(tok):
    if tok.upper() == "ANY":
        return 0, U32
    if "/" in tok:
        net = ipaddress.ip_network(tok, strict=False)
        return int(net.network_address), int(net.broadcast_address)
    if "-" in tok:
        a, b = tok.split("-")
        return int(ipaddress.ip_address(a)), int(ipaddress.ip_address(b))
    v = int(ipaddress.ip_address(tok))
    return v, v


def parse_fw(text):
    fields = [("proto", 0, 255), ("src_ip", 0, U32), ("dst_ip", 0, U32), ("dst_port", 0, 65535)]
    rules, default = [], "DENY"
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        w = line.split()
        if w[0].upper() == "DEFAULT":
            default = w[1].upper()
            continue
        action, proto = w[0].upper(), w[1].upper()
        assert w[2].upper() == "FROM" and w[4].upper() == "TO"
        if proto == "ANY":
            pr = (0, 255)
        elif proto in PROTOS:
            pr = (PROTOS[proto], PROTOS[proto])
        else:
            pr = (int(proto), int(proto))
        port = (0, 65535)
        if len(w) > 6 and w[6].upper() == "PORT" and w[7].upper() != "ANY" and pr != (1, 1):
            a, _, b = w[7].partition("-")
            port = (int(a), int(b or a))
        rules.append({"id": "R%d" % (len(rules) + 1), "action": action,
                      "cond": [pr, ip_range(w[3]), ip_range(w[5]), port]})
    return fields, rules, default


def parse_ng(text):
    text = re.sub(r"#.*", "", text)
    fields, rules, default = [], [], None
    for stmt in [s.strip() for s in text.split(";") if s.strip()]:
        m = re.match(r"field\s+(\w+)\s*:\s*(\d+)\s*\.\.\s*(\d+)$", stmt)
        if m:
            fields.append((m.group(1), int(m.group(2)), int(m.group(3))))
            continue
        m = re.match(r"default\s+(\w+)$", stmt)
        if m:
            default = m.group(1)
            continue
        m = re.match(r"rule\s+(\w+)\s*:\s*(\w+)\s+when\s+(.*)$", stmt, re.S)
        if m:
            cond = [(lo, hi) for _, lo, hi in fields]
            for c in re.split(r"\s+and\s+", m.group(3).strip()):
                r = re.match(r"(\w+)\s+in\s+(\d+)\s*\.\.\s*(\d+)$", c) or re.match(r"(\w+)\s*==\s*(\d+)()$", c)
                k = [f[0] for f in fields].index(r.group(1))
                lo, hi = int(r.group(2)), int(r.group(3) or r.group(2))
                cond[k] = (max(cond[k][0], lo), min(cond[k][1], hi))
            rules.append({"id": m.group(1), "action": m.group(2), "cond": cond})
    return fields, rules, default


# ---------------------------------------------------------------- oracle
def first_match(rules, default, pkt):
    for r in rules:
        if all(lo <= v <= hi for v, (lo, hi) in zip(pkt, r["cond"])):
            return r["action"], r["id"]
    return default, "DEFAULT"


def random_packets(fields, rules, n, seed):
    rnd = random.Random(seed)
    pkts = []
    for _ in range(n):
        pkt = []
        for k, (_, dlo, dhi) in enumerate(fields):
            if not rules or rnd.random() < 0.25:
                v = rnd.randint(dlo, dhi)
            else:
                lo, hi = rnd.choice(rules)["cond"][k]
                v = rnd.choice((lo, hi)) + rnd.choice((-1, 0, 1))
            pkt.append(min(max(v, dlo), dhi))
        pkts.append(pkt)
    return pkts


def fmt(fields, pkt):
    out = []
    for (name, _, _), v in zip(fields, pkt):
        out.append("%s=%s" % (name, ipaddress.ip_address(v) if name.endswith("ip") else v))
    return " ".join(out)


VALID = ["firewall_basic.fw", "firewall_anomalies.fw", "tax.ng",
         "classbench_fw1_100.ng", "classbench_acl1_200.ng", "classbench_ipc1_200.ng"]


@pytest.mark.parametrize("name", VALID)
def test_classify_batch_matches_python_oracle(name):
    path = os.path.join(EXAMPLES, name)
    with open(path, encoding="utf-8") as f:
        text = f.read()
    fields, rules, default = parse_ng(text) if name.endswith(".ng") else parse_fw(text)
    pkts = random_packets(fields, rules, N_PACKETS, seed=sum(name.encode()))
    lines = [fmt(fields, p) for p in pkts]
    proc = subprocess.run([binary_path(), "classify-batch", path], input="\n".join(lines) + "\n",
                          capture_output=True, text=True, timeout=60)
    assert proc.returncode == 0, proc.stderr
    results = [json.loads(l) for l in proc.stdout.splitlines()]
    assert len(results) == N_PACKETS
    mismatches = []
    for pkt, line, res in zip(pkts, lines, results):
        assert res["ok"], res
        want_action, want_rule = first_match(rules, default, pkt)
        if (res["decision"], res["decided_by"]) != (want_action, want_rule) or not res["oracle_agrees"]:
            mismatches.append((line, res["decision"], res["decided_by"], want_action, want_rule))
    assert not mismatches, mismatches[:5]


def test_boundaries_are_exercised():
    """The generator really hits rule edges (otherwise the test is weak)."""
    with open(os.path.join(EXAMPLES, "firewall_anomalies.fw"), encoding="utf-8") as f:
        fields, rules, default = parse_fw(f.read())
    pkts = random_packets(fields, rules, N_PACKETS, seed=1)
    ports = {p[3] for p in pkts}
    for edge in (21, 22, 23, 79, 80, 89, 90, 100, 101, 8079, 8080, 8081):
        assert edge in ports


def test_optimized_policy_matches_oracle_of_original():
    """The optimized source emitted by the C compiler decides like the original."""
    path = os.path.join(EXAMPLES, "firewall_anomalies.fw")
    out = subprocess.run([binary_path(), "compile", path, "--json"], capture_output=True, text=True, timeout=60)
    optimized = json.loads(out.stdout)["optimization"]["optimized_source"]
    with open(path, encoding="utf-8") as f:
        fields, rules, default = parse_fw(f.read())
    _, opt_rules, opt_default = parse_fw(optimized)
    assert len(opt_rules) == 5
    for pkt in random_packets(fields, rules, N_PACKETS, seed=7):
        assert first_match(rules, default, pkt)[0] == first_match(opt_rules, opt_default, pkt)[0]


def test_errors_example_is_rejected():
    proc = subprocess.run([binary_path(), "classify-batch", os.path.join(EXAMPLES, "errors.fw")],
                          input="proto=TCP src_ip=1.1.1.1 dst_ip=2.2.2.2 dst_port=80\n",
                          capture_output=True, text=True, timeout=60)
    assert proc.returncode == 1
    doc = json.loads(proc.stdout)
    assert doc["ok"] is False
    assert len({d["line"] for d in doc["diagnostics"] if d["level"] == "error"}) >= 6
