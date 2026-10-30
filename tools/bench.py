#!/usr/bin/env python3
"""Benchmark NetGuard on ClassBench filter sets and write outputs/bench.md.

For each series (fw1, acl1, ipc1) and size (25, 50, 100, 200, 400, 800 rules)
it imports the first N rules with tools/import_classbench.py, runs
`bin/netguard compile --json`, and records the numbers the compiler reports
(stats.phase_ms, automaton sizes, analysis counts).  A series stops at the
first size that fails to compile or takes longer than --timeout seconds.

With --before OLD_BINARY it also runs an older build (e.g. the Review-2
binary, which recompiled the policy once per rule in analysis/optimization)
on the same files and reports both totals, so the speed-up is measured,
not estimated.

usage: python3 tools/bench.py [--sizes 25,50,...] [--before PATH] [--timeout 120]
"""
import argparse
import json
import os
import subprocess
import sys
import tempfile
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RULES = os.path.join(ROOT, "datasets", "classbench", "rules", "1k_1")
SERIES = ["fw1", "acl1", "ipc1"]
PHASES = ["lex", "parse", "partition", "nfa", "dfa", "minimize", "analysis", "optimize", "equivalence", "dot", "total"]


def binary():
    for name in ("netguard.exe", "netguard"):
        p = os.path.join(ROOT, "bin", name)
        if os.path.isfile(p):
            return p
    sys.exit("bin/netguard not found: run make first")


def run(binary_path, path, timeout):
    """Returns (doc or None, wall seconds, error message)."""
    t0 = time.perf_counter()
    try:
        p = subprocess.run([binary_path, "compile", path, "--json"], capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return None, time.perf_counter() - t0, "timeout > %d s" % timeout
    wall = time.perf_counter() - t0
    try:
        doc = json.loads(p.stdout)
    except ValueError:
        return None, wall, "no JSON (exit %d)" % p.returncode
    if not doc.get("ok"):
        msgs = []
        for d in doc.get("diagnostics", []):
            if d["level"] == "error" and d["message"] not in msgs:
                msgs.append(d["message"])
        msg = "; ".join(msgs)[:200]
        return None, wall, msg or "compile failed"
    return doc, wall, ""


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--sizes", default="25,50,100,200,400,800")
    ap.add_argument("--before", help="older netguard binary to compare against")
    ap.add_argument("--timeout", type=int, default=120)
    ap.add_argument("--out", default=os.path.join(ROOT, "outputs", "bench.md"))
    a = ap.parse_args()
    if a.before:
        a.before = os.path.abspath(a.before)
    if not os.path.isdir(RULES):
        sys.exit("ClassBench rules not found in %s -- see datasets/classbench/README.md" % RULES)
    sizes = [int(x) for x in a.sizes.split(",")]
    exe = binary()
    rows, before_rows = [], []
    with tempfile.TemporaryDirectory() as tmp:
        for s in SERIES:
            src = os.path.join(RULES, "%s_seed_1.rules" % s)
            before_alive = bool(a.before)
            for n in sizes:
                path = os.path.join(tmp, "%s_%d.ng" % (s, n))
                with open(path, "w") as f:
                    subprocess.run([sys.executable, os.path.join(ROOT, "tools", "import_classbench.py"), src, str(n)],
                                   stdout=f, check=True)
                doc, wall, err = run(exe, path, a.timeout)
                print("%-5s %5d  %s" % (s, n, err or "%.0f ms" % doc["stats"]["phase_ms"]["total"]), flush=True)
                if before_alive:
                    bdoc, bwall, berr = run(a.before, path, a.timeout)
                    before_rows.append((s, n, bdoc, bwall, berr, doc))
                    print("      before: %s" % (berr or "%.0f ms" % bdoc["stats"]["phase_ms"]["total"]), flush=True)
                    if berr:
                        before_alive = False
                rows.append((s, n, doc, wall, err))
                if err or wall > a.timeout:
                    break

    out = []
    out.append("# NetGuard on ClassBench filter sets\n")
    out.append("Measured on %s with `bin/netguard compile --json`; every number below is read from the compiler's "
               "own JSON (`stats.phase_ms` is `clock()` CPU time per phase; *wall* is the measured process time). "
               "Policies are the first N rules of `datasets/classbench/rules/1k_1/<series>_seed_1.rules` "
               "imported by `tools/import_classbench.py` (actions assigned with seed 7, P(DENY)=0.3, default DENY: "
               "ClassBench has no actions).\n" % time.strftime("%Y-%m-%d"))
    out.append("| series | rules | cells | symbols | NFA | DFA | Min DFA | shadowed | redundant | optimized rules | "
               + " | ".join("%s ms" % p for p in PHASES) + " | wall s |")
    out.append("|" + "---|" * (10 + len(PHASES) + 1))
    for s, n, doc, wall, err in rows:
        if err:
            out.append("| %s | %d | %s |" % (s, n, "**failed:** " + err.replace("|", "/")) + " |" * (8 + len(PHASES)) + " %.2f |" % wall)
            continue
        c = doc["analysis"]["counts"]
        ms = doc["stats"]["phase_ms"]
        out.append("| %s | %d | %d | %d | %d | %d | %d | %d | %d | %d | %s | %.2f |" % (
            s, n, doc["partition"]["cells"], doc["partition"]["alphabet"], doc["nfa"]["states"], doc["dfa"]["states"],
            doc["min_dfa_modes"]["action"]["states"], c["shadowed"], c["redundant"],
            doc["optimization"]["optimized_rules"], " | ".join("%.1f" % ms[p] for p in PHASES), wall))
    if before_rows:
        out.append("\n## Speed-up of the scan-based analysis/optimizer (P1-a)\n")
        out.append("*Before* = `%s` (one full recompile + equivalence check per rule in analysis and in the optimizer; "
                   "its limits were 256 rules / 20,000 NFA / 50,000 DFA states). *After* = current build "
                   "(exact scan of the unminimized DFA, one equivalence proof at the end). Same input files.\n"
                   % os.path.relpath(a.before, ROOT) if a.before.startswith(ROOT) else
                   "*Before* = an older binary (one recompile + equivalence check per rule). *After* = current build.\n")
        out.append("| series | rules | before analysis+optimize ms | after analysis+optimize ms | before total ms | after total ms | speed-up (total) | same result |")
        out.append("|---|---|---|---|---|---|---|---|")
        for s, n, bdoc, bwall, berr, doc in before_rows:
            if berr or doc is None:
                out.append("| %s | %d | %s | | | | | |" % (s, n, ("before failed: " + berr) if berr else "after failed"))
                continue
            bm, am = bdoc["stats"]["phase_ms"], doc["stats"]["phase_ms"]
            same = (bdoc["optimization"]["kept"] == doc["optimization"]["kept"] and
                    [r["status"] for r in bdoc["analysis"]["rules"]] == [r["status"] for r in doc["analysis"]["rules"]])
            out.append("| %s | %d | %.1f | %.1f | %.1f | %.1f | %.1fx | %s |" % (
                s, n, bm["analysis"] + bm["optimize"], am["analysis"] + am["optimize"], bm["total"], am["total"],
                bm["total"] / am["total"] if am["total"] > 0 else float("inf"), "yes" if same else "NO"))
    os.makedirs(os.path.dirname(a.out), exist_ok=True)
    with open(a.out, "w") as f:
        f.write("\n".join(out) + "\n")
    print("wrote", a.out)


if __name__ == "__main__":
    main()
