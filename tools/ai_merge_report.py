#!/usr/bin/env python3
"""Run the AI-merge loop (web/ai.py) on examples and write outputs/ai_merge.md.

Uses a live Gemini call when GEMINI_API_KEY is set, otherwise the cached
responses in examples/ai_cache/ (labelled DEMO in the report).  Every count in
the report comes from `bin/netguard compile --json` and `bin/netguard equiv`.

usage: python3 tools/ai_merge_report.py [EXAMPLE ...]
       (default: every example that has a cache, plus uci_induced.ng if present)
"""
import os
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "web"))
import ai  # noqa: E402


def main():
    names = sys.argv[1:]
    if not names:
        names = sorted(f[:-5] for f in os.listdir(ai.CACHE_DIR) if f.endswith(".json"))
        if os.path.isfile(os.path.join(ROOT, "examples", "uci_induced.ng")) and "uci_induced.ng" not in names:
            names.append("uci_induced.ng")
    binary = os.path.join(ROOT, "bin", "netguard.exe" if os.name == "nt" else "netguard")
    out = ["# AI-assisted rule merging (Gemini proposes, NetGuard proves)\n",
           "Generated %s by `tools/ai_merge_report.py`. A proposal is accepted only if `netguard equiv` proves it "
           "equivalent to the ORIGINAL policy (product automaton over the partition of both policies) **and** it has "
           "fewer rules than NetGuard's optimizer. Rejected attempts get a counterexample packet back (max 3 attempts). "
           "*Recorded real Gemini reply* = a real gemini-3.5-flash response saved by tools/make_ai_cache.py and re-proven "
           "by NetGuard when this report was generated.\n"
           % time.strftime("%Y-%m-%d"),
           "| example | mode | original rules | optimizer rules | AI rules (proven) | attempts | accepted | verdict |",
           "|---|---|---|---|---|---|---|---|"]
    details = []
    for name in names:
        with open(os.path.join(ROOT, "examples", name), encoding="utf-8") as f:
            source = f.read()
        r = ai.ai_merge(binary, source, name.rsplit(".", 1)[1], example=name)
        if not r.get("ok"):
            out.append("| %s | %s | | | | | | %s |" % (name, r.get("mode", ""), r.get("error", "")[:120]))
            continue
        if r["mode"] == "live":
            mode = "LIVE %s" % r["model"]
        elif r["cache"] and r["cache"]["real"]:
            mode = "recorded real Gemini reply"
        else:
            mode = "HAND-WRITTEN demo"
        out.append("| %s | %s | %d | %d | %s | %s | %s | %s |" % (
            name, mode, r["rules_before"], r["rules_after_optimizer"],
            r["rules_after_ai"] if r["rules_after_ai"] is not None else "—",
            " → ".join("✅" if a["equivalent"] else "❌" for a in r["attempts"]),
            "yes" if r["accepted"] else "no", r["verdict"]))
        details.append("\n## %s (%s)\n" % (name, mode))
        if r.get("cache"):
            details.append("*Cache provenance:* %s\n" % r["cache"]["provenance"])
            if r["cache"].get("note"):
                details.append("*Note:* %s\n" % r["cache"]["note"])
        for a in r["attempts"]:
            if a["equivalent"]:
                details.append("- attempt %d: **EQUIVALENT** (%d rules, %d product state pairs explored)"
                               % (a["attempt"], a["rules"], a["product_pairs_explored"]))
            elif not a["parsed"]:
                details.append("- attempt %d: **does not parse**: %s" % (a["attempt"], "; ".join(
                    "%d:%d %s" % (d["line"], d["col"], d["message"]) for d in a["diagnostics"] if d["level"] == "error")))
            else:
                cx = a["counterexample"] or {}
                details.append("- attempt %d: **NOT EQUIVALENT**: counterexample `%s` -- original %s (%s), AI policy %s (%s)"
                               % (a["attempt"], cx.get("text"), a["action_original"], cx.get("decided_by_original"),
                                  a["action_suggested"], cx.get("decided_by_suggested")))
    os.makedirs(os.path.join(ROOT, "outputs"), exist_ok=True)
    path = os.path.join(ROOT, "outputs", "ai_merge.md")
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(out + details) + "\n")
    print("wrote", os.path.relpath(path, ROOT))


if __name__ == "__main__":
    main()
