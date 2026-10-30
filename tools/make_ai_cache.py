#!/usr/bin/env python3
"""Record REAL Gemini replies as a demo cache: examples/ai_cache/<example>.json.

Runs the same propose -> prove -> retry loop as the web app (web/ai.py) with a
live API call and stores the text of every attempt, so the demo can replay it
offline.  Requires GEMINI_API_KEY (and optionally GEMINI_MODEL).

usage: GEMINI_API_KEY=... python3 tools/make_ai_cache.py firewall_anomalies.fw [tax.ng ...]

If the model's first reply is already correct there is no rejected attempt to
show; the cache then records that honestly (the hand-written caches exist to
demonstrate a rejection offline).
"""
import json
import os
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "web"))
import ai  # noqa: E402


def main():
    if not os.environ.get("GEMINI_API_KEY"):
        sys.exit("GEMINI_API_KEY is not set")
    binary = os.path.join(ROOT, "bin", "netguard.exe" if os.name == "nt" else "netguard")
    for name in sys.argv[1:]:
        with open(os.path.join(ROOT, "examples", name), encoding="utf-8") as f:
            source = f.read()
        r = ai.ai_merge(binary, source, name.rsplit(".", 1)[1])
        if not r.get("ok") or r["mode"] != "live":
            print("%s: live call failed (%s); cache not written" % (name, r.get("fallback_reason") or r.get("error")))
            continue
        cache = {
            "example": name,
            "provenance": "REAL Gemini reply: model %s, recorded %s by tools/make_ai_cache.py" % (r["model"], time.strftime("%Y-%m-%d")),
            "note": "; ".join("attempt %d: %s" % (a["attempt"], "equivalent" if a["equivalent"] else
                                                   ("does not parse" if not a["parsed"] else "NOT equivalent"))
                              for a in r["attempts"]),
            "attempts": [a["text"] for a in r["attempts"]],
        }
        if r.get("warning"):
            cache["note"] += "; " + r["warning"]
        with open(os.path.join(ROOT, "examples", "ai_cache", name + ".json"), "w", encoding="utf-8") as f:
            json.dump(cache, f, indent=2)
        print("%s: %s -> %s" % (name, cache["note"], r["verdict"]), flush=True)


if __name__ == "__main__":
    main()
