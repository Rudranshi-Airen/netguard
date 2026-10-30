"""AI-assisted rule merging, verified by NetGuard's equivalence checker.

The AI (Google Gemini) only PROPOSES a rewritten policy.  NetGuard's C binary
(`netguard equiv ORIGINAL SUGGESTED --json`, a product-automaton equivalence
proof) decides whether the proposal is correct.  A rejected proposal comes
back with a concrete counterexample packet, which is fed to the model in a
follow-up prompt (counterexample-guided retry, at most MAX_ATTEMPTS).

A proposal is ACCEPTED only if it is proven equivalent to the ORIGINAL policy
AND it has fewer rules than NetGuard's own optimizer result.

No compiler or analysis logic lives here: this module builds prompts, calls the
HTTP API with the standard library, and runs the binary.

Environment:
    GEMINI_API_KEY   API key (never logged, never returned to the client)
    GEMINI_MODEL     model name, default gemini-3.5-flash (gemini-2.5-flash is no
                     longer available to new API keys: the API answers 404)
    GEMINI_TIMEOUT   seconds per API call, default 60 (one retry on 429/5xx/timeout)
    GEMINI_BUDGET    seconds for a whole AI-merge run, default 150
Without a key, or when the call fails, cached responses from
examples/ai_cache/<example>.json are used and labelled DEMO.
"""

import json
import os
import re
import subprocess
import tempfile
import time
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
CACHE_DIR = os.path.join(ROOT, "examples", "ai_cache")
EXAMPLES = os.path.join(ROOT, "examples")
MAX_ATTEMPTS = 3
TIMEOUT_S = float(os.environ.get("GEMINI_TIMEOUT", "60"))
BUDGET_S = float(os.environ.get("GEMINI_BUDGET", "150"))
DEFAULT_MODEL = "gemini-3.5-flash"
RETRY_CODES = (429, 500, 502, 503, 504)
API_URL = "https://generativelanguage.googleapis.com/v1beta/models/%s:generateContent"

GRAMMAR = {
    "fw": """policy       := { stmt NEWLINE }
stmt         := rule | default_decl | (empty line)
default_decl := 'DEFAULT' action            (at most once; DENY if absent)
rule         := action proto 'FROM' addr 'TO' addr [ 'PORT' portspec ]
action       := 'ALLOW' | 'DENY'
proto        := 'TCP' | 'UDP' | 'ICMP' | 'ANY' | INT    (TCP=6, UDP=17, ICMP=1, ANY=0..255)
addr         := 'ANY' | IPV4 | IPV4 '/' INT (CIDR) | IPV4 '-' IPV4
portspec     := 'ANY' | INT | INT '-' INT                (0..65535; omitted = ANY)
Comments start with '#'. One rule per line. Fields: proto, src_ip, dst_ip, dst_port.""",
    "ng": """program    := 'ruleset' IDENT ';' { field_decl } default_decl { rule_decl }
field_decl := 'field' IDENT ':' INT '..' INT ';'
default_decl := 'default' IDENT ';'
rule_decl  := 'rule' IDENT ':' IDENT 'when' cond { 'and' cond } ';'
cond       := IDENT 'in' INT '..' INT  |  IDENT '==' INT
Comments start with '#'. Keep the ruleset line, the field declarations (same
names, order and domains) and the default exactly as they are. A field a rule
does not mention matches its whole domain. Every rule needs at least one cond.""",
}

PROMPT = """You are optimizing a firewall policy written in this exact language:

{grammar}

First match wins: the first rule (top to bottom) whose conditions all hold decides the packet; if no rule matches, the default decides.
Merge rules with the same action whose ranges are adjacent or overlapping, and remove rules that are unnecessary, so that the policy has fewer rules but makes EXACTLY the same decision for every packet.
Output ONLY the complete new policy in the same syntax, no explanation, no markdown fences.

Policy:
{policy}
"""

RETRY = """Your previous policy is NOT equivalent to the original, so it was rejected by a formal equivalence checker.
{problem}
Fix it. The corrected policy must make EXACTLY the same decision as the original for every packet, and should still have fewer rules.
Output ONLY the complete corrected policy in the same syntax, no explanation, no markdown fences.

Original policy (the reference):
{original}

Your previous (rejected) policy:
{previous}
"""


class AIError(Exception):
    pass


def strip_fences(text):
    """Remove ``` fences and surrounding blank lines from a model reply."""
    text = text.strip()
    text = re.sub(r"^```[a-zA-Z0-9_-]*\s*\n", "", text)
    text = re.sub(r"\n?```\s*$", "", text)
    return text.replace("```", "").strip() + "\n"


def _api_message(err):
    """Google's error message from an HTTPError body (never contains the key)."""
    try:
        return json.loads(err.read().decode("utf-8")).get("error", {}).get("message", "")[:200]
    except (ValueError, OSError, AttributeError):
        return ""


def call_gemini(prompt, api_key, model, timeout=None):
    """One generateContent call using only urllib (one retry on 429/5xx/timeout)."""
    timeout = timeout or TIMEOUT_S
    body = json.dumps({"contents": [{"parts": [{"text": prompt}]}],
                       "generationConfig": {"temperature": 0.2}}).encode("utf-8")
    last = None
    for attempt in range(2):
        req = urllib.request.Request(API_URL % model, data=body, method="POST",
                                     headers={"Content-Type": "application/json", "x-goog-api-key": api_key})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                doc = json.loads(resp.read().decode("utf-8"))
            break
        except urllib.error.HTTPError as e:
            msg = _api_message(e).replace(api_key, "<key>")
            last = AIError("Gemini API returned HTTP %d%s" % (e.code, (": " + msg) if msg else ""))
            if e.code not in RETRY_CODES:
                raise last
        except (urllib.error.URLError, TimeoutError, OSError) as e:
            last = AIError("Gemini API not reachable or timed out after %.0f s (%s)" % (timeout, type(e).__name__))
        except ValueError:
            raise AIError("Gemini API returned invalid JSON")
        if attempt == 0:
            time.sleep(2)
    else:
        raise last
    try:
        parts = doc["candidates"][0]["content"]["parts"]
        return "".join(p.get("text", "") for p in parts if not p.get("thought"))
    except (KeyError, IndexError, TypeError):
        raise AIError("Gemini reply had no text candidate")


def run_binary(binary, args, timeout=60):
    p = subprocess.run([binary] + args, capture_output=True, text=True, timeout=timeout)
    try:
        return json.loads(p.stdout)
    except ValueError:
        raise AIError("netguard %s failed (exit %d): %s" % (args[0], p.returncode, p.stderr.strip()[:300]))


def write_temp(text, syntax):
    fd, path = tempfile.mkstemp(suffix="." + syntax, prefix="netguard_ai_")
    with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as f:
        f.write(text)
    return path


def check_suggestion(binary, original_path, text, syntax):
    """Prove `text` equivalent to the ORIGINAL policy (or get a counterexample)."""
    path = write_temp(text, syntax)
    try:
        doc = run_binary(binary, ["equiv", original_path, path, "--syntax", syntax, "--json"])
    finally:
        os.unlink(path)
    return {
        "text": text,
        "parsed": bool(doc.get("parsed_suggested")),
        "equivalent": doc.get("equivalent") is True,
        "counterexample": doc.get("counterexample"),
        "action_original": doc.get("action_original"),
        "action_suggested": doc.get("action_suggested"),
        "diagnostics": doc.get("diagnostics", []),
        "error": doc.get("error"),
        "rules": doc.get("rules_suggested", -1),
        "product_pairs_explored": doc.get("product_pairs_explored", 0),
    }


def feedback(attempt):
    """Describe why an attempt was rejected, for the retry prompt."""
    if not attempt["parsed"]:
        lines = ["Line %d, column %d: %s (hint: %s)" % (d["line"], d["col"], d["message"], d["hint"])
                 for d in attempt["diagnostics"] if d["level"] == "error"]
        return "It does not parse. Compiler diagnostics:\n" + "\n".join(lines[:20])
    if attempt.get("error") and not attempt.get("counterexample"):
        return "It could not be compared: %s" % attempt["error"]
    cx = attempt["counterexample"]
    return ("Counterexample packet: %s\nThe ORIGINAL policy decides %s (rule %s); your policy decides %s (rule %s)."
            % (cx["text"], attempt["action_original"], cx["decided_by_original"],
               attempt["action_suggested"], cx["decided_by_suggested"]))


def find_example_name(source):
    """The example file whose content equals `source` (for the demo cache)."""
    norm = source.replace("\r\n", "\n").strip()
    for name in sorted(os.listdir(EXAMPLES)):
        path = os.path.join(EXAMPLES, name)
        if os.path.isfile(path) and name.endswith((".fw", ".ng")):
            with open(path, encoding="utf-8") as f:
                if f.read().replace("\r\n", "\n").strip() == norm:
                    return name
    return None


def load_cache(name):
    if not name:
        return None
    path = os.path.join(CACHE_DIR, name + ".json")
    if not os.path.isfile(path):
        return None
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def ai_merge(binary, source, syntax, example=None, api_key=None, model=None, call=call_gemini, prefer_cache=False):
    """Run the propose -> prove -> retry loop.  Returns the JSON-able result.

    prefer_cache: replay the recorded response for this example (if there is
    one) instead of calling the API; NetGuard still re-proves every attempt."""
    api_key = api_key if api_key is not None else os.environ.get("GEMINI_API_KEY", "")
    model = model or os.environ.get("GEMINI_MODEL", DEFAULT_MODEL)
    started = time.monotonic()
    original_path = write_temp(source, syntax)
    try:
        compiled = run_binary(binary, ["compile", original_path, "--syntax", syntax, "--json"])
        if not compiled.get("ok"):
            return {"ok": False, "error": "The original policy does not compile; fix its errors first.",
                    "diagnostics": compiled.get("diagnostics", [])}
        opt = compiled["optimization"]
        base = {"ok": True, "rules_before": opt["original_rules"], "rules_after_optimizer": opt["optimized_rules"],
                "optimizer_text": opt["optimized_source"], "model": model}

        mode, fallback = "live", None
        name = example or find_example_name(source)
        if prefer_cache and load_cache(name) is not None:
            mode, fallback = "demo", "replay of the recorded response was requested"
        elif not api_key:
            mode, fallback = "demo", "GEMINI_API_KEY is not set"
        attempts = []
        if mode == "live":
            prompt = PROMPT.format(grammar=GRAMMAR[syntax], policy=opt["optimized_source"])
            try:
                for _ in range(MAX_ATTEMPTS):
                    if attempts and time.monotonic() - started > BUDGET_S:
                        base["warning"] = "stopped after attempt %d: time budget of %.0f s used up" % (len(attempts), BUDGET_S)
                        break
                    text = strip_fences(call(prompt, api_key, model))
                    att = check_suggestion(binary, original_path, text, syntax)
                    attempts.append(att)
                    if att["parsed"] and att["equivalent"]:
                        break
                    prompt = RETRY.format(problem=feedback(att), original=source, previous=text)
            except AIError as e:
                if not attempts:
                    mode, fallback = "demo", str(e)
                else:
                    base["warning"] = "stopped after attempt %d: %s" % (len(attempts), e)
        cache_info = None
        if mode == "demo":
            cache = load_cache(name)
            if cache is None:
                return dict(base, ok=False, mode="demo", fallback_reason=fallback,
                            error="No live Gemini call was possible (%s) and there is no cached AI response for this "
                                  "policy. Set GEMINI_API_KEY, or load one of the examples that has a cache in "
                                  "examples/ai_cache/." % fallback)
            cache_info = {"example": name, "provenance": cache.get("provenance", ""), "note": cache.get("note", ""),
                          "real": cache.get("provenance", "").startswith("REAL")}
            for text in cache["attempts"][:MAX_ATTEMPTS]:
                att = check_suggestion(binary, original_path, strip_fences(text), syntax)
                attempts.append(att)
                if att["parsed"] and att["equivalent"]:
                    break
    finally:
        os.unlink(original_path)

    final = attempts[-1] if attempts else None
    proven = bool(final and final["parsed"] and final["equivalent"])
    fewer = bool(proven and final["rules"] < base["rules_after_optimizer"])
    accepted = proven and fewer
    if accepted:
        verdict = "accepted: proven equivalent to the original and %d < %d rules" % (final["rules"], base["rules_after_optimizer"])
    elif proven:
        verdict = ("rejected: proven equivalent, but %d rules is not fewer than the optimizer's %d; the optimizer's policy is kept"
                   % (final["rules"], base["rules_after_optimizer"]))
    else:
        verdict = "rejected: no attempt was proven equivalent; the optimizer's policy is kept"
    for i, a in enumerate(attempts):
        a["attempt"] = i + 1
    return dict(base, mode=mode, fallback_reason=fallback, cache=cache_info, attempts=attempts,
                accepted=accepted, proven_equivalent=proven, verdict=verdict,
                final_text=final["text"] if accepted else base["optimizer_text"],
                ai_text=final["text"] if final else None,
                rules_after_ai=final["rules"] if proven else None)
