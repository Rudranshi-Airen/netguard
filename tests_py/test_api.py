"""Flask API tests (each endpoint, plus the error paths)."""

import os

import pytest

from conftest import EXAMPLES

import app as webapp

TOP_KEYS = {"ok", "diagnostics", "tokens", "policy", "partition", "nfa", "dfa", "min_dfa", "analysis",
            "optimization", "equivalence", "stats"}


def example(name):
    with open(os.path.join(EXAMPLES, name), encoding="utf-8") as f:
        return f.read()


@pytest.fixture
def client():
    webapp.app.config["TESTING"] = True
    with webapp.app.test_client() as c:
        yield c


def test_index_and_status(client):
    assert client.get("/").status_code == 200
    r = client.get("/api/status").get_json()
    assert r["ok"] is True


def test_examples(client):
    r = client.get("/api/examples").get_json()
    names = {e["name"] for e in r["examples"]}
    assert {"firewall_basic.fw", "firewall_anomalies.fw", "errors.fw", "tax.ng"} <= names
    assert all(e["syntax"] in ("fw", "ng") for e in r["examples"])


def test_compile_anomalies(client):
    resp = client.post("/api/compile", json={"source": example("firewall_anomalies.fw"), "syntax": "fw"})
    assert resp.status_code == 200
    r = resp.get_json()
    assert TOP_KEYS <= set(r)
    assert r["ok"] is True
    status = {x["id"]: x for x in r["analysis"]["rules"]}
    assert status["R2"]["status"] == "shadowed" and status["R2"]["severity"] == "high"
    assert status["R2"]["shadow_kind"] == "single" and status["R2"]["covered_by"] == ["R1"]
    assert status["R7"]["status"] == "shadowed" and status["R7"]["shadow_kind"] == "union"
    assert status["R7"]["covered_by"] == ["R5", "R6"]
    assert status["R8"]["status"] == "redundant" and status["R9"]["status"] == "redundant"
    for rid in ("R1", "R3", "R4", "R5", "R6", "R10"):
        assert status[rid]["status"] == "ok"
    assert [x["id"] for x in r["optimization"]["removed"]] == ["R2", "R7", "R9", "R8", "R1"]
    assert r["optimization"]["kept"] == ["R3", "R4", "R5", "R6", "R10"]
    assert r["equivalence"]["equivalent"] is True and r["equivalence"]["counterexample"] is None
    for stage in ("nfa", "dfa", "min_dfa"):
        assert "too_large" in r[stage]
    assert r["partition"]["cells"] > 0


def test_compile_tax_ng(client):
    r = client.post("/api/compile", json={"source": example("tax.ng"), "syntax": "ng"}).get_json()
    status = {x["id"]: x for x in r["analysis"]["rules"]}
    assert status["t5"]["status"] == "shadowed"
    assert status["t5"]["contained_by"] == "t3"
    assert status["t5"]["covered_by"] == ["t2", "t3"]
    assert status["t5"]["conflicting"] is True
    assert status["t2"]["status"] == "partial" and status["t2"]["beaten_by"] == ["t1"]


def test_compile_errors(client):
    resp = client.post("/api/compile", json={"source": example("errors.fw"), "syntax": "fw"})
    assert resp.status_code == 200
    r = resp.get_json()
    assert r["ok"] is False
    errs = [d for d in r["diagnostics"] if d["level"] == "error"]
    assert len({d["line"] for d in errs}) >= 6
    assert all(d["hint"] for d in errs)
    assert r["analysis"] is None


def test_compile_min_by_rule(client):
    r = client.post("/api/compile", json={"source": example("tax.ng"), "syntax": "ng", "min_by": "rule"}).get_json()
    assert r["min_dfa"]["mode"] == "rule"
    assert r["min_dfa"]["states"] == r["min_dfa_modes"]["rule"]["states"]


@pytest.mark.parametrize("body", [None, {"syntax": "fw"}, {"source": 5}, {"source": "x", "syntax": "c"}])
def test_compile_bad_requests(client, body):
    resp = client.post("/api/compile", json=body) if body is not None else client.post("/api/compile", data="nope")
    assert resp.status_code == 400
    assert resp.get_json()["ok"] is False


def test_classify(client):
    r = client.post("/api/classify", json={"source": example("firewall_anomalies.fw"), "syntax": "fw",
                                           "packet": "proto=TCP src_ip=10.1.2.3 dst_ip=8.8.8.8 dst_port=443"}).get_json()
    assert r["ok"] is True
    assert r["decision"] == "ALLOW" and r["decided_by"] == "R3"
    assert r["oracle_agrees"] is True
    assert [f["rule"] for f in r["failures"]] == ["R1", "R2"]
    assert len(r["trace"]) == 4


def test_classify_bad_packet(client):
    resp = client.post("/api/classify", json={"source": example("firewall_basic.fw"), "syntax": "fw",
                                              "packet": "proto=TCP src_ip=999.1.1.1 dst_ip=1.1.1.1 dst_port=1"})
    assert resp.status_code == 400
    assert resp.get_json()["ok"] is False
    resp = client.post("/api/classify", json={"source": example("firewall_basic.fw"), "syntax": "fw"})
    assert resp.status_code == 400


def test_verify(client):
    r = client.post("/api/verify", json={"source": example("firewall_anomalies.fw"), "syntax": "fw", "n": 3000}).get_json()
    assert r["ok"] is True and r["n"] == 3000
    assert r["all_agree"] is True
    assert r["min_dfa_vs_oracle"]["agree"] == 3000


def test_verify_bad_n(client):
    resp = client.post("/api/verify", json={"source": "DEFAULT DENY", "syntax": "fw", "n": 0})
    assert resp.status_code == 400


def test_missing_binary(client, monkeypatch):
    monkeypatch.setattr(webapp, "find_binary", lambda: None)
    resp = client.post("/api/compile", json={"source": "DEFAULT DENY", "syntax": "fw"})
    assert resp.status_code == 503
    assert "make" in resp.get_json()["error"]
