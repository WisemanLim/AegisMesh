"""오케스트레이터 (FR-P04·P15, PRD §8.2·§8.6) — 관문 하나에 바인딩된 에이전트를 병렬 호출하고 합성한다.

- 관문 하드 타임아웃 = 관문 p95 예산 × AEGIS_TIMEOUT_FACTOR. 시간 안에 못 끝낸 에이전트는 failMode 로 강등.
- 한 에이전트의 장애·지연이 다른 에이전트 판정에 영향을 주지 않는다(NFR-A2).
- transform 이 여럿이면 에이전트 ID 순서로 차례로 적용한다(결정적, NFR-Q4).
"""
from __future__ import annotations

import os
import time
from concurrent.futures import ThreadPoolExecutor, wait

from aegis.agent import Agent
from aegis.schemas import Finding, JudgeRequest

GATE_BUDGET_MS = {"input": 80, "tool": 20, "output": 150}        # NFR-L1·L2·L3 (p95)
TRANSFORM_FIELD = {"input": "text", "output": "output"}
_POOL = ThreadPoolExecutor(max_workers=int(os.environ.get("AEGIS_JUDGE_WORKERS", "32")), thread_name_prefix="judge")


def timeout_s(gate: str) -> float | None:
    budget = GATE_BUDGET_MS.get(gate)
    if budget is None:
        return None                                   # 상시·증적 계열은 경로 밖 — 시간 제한 없음
    return budget * float(os.environ.get("AEGIS_TIMEOUT_FACTOR", "4")) / 1000


def agent_request(a: Agent, req: JudgeRequest, params: dict[str, dict] | None, strict: bool = True) -> JudgeRequest:
    """에이전트 하나에 넘길 요청 — 정책 agentParams 가 요청 params 보다 우선한다.
    strict(실제 관문 경로)면 매니페스트가 선언한 설정 키의 호출자 값은 버린다: 호출자가 허용목록을 넓히거나
    임계를 낮출 수 없다(정책에 없으면 엔진 기본값). 실행 상태 값(now·usage 등 미선언 키)은 그대로 둔다."""
    cfg = a.manifest.spec.config
    pp = (params or {}).get(a.id)
    if not pp and not (strict and cfg and req.params):
        return req
    if pp and "byPrincipal" in pp:                      # 보호 대상(주체)별 계약이 있으면 그 값이 에이전트 공통 값보다 우선
        pid = req.subject.principal.id if req.subject.principal else None
        pp = {k: v for k, v in pp.items() if k != "byPrincipal"} | (pp["byPrincipal"].get(pid) or {})
    base = {k: v for k, v in req.params.items() if not (strict and k in cfg)}
    return req.model_copy(update={"params": base | (pp or {})})


def run_gate(gate: str, req: JudgeRequest, agents: list[Agent], params: dict[str, dict] | None = None,
             strict: bool = True) -> dict:
    t0 = time.perf_counter()
    req = req.model_copy(update={"gate": gate})
    reqs = {a.id: agent_request(a, req, params, strict) for a in agents}
    futures = {_POOL.submit(a.judge, reqs[a.id]): a for a in agents}
    done, pending = wait(futures, timeout=timeout_s(gate))
    findings: list[Finding] = []
    for fut, a in futures.items():
        if fut in done:
            findings.append(fut.result())
        else:
            fut.cancel()
            findings.append(a.degraded(reqs[a.id], f"관문 타임아웃 {timeout_s(gate) * 1000:.0f}ms 초과",
                                       (time.perf_counter() - t0) * 1000))
    findings.sort(key=lambda f: f.agent.id)
    transformed = _chain_transforms(gate, reqs, {a.id: a for a in agents}, findings)
    latency = (time.perf_counter() - t0) * 1000
    budget = GATE_BUDGET_MS.get(gate)
    return {"findings": findings, "latencyMs": round(latency, 3), "budgetMs": budget,
            "overBudget": bool(budget and latency > budget), "transformed": transformed,
            "degraded": [f.agent.id for f in findings if f.degraded]}


def _chain_transforms(gate: str, reqs: dict[str, JudgeRequest], by_id: dict[str, Agent], findings: list[Finding]) -> dict | None:
    field = TRANSFORM_FIELD.get(gate)
    ts = [f for f in findings if f.verdict == "transform" and f.action.transform is not None]
    if not field or not ts:
        return None
    value = ts[0].action.transform
    for f in ts[1:]:                                   # 앞선 무해화 결과 위에 다음 에이전트를 다시 적용
        nxt = by_id[f.agent.id].judge(reqs[f.agent.id].model_copy(update={field: value}))
        if nxt.verdict == "transform" and nxt.action.transform is not None:
            value = nxt.action.transform
    return {"field": field, "value": value}
