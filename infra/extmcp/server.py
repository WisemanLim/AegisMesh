"""ExtMCP 정책 서버 (Epic 67 · PRD '전용 인프라: agentgateway') — agentgateway MCP 가드레일 → AegisMesh 관문.

- 요청 단계(tools/call): 도구 이름·인자 → `POST /v1/judge:batch` gate=tool, target=AGW_TARGET. allow·alert → 통과,
  block → 거부(규칙·trace), require_approval → 거부(승인 요청 ID — 승인 뒤 다시 호출).
- 응답 단계(tools/call 결과): 텍스트 내용 → gate=output. transform → 무해화한 결과로 바꿈(mutated), block → 거부.
- AegisMesh 에 닿지 못하면 gRPC 오류 → agentgateway failureMode(failClosed = 거부). 원문은 이 서버에 남기지 않는다.
- 호출 주체: 요청 헤더 x-aegis-principal(게이트웨이가 넘긴 경우) 또는 'agentgateway'.
"""
import json
import logging
import os
import ssl
import urllib.error
import urllib.request
from concurrent import futures

import ext_mcp_pb2 as pb
import ext_mcp_pb2_grpc as rpc
import grpc

URL = os.environ.get("AEGIS_URL", "http://api:8000").rstrip("/")
TOKEN = os.environ.get("AEGIS_TOKEN", "")
TARGET = os.environ.get("AGW_TARGET", "agw.demo")
TIMEOUT = float(os.environ.get("AEGIS_TIMEOUT_SEC", "3"))
log = logging.getLogger("extmcp")


def _ctx():
    d = os.environ.get("TLS_DIR")
    if not d:
        return None
    c = ssl.create_default_context(cafile=f"{d}/ca.crt")
    c.load_cert_chain(f"{d}/tls.crt", f"{d}/tls.key")
    return c


def judge(gate: str, request: dict) -> dict:
    body = json.dumps({"gate": gate, "target": TARGET, "request": request}).encode()
    req = urllib.request.Request(f"{URL}/v1/judge:batch", data=body, headers={"content-type": "application/json",
                                                                             "authorization": f"Bearer {TOKEN}"})
    with urllib.request.urlopen(req, timeout=TIMEOUT, context=_ctx()) as r:
        return json.load(r)


def principal(headers) -> str:
    for h in headers:
        if h.key.lower() == "x-aegis-principal":
            return h.value.decode(errors="replace")[:128]
    return "agentgateway"


def _rules(d: dict) -> str:
    return ", ".join(x["ruleId"] for x in d.get("decisions", []) if x.get("effective") not in (None, "allow"))[:300]


def deny(reason: str) -> pb.AuthorizationError:
    return pb.AuthorizationError(code=pb.AuthorizationError.PERMISSION_DENIED, reason=reason)


def texts(result: dict) -> list[int]:
    return [i for i, c in enumerate(result.get("content") or []) if isinstance(c, dict) and c.get("type") == "text"]


class ExtMcp(rpc.ExtMcpServicer):
    def CheckRequest(self, request, context):
        if request.method != "tools/call":
            return pb.McpRequestResult(**{"pass": pb.Pass()})          # pass 는 파이썬 예약어
        params = json.loads(request.mcp_request or b"{}")
        who = principal(request.headers)
        try:
            d = judge("tool", {"tool": {"name": params.get("name"), "args": params.get("arguments") or {}},
                               "subject": {"principal": {"id": who}}})
        except (OSError, ValueError) as exc:                     # failClosed 는 agentgateway 가 정한다
            log.warning("AegisMesh 판정 실패: %s", exc)
            context.abort(grpc.StatusCode.UNAVAILABLE, f"AegisMesh 판정 실패: {type(exc).__name__}")
        meta = {"aegisTraceId": d["traceId"], "aegisVerdict": d["verdict"]}
        log.info("tools/call %s by %s → %s (%s)", params.get("name"), who, d["verdict"], d["traceId"])
        if d["verdict"] == "block":
            return pb.McpRequestResult(error=deny(f"AegisMesh 도구 관문 차단 — {_rules(d)} (trace {d['traceId']})"), metadata=meta)
        if d["verdict"] == "require_approval":
            return pb.McpRequestResult(error=deny(f"AegisMesh 승인 필요 — {_rules(d)} · 승인 요청 {d.get('approvalRef')} "
                                                  f"(승인 뒤 다시 호출, trace {d['traceId']})"), metadata=meta)
        return pb.McpRequestResult(**{"pass": pb.Pass()}, metadata=meta)

    def CheckResponse(self, response, context):
        if response.method != "tools/call":
            return pb.McpResponseResult(**{"pass": pb.Pass()})
        result = json.loads(response.mcp_response or b"{}")
        idx = texts(result)
        if not idx:
            return pb.McpResponseResult(**{"pass": pb.Pass()})
        sep = "\n␞\n"                                      # 내용 조각 구분(무해화 뒤 다시 나눈다)
        joined = sep.join(result["content"][i]["text"] for i in idx)
        try:
            d = judge("output", {"output": joined})
        except (OSError, ValueError) as exc:
            context.abort(grpc.StatusCode.UNAVAILABLE, f"AegisMesh 판정 실패: {type(exc).__name__}")
        log.info("tools/call result → %s (%s)", d["verdict"], d["traceId"])
        if d["verdict"] == "block":
            return pb.McpResponseResult(error=deny(f"AegisMesh 출력 관문 차단 — {_rules(d)} (trace {d['traceId']})"))
        tr = d.get("transformed") or {}
        if d["verdict"] == "transform" and isinstance(tr.get("value"), str):
            parts = tr["value"].split(sep)
            if len(parts) == len(idx):
                for i, p in zip(idx, parts):
                    result["content"][i]["text"] = p
                return pb.McpResponseResult(mutated=json.dumps(result, ensure_ascii=False).encode())
            return pb.McpResponseResult(error=deny("AegisMesh 출력 관문 변환 결과를 내용 조각에 맞출 수 없음 — 차단"))
        return pb.McpResponseResult(**{"pass": pb.Pass()})


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s extmcp %(message)s")
    if not TOKEN:
        raise SystemExit("AEGIS_TOKEN 없음 — make agw-up 이 infra/agentgateway/extmcp.env 를 만든다")
    srv = grpc.server(futures.ThreadPoolExecutor(max_workers=16))
    rpc.add_ExtMcpServicer_to_server(ExtMcp(), srv)
    srv.add_insecure_port(f"[::]:{os.environ.get('PORT', '9001')}")
    srv.start()
    log.info("listening :%s → %s target %s", os.environ.get("PORT", "9001"), URL, TARGET)
    srv.wait_for_termination()


if __name__ == "__main__":
    main()
