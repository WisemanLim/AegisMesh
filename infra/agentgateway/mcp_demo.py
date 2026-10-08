"""MCP 시연 서버 (Epic 67) — Streamable HTTP(JSON 응답), 표준 라이브러리만. 도구는 흉내만 낸다(셸 실행·송금 없음).

  search_docs(q) · get_order(orderId) · run_shell(command) · transfer(amount, to)
get_order 의 ORD-7731 결과에는 시험용 AWS 키 예시(AKIAIOSFODNN7EXAMPLE)가 들어 있다 — 출력 관문 무해화 확인용.
"""
import json
import secrets
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

TOOLS = [
    {"name": "search_docs", "description": "사내 문서 검색", "inputSchema": {"type": "object", "properties": {"q": {"type": "string"}}, "required": ["q"]}},
    {"name": "get_order", "description": "주문 조회", "inputSchema": {"type": "object", "properties": {"orderId": {"type": "string"}}, "required": ["orderId"]}},
    {"name": "run_shell", "description": "셸 명령 실행(시연 — 실행하지 않음)", "inputSchema": {"type": "object", "properties": {"command": {"type": "string"}}, "required": ["command"]}},
    {"name": "transfer", "description": "송금(시연 — 이체하지 않음)", "inputSchema": {"type": "object", "properties": {"amount": {"type": "number"}, "to": {"type": "string"}}, "required": ["amount"]}},
]


def call(name: str, args: dict) -> str:
    if name == "search_docs":
        return f"'{args.get('q', '')}' 검색 결과 2건: 환불 규정 v3, 연회비 안내"
    if name == "get_order":
        oid = args.get("orderId", "")
        return f"주문 {oid}: 어제 출고, 내일 도착" + (" · 연동 키 AKIAIOSFODNN7EXAMPLE" if oid == "ORD-7731" else "")
    if name == "run_shell":
        return f"(시연) 실행하지 않음: {args.get('command', '')}"
    if name == "transfer":
        return f"(시연) 이체하지 않음: {args.get('amount')} → {args.get('to', '-')}"
    raise KeyError(name)


class Handler(BaseHTTPRequestHandler):
    def _send(self, code: int, obj: dict | None, headers: dict | None = None) -> None:
        body = json.dumps(obj, ensure_ascii=False).encode() if obj is not None else b""
        self.send_response(code)
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        if obj is not None:
            self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        self._send(405, None) if self.path == "/mcp" else self._send(200, {"ok": True})

    def do_DELETE(self):
        self._send(200, None)

    def do_POST(self):
        msg = json.loads(self.rfile.read(int(self.headers.get("content-length") or 0)) or b"{}")
        if "id" not in msg:                                          # 알림(notifications/initialized 등)
            return self._send(202, None)
        m, rid, p = msg.get("method"), msg["id"], msg.get("params") or {}
        if m == "initialize":
            return self._send(200, {"jsonrpc": "2.0", "id": rid, "result": {
                "protocolVersion": p.get("protocolVersion", "2025-06-18"), "capabilities": {"tools": {}},
                "serverInfo": {"name": "aegis-mcp-demo", "version": "1.0.0"}}}, {"Mcp-Session-Id": secrets.token_hex(8)})
        if m == "tools/list":
            return self._send(200, {"jsonrpc": "2.0", "id": rid, "result": {"tools": TOOLS}})
        if m == "tools/call":
            try:
                text = call(p.get("name"), p.get("arguments") or {})
            except KeyError:
                return self._send(200, {"jsonrpc": "2.0", "id": rid, "error": {"code": -32602, "message": "알 수 없는 도구"}})
            return self._send(200, {"jsonrpc": "2.0", "id": rid, "result": {"content": [{"type": "text", "text": text}], "isError": False}})
        if m == "ping":
            return self._send(200, {"jsonrpc": "2.0", "id": rid, "result": {}})
        self._send(200, {"jsonrpc": "2.0", "id": rid, "error": {"code": -32601, "message": "없는 메서드"}})

    def log_message(self, *_):
        pass


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
