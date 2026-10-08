"""MCP 어댑터 — 에이전트 하나를 MCP 서버로 노출. 도구 judge·explain·list_rules (PRD §12.4)."""
from __future__ import annotations

from mcp.server.mcpserver import MCPServer

from aegis.agent import Agent
from aegis.schemas import JudgeRequest


def create_server(agent: Agent) -> MCPServer:
    mcp = MCPServer(f"aegis-{agent.id}", version=agent.manifest.metadata.version)

    @mcp.tool()
    def judge(request: dict) -> dict:
        """AegisMesh JudgeRequest/v1 을 판정해 Finding/v1 을 반환한다."""
        return agent.judge(JudgeRequest.model_validate(request)).dump()

    @mcp.tool()
    def explain(rule_id: str, lang: str = "ko") -> str:
        """규칙 ID(예 D1-05.unicode-tag)의 의미와 근거를 설명한다. lang=en 이면 영어(NFR-C4)."""
        return agent.explain_rule(rule_id, lang)

    @mcp.tool()
    def list_rules() -> list[str]:
        """이 에이전트가 낼 수 있는 규칙 ID 목록."""
        return sorted(agent.rules)

    return mcp


def serve_stdio(agent: Agent) -> None:
    create_server(agent).run("stdio")
