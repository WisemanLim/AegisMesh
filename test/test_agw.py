"""Epic 67 — agentgateway 연동: ExtMCP 정책 서버용 서비스 계정·보호 대상 프로파일, 게이트웨이 설정 불변식(실패 시 거부·도구 호출 양 단계).

실제 MCP 경로(agentgateway v1.6.0 → ExtMCP → 관문 → 시연 MCP)는 compose 프로파일 agw 실측(test/impl/67th).
"""
from pathlib import Path

import yaml

from app import agw, db, profiles

ROOT = Path(__file__).resolve().parent.parent


def test_setup_issues_service_token_and_protects_target(client):
    with db.system_session() as s:
        tok = agw.setup(s, hours=1)
        again = agw.setup(s, hours=1)
        assert profiles.active_for(s, "default", agw.TARGET).profile_id == agw.PROFILE
    assert tok != again
    d = client.post("/v1/judge:batch", headers={"Authorization": f"Bearer {tok}"},
                    json={"gate": "tool", "target": agw.TARGET, "request": {"tool": {"name": "run_shell", "args": {"command": "sudo su -"}}}}).json()
    assert d["verdict"] == "block" and d["profile"] == "tool-agent"


def test_gateway_config_fails_closed_on_both_phases():
    cfg = yaml.safe_load((ROOT / "infra" / "agentgateway" / "config.yaml").read_text())
    p = cfg["mcp"]["policies"]["mcpGuardrails"]["processors"][0]
    assert p["failureMode"] == "failClosed" and p["methods"] == {"tools/call": "full"} and p["host"] == "extmcp:9001"
    compose = yaml.safe_load((ROOT / "docker-compose.local.yml").read_text())["services"]
    assert "@sha256:" in compose["agentgateway"]["image"] and compose["agentgateway"]["ports"][0].startswith("127.0.0.1:")
