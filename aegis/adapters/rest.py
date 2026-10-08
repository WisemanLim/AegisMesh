"""REST 어댑터 — 에이전트 하나를 단독 HTTP 서버로 노출 (M1, PRD §8.4). 플랫폼 의존 없음."""
from __future__ import annotations

from fastapi import Body, FastAPI

from aegis.agent import Agent
from aegis.schemas import JudgeRequest


def create_app(agent: Agent) -> FastAPI:
    app = FastAPI(title=f"aegis agent {agent.id}", version=agent.manifest.metadata.version)

    @app.post("/v1/judge")
    def judge(req: JudgeRequest = Body(...), engine: str | None = None):
        return agent.judge(req, engine).dump()

    @app.get("/v1/manifest")
    def manifest():
        return agent.manifest.model_dump(by_alias=True, mode="json")

    @app.get("/v1/rules")
    def rules():
        return agent.rules

    @app.get("/healthz")
    def healthz():
        return {"status": "ok", "agent": agent.id}

    @app.get("/readyz")
    def readyz():
        return {"status": "ready", "engines": sorted(agent.engines)}

    return app
