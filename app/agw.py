"""agentgateway 연동 준비 (Epic 67 · PRD '전용 인프라: agentgateway') — ExtMCP 정책 서버가 쓸 서비스 계정 토큰 + 보호 대상 프로파일.

  python -m app.agw setup     # 서비스 계정 svc.agentgateway 토큰(표준 출력 → infra/agentgateway/extmcp.env) + agw.demo 에 tool-agent 적용
"""
from __future__ import annotations

import secrets
import sys
from datetime import timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from app import auth, db, models, profiles

SERVICE, TARGET, PROFILE = "svc.agentgateway", "agw.demo", "tool-agent"


def setup(s: Session, hours: int = 24) -> str:
    db.set_scope(s, "*")
    u = s.scalars(select(models.User).where(models.User.username == SERVICE)).first()
    if u is None:
        u = auth.create_user(s, None, SERVICE, "agentgateway ExtMCP 정책 서버", ["service"], "default", "Ag-" + secrets.token_urlsafe(24))
    u.active = True
    _, tok = auth.issue(s, u, "api_token", "agentgateway-extmcp", timedelta(hours=hours))
    if profiles.active_for(s, "default", TARGET) is None:
        profiles.apply(s, PROFILE, "default", TARGET, "enforce", "agw-setup")
    s.commit()
    return tok


if __name__ == "__main__":
    if sys.argv[1:] != ["setup"]:
        raise SystemExit(__doc__)
    with db.system_session() as s:
        print(f"# make agw-up 이 만든다(비커밋) — 서비스 계정 {SERVICE} 토큰(24시간)\nAEGIS_TOKEN={setup(s)}\nAGW_TARGET={TARGET}")
