"""aegismesh — 제어 API (FastAPI entrypoint). PRD §12.3."""
import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import JSONResponse

from app import db
from app.api import airgap as airgap_api
from app.api import auth as auth_api
from app.api import console as console_api
from app.api import evidence as evidence_api
from app.api import governance as governance_api
from app.api import domains as domains_api
from app.api import instant as instant_api
from app.api import workflow as workflow_api
from app.api import compliance as compliance_api
from app.api import success as success_api
from app.api import samples as samples_api
from app.api import quality as quality_api
from app.api import identity as identity_api
from app.api import judge as judge_api
from app.api import observability as observability_api
from app.api import sandbox as sandbox_api
from app.api import policy as policy_api
from app.api import registry as registry_api
from app.api import scan as scan_api
from app.core.config import settings

log = logging.getLogger("aegismesh")


def migrate() -> None:
    from alembic import command
    from alembic.config import Config
    root = Path(__file__).resolve().parent.parent
    cfg = Config(str(root / "alembic.ini"))
    cfg.set_main_option("script_location", str(root / "migrations"))
    command.upgrade(cfg, "head")


@asynccontextmanager
async def lifespan(_: FastAPI):
    from app import telemetry
    telemetry.setup("aegismesh-api")
    if settings.auto_migrate:
        migrate()
        from app.seed import run
        log.warning("auto seed: %s", run())
    from app.admin import announce_bootstrap
    announce_bootstrap(log)
    yield
    from app import evidence_writer, sandbox
    evidence_writer.shutdown()                        # 대기 증적 적재 후 종료
    sandbox.shutdown()


app = FastAPI(title=settings.app_name, version="0.1.0", lifespan=lifespan)
app.include_router(auth_api.public)
app.include_router(auth_api.router)
app.include_router(identity_api.public)
app.include_router(identity_api.router)
app.include_router(registry_api.router)
app.include_router(judge_api.router)
app.include_router(policy_api.router)
app.include_router(observability_api.router)
app.include_router(sandbox_api.router)
app.include_router(airgap_api.router)
app.include_router(console_api.router)
app.include_router(evidence_api.router)
app.include_router(scan_api.router)
app.include_router(governance_api.router)
app.include_router(quality_api.router)
app.include_router(domains_api.router)
app.include_router(instant_api.router)
app.include_router(workflow_api.router)
app.include_router(compliance_api.router)
app.include_router(success_api.router)
app.include_router(samples_api.router)


@app.get("/health")
def health():
    try:
        db.ping()
        db_status = "ok"
    except Exception as exc:  # noqa: BLE001 — 헬스 응답에 원인 노출(시크릿 제외)
        db_status = f"error: {type(exc).__name__}"
    body = {"status": "ok" if db_status == "ok" else "degraded",
            "env": settings.app_env, "db": {"engine": settings.db_engine, "status": db_status}}
    return JSONResponse(body, status_code=200 if db_status == "ok" else 503)


@app.get("/healthz")
def healthz():
    return {"status": "ok"}


@app.get("/readyz")
def readyz():
    return health()
