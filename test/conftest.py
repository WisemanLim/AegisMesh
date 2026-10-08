"""공통 픽스처 — 시험마다 임시 SQLite 에 alembic 마이그레이션 + 시드."""
import os
import tempfile
from pathlib import Path

_TMP = Path(tempfile.mkdtemp(prefix="aegis-test-"))
os.environ["DATABASE_URL"] = f"sqlite:///{_TMP}/test.db"
os.environ["LEDGER_KEY_FILE"] = str(_TMP / "ledger.key")
os.environ["AUTO_MIGRATE"] = "false"
os.environ["REGISTRY_DIR"] = str(_TMP / "registry")
os.environ["REVIEW_CPU_SEC"] = "3"
os.environ["LEDGER_CHECKPOINT_EVERY"] = "5"
os.environ["OTEL_ENDPOINT"] = ""                       # 시험은 메모리 내보내기(test_observability)
os.environ["SECRETS_BACKEND"] = "builtin"              # make bao-up 의 api.env 가 시험 컨테이너에 새어 들지 않게 — OpenBao 는 test_openbao 가 가짜로
os.environ["OPENBAO_TOKEN"] = ""
os.environ["GUARD_URL"] = ""                           # make guard-up 의 api.env 가 새어 들지 않게 — 깊은 검사는 test_guard 가 가짜 서버로
os.environ["INJGUARD_URL"] = ""                        # make injguard-up 의 api.env 도 — 인라인 모델은 test_injguard 가 가짜 서버로
os.environ["ENGINE_OVERRIDES"] = ""
os.environ["SANDBOX_L2_URL"] = ""                       # make l2-up 의 api.env 도 — L2 브로커는 test_sandbox_l2 가 가짜 서버로
os.environ["KMS_BACKEND"] = "builtin"                 # 저장 암호화 키 고리·비밀 파일은 임시 디렉터리 — 개발 데이터 볼륨의 파일을 시험 키로 포장하지 않게
os.environ["KMS_KEYRING_FILE"] = str(_TMP / "kms_keyring.json")
os.environ["AUTH_SECRET_FILE"] = str(_TMP / "auth_secret.key")
os.environ["SVID_KEY_FILE"] = str(_TMP / "svid.key")

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402


@pytest.fixture(scope="session")
def migrated():
    from app.main import migrate
    from app.seed import run
    migrate()
    return run()


def _token(name: str, roles: list[str], tenant: str | None = None) -> str:
    """시험용 사용자 + API 토큰 (DB 직접 — 비밀번호 로그인 시험은 test_tenancy)."""
    from sqlalchemy import select

    from app import auth, db, models
    with db.system_session() as s:
        u = s.scalars(select(models.User).where(models.User.username == name)).first()
        if u is None:
            u = auth.create_user(s, None, name, name, roles, tenant, "pytest-password-0001")
        elif sorted(u.roles) != sorted(roles) or u.tenant != tenant:   # 같은 이름을 다른 역할로 재사용
            u.roles, u.tenant = sorted(roles), tenant
        _, tok = auth.issue(s, u, "api_token", "pytest", None)
        s.commit()
    return tok


@pytest.fixture(scope="session")
def admin_headers(migrated):
    return {"Authorization": f"Bearer {_token('test.admin', ['platform_admin'])}"}


@pytest.fixture
def as_user(migrated):
    """as_user('alice', 'approver', tenant='garam') → Authorization 헤더."""
    def make(name: str, *roles: str, tenant: str | None = None) -> dict:
        return {"Authorization": f"Bearer {_token(name, list(roles) or ['security_engineer'], tenant)}"}
    return make


@pytest.fixture
def client(admin_headers):
    """기본 주체 = 플랫폼 관리자(test.admin). 다른 주체는 요청마다 headers=as_user(...) 로 덮어쓴다."""
    from app.main import app
    with TestClient(app, headers=admin_headers) as c:
        yield c


@pytest.fixture
def anon(migrated):
    from app.main import app
    with TestClient(app) as c:
        yield c
