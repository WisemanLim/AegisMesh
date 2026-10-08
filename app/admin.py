"""관리 CLI — 부트스트랩 토큰 발급 (SCR-A06, 설치 출력의 1회용 토큰).

  python -m app.admin bootstrap-token            # 관리자가 없을 때만 발급
  python -m app.admin bootstrap-token --reset    # break-glass 재발급(aegis admin reset) — 원장에 기록
"""
import argparse
import logging

from app import auth, db


def announce_bootstrap(log: logging.Logger) -> None:
    """API 기동 시 관리자가 없으면 토큰을 발급해 로그로 알린다(테이블이 없으면 마이그레이션 안내만)."""
    try:
        with db.system_session() as s:
            if auth.has_admin(s):
                return
            token = auth.issue_bootstrap(s, keep_valid=True)
            s.commit()
    except Exception as exc:  # noqa: BLE001 — 마이그레이션 전 기동·동시 기동 경합
        log.warning("부트스트랩 확인 생략 (%s) — make admin-token 으로 발급", type(exc).__name__)
        return
    if token:
        log.warning("AegisMesh 첫 실행 — 부트스트랩 토큰(24시간, 1회용): %s  → 콘솔 /setup", token)
    else:
        log.warning("AegisMesh 첫 실행 대기 — 유효한 부트스트랩 토큰이 이미 있다(분실 시 make admin-token)")


def main() -> int:
    ap = argparse.ArgumentParser(prog="python -m app.admin")
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("bootstrap-token")
    p.add_argument("--reset", action="store_true", help="관리자가 있어도 재발급(break-glass)")
    a = ap.parse_args()
    with db.system_session() as s:
        token = auth.issue_bootstrap(s, force=a.reset)
        s.commit()
    if token is None:
        print("관리자가 이미 있다 — break-glass 재발급은 --reset")
        return 1
    print(f"bootstrap token (24h, 1회용): {token}\n콘솔 /setup 에서 사용")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
