# 시험 결과 / Test Result — dev-env 1st
- 일자 Date: 2026-10-06
- 대상 Target: aegismesh (python-fastapi · local=sqlite / prod=postgres)
- 커밋 Commit: — (git 저장소 아님)
- 환경: Docker 29.3.0, Compose v5.5.1, macOS (Darwin 25.6.0), 컨테이너 Python 3.12

## 요약 / Summary
- 전체 Total: 8, 통과 Pass: 8, 실패 Fail: 0 (ENV-06·07 은 1·2차 실패 후 3차 통과), 최종 Verdict: **PASS**

## 케이스 / Cases
| id | 결과 result | 비고 note |
|----|-------------|-----------|
| ENV-01 | PASS | `Preflight OK`. WARN: `.env.prod` CHANGE_ME placeholder (리허설 허용) |
| ENV-02 | PASS | `aegismesh-local-api-1` Up (healthy), 127.0.0.1:8000 |
| ENV-03 | PASS | HTTP 200 `{"status":"ok","env":"local","db":{"engine":"sqlite","status":"ok"}}` (실제 `SELECT 1`) |
| ENV-04 | PASS | `sqlite OK: /app/data/app.db` |
| ENV-05 | PASS | `1 passed, 1 warning` — StarletteDeprecationWarning(httpx → httpx2 권고) |
| ENV-06 | PASS (3차) | app + db healthy, HTTP 200 `{"env":"prod","db":{"engine":"postgres","status":"ok"}}` |
| ENV-07 | PASS | `postgres OK` (pg_isready) — 1차부터 db 컨테이너 자체는 정상 |
| ENV-08 | PASS | aegismesh 컨테이너 0개 |

## 발견 오류 및 수정 / Bugs & Fixes
| round | 오류 bug | 원인 cause | 수정 fix | 재시험 retest |
|-------|----------|------------|----------|---------------|
| 1 | `make prod-all` exit 2: `Bind for 127.0.0.1:8000 failed: port is already allocated` | local·prod 가 같은 호스트 포트(`API_PORT=8000`)를 쓰는데 local 스택이 기동 중 | 절차 수정: prod 리허설 전 `make local-stop` (설정 변경 없음 — 모드는 호스트당 배타 실행 전제) | round 2 |
| 2 | prod api `/health` 503, `failed to resolve host 'db'`, 포트 미게시 | 1차에서 네트워크 설정 실패한 api 컨테이너가 남아 `up` 시 재생성 없이 시작됨 → 네트워크 미연결 | `make prod-stop` 으로 컨테이너 제거 후 `make prod-all` 재생성 | round 3 PASS |

## 메모 / Notes
- 시나리오 순서 권고: ENV-05 다음에 `make local-stop` 을 넣고 ENV-06 진행 (같은 포트 공유). 동시 기동이 필요하면 `.env.prod` 의 `API_PORT` 를 분리.
- 개선 후보(미적용): `make db-ping`(local) 은 디렉터리 생성·echo 만 수행 — 실제 연결 검증은 `/health` 의 `SELECT 1` 이 담당.
- 개선 후보(미적용): 컨테이너 Python 3.12 — 트렌드 캐시 권장 3.13. 의존성 호환 확인 후 결정.

## 첨부 / Logs
- `logs/env-01-preflight.txt` … `logs/env-08-stop.txt` (round 별 `r2`·`r3` 접미사)
