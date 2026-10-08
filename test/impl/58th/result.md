# 시험 결과 / Test Result — impl 58th (Epic 58 고정 판 갱신 자동화)
- 일자: 2026-10-08 · 대상: local 이미지 빌드(BuildKit) · 커밋: —

## 요약 / Summary
- 전체 5, 통과 5, 실패 0 → 최종 **PASS** (재시도 0)
- `make pins-refresh`: 이미지 빌드(`pins` 스테이지) 안에서 다음 판을 정해 `build/pins/pins.json` 으로 내보내고, Dockerfile 맨 위 전역 ARG 3줄만 고쳐 쓴다 — 지금은 DB-IP 2026-10·MDS3 no 290(다음 갱신 2026-11-01)이 최신이라 변경 0
- 옛 판(2026-09) 가정 빌드: 실제 DB-IP 서버에서 2026-10 판을 받아 sha256 `c839d407…`(지금 고정값과 같음)
- MDS 요청 절약: 판 이름(FIDO_MDS_SNAPSHOT)이 같으면 BuildKit 캐시 사본만 — 바뀐 mds 스테이지 재빌드에서도 `source: cache`
- 실행 중 낡음 점검: worker 매일 → 원장 `pins_checked|pins_stale` → 낡으면 알림 "고정 판"(업데이트 화면 링크), `GET /v1/updates` 의 `pins` · `make test` 462 passed

## 구현
- `scripts/pins.py` `resolve`(빌드 안: DB-IP 이번 달 → 없으면 지난달, 지금 판이면 받지 않음 · MDS nextUpdate 지나면 판 이름을 이번 달로) · `apply`(전역 ARG 정규식 교체, 값 형식 검사)
- Dockerfile 전역 ARG `DBIP_MONTH`·`DBIP_SHA256`·`FIDO_MDS_SNAPSHOT`(단일 근거) · `pins`·`pins-out` 스테이지 · `scripts/fetch_mds.py` 캐시 판 일치(`snapshot`, 옛 사본은 받은 달)
- `app/pins.py`(MDS 낡음 = nextUpdate 지남, DB-IP 낡음 = 빌드 45일 초과) · worker `pins` 작업 · 알림 · 업데이트 API·화면 "고정 판" 표 · Makefile `pins-refresh` · `.gitignore` `build/pins/` · `test/test_pins.py` 4

## 케이스 / Cases
| id | 결과 | 비고 |
|----|------|------|
| C01 | PASS | `make test` 462 passed · test_pins 4 · `make test-web` 17 |
| C02 | PASS | c02-pins-refresh.txt — `{"applied": [] …}` |
| C03 | PASS | c03-pins-older.txt — `['DBIP_MONTH', 'DBIP_SHA256'] 2026-10 c839d407f85a1e0b 2026-11-01` |
| C04 | PASS | c04-check-local.txt — stale [] · `{'job': 'pins', 'stale': []}` |
| C05 | PASS | c02-pins-refresh.txt mds 단계 `"source": "cache"` · c05-mds-cache.txt CACHED |

## 남은 것 / Notes
- 판 교체는 사람이 `make pins-refresh` → diff 확인 → 재빌드(자동 커밋·배포 없음). MDS3 는 요청 제한이 있어 판 이름이 바뀔 때만 받는다.
