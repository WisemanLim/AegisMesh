# 시험 결과 / Test Result — impl 37th (Epic 37 증적 보존기한 만료 배치 + API 계약 시험)
- 일자: 2026-10-07 · 대상: local compose + 헤드리스 Chromium · 커밋: —

## 요약 / Summary
- 전체 8, 통과 8, 실패 0 → 최종 **PASS** (재시도 3회: 테넌트 생성 기록 수 가정 / 승인 적용 기록 순서 가정 / 증명서 fromSeq 가 체인 첫 seq 가 아님)
- `test_retention` 3 · `test_contract` 2 passed · 화면 E2E(logs/e2e.txt)
- 측정으로 찾은 결함: **보존기한 만료 배치가 없었다** — 원장은 지울 수 없어 보존기한(NFR-S·PIPA 최소화)을 지킬 수단이 없었고, 포렌식 화면의 “만료 배치 제외” 문구가 근거 없는 약속이었다

## 구현
- 0016 `ledger_purges`(추가 전용 트리거) + evidence DELETE 가드(PG 함수·SQLite WHEN — 승인 구간만) · `app/retention.py`(법적 보존·계획·요청·적용·증명서 서명·검증·worker 요청) · `ledger._verify_chain` 앵커 재시작·증명서/앵커 사슬 확인·`purged` 요약
- API `GET /v1/evidence/retention` · `POST /v1/evidence/retention:request`(privacy) · `GET /v1/evidence/purges/{id}` · 승인 행동 `evidence_purge` · worker 일 1회
- 계약: `scripts/contract_snapshot.py` → `test/contract/openapi.snapshot.json`(213 작업) · `test/test_contract.py` · `make contract-update`
- 콘솔 `/evidence/retention`(원장 화면에서 이동) + 증명서 내려받기

## 케이스 / Cases
| id | 결과 | 비고 |
|----|------|------|
| T37-01 | PASS | through = 두 번째 체크포인트, purge = 체인 앞 기록 수(테넌트 생성 2 + 4) · 403 · 409 · 승인 뒤 체크포인트 다음 seq 부터 남음 |
| T37-02 | PASS | signatureOk · approvers {apr.r1, apr.r2} · retention_purged 기록 · verify ok, purged.records 일치 |
| T37-03 | PASS | 구간 밖 DELETE → 트리거 예외 |
| T37-04 | PASS | legalHold.minSeq = 보존 기록이 가리킨 seq, incidents [inc_test], 경계 = 앞 체크포인트 |
| T37-05 | PASS | verify ok=false “삭제 증명 prg_forged: 서명·앵커 불일치” |
| T37-06 | PASS | eligible false “기한 지난 서명 체크포인트 없음” · 409 |
| T37-07 | PASS | 213 작업 · 깨지는 변경 0 · 태그 누락 0(/health·/readyz 제외) |
| T37-08 | PASS | retdemo 17건 중 seq 110306~110315 10건 대상 → worker 가 이미 요청(apr_941a8ba7c70d) → plat.appr1·2 승인 → 증명서 prg_0428a65ed199 서명 ✓ · 내려받기 JSON · 체인 검증 ok(남은 11건, purged 10) · en 한글 0 · 콘솔 오류 0 |

## 회차 / Rounds
- round 1~2: 시험 기대값을 테넌트 생성 기록·승인 적용 기록 순서와 무관하게 DB 에서 계산
- round 3: 시연 증명서의 fromSeq 가 1(체인 기준이 아닌 0+1) → 체인 안 첫 seq 로 수정(이미 발급된 시연 증명서는 추가 전용이라 그대로 남음)

## 남은 것 / Notes
- Finding·사건 등 원장 밖 테이블의 보존기한 정리는 범위 밖(원장만). 증명서는 원장 서명 키로 서명 — 키 회전 시 이전 키 공개키 보관 필요.
