# 시험 결과 / Test Result — impl 10th (Epic 10 등록 심사 R2~R5)
- 일자: 2026-10-06 · 대상: aegismesh local (SQLite) · 커밋: —

## 요약 / Summary
- 전체 11 (pytest 222건 포함), 통과 11, 실패 0 → 최종 **PASS** (재시도 4회)

## 케이스 / Cases
| id | 결과 | 비고 |
|----|------|------|
| U-01~U-09 | PASS | `make test` 222 passed |
| F-01 | PASS | 변조 `422 rejected (R2 서명 검증 실패)` · 정상 `201 active` R4 `p95 0.017ms` · `judge x10: transform X10.aws-access-key` |
| F-02 | PASS | 무한 루프 `review_hold — 자원 한도 초과로 강제 종료(신호 9: CPU 20초)` · 메모리 폭주 `review_hold — 재생 중 예외·무효 판정 21건 (MemoryError)` |

## 발견 오류 및 수정 / Bugs & Fixes
| round | 오류 | 원인 | 수정 | 재시험 |
|-------|------|------|------|--------|
| 1 | 시험의 monkeypatch 가 관문 판정에 반영 안 됨 | `lru_cache` 가 `f(x)` 와 `f(x, "builtin")` 을 다른 키로 저장 | 위치 인자 고정 래퍼 | PASS |
| 1 | 번들 등록 응답 500 (`NoneType.id`) | `merge` 후 flush 전 `get` 은 None | merge 반환값 사용 + flush | PASS |
| 1 | 등록 API UnboundLocalError 위험 | 함수 지역 변수 `review` 가 모듈 `review` 를 가림 | 지역 변수명 변경 | PASS |
| 2 | 정상 번들이 R3 보류 | 공격 코퍼스(tests/attacks)의 자격증명 '형태' 문자열을 비밀로 판단 | 공격셋 디렉터리는 비밀 스캔 제외(근거 주석) | PASS |
| 3 | **메모리 폭주 번들이 alert_only 로 등록** (실서버) | R4 하위 프로세스는 한도로 막혔으나 하네스가 예외를 강등 판정으로 흡수 → R5 품질 미달로만 처리. 관문에서는 한도 없는 API 프로세스에서 실행됨 | 재생 중 예외·무효 판정 1건이라도 있으면 R4 보류, 재생 p95 > 예산도 보류 | round 2 PASS |
| 3 | 무한 루프 보류 사유가 빈 문자열 | 신호 종료라 stderr 없음 | 신호 번호·한도 명시 | round 2 PASS |
| 4 | CPU 한도 시험이 20초 소요 | 한도 고정값 | `REVIEW_CPU_SEC`(기본 20, 시험 3) | PASS (31s → 15s) |

## 한계 (정직한 평가)
- R4 는 **하위 프로세스 + rlimit** 이지 microVM 이 아니다. 파일 읽기·네트워크는 R3 의 AST import·내장 함수 허용목록으로 막는다(정적 우회 가능성 존재). PRD 의 L3 1회용 microVM 은 Firecracker/gVisor 도입 결정 필요.
- 심사는 등록 요청 안에서 동기로 돈다 — 악성 번들 하나가 API 스레드를 최대 CPU 한도(20초)만큼 점유한다. worker 큐로 비동기화가 바람직(후속).
- 심사를 통과한 L0 번들은 관문에서 API 프로세스 안에서 실행된다(PRD §7.4 L0 = 동일 프로세스 정의와 일치). 런타임 자원 한도는 관문 타임아웃(강등)뿐이다.

## 첨부 / Logs
- logs/make-test.txt, keygen.json, publisher.txt, f-review.txt(round 1), f-review-r2.txt(round 2)
