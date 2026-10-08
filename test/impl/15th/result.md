# 시험 결과 / Test Result — impl 15th (Epic 15 관측 OTel)
- 일자: 2026-10-06 · 대상: local (SQLite + otel-collector-contrib 0.162.0, debug detailed) + prod 리허설 (PostgreSQL 17 + collector, debug basic) · 커밋: —
- 브라우저: 헤드리스 Chromium (gstack browse)

## 요약 / Summary
- 전체 9, 통과 9, 실패 0 → 최종 **PASS** (재시도 2회: 수집기 설정 경로 형식, SDK 폐기 예정 API)
- `make test` **264 passed** (경고 0) · `make test-web` 7 + tsc · coverage 80/80 · ruff(F,E9) clean · `gen_otel_config.py --check` 최신

## 케이스 / Cases
| id | 결과 | 비고 |
|----|------|------|
| T15-01 | PASS | `otelcol validate` exit 0, “Everything is ready”, api·worker “관측 내보내기 활성 → http://otel-collector:4318” |
| T15-02 | PASS | 입력 관문 block 1건 → 수집기에 trace `f529d686…` 레코드 7(루트 `aegis.gate.input` + `aegis.agent.d1-01~05` + finding 로그), 하위 span Parent ID = 루트 |
| T15-03 | PASS | 카드번호·요청 원문이 수집기 출력에 0건 (속성은 규칙·판정·위치만) |
| T15-04 | PASS | 시험 로그(이메일·전화·카드·주민번호·API 키) → 수집기 Body·속성 모두 `[REDACTED_*]`, 원문 0건 (local·prod) |
| T15-05 | PASS | 지표 aegis.gate.requests·duration·findings, finding 로그 3건 (15초 주기) |
| T15-06 | PASS | 규칙 6종 표본 치환·보존 예 유지·RE2 호환(pytest), 생성 설정 = 규칙×6 문장, `--check` 최신 |
| T15-07 | PASS | 거버넌스 자체 점검 hits `D10-02.retention-short`, `X03.approval-fatigue` — **D10-07.no-collector 해소** (local·prod) |
| T15-08 | PASS | `/observability` 파이프라인(수신→memory_limiter·transform/mask·batch→debug, 전송 성공 13·4·3/실패 0)·규칙 표·미리보기/전송·SLO(입력 0.58/80ms 등)·오탐 예산, 콘솔 오류 0 |
| T15-09 | PASS | 264 passed · prod: 5 서비스 기동, 수집기 원문 PII 0, api 내보내기 traces 2·metrics 1·logs 1 (실패 0) |

## 발견 오류 및 수정 / Bugs & Fixes
| round | 오류 | 원인 | 수정 | 재시험 |
|-------|------|------|------|--------|
| 1 | 수집기 경고 “paths were modified to include their context prefix” | 0.162 OTTL 은 `span.attributes` 처럼 문맥 접두사 경로를 권장 | 생성기에서 `span.`·`spanevent.`·`log.`·`datapoint.` 접두사 사용 | 경고 0 |
| 1 | pytest 경고 2건 (InMemoryLogExporter·LoggingHandler 폐기 예정) | SDK 1.45 API 변경 | 로그는 OTel Logs API `Logger.emit` 로 직접 기록(추가 의존성 없음), 시험은 InMemoryLogRecordExporter | 경고 0, 수집기 로그 재확인 |
| — | 시험 명령: 수집기 로그가 파일 대신 화면으로 | `2>&1 >file` 순서 (수집기는 stderr 출력) | `>file 2>&1` | — |

## 설계 결정 기록
- 마스킹 규칙 단일 원천 `observability/masking.yaml` → 생성기 → `infra/otel/collector.yaml`(transform 프로세서). 같은 규칙으로 API 미리보기. CI·pytest 가 생성물 최신 여부 확인.
- 관문 traceId(원장·판정 조회 ID) = OTel trace id (사용자 정의 IdGenerator). 판정 원문·무해화 결과는 관측으로 보내지 않는다.
- 수집기 내보내기는 debug(로컬 상세·운영 기본). 운영 백엔드(Tempo·Loki·Prometheus 등)는 생성기 exporters 에 추가 — 벤더 형식 강제 없음(NFR-O3).
- 전송 통계는 프로세스 단위(prod api 워커 2개는 각자 집계).

## 첨부 / Logs
- logs/ (비커밋): t15-*.txt, collector c1~c4·prod-collector 출력, 스크린샷, regression.txt
