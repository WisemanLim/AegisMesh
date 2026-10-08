# 시험 결과 / Test Result — impl 66th (Epic 66 노드당 2,000 rps)
- 일자: 2026-10-08 · 대상: prod 리허설(같은 VM 18 vCPU 공유 — 부하 클라이언트·PG 주·대기·외부 복사·**다른 프로젝트 스택**) · 커밋: —

## 요약 / Summary
- 전체 7 — 통과 6, **목표 미달 1(C06)** → 최종 **BLOCKED**(개선은 반영·시험 통과, 2,000 rps 는 이 공유 VM 에서 확인 못 함)
- 병목 3개를 찾아 고침: ① **사건 행 잠금 경합**(같은 주체 반복 공격이 열린 사건 한 행을 요청마다 갱신·커밋까지 잠금 — 부하 중 최대 ~140 연결 대기) → 덧붙이기를 증적 작성기로(묶음마다 사건당 1회), ② **요청당 DB 왕복** SQL 8 + 커밋 2 → **SQL 3**, ③ allow 판정 추적(span 11개/요청) → 비율 표본(`OTEL_ALLOW_TRACE_RATIO`, prod 0.1 — 비허용·강등·예산 초과는 항상, 지표는 전부)
- 처리량(작업 16, 동시 256, 오류 0): 기준선 최고 **1,583 rps** → 개선 후 최고 **1,797 rps**(+13.5%) · p99 꼬리 최대 4.9 s → 0.6~1.1 s. 같은 설정 반복 편차가 크다(749~1,797) — 다른 프로젝트 스택(CPU 100%+ 컨테이너 2~3개)·외부 복사(objstore 145%)와 VM 공유
- 결정 필요: 2,000 rps 는 **전용 노드(부하 클라이언트·DB 분리)** 에서 재측정할지, 이 VM 최고 1,797 rps 를 리허설 값으로 둘지
- **결정(2026-10-08, 완료 게이트 BLOCKED 질문)**: 현재 수치 수용·기록 — 공유 VM 최고 1,797 rps 를 리허설 값으로, 2,000 rps 확인은 전용 노드 몫(PRD NFR-P1 에 기록). 재실행 없음

## 구현
- `app/api/deps.py` ctx — 쓴 것(최근 사용 시각 30초 단위·DPoP jti·원장)이 있을 때만 커밋(범위는 set_config 로 같은 트랜잭션에 이미 적용) → 커밋·다음 BEGIN 의 set_config·만료 속성 재조회(users) 제거
- `app/auth.py` Ctx.session_row — resolve 가 읽은 세션 행을 들고 있어 DPoP·위치 검사(mfa.enforce)에서 다시 조회하지 않음(약한 참조 식별 맵이 행을 놓치던 것)
- `app/tenancy.py` require(cached) — 인라인 판정 경로만 hotcache(TTL 2 s, 이 프로세스 테넌트 쓰기 시 즉시 무효화)
- `app/incidents.py` correlate(deltas) + apply — 열린 사건 덧붙이기는 증적 작성기가 묶음마다 사건 id 순으로 `FOR UPDATE` 1회(작성기 간 교착 없음), 새 사건·offline 재점검은 그대로 즉시 · `app/evidence_writer.py` Item.incidents
- `app/telemetry.py` traced() — allow 추적 비율 표본(trace id 앞 8자리로 정해 노드 간 일관), 지표는 표본 없이
- 시험: `test_repeat_attacks_do_not_lock_incident_row_in_request`(사건 UPDATE 는 evidence-writer 스레드에서만) · `test_allow_traces_sampled_but_metrics_complete`

## 케이스 / Cases
| id | 결과 | 비고 |
|----|------|------|
| C01 | PASS | `c01-baseline-w16.txt` 1,583 rps(관문 실행 p95 input 15.2 / tool 11.7 / output 15.2 ms) — 직후 반복 235·698 rps(앞 실행의 증적 적재 잔량 ~30 s) |
| C02 | PASS | `profile-w16.txt`(psycopg 59%) · `profile-gil-w16.txt`(SQLAlchemy 실행 25%·만료 재조회 8%) · `c03-sql-per-request-before.txt` · `c10-pg-wait.txt`(Lock incidents 최대 ~140) · `c09-worker-cpu.txt`(작업 16~70% — 대기) |
| C03 | PASS | `c04-sql-per-request-after1.txt` → 요청 경로 set_config 2 + auth_sessions 1 (테넌트·users·두 번째 세션 조회 없음) |
| C04 | PASS | `c13-pg-wait-opt3.txt` incidents 잠금 대기 0 · 시험 통과(같은 사건·계수 유지) |
| C05 | PASS | 시험 통과 · prod `OTEL_ALLOW_TRACE_RATIO=0.1` |
| C06 | **미달** | `c06-opt1.txt` 1,797 / 981 · `c08-opt2.txt` 1,583 / 910 / 1,118 · `c12-opt3.txt` 1,556 / 1,293 / 1,099 · `c15-workers.txt` 작업 12 = 1,221·1,200, 작업 20 = 1,403·1,298 · `c16-final-w20.txt` 1,105~1,244(다른 프로젝트 스택 실행 중, tool 관문 실행 p95 34~47 ms > 예산 20) |
| C07 | PASS | `make-test.txt` 478 passed |

## 회차 / Rounds
- round 1: py-spy 전체 표본은 대기 스레드까지 세어 DB 가 59% — GIL 표본으로 다시 봐 실제 파이썬 CPU(SQLAlchemy 실행·만료 재조회·세션 BEGIN)를 가림
- round 2: 요청당 SQL 8 → 5 → 3 (커밋 조건화 → 세션 행 유지)
- round 3: 추적 표본 뒤에도 처리량 편차·꼬리 → 작업 프로세스 CPU 가 포화가 아님(16~70%) → PG 대기 사건 확인 → 사건 행 잠금 경합 제거
- round 4: 작업 수 12·16·20 비교 — 20 은 tool 관문 실행 p95 가 예산(20 ms) 초과(과다 구독). 권장 = 노드 코어에 맞춘 16 내외

## 남은 것 / Notes
- 같은 VM 에 다른 프로젝트 스택·부하 클라이언트·PG 주·대기·외부 복사가 함께 돌아 처리량 상한을 분리해 볼 수 없다. 2,000 rps 확인은 전용 노드 + 클라이언트 분리가 필요
- 다음 후보(이번엔 안 함): 묶음 실행으로 스레드 왕복 줄이기(NFR-A2 '한 에이전트 지연이 다른 판정에 영향 없음'과 충돌) · 토큰 확인 캐시(회수 즉시성 저하) · allow 판정 Finding 행을 관문 기록으로 합치기(증적 모델 변경)
