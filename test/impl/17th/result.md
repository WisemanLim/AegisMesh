# 시험 결과 / Test Result — impl 17th (Epic 17 샌드박스 브로커)
- 일자: 2026-10-06 · 대상: local (SQLite, root 사용자 dev 컨테이너) + prod 리허설 (PostgreSQL 17, 비루트 uid 10001) · 커널 linuxkit 7.0.12 aarch64 · 커밋: —
- 브라우저: 헤드리스 Chromium (gstack browse)

## 요약 / Summary
- 전체 8, 통과 8, 실패 0 → 최종 **PASS** (재시도 3회: 감사 훅 범위, dev 핫리로드, 내장 동기화 덮어쓰기)
- `make test` **278 passed** (+ test_sandbox 8, test_review R4 갱신) · `make test-web` 7 + tsc · coverage 80/80 · ruff(F,E9) clean

## 케이스 / Cases
| id | 결과 | 비고 |
|----|------|------|
| T17-01 | PASS | L0·L1 사용 가능, L2·L3 “런타임 없음 — 보류(격리 강등 금지)”. 실측 Landlock ABI 8 · seccomp 18 차단(소켓·연결·exec·fork·ptrace·mount·unshare·setns·chroot…) · rlimit CPU 60s·768MB·파일 64·쓰기 16MB |
| T17-02 | PASS | 콘솔 “지금 점검” 10/10 차단: libc socket 직접 호출 **EPERM**(seccomp) · libc open(/app/data/app.db) **EACCES**(Landlock) · 외부 연결·하위 프로세스·fork·/app/data 쓰기·원장 키 읽기·/etc 쓰기·메모리 2GB·환경 비밀, 임시 쓰기만 허용, 원장 기록 (local·prod 비루트) |
| T17-03 | PASS | 서명 번들(isolation L1) 콘솔 등록 → R4 “골든 10·공격 11 재생 (L1 샌드박스(Landlock·seccomp))” → active (이전 차수: 보류) |
| T17-04 | PASS | judge ×3 transform `X10.aws-access-key` (웜 왕복 0.26~0.5ms), judge:batch 출력 관문 [d2-03, x10] transform · L1 served 5 · 웜 슬롯 1 · 거부 0. Finding 의 에이전트·표준은 부모가 매니페스트로 구성 |
| T17-05 | PASS | pytest: detect 안에서 외부 연결·/app/data 쓰기·subprocess → “sandbox L1 … 차단” 사유로 failMode 강등 |
| T17-06 | PASS | pytest: 무한 루프 → 시간 초과 + 하위 프로세스 회수 / 슬롯 점유 시 “풀 고갈 — 대기 후 거부 (격리 강등 금지)”, 슬롯이 나면 정상 판정 |
| T17-07 | PASS | pytest: isolation L2 번들 → review_hold “L2 실행 환경 없음” |
| T17-08 | PASS | 278 passed · prod(uid 10001): maxLevel L1, Landlock 8, seccomp 18, 탈출 점검 10/10 |

## 발견 오류 및 수정 / Bugs & Fixes
| round | 오류 | 원인 | 수정 | 재시험 |
|-------|------|------|------|--------|
| 1 | L1 하위 프로세스가 첫 요청 전에 종료, R4 재생 실패 | 감사 훅이 `sys._getframe` 을 막아 pydantic 모델 생성 실패 | 거부 목록에서 제외(커널 층이 실제 경계) | PASS |
| 2 | 등록 직후 x10 이 내장 에이전트로 되돌아감 | ① local dev `uvicorn --reload` 가 /app/data(심사 번들 풀린 곳)까지 감시 → 재기동 → 자동 시드 ② 내장 동기화가 같은 ID 의 서드파티(api) 행을 덮어씀 | ① 핫리로드 감시를 소스 디렉터리로 한정 ② 내장 동기화는 api 출처 행을 건너뜀(DP1) + 회귀 시험 | round 3 PASS (재기동 0) |
| — | 시험 가정 오류 | d2-03 은 fail_open — 차단을 가정 | 매니페스트 failMode 기준으로 단언 | PASS |

## 설계 결정 기록
- PRD L1(별도 컨테이너·읽기 전용 루트·seccomp)을 API 컨테이너 안에서 커널 기능으로 구현: 별도 프로세스 + rlimit + 빈 환경 + 일회용 임시 FS + Landlock(FS 경계) + seccomp-BPF(네트워크·프로세스·마운트) + 감사 훅(보조). 네트워크는 허용목록이 아니라 전면 차단.
- 요청 단위 발급·회수 = 에이전트별 웜 하위 프로세스를 요청마다 슬롯(세마포어)으로 임대, 200회·오류·시간 초과 시 회수. 풀 고갈 시 대기 후 거부(강등 없음).
- 하위 프로세스는 Decision 만 반환 — 근거·판정 유형 검증과 Finding 구성은 부모(Agent.judge)가 한다.
- 통계는 API 프로세스 단위(prod 워커 2개는 각자). L2·L3(gVisor·microVM)는 런타임이 없어 해당 에이전트는 보류.

## 첨부 / Logs
- logs/ (비커밋): t17-*.txt, x10l1.bundle.json, keygen.json, 스크린샷, regression·prod
