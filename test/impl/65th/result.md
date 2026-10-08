# 시험 결과 / Test Result — impl 65th (Epic 65 L2 격리 gVisor)
- 일자: 2026-10-08 · 대상: local (Docker Desktop arm64 VM) · gVisor runsc release-20260928.0 (systrap, KVM 불필요) · 커밋: —

## 요약 / Summary
- 전체 8, 통과 8, 실패 0 → 최종 **PASS** (재시도 3회: sidecar `gvisor-bin` 누락 / 읽기 전용 루트 FS 에 번들 자리 없음 / 내장 x10 과 ID 충돌 — 시험과 같이 잠시 비우고 되돌림)
- **L2 사용 가능**: `GET /v1/sandbox` maxLevel L2 · 커널 `4.19.0-gvisor` · 샌드박스 기동 중앙 406 ms(웜 슬롯이라 판정마다 아님) · 웜 판정 p50 0.9 / p95 1.9 ms
- L2 요구 서드파티 에이전트: 보류 → **R4 재생을 L2 에서 통과**(골든 10·공격 11) → L3 없음이라 경보 전용(OQ2, 차단 승격은 2인 승인)
- 탈출 점검 23/23 막힘(gVisor 경계 13 + 안쪽 잠금 층 10) · 에이전트 코드 우회 시도 6/6 막힘 · Landlock 은 gVisor 가 주지 않음(0) — 감사 훅·seccomp·gVisor 루트 FS 가 대신

## 구현
- `Dockerfile` — 전역 ARG `GVISOR_RELEASE`·`GVISOR_SHA256_{X86_64,AARCH64}`(게시 sha512 로 확인한 뒤 sha256 고정) · `gvisor` 스테이지(받기·검증, 불일치 = 빌드 실패) · `l2` 스테이지(runsc + gvisor-bin, 샌드박스 루트 FS = runtime 이미지 사본 + /agent 자리, 브로커)
- `infra/gvisor/broker.py`(표준 라이브러리) — `runsc --rootless --network=none do -root /sandbox-rootfs -volume <번들>:/agent`, 번들별 웜 샌드박스 임대·회수(사용 횟수·오류·시간 초과), 슬롯·대기 후 거부, `/decide`·`/replay`·`/probe`·`/warm`·`/retire`·`/health`, 번들 이름 검증(경로 탈출 거부), prod 상호 TLS
- compose `sandbox-l2`(프로파일 l2) — 비루트(10001)·`cap_drop: ALL`·`no-new-privileges`·`read_only`·tmpfs /tmp·mem 3g·pids 1024, 번들은 appdata 의 registry 하위 경로만 읽기 전용. 사용자 이름공간 때문에 seccomp·AppArmor 만 unconfined
- `app/sandbox.py` — `SANDBOX_L2_URL` 브로커 준비 = L2 사용 가능(15 s 캐시), `decide_l2`·L2 replay·probe·warm·retire, 상태 화면 L2 풀(runsc 판·커널·기동·브로커 통계) · `app/registry.py` L1·L2·L3 는 요구 등급 격리에서만(없으면 기동 거부) · `app/review.py` R4 L2 재생 · `app/sandbox_child.py` `l2probe`(잠금 없이 gVisor 경계), 안쪽 프로세스 스스로 rlimit, 차단 문구에 실제 등급
- `POST /v1/sandbox:probe?level=L1|L2` · `make l2-up|l2-down [ENV=prod]` · env `SANDBOX_L2_URL`·`SANDBOX_L2_SLOTS` · certs 잎 `sandbox-l2`
- `test/test_sandbox_l2.py` 3건(브로커로만 심사·판정 / 고갈·중단 = 강등·기동 거부, L1 대체 없음 / probe level·번들 이름 검증)

## 케이스 / Cases
| id | 결과 | 비고 |
|----|------|------|
| C01 | PASS | `c01-build.txt`·`c02-l2-up.txt` · health `ready true · runsc release-20260928.0 · kernel 4.19.0-gvisor · coldStartMs 79` |
| C02 | PASS | 권한 조합 실측(seccomp·AppArmor unconfined 만으로 동작, 능력·root 불필요) · probe `/tls`·`/registry`·`/opt/l2/broker.py`·docker.sock·/dev/kvm 없음, /proc 에 보이는 프로세스 1 |
| C03 | PASS | `c03-e2e.txt` C02 — `골든 10·공격 11 재생 (L2 샌드박스(gVisor), p95 0.015ms) · 격리 미달(L3 없음 → L2 대체)` · outcome alert_only |
| C04 | PASS | C03·C04 — transform `X10.aws-access-key` degraded false · 60건 브로커 served 60 · 판정 p50 0.9 / p95 1.9 ms · API 왕복 p50 4.2 / p95 14.5 ms · `c04-cold-start.txt` 기동 372~542 ms |
| C05 | PASS | C05 ok=True — 커널 gVisor · 네트워크 api·db(이름 풀이 없음)·1.1.1.1(unreachable) · 밖 파일 6 · /proc · 환경 비밀 · 루트 FS 쓰기 잔존 없음 · 안쪽 seccomp EPERM·감사 훅·rlimit(2GB MemoryError) |
| C06 | PASS | C06 — getaddrinfo·ctypes.dlopen·subprocess.Popen 차단, `/tls/tls.key`·`/proc/1/cmdline` 읽기 차단, 무한 루프 3 s 시간 초과 → 회수 |
| C07 | PASS | `test_broker_busy_or_gone_degrades_never_downgrades` — 고갈 503 → 강등 '풀 고갈', 중단 → 강등 'L2 격리 실행 환경 없음', L1 served 불변, 캐시 비우면 기동 거부 |
| C08 | PASS | `make-test.txt` 476 passed · 계약 227 작업 |

## 회차 / Rounds
- round 1: 브로커 준비 실패 — 새 gVisor 판은 `runsc` 옆 `gvisor-bin/gvisor_sentry` 사이드카가 필요(STRICT) → 함께 복사
- round 2: 번들 붙이기 실패(`mkdir /sandbox-rootfs/agent: read-only file system`) → 이미지에 /agent 자리
- round 3: 등록 422 — x10 은 내장 에이전트(DP1 항목당 하나) → 시험과 같이 내장 행을 잠시 비우고 등록, 끝에 내장 재동기(`restore: builtin x10 builtin`)

## 남은 것 / Notes
- seccomp·AppArmor unconfined 는 브로커 컨테이너만 — 사용자 이름공간 허용 프로필(기본 프로필 + unshare·clone NEWUSER)로 좁히는 것은 다음 단계
- 샌드박스 루트 FS 는 이미지 빌드 시점 사본 — local 에서 app/aegis 코드를 바꾸면 `make l2-up`(빌드 포함)으로 맞춘다
- L3(1회용 microVM)는 KVM 없음으로 계속 보류. OQ2 '경보 전용 + 2인 승인 승격'은 L2 에서도 그대로(R4 요구 등급 = L3)
