# 시험 결과 / Test Result — impl 46th (Epic 46 OpenBao 운영형 리허설)
- 일자: 2026-10-07 · 대상: local compose + OpenBao 2.4.1 서버 모드(raft) · 커밋: —

## 요약 / Summary
- 전체 7, 통과 7, 실패 0 → 최종 **PASS** (재시도 5회: 설정 중복·볼륨 소유권 / 초기화 응답 시간 초과 / 리더 선출 전 요청 / 감사 장치 API 금지 / 시험 환경 누수)
- 실측(logs/e2e.txt): 재기동 → sealed · 확인 거부("Vault is sealed") · 발급 503 → `make bao-unseal` → **재기동 전 임대 그대로 유효**(보유자 200) → 회수 403 · 감사 로그 25줄, 임대 원문 없음·HMAC 188 필드
- `make test` 404 passed(logs/make-test.txt) · `test_openbao` 5(봉인 상태 1 추가)
- 측정으로 찾은 것: ① 초기화 응답을 놓치면 봉인 해제 키를 영영 잃는다(raft 부트스트랩이 5초를 넘김) → 초기화만 120초 대기 ② OpenBao 2.4 는 감사 장치를 API 로 켤 수 없다 → 설정 선언 ③ `make bao-up` 상태에서 `make test` 를 돌리면 시험 컨테이너가 OpenBao 설정을 물려받아 내장 브로커 시험이 실제 OpenBao 를 친다 → conftest 에서 내장으로 고정(실결함)

## 구현
- `infra/openbao/config.hcl`(raft·감사 장치 선언·로컬 TLS 끔) · compose `bao-server` + `baodata`·`baoaudit` 볼륨
- `scripts/bao_setup.py` `init`·`unseal`·리더 대기·감사 확인, 루트 토큰은 init.json(구성 전용) · `make bao-up MODE=server`·`make bao-unseal`·`bao-down`(두 모드) · `.gitignore` `infra/openbao/init.json`
- `app/openbao.py` 상태에 sealed·initialized 구분 · 콘솔 신원 화면 '봉인됨' 문구 · `test/conftest.py` 시험은 내장 브로커

## 케이스 / Cases
| id | 결과 | 비고 |
|----|------|------|
| T46-01 | PASS | init — 키 3·임계 2 → init.json(600) · unseal sealed False 2/3 · audit 선언 장치 ['file/'] · api backend=openbao addr=http://bao-server:8200 |
| T46-02 | PASS | {'policies': ['aegis-broker', 'default'], 'period': 86400, 'orphan': True} |
| T46-03 | PASS | {'sealed': True, 'initialized': True, 'ok': False} · introspect '확인 불가(fail-closed) — Vault is sealed' · 발급 HTTP 503 · 콘솔 문구는 test_openbao(봉인)로 확인 |
| T46-04 | PASS | lse_4dd27835d5b8 — 봉인 해제 뒤 active, 보유자 lookup-self 200 |
| T46-05 | PASS | revoked · 보유자 403 |
| T46-06 | PASS | 요청 경로: create/aegis-lease 1 · lookup-accessor 2 · revoke-accessor 1 · 정책·역할·브로커 생성 · 원문 포함 False |
| T46-07 | PASS | bao-up(server, api backend=openbao) 상태에서 `make test` 404 passed (logs/make-test-bao-up.txt) → bao-down |

## 회차 / Rounds
- round 1: 진입점이 설정 디렉터리를 이미 붙여 중복 경고 + raft 경로(/openbao/data) 소유권 거부 → 명령 `server` 만, 저장소·감사는 진입점이 소유자를 맞추는 /openbao/file·/openbao/logs
- round 2: `sys/init` 응답이 5초 시간 초과 — 서버는 초기화를 끝냈지만 키를 받지 못함 → 방금 만든 리허설 볼륨 2개를 지우고 초기화만 120초 대기
- round 3: 봉인 해제 직후 `sys/audit` 500 — raft 리더 선출 전 → `sys/leader` is_self 대기
- round 4: 감사 장치 API 활성화 400("use declarative, config-based audit device management") → config.hcl 선언, 재기동 → 봉인 해제가 재기동 시나리오도 검증
- round 5: bao-up 상태의 `make test` 1건 실패(내장 브로커 시험이 OpenBao 토큰을 받음) → conftest 에서 SECRETS_BACKEND=builtin

## 남은 것 / Notes
- 운영: TLS 인증서, 자동 봉인 해제(KMS/transit), 다중 노드 raft, 키 보관자 분리, 감사 로그 수집은 운영 절차(이번은 단일 노드 로컬 리허설).
- 브로커 토큰은 `make bao-up` 마다 새로 만든다(이전 것은 주기 만료까지 유효) — 운영은 회전 절차 필요.
- 시험 뒤 `make bao-down` 으로 내장 브로커 기본값으로 되돌렸다(raft 볼륨·init.json 은 남김).

## 완료 게이트 (7차 실행, logs/gate/)
- `make test` 404 passed · `make test-web` 15 + tsc · `make contract-update` 218 작업(새 작업 없음, 필드 추가만)
- 전 경로 회귀(run.txt): **256쪽 axe serious·critical 0** · en 한글 관문 14틀 0 · 재배치·글자 간격·글자 200% **129/129** · 키보드·입력 목적 54/54
- prod 회귀(PostgreSQL, prod-build → 0018 head → db-ping → 스모크): 원장 전체 검증 ok(1,126,654건) · D1 의역 공격 alert(분류기, 관문 0.5ms) · 코퍼스 API benign·U+2028 · 성공 지표 계산(코퍼스 없음 = 값 없음) · 임대 엔진 builtin · 계약 218
- **prod 에서 찾은 실결함**: 롤링 교체(`/v1/updates/agents/{id}:reload`)가 품질 게이트를 통과해도 `version` 만 바꾸고 저장된 매니페스트는 옛 판으로 둠 → 상세 화면이 '1.0.0·규칙 전용 엔진'을 보임 → 교체 시 매니페스트·이름·예산·실패 모드도 갱신, 회귀 시험 추가, prod 재빌드 뒤 d1-01·d1-03 '1.1.0·분류기 엔진' 확인(prod-smoke.txt, prod-smoke-final.txt)
- `make prod-stop` → `make local-all` 복귀
