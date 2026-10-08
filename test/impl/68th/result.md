# 시험 결과 / Test Result — impl 68th (Epic 68 봉인 해제 HSM)
- 일자: 2026-10-08 · 대상: prod 리허설 · OpenBao v2.4.1+hsm (`openbao/openbao-hsm@sha256:bdba099c…`, cgo) · SoftHSM 2.6.1 · OpenSC 0.26.0 · 커밋: —

## 요약 / Summary
- 전체 6, 통과 6, 실패 0 → 최종 **PASS** (재시도 1회: AES-GCM 키에서 bao 중단 → RSA-OAEP 로)
- PKCS#11 자동 봉인 해제: 초기화 6.2 s(복구 키 3/2 — 봉인 해제 키가 아니라 복구용), **재기동 3회 모두 사람 없이 1.0~1.2 s 에 봉인 해제**, 점검 비밀 그대로
- 봉인 키 = 토큰 안에서 만든 RSA-3072 개인 키 `sensitive, always sensitive, never extractable, local` — 키 값은 HSM 밖으로 나오지 않는다
- HSM 이 없거나(다른 토큰) PIN 이 틀리면 **서버가 기동을 거부**(봉인 해제 불가) · 키 이름만 틀리면 봉인 블롭에 기록된 키로 풀리고 '봉인 키 갱신 실패' 경고만 — 설정 오류로 잠기지 않는 동작

## 구현
- `infra/openbao/hsm/`(Dockerfile·softhsm2.conf·token.sh) — HSM 빌드 고정 판 + SoftHSM2·OpenSC, 토큰 저장소 = 볼륨 baohsmtokens. token.sh: 토큰 AegisMesh 초기화·RSA-3072 키 쌍(민감) 생성(있으면 그대로)
- `infra/openbao/hsm.hcl` — raft 단일 노드 · 상호 TLS 1.3 · `seal "pkcs11"`(lib·token_label·key_label·CKM_RSA_PKCS_OAEP·rsa_oaep_hash sha1 — SoftHSM 한계), PIN 은 `BAO_HSM_PIN`(비커밋 hsm.env)
- compose prod 프로파일 `bao-hsm`(볼륨 baohsmdata·baohsmtokens, tls 잎 bao-hsm) · `make bao-hsm-up|bao-hsm-status|bao-hsm-down` · `scripts/bao_setup.py hsm-init|hsm-status` · SO PIN 은 토큰 준비 단계에만(`hsm-so.pin`, 비커밋)
- `test/test_openbao.py::test_hsm_seal_rehearsal_config_consistent`

## 케이스 / Cases
| id | 결과 | 비고 |
|----|------|------|
| C01 | PASS | `c01-bao-hsm-up.txt` · `bao-hsm: 발급 CN=bao-hsm` · `OpenBao v2.4.1+hsm (cgo)` |
| C02 | PASS | `Access: sensitive, always sensitive, never extractable, local` · hsm.env·hsm-so.pin 600, .gitignore |
| C03 | PASS | `hsm — sealed False · type pkcs11 · recovery_seal True · 6.2s` · 점검 비밀 v1 |
| C04 | PASS | `c02-restart.txt` 1.0 / 1.2 / 1.2 s · 점검 비밀 v1 같은 표식 |
| C05 | PASS | `c03-negative.txt` PIN 틀림 → `failed to login: CKR_PIN_INCORRECT` 기동 거부 · 다른 토큰 → `failed to find token with label: OtherHSM` exit 1 · 키 이름 틀림 → 풀림 + `post-unseal upgrade seal keys failed: no key found` · 복귀 정상 |
| C06 | PASS | 완료 게이트 `make test` 482 passed |

## 회차 / Rounds
- round 1: AES-256(CKM_AES_GCM) 키로 초기화하자 bao 가 `C_EncryptInit` 에서 중단(SIGABRT — SoftHSM 의 C++ 범위 검사: 래퍼가 IV 를 토큰이 만들기를 기대하나 SoftHSM 은 못 함) → 반쯤 된 초기화가 남은 리허설 전용 새 볼륨(baohsmdata)을 지우고 RSA-3072 + CKM_RSA_PKCS_OAEP(SoftHSM 은 OAEP 해시 SHA-1 만)로 다시

## 남은 것 / Notes
- SoftHSM 은 소프트웨어 — 키는 컨테이너 볼륨 파일(토큰 PIN 으로 암호화)에 있다. 운영 = 실제 HSM 의 PKCS#11 모듈·토큰으로 lib·token_label 만 바꾸고 AES-GCM 또는 OAEP-SHA256
- 이번 리허설 노드는 단일 노드·api 미연결(56th 클러스터는 그대로 transit). 클러스터 봉인 방식 이전(seal migration)은 다음 단계

## 10차 완료 게이트 (이 차수에 기록)
| 항목 | 결과 | 근거 |
|------|------|------|
| `make test` | 482 passed | `gate-make-test.txt` |
| `make test-web` | 18 passed + tsc | `gate-test-web.txt`·`gate-test-web-r2.txt` |
| API 계약 | 227 작업, 변경 없음 | `gate-contract.txt` |
| 접근성 전 경로 | 254쪽 axe serious·critical 0 · 재배치·간격·200% 128/128 · 보조기술 4종 — 실패 3건(en `/incidents/[id]` 제목 한글, `/setup` ko·en main 2) → 수정 뒤 대상 재점검 통과 | `a11y-gate/`·`a11y-gate-r3/`·`a11y-gate-r4/` |
| prod 회귀 | PG 0023 · db-ping · 원장 검증 5,542,569건 · 평문 0 · OTLP 내보내기 · 고정 판 낡음 0 · 계약 227 · injguard ENV=prod(상호 TLS, injection_model) · L2 ENV=prod(probe 23/23, 인증서 없는 접속 거부) · bao-hsm | `gate-prod-*.txt` |

게이트에서 찾아 고친 것:
- 사건 상세·대응 화면이 서버가 만든 한국어 사건 제목을 en 에서 그대로 보임(목록은 번역) → `LX()` 로 감쌈
- 로그인 상태 `/setup` 이 셸 안에서 `<main>` 을 하나 더 그림 → 로그인 상태면 `<div>`
- local worker 가 SQLite 잠김(`database is locked`) 예외로 주기 루프 밖에서 종료(재시작 정책 없음) → 주기 실패를 기록하고 다음 주기로(`test_worker_loop.py`)
- prod otel-collector 가 VM 재시작 뒤 꺼져 있어 OTLP 내보내기 실패 → 다시 올림(설정 변경 없음)

점검 중 본 것(조치 없음): 격리 자가 점검 `policy-ns` 실패 = 누수 0, run 9 시험이 만든 테넌트 `retdemo` 에 기본 정책 없음(2026-10-07 부터) · 대상 재점검의 `/incidents/[id]/response` 실패 = ONLY 모드가 템플릿 `[id]` 를 글자 그대로 연 것(실제 사건 쪽은 통과) · 재점검 중 web dev 서버 메모리 초과 재시작 → DPoP 세션 불일치(다시 로그인으로 해소)
