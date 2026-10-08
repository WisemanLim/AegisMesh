# 시험 결과 / Test Result — impl 56th (Epic 56 OpenBao 운영 마감 + CLI 영어)
- 일자: 2026-10-08 · 대상: prod 리허설(PostgreSQL·상호 TLS) + OpenBao 2.4.1 봉인 해제기 1 + raft 3노드 · 커밋: —

## 요약 / Summary
- 전체 7, 통과 7, 실패 0 → 최종 **PASS** (재시도 3회: 리더 선출 중 307 / 선출 중 전 노드 미처리 / 대기 노드 health 429)
- `make bao-cluster-up ENV=prod`: 봉인 해제기(Shamir 3/2) → transit `aegis-autounseal` → bao-1 초기화(복구 키 3/2) → bao-2·3 retry_join·자동 봉인 해제 → **투표자 3 (10~30 s)** → api·worker 가 3주소·상호 TLS 로 임대
- 리스너: 평문 HTTP 400 · 클라이언트 인증서 없음 `TLSV13_ALERT_CERTIFICATE_REQUIRED` · TLS 1.2 `PROTOCOL_VERSION` · 내부 CA 인증서 + TLS 1.3 만 200
- 자동 봉인 해제: 3노드 동시 재기동 0.5 s · 전원 정지 후 기동(콜드) 봉인 해제 ≈1 s, 리더 선출 17 s — 운영자 개입 0
- 리더 장애: 75 s 동안 임대 발급·조회·회수 136건 **실패 0**, 최대 공백 1.9 s · 새 리더 ≈1 s · 복귀 노드 자동 재가입
- 봉인 해제기 장애: 운영 중 노드는 계속(임대 19/19), 재기동 노드는 기동 실패·재시작 반복 → 봉인 해제기 Shamir 해제 뒤 ≈1 s 만에 스스로 복귀
- CLI: `aegis --lang en`·`AEGIS_LANG=en`·`LANG=en_*` → list·eval·coverage·verify-bundle·airgap·sbom·a2a·도움말 한글 0 · `make test` 455 passed

## 구현
- `infra/openbao/cluster.hcl`(raft retry_join 3 · 리스너 TLS 1.3 + 클라이언트 인증서 필수 · transit 봉인 · 감사 장치) · `unsealer.hcl` · compose prod 프로파일 `bao-cluster`(bao-unsealer·bao-1~3, 노드별 볼륨·인증서 하위 경로, `bao status` 상호 TLS 헬스) · `scripts/certs.py` 말단 bao-unsealer·bao-1~3(uid 100)
- `scripts/bao_setup.py` `unsealer`·`cluster-init`·`cluster-status`(상호 TLS) · Makefile `bao-cluster-up|unseal|status|down` · 비커밋 `unsealer-init.json`·`cluster-init.json`·`cluster.env`(봉인 토큰, 포장·해제 전용 주기 토큰)·`cluster-api.env`
- `app/openbao.py` — `OPENBAO_ADDR` 다중 주소: 연결 거부·이름 없음·503·307 = 미처리 → 다음 노드, 전 노드 미처리면 1 s 쉬고 최대 3바퀴, 시간 초과는 재전송 없음(발급 중복 방지) · `OPENBAO_CA_FILE`·`OPENBAO_CLIENT_CERT`·`OPENBAO_CLIENT_KEY`(파일이 바뀌면 다시 읽음) · 상태에 응답 노드·standby·tls
- `aegis/i18n.py`(언어 결정 + 다른 모듈 메시지 en 패턴) · `aegis/cli.py` 출력·도움말 한/영, `--lang` 은 어느 자리든 · `aegis/__main__.py` 파이프 끊김(`| head`) 조용히 종료 · `test/test_cli_i18n.py` 4 · `test/test_openbao.py` 장애 조치 1

## 케이스 / Cases
| id | 결과 | 비고 |
|----|------|------|
| C01 | PASS | `make test` 455 passed, 1 skipped(MDS 스냅숏 — Epic 54) |
| C02 | PASS | c02-bao-cluster-up.txt · c02-cluster-status-final.txt(봉인 해제기 shamir · 노드 transit·recovery · raft bao-1, bao-3, bao-2*) · c02-api-leases.txt(backend openbao · node bao-1 standby · tls true · 발급 → introspect active → revoke → inactive) |
| C03 | PASS | c03-tls.txt |
| C04 | PASS | c04-autounseal.txt(재기동 0.5 s) · c04-autounseal-cold.txt(기동 00:34:59 → 봉인 해제 00:35:00 → 리더 00:35:16) |
| C05 | PASS | round 3: c05-leases-r3.txt `ok 136 fail 0 gapsSec [1.7, 1.9]` · c05-election-r3.txt 리더 bao-3 정지 1 s 안 bao-1 리더 · 30 s 뒤 bao-3 자동 봉인 해제·재가입 |
| C06 | PASS | c06-leases-unsealer-down.txt `ok 19 fail 0` · 재기동 노드 "Error parsing Seal configuration … no such host" 재시작 반복 · c06-recover.txt 봉인 해제기 해제(00:40:59) → 00:41:00 전원 봉인 해제 |
| C07 | PASS | c07-cli-en.txt · test_cli_i18n(en 명령·도움말 한글 0, ko 기본·환경 변수·플래그 우선, a2a 메시지) |

## 회차 / Rounds
- round 1: 리더 정지 순간 대기 노드가 307(리다이렉트) → POST 는 따라가지 않아 1건 실패 → 307 도 미처리로 보고 다음 노드
- round 2: 선출 중엔 두 대기 노드가 모두 307 → 한 바퀴로 부족 → 전 노드 미처리면 1 s 쉬고 최대 3바퀴 → round 3 실패 0
- round 3: 정식 `make bao-cluster-up` 에서 configure 가 대기 노드 `sys/health` 429(standby) → `standbyok=true` · 재빌드 후 통과

## 9차 완료 게이트
| 항목 | 결과 |
|------|------|
| `make test` | 456 passed (logs/make-test-final.txt) |
| `make test-web` | 17 passed + tsc |
| `make contract-update` | 223 작업 |
| `make e2e-passkey` | 15/15 (geo 바꾼 뒤 새 위치 재인증 흐름 회귀 없음) |
| `make e2e-a11y` 전 경로 | gate-a11y-full/: 254쪽 serious·critical 0 · 키보드·인증 53/53 · 재배치 320px·글자 간격·글자 200% 128/128 · en 한글 0. 앞선 두 번은 실패 — `/domains/d8/context` 추적 칩 target-size(링크 24px 로), 헤더 테넌트 선택 상자 폭(긴 시험 테넌트 이름 → `max-w-48`), D5-03 새 근거 문구 en 누락(카탈로그) |
| prod 회귀 | `prod-build`(엄격, MDS 캐시) → 0021 → db-ping postgres OK → prod-smoke9-final.txt: health·평문 거부·원장 검증 157만·DR·TLS·KMS·판정·계약·OTLP·격리·외부 복사·신원·MDS 290·지오·OpenBao 클러스터 모두 정상 |
| prod SPIRE | `make spire-up ENV=prod` → uid 10001 선택자·관리 소켓 그룹 0·등록 86·ES256 발급·검증 → `spire-down` builtin 복귀 |
| 정리 | `make bao-cluster-down` → api secrets builtin · `make prod-stop` |

## 남은 것 / Notes
- 봉인 해제기는 같은 호스트의 리허설 — 운영은 클라우드 KMS·HSM 또는 별도 사이트 봉인 해제기, Shamir 키 보관자 분리.
- 봉인 해제기가 없으면 재기동 노드는 봉인 상태로도 뜨지 않는다(OpenBao 2.4 동작) — 봉인 해제기 가용성이 클러스터 재기동 조건.
- 저장 암호화 KEK(KMS_BACKEND=openbao)는 클러스터에서도 같은 transit 경로지만 리허설 api.env 에는 켜지 않았다(클러스터를 내리면 그 동안 포장한 DEK 를 못 연다).
