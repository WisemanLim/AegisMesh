# 시험 결과 / Test Result — impl 54th (Epic 54 보안 키 증명 체인)
- 일자: 2026-10-08 · 대상: local + prod 리허설, FIDO MDS3 BLOB no 290(2026-10, 이미지 빌드 고정 판) · 커밋: —

## 요약 / Summary
- 전체 5, 통과 5, 실패 0 → 최종 **PASS** (재시도 2회: MDS 요청 제한 대기 / E2E 의 가상 인증기 AAGUID 확보 순서)
- 빌드 때 MDS3 검증: 서명자 `CN=mds.fidoalliance.org`(EV) → GlobalSign GCC R46 EV TLS CA 2025 → GlobalSign Root R46 → **GlobalSign Root CA - R3(sha256 고정)** · CRL 3단계 폐기 없음 · 348 기종(AAGUID) · 유출/우회 보고 1(TruU Windows Authenticator — REVOKED) · 0.05 s
- 변조 5종(본문 세탁·서명·루트 교체·meta 해시·스냅숏 없음) 모두 `python -m app.fido verify` exit 1 = 빌드 실패
- 콘솔 E2E 7/7: 허용목록 없는 테넌트 = 소유 증명만(가상 인증기 등록) · 허용목록 테넌트에서 가상 인증기(packed, AAGUID 0102…)는 **허용목록에 그 AAGUID 를 넣어도** FIDO MDS 체인이 없어 거부(`mds_unknown`) — 자기 신고 AAGUID 로는 통과 못 한다
- `make test` 통과(test_fido 5 — 실제 스냅숏 1 포함)

## 구현
- `app/fido.py` — MDS3 BLOB: JWS(RS256·ES256) · x5c 체인(유효 기간·발급자 서명·CA) → 고정 루트 지문 · 서명자 이름(fidoalliance.org) · 빌드 때 CRL · AAGUID 색인(설명·증명 유형·루트·상태) · `read_dir`/`load`(프로세스 캐시, 실패 = 닫힌 실패) · `status` · packed 증명: 서명(authData‖clientDataHash, ES·RS·EdDSA) · 증명서 요건(v3·OU·CA 아님) · AAGUID 확장(1.3.6.1.4.1.45724.1.1.4) = 신고 AAGUID · MDS 상태(REVOKED·USER_VERIFICATION_BYPASS·*_COMPROMISE 거부) · 체인 → 해당 기종 attestationRootCertificates · none·자기 증명·그 밖의 형식 거부
- `app/mfa.py` — 허용목록 테넌트: AAGUID 허용 + 증명 체인 검증, 원장 `mfa_rejected` 사유 코드·`mfa_enrolled` 에 증명 결과(기종·루트·인증 등급). 허용목록 없는 테넌트: MDS 가 유출·우회를 보고한 기종만 거부 · `app/webauthn.py` 등록 검증이 증명문·authData·clientDataHash 를 넘김
- `scripts/fetch_mds.py`(표준 라이브러리, Retry-After·BuildKit 캐시 7일·실패 시 캐시 사본) · Dockerfile `mds` 스테이지(`FIDO_MDS_SNAPSHOT`, 받기 → `verify --crl`, 실패 = 빌드 실패, `FIDO_MDS_OPTIONAL=1` 명시 때만 받기 실패를 넘김) · `GET /v1/auth/mds` · 콘솔 등록 거부 사유 en 카탈로그 · `test/test_fido.py` 5

## 케이스 / Cases
| id | 결과 | 비고 |
|----|------|------|
| C01 | PASS | `make test` · test_fido 5(합성 PKI 4 + 이미지 스냅숏 1) |
| C02 | PASS | c02-mds-build.txt — `{"ok": true, "no": 290, "nextUpdate": "2026-11-01", "entries": 348, "flagged": 1, … "crl": [3 × revoked false]}` · 이후 빌드는 캐시 사본(`"source": "cache"`) |
| C03 | PASS | c03-tamper.txt — pristine exit 0 · payload laundered `mds_signature` · signature altered `mds_signature` · pinned root replaced `mds_root` · meta hash `mds_format` · missing `mds_missing` (모두 exit 1) |
| C04 | PASS | local·prod `GET /v1/auth/mds` loaded·290·348·flagged 1·stale false · c04-snapshot-summary.txt(YubiKey 5 Series basic_full, 루트 1) · prod 스모크 Epic 54 줄 |
| C05 | PASS | e2e54-attest.txt 7/7 · 원장 `[('mds_unknown','packed'), ('aaguid_not_allowed','packed')]` · c05-enroll-*.png |

## 회차 / Rounds
- round 1: MDS 가 같은 IP 의 반복 요청을 429 로 막음(약 1시간). 받기에 재시도·BuildKit 캐시(7일)·캐시 사본 대체를 넣고, 20분 간격 1회 시도 → 00:55 성공. 그동안 55·56 은 `FIDO_MDS_OPTIONAL=1`(명시) 이미지로 진행, 성공 뒤 엄격 모드로 local·prod 재빌드
- round 2: E2E — Chrome 가상 인증기는 attestation none 이면 AAGUID 를 0 으로 가림 → 허용목록 테넌트의 첫 거부 기록에서 실제 AAGUID 를 얻어 허용목록에 넣고 다시 등록 → 체인 검증 거부 확인

## 남은 것 / Notes
- 실제 하드웨어 보안 키의 통과 경로는 합성 PKI 단위 시험으로만 확인(이 환경에 실물 키 없음) — 실물 확인은 수동.
- packed 만 지원(TPM·android-key·apple 은 거부) — 허용목록 테넌트는 보안 키 전용 정책이라는 전제.
- MDS3 는 매달 갱신(nextUpdate 2026-11-01) — 지나면 상태 API `stale: true`, 새 판은 `FIDO_MDS_SNAPSHOT` 을 바꿔 재빌드(캐시 7일 이후 다시 받음).
