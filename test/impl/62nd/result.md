# 시험 결과 / Test Result — impl 62nd (Epic 62 TPM·android-key 증명)
- 일자: 2026-10-08 · 대상: local, 합성 PKI(실물 장치 없음) + 실제 MDS3 no 290 · 커밋: —

## 요약 / Summary
- 전체 3, 통과 3, 실패 0 → 최종 **PASS** (재시도 0)
- 허용목록 테넌트가 받을 수 있는 증명 형식 = packed · **tpm(TPM 2.0)** · **android-key** — 형식별 검증 뒤 같은 MDS 체인·AAGUID 확장·상태 검사
- android-key 거부 5종(challenge·allApplications·가져온 키·서명 용도 아님·다른 키) · tpm 거부 6종(extraData·name·pubArea 키·서명 키·EKU 없음·ver) 모두 기대 사유 코드
- 실제 MDS3 에 Windows Hello Hardware·VBS Hardware Authenticator(attca)·Android Authenticator(루트 45) 등 10 기종 — 이제 허용목록에 넣으면 체인으로 확인된다

## 구현
- `app/fido.py` — 형식 분기(`_packed`·`_tpm`·`_android_key`), 최소 DER 읽기(높은 태그 번호·긴 길이), AuthorizationList(문맥 태그 1·600·702), TPMT_PUBLIC(RSA·ECC P-256)·TPMS_ATTEST 파서, RS1(-65535) 해시, 자격 증명 키 비교 · 콘솔 en 카탈로그 사유 문구 · `test/test_fido.py` +2

## 케이스 / Cases
| id | 결과 | 비고 |
|----|------|------|
| C01 | PASS | c01-test-fido.txt — 7 passed(android_key·tpm 포함) |
| C02 | PASS | c02-mds-tpm-android.txt — 10 기종 |
| C03 | PASS | packed 시험 그대로 · 미지원 형식 fido-u2f → attestation_format · `make test`(게이트) |

## 남은 것 / Notes
- 실물 Windows Hello·Android 기기로 등록하는 통과 경로는 수동 확인 대상(이 환경엔 TPM·안드로이드 기기 없음).
- android-key 는 TEE 강제 목록(teeEnforced)을 요구 — 소프트웨어 키 저장소만 있는 기기는 거부된다(허용목록 = 하드웨어 키 정책 전제).
- apple(익명 증명)·fido-u2f(AAGUID 없음)는 AAGUID 허용목록과 맞지 않아 계속 거부.
