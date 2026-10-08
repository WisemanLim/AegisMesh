# 시험 결과 / Test Result — impl 18th (Epic 18 폐쇄망 번들·장터)
- 일자: 2026-10-06 · 대상: local (SQLite, 0008→0009) + prod 리허설 (PostgreSQL 17, 0009) + 무네트워크 컨테이너(`--network none`) · 커밋: —
- 브라우저: 헤드리스 Chromium (gstack browse) — plat.admin · plat.appr1 · plat.appr2 실제 로그인

## 요약 / Summary
- 전체 9, 통과 9, 실패 0 → 최종 **PASS** (재시도 1회: 거부 기록에 통과 단계 누락)
- `make test` **284 passed** (+ test_airgap 6, test_ledger 구간 시험 순서 독립화) · `make test-web` 7 + tsc · coverage 80/80 · ruff(F,E9) clean

## 케이스 / Cases
| id | 결과 | 비고 |
|----|------|------|
| T18-01 | PASS | 콘솔 키 등록 요청 → pending → plat.appr1 `1/2` → plat.appr2 `2/2` → rel-2026 active, 신뢰 번들 내보내기 (local·prod) |
| T18-02 | PASS | `docker run --network none`(연결 시도 “Network is unreachable”)에서 `aegis airgap verify` → signature·hash·sbom OK (CycloneDX 63개, 취약점 0) / 빈 신뢰 저장소 → `FAIL signature` exit 1 |
| T18-03 | PASS | 콘솔 업로드 → 서명✓ 해시✓ SBOM✓ 적용✓ — 프로파일 5 · 취약점 DB 2026.10.01 · 장터 등록 1 |
| T18-04 | PASS | 구성요소 변조 → 서명✓ 해시✗ “profiles/regulated-kr.yaml 해시 불일치”, 같은 keyId·다른 키 → 서명✗, 적용 0, 원장 bundle_rejected (prod 422) |
| T18-05 | PASS | pytest: 서명된 번들의 취약점 DB 가 설치된 의존성 버전을 critical 로 지정 → sbom 단계 차단 |
| T18-06 | PASS | 장터 x10@1.0.0(커뮤니티·Apache-2.0·L1) 설치 요청 → 설치 전 404 → 2인 승인 → 등록 심사(L1) → “설치됨”, judge transform `X10.aws-access-key` |
| T18-07 | PASS | pytest: 새 버전 반입 → 심사 후 1.0.0→1.1.0 무중단 교체 / 출처 미확인 게시자 → tier external → 설치 요청 403 (prod 에서도 미등록 게시자는 external) |
| T18-08 | PASS | `/v1/sbom` CycloneDX 1.5 142 구성요소(에이전트 80 포함) · 취약점 0, 콘솔 내려받기 `application/vnd.cyclonedx+json` attachment |
| T18-09 | PASS | 284 passed · prod 0009 · 신뢰 키 2인 승인 · 반입 4단계 · 변조 422 · SBOM 대조 |

## 발견 오류 및 수정 / Bugs & Fixes
| round | 오류 | 원인 | 수정 | 재시험 |
|-------|------|------|------|--------|
| 1 | 거부된 반입 기록에 앞서 통과한 단계(서명 ✓)가 빠짐 | BundleError 가 실패 단계만 전달 | 통과 단계 목록을 예외에 실어 기록·표시 | round 2 “✓ ✗ · ·” |
| — | test_ledger 구간 내보내기 시험 실패(전체 실행 시) | 전역 seq 3~6 가 default 체인이라는 가정 — 새 시험이 플랫폼 체인 기록을 먼저 남김 | 체인 레코드에서 구간을 골라 시험(순서 독립) | 284 passed |
| — | 무네트워크 검증 컨테이너에 구 코드 | local 이미지는 소스 바인드 전제 | 소스를 읽기 전용으로 마운트해 실행 | PASS |

## 설계 결정 기록
- 번들 = tar.gz(bundle.json 서명 매니페스트 + 구성요소 + CycloneDX SBOM). 경로 탈출·링크·목록 외 파일 거부, 50MB 한도. 서명 키는 내부 신뢰 저장소만(외부 조회 없음), 추가·폐기는 2인 승인.
- 적용 대상: 프로파일·내부 취약점 DB·서드파티 에이전트 번들(설치된 것은 심사 후 롤링 교체, 새것은 장터). 컨테이너 이미지·헬름 차트 미러(Harbor)는 이 설치 범위 밖 — 이미지는 `make prod-build` 경로.
- 장터 신뢰 등급 = 게시자 키 등급(official·partner·community), 미등록 게시자는 external(설치 불가). 설치 = 2인 승인 → 등록 심사 R1~R5(L1 재생).
- 취약점 DB 비교는 정확한 버전 목록 일치(범위 해석 없음). 서명 검증된 번들의 더 새 DB 를 기준으로 쓴다.

## 첨부 / Logs
- logs/ (비커밋): t18-*.txt, rel-1.0.0·tampered·rogue 번들, trust.json, sbom-download.json, 스크린샷
