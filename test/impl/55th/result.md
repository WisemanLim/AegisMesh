# 시험 결과 / Test Result — impl 55th (Epic 55 지오 IP·불가능한 이동)
- 일자: 2026-10-08 · 대상: local + DB-IP IP to City Lite 2026-10(이미지 고정 판) · 커밋: —

## 요약 / Summary
- 전체 5, 통과 5, 실패 0 → 최종 **PASS** (재시도 2회: DB-IP 도시명 단위 / E2E 스크립트 경합)
- 고정 판: `ADD --checksum=sha256:c839d407…b14` — 틀린 해시는 `digest mismatch` 로 빌드 실패, 실행 중 네트워크 없음
- 실제 DB 로 콘솔 E2E **14/14**: 대도시권(23 km, 경기 성남 → 서울 용산) 망 전환은 재인증 없음 · 서울 → 미국 캘리포니아 9,080 km 를 수 초 만에 = **✈ 불가능한 이동** → 재인증·D5-03 경보·원장 · 세션 사이(살아 있는 미국 세션 → 곧바로 국내 로그인)도 같은 판단
- 사설망(RFC 1918·CGNAT 등)·문서용 대역·DB 미등재는 지오 없이 기존 /24·/48 대역 규칙 · `make test` 454+ passed

## 구현
- `app/geo.py` — DB-IP Lite(`maxminddb`)로 IP → 나라·시도·도시·좌표, 분류(public·private·unknown), 표시 = 나라 · 시도, 새 위치(다른 나라 또는 `GEO_SAME_PLACE_KM` 100 km 밖, 지오 없으면 대역), 불가능한 이동(거리 ≥ `GEO_TRAVEL_MIN_KM` 500 km 이고 속도 > `GEO_TRAVEL_MAX_KMH` 900 km/h), 상태
- `app/mfa.py` — 로그인 결속 때 같은 사용자의 다른 활성 세션이 마지막으로 본 지점과 비교(세션 사이), 요청마다 세션 지점과 비교(세션 안), 대도시권 안 이동은 지점·시각만 갱신. 재인증이 새 지점으로 다시 묶는다
- D5-03 v1.2.0 — 규칙 `impossible-travel`(경보, 지문 불일치와 겹치면 차단) · 공격 2·골든 1 추가 · `aegis/schemas.py` Session `travelKm`·`travelKmh`
- 마이그레이션 0021(`auth_sessions.geo`·`geo_lat`·`geo_lon`·`geo_at`) · `GET /v1/auth/geoip[?ip=]` · 세션 목록·`/v1/auth/me` 에 `geo`
- Dockerfile `geoip` 스테이지(`DBIP_MONTH`·`DBIP_SHA256`) · 콘솔 `/account` 세션 표 위치 = 나라 · 시도 + IP 대역, 사설망·미확인 표시, "IP Geolocation by DB-IP"(CC BY 4.0) · env `GEO_SAME_PLACE_KM`·`GEO_TRAVEL_MAX_KMH`·`GEO_TRAVEL_MIN_KM`

## 케이스 / Cases
| id | 결과 | 비고 |
|----|------|------|
| C01 | PASS | `make test` · test_geo 6(실제 DB 1 포함) · `aegis eval d5-03` golden 15 fp 0 · attacks 15 det 1.000 |
| C02 | PASS | 고정 해시 빌드 exit 0 · 틀린 해시 `digest mismatch sha256:c839d407…: sha256:0000…` exit 1 (logs/c02-*.txt) |
| C03 | PASS | `/v1/auth/geoip` loaded · 2026-10 · built 2026-10-01 · nodes 14,297,794 · 8.8.8.8 → US · California · 168.126.63.1 → KR · Gyeonggi-do · 10.1.2.3 private · 198.51.100.7 unknown |
| C04 | PASS | e2e55-geo.txt — 대도시권 통과 · ✈ KR · Seoul → US · California · 9,080 km / 0 min → /reauth → 비밀번호 재인증 → 계속 · 로그인 ✈ US · California → KR · Gyeonggi-do · 원장 impossible_travel ×2(alert) · 발견 D5-03.impossible-travel · session_anomaly 0 |
| C05 | PASS | c05-account-geo-ko.png — 위치 "KR · Seoul / 164.124.101.0/24", DB-IP 출처 표기 · c04-*.png 재인증 화면 |

## 회차 / Rounds
- round 1: DB-IP 도시명이 동 단위("Yongsan-dong (Hangang-daero)")라 '같은 도시' 비교가 너무 촘촘 → 표시는 나라 · 시도, 새 위치는 나라 변경 또는 100 km 밖(대도시권 안 이동은 망 전환)으로 변경
- round 2: E2E 12/14 — 재인증 제출 완료 전에 다음 화면으로 이동(경합), 화면 언어를 브라우저 locale 로 가정 → 스크립트 수정 후 14/14

## 남은 것 / Notes
- 도시 수준 DB 라 VPN·이동 통신 출구가 먼 곳이면 불가능한 이동으로 보일 수 있다 — 판단은 재인증·경보(차단 아님), 임계는 env 로 조정.
- 월간 판 교체 = `DBIP_MONTH`·`DBIP_SHA256` 을 함께 바꿔 재빌드(해시는 받은 파일로 확인).
- prod 회귀(마이그레이션 0021)는 완료 게이트에서.
