# 시험 시나리오 / Test Scenario — impl 41st (Epic 41 OpenBao 시크릿 백엔드)
- 근거: 원본 PRD §1.3 발견 6(동적 시크릿은 OpenBao/Vault 연동이 표준, Vault BUSL 은 기본값 제외 MSG-027) · FR-P07(호출 단위·최소 범위·짧은 수명 임대) · 계획표 41 수용 기준 "compose `bao` 프로파일, 동적 시크릿 임대를 OpenBao 로(내장 브로커 대체 가능), 회수·만료 동작".
- 방식: `SECRETS_BACKEND=openbao` 면 임대 원문 = OpenBao 서비스 토큰(토큰 역할 `aegis-lease`: orphan·갱신 가능·`token_explicit_max_ttl` = SECRET_LEASE_MAX_SEC, 정책 `aegis-lease-holder` = lookup-self 만). 범위·테넌트·경로·보유자는 토큰 meta. AegisMesh 는 접근자(accessor)·해시만 보관하고, 확인(introspect)은 OpenBao 에 묻는다(연결 불가 = 거부). 브로커 토큰은 정책 `aegis-broker`(역할로 만들기 + accessor 조회·갱신·회수만) — 루트 토큰은 `make bao-up` 구성에만.
- 환경: local compose `bao` 프로파일(openbao/openbao:2.4.1 dev 서버, 127.0.0.1:8210) · `make bao-up` / `make bao-down` · plat.admin · 테넌트 garam

| id | 목적 | 입력 | 기대 | 우선 |
|----|------|------|------|------|
| T41-01 | 구성 | `make bao-up` | 정책 2·토큰 역할·브로커 토큰(비커밋 env) · api·worker 재기동 → 백엔드 openbao 정상 | P0 |
| T41-02 | 발급 | 임대 ttl 7200 | 원문 = OpenBao 토큰(s.…) · 15분 절단 · meta(lease·tenant·path·scopes·holder) · 접근자 비공개 | P0 |
| T41-03 | 최소 권한 | 보유자가 임대 토큰으로 OpenBao 호출 | lookup-self 만 200, 정책 조회 403 | P0 |
| T41-04 | 확인·범위 | introspect db:read / db:write | 활성 + ttl / 범위 밖 거부 | P0 |
| T41-05 | 갱신 상한 | renew · 생성 뒤 반복 갱신 | OpenBao renew-accessor, 생성 시각 기준 15분을 넘지 않음 | P0 |
| T41-06 | 회수 | revoke | OpenBao 에서 토큰 사라짐(보유자 403) · introspect revoked | P0 |
| T41-07 | 원본 = OpenBao | OpenBao 에서 직접 회수 | introspect 거부 + 목록 revoked(by openbao) + 원장 | P0 |
| T41-08 | 만료 | ttl 30초 | 30초 뒤 OpenBao 토큰 없음(보유자 403) · introspect expired | P1 |
| T41-09 | 장애 | OpenBao 중지 | 확인 거부(fail-closed) · 발급 503 · 상태 ok=false | P0 |
| T41-10 | 재기동·복귀 | dev 재기동 + 재구성 · `make bao-down` | 옛 임대 거부·새 임대 정상 · 내장 브로커 복귀, OpenBao 임대는 계속 거부 | P1 |
| T41-11 | 콘솔 | /admin/identity ko·en | 임대 엔진 상태 · 임대별 엔진 · 'OpenBao 회수' 표시 · 접근성 위반 0 · en 한글 0 | P1 |
| T41-12 | 회귀 | pytest(가짜 OpenBao 4건 포함) | 전체 통과 | P0 |
