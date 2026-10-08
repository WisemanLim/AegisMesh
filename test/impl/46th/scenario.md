# 시험 시나리오 / Test Scenario — impl 46th (Epic 46 OpenBao 운영형 리허설)
- 근거: FR-P07 · 원본 §1.3 발견 6 · 41차 남은 것(dev 서버는 메모리 저장 — 재기동하면 임대가 사라짐, 운영 클러스터 리허설 없음).
- 방식: compose `bao-server`(프로파일 bao-server) = OpenBao 2.4.1 서버 모드 · raft 통합 저장소(`baodata` 볼륨) · 감사 장치는 설정으로 선언(`infra/openbao/config.hcl`, 2.4 는 API 로 켤 수 없음) · `make bao-up MODE=server` = 초기화(키 3·임계 2 → 비커밋 `infra/openbao/init.json`) → 봉인 해제 → 리더 대기 → 정책·토큰 역할·브로커 토큰 · `make bao-unseal` = 재기동 뒤 봉인 해제. api 는 브로커 토큰만(루트는 구성에만).
- 환경: local compose · plat.admin · garam

| id | 목적 | 입력 | 기대 | 우선 |
|----|------|------|------|------|
| T46-01 | 초기화·봉인 해제 | `make bao-up MODE=server` | init.json(600)·sealed false·감사 장치 file/·api.env(openbao·bao-server) | P0 |
| T46-02 | 최소 권한 | 브로커 토큰 조회 | 정책 aegis-broker(+default)·주기 토큰·orphan, 루트 아님 | P0 |
| T46-03 | 재기동 = 봉인 | OpenBao 재기동 | 상태 sealed true·ok false · 확인 거부 · 발급 503 · 콘솔 '봉인됨' 문구 | P0 |
| T46-04 | 저장 유지 | `make bao-unseal` | 재기동 전에 발급한 임대가 다시 유효(보유자 lookup-self 200) | P0 |
| T46-05 | 회수 | revoke | 보유자 403 | P1 |
| T46-06 | 감사 | 감사 로그 | 발급·조회·회수 요청 기록 · 임대 원문 없음(HMAC) | P0 |
| T46-07 | 시험 격리 | bao-up 상태에서 `make test` | 시험이 OpenBao 설정을 물려받지 않음 · 전부 통과 | P1 |
