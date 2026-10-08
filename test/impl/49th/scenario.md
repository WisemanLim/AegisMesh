# 49th — 저장 암호화 (Epic 49 · NFR-D2)

근거: 원본 PRD NFR-D2 "증적·설정·시크릿 전 구간 암호화. 키는 외부 관리 시스템 위임", 8차 확인 질문(OpenBao transit + 내장 대체).
범위: 증적 원장 본문·정책 본문·프로파일 명세·발견 본문·승인 요약·승인 결정 사유·트래픽 표본·골든 표본(값 단위 봉투 암호화) · 2단계 OTP 비밀 · 원장/SVID 서명 키·세션 서명 비밀 파일.
제약: 원장은 추가 전용(UPDATE 거부 트리거) → 암호화 전 원장 기록은 그대로 두고 보존기한 삭제로만 사라진다. 비밀 값·DEK 는 출력하지 않는다.

| id | 목적 | 입력 | 기대 | 우선 |
|----|------|------|------|------|
| C01 | 단위 회귀 | `make test` | 전부 통과 (`test/test_kms.py` 9건) | P0 |
| C02 | transit 위임 (운영형 OpenBao) | `make bao-up MODE=server` → 일회용 DB 에 KMS_BACKEND=openbao 로 시드·카나리 기록 | 모든 대상 열·키 파일이 `vault:v1` 포장 DEK, DB 파일에 카나리 0 | P0 |
| C03 | KEK 회전 (transit) | `make bao-rotate-kek MODE=server` → 새 기록 · `kms rewrap` | 새 기록 `openbao:v2`, 옛 기록 그대로 열림, 수정 가능한 표 전부 v2, 원장 검증 OK | P0 |
| C04 | 최소 권한 | 브로커 토큰으로 transit 회전·키 읽기 | 거부(403) | P0 |
| C05 | KMS 봉인 시 닫힘 | OpenBao 봉인 → 새 프로세스가 암호화된 기록 읽기 → 봉인 해제 → 다시 읽기 | 봉인 중 KmsError(실패 시 닫힘) · 해제 후 정상 | P0 |
| C06 | 감사 | OpenBao 감사 로그 | transit encrypt·decrypt 기록, 요청·응답 값은 HMAC | P1 |
| C07 | prod 기동·옛 데이터 | `make prod-build` | 옛 평문 기록 정상 읽힘, 새 기록 암호화, 키 파일 3종 포장본으로 전환, 원장 검증 OK | P0 |
| C08 | 덤프·백업 평문 0 | prod 에 카나리를 모든 대상 열에 기록 → `pg_dump` · 기본 백업 + 보관 WAL | 카나리 0 건 | P0 |
| C09 | 재암호화·builtin 회전 | `make kms-rewrap ENV=prod ROTATE=1` | 수정 가능한 표 전부 builtin:v2(옛 평문 포함), 원장 검증 OK | P0 |
| C10 | 성능 | `make loadtest ENV=prod` | 오류 0, 관문 실행 p95 예산 이내(48th 261 rps 대비 기록) | P1 |
| C11 | 복구 회귀 | `make db-restore-drill ENV=prod` | 복원 DB 의 암호화 기록 검증 통과(키 고리는 appdata — DB 백업과 분리) | P1 |
| C12 | 콘솔 | `/observability` ko·en (local) · prod 카드 | KMS 카드, en 한글 0, 접근성 위반 0 | P1 |
