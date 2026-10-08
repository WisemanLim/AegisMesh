# 시험 결과 / Test Result — impl 60th (Epic 60 발견 버스 NATS)
- 일자: 2026-10-08 · 대상: local + prod 리허설, NATS 2.11.9(JetStream) · 커밋: —

## 요약 / Summary
- 전체 7, 통과 7, 실패 0 → 최종 **PASS** (재시도 3회: 중계 처리량 / prod 키 고리 미연결 / env 파일 줄바꿈)
- 원장 seq 를 커서로 비허용 발견·사건·인증 보안 이벤트를 JetStream `AEGIS` 에 게시 — `aegis.findings.<tenant>.<verdict>` · `aegis.incidents.<tenant>` · `aegis.auth.<tenant>`, 요약만(입력 원문·근거 메모·사용자 이름 없음)
- **누락 0**: 중계를 멈춘 채 판정 1,539건 → 재개 뒤 원장 기대 416 = 스트림 증가 416 · **중복 0**: 커서를 3,000 되감아 107건 재전송 → 전부 `duplicate`(Nats-Msg-Id = 원장 ID), 스트림 증가 0
- NATS 재기동 뒤 934건 보존 · 새 지속 소비자 `audit` 가 934/934 재생 · 소비자 `siem` 은 확인한 곳 다음부터
- prod: 평문 접속 `tls_required`·CONNECT 끊김 · 인증서 없는 TLS `TLSV13_ALERT_CERTIFICATE_REQUIRED` · 내부 CA 인증서로 중계 846건·지연 0·소비 OK

## 구현
- `app/bus.py` — 표준 라이브러리 NATS 클라이언트(TCP·TLS, PUB/HPUB/SUB/MSG/HMSG/PING, 요청/응답·풀 소비) · JetStream 스트림 보장(파일·보존 BUS_MAX_AGE_DAYS·중복 창 2분) · 원장 → 메시지 · 중계(확인 뒤 커서, 밀려 있으면 쉬지 않음) · 상태 · 소비 예(`tail`)
- 마이그레이션 0023 `bus_cursors` · `GET /v1/evidence/bus` · compose local·prod 프로파일 `bus`(nats·bus-relay, prod 는 상호 TLS `infra/nats/nats-prod.conf`·인증서 말단 nats) · Makefile `bus-up|bus-down|bus-tail [ENV=prod]` · env `BUS_URL`·`BUS_START`·`BUS_MAX_AGE_DAYS` · `test/test_bus.py` 2

## 케이스 / Cases
| id | 결과 | 비고 |
|----|------|------|
| C01 | PASS | test_bus 2 · `make test`(게이트) |
| C02 | PASS | c02-bus-up.txt |
| C03 | PASS | c03-status.txt → 따라잡은 뒤 지연 0·517건 |
| C04 | PASS | c04-tail.txt — 5건 뒤 다음 3건이 이어서 |
| C05 | PASS | c05-outage.txt `expected new messages 416` · `stream delta 416` · c05-dup.txt `published 63, duplicates 63` · `44/44`, 스트림 934 |
| C06 | PASS | c06-restart.txt 934 · `replayed by new durable 'audit': 934` |
| C07 | PASS | c07-prod.txt — 부하 308 rps 오류 0 · 846건 · TLS 거부 2종 |

## 회차 / Rounds
- round 1: 중계가 묶음 500 · 매번 1초 쉼 → 판정 부하(초당 발견 수백)를 못 따라감 → 묶음 2000, 밀려 있으면 쉬지 않음
- round 2: prod 중계가 원장 본문 복호화 실패(`키 고리에 KEK 버전 2 없음`) — bus-relay 에 appdata 볼륨(키 고리) 읽기 전용 연결, 중계 루프는 모든 예외를 기록하고 재시도
- round 3: `make bus-up ENV=prod` 의 TLS env 가 `\n` 문자 그대로 → printf `%b`

## 남은 것 / Notes
- 소비 쪽(SIEM) 연동은 예시(`make bus-tail`) — 실제 SIEM 은 같은 지속 소비자 방식으로 붙인다(주제 필터·확인).
- 중계는 원장 쓰기 뒤 비동기 — 지연은 부하에 따라 수 초(따라잡으면 0).
