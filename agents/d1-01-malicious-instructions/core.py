"""D1-01 악성 지시 주입(간접 프롬프트 인젝션) — 출처 신뢰 등급 + 지시 패턴. 순수 함수."""
from aegis.decide import decide

KINDS = {"override": "이전 지시 무시 요구", "persona": "역할 재정의", "covert": "사용자 은폐 요구",
         "action": "외부 전송·송금 행동 유도", "role-marker": "시스템/역할 구분자 위조", "new-instructions": "새 지시 선언"}
RULES = {f"D1-01.{k}": f"untrusted 컨텍스트 조각에 {v}. 데이터가 지시로 해석될 위험 → 차단." for k, v in KINDS.items()}
RULES["D1-01.classifier"] = "규칙에 걸리지 않은 untrusted 조각을 소형 분류기가 지시 주입으로 판단(경보 임계 이상). 경보 — 사람 검토."
RULES["D1-01.classifier-block"] = "소형 분류기 점수가 차단 임계 이상. 데이터가 지시로 해석될 위험 → 차단."
RULES["D1-01.pass"] = "untrusted 조각에서 지시 패턴 미검출(규칙·분류기)."
VERDICT = {k: "block" for k in KINDS} | {"classifier": "alert", "classifier-block": "block"}   # 이중 판정(OQ4)


def detect(req, engine):
    return decide("D1-01", engine.scan(req), VERDICT, rules=len(KINDS) + (1 if engine.id == "spotlight_classifier" else 0))
