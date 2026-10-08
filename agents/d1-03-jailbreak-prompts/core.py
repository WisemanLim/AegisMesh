"""D1-03 탈옥 프롬프트 — 코퍼스 매칭은 차단, 적대 접미사 휴리스틱은 경보(오탐 위험)."""
from aegis.decide import decide

KINDS = ["dan", "dev-mode", "no-rules", "persona", "fiction-wrapper", "ko-jailbreak", "encoded", "override", "ko-override",
         "prompt-extraction"]
RULES = {f"D1-03.{k}": f"탈옥 코퍼스 유형 '{k}' 매칭(leetspeak 정규화 후). 차단." for k in KINDS}
RULES["D1-03.adversarial-suffix"] = "GCG 계열 적대 접미사 형태. 휴리스틱이라 경보만."
RULES["D1-03.classifier"] = "코퍼스 규칙에 걸리지 않은 입력을 전용 분류기가 탈옥·지시 덮어쓰기로 판단(경보 임계 이상). 경보 — 사람 검토."
RULES["D1-03.classifier-block"] = "전용 분류기 점수가 차단 임계 이상. 차단."
RULES["D1-03.model"] = "주입 분류 모델(인라인, 입력 앞·뒤 창)이 지시 주입으로 판단(경보 임계 이상). 경보 — 사람 검토."
RULES["D1-03.model-block"] = "주입 분류 모델 점수가 차단 임계 이상. 차단."
RULES["D1-03.guard"] = "안전 분류 모델(Qwen3Guard-Gen)이 입력을 위험(유해 의도·탈옥 포장)으로 판단 — 응답 후 깊은 검사라 경보만."
RULES["D1-03.pass"] = "탈옥 코퍼스·인코딩·접미사·분류기 검사 통과."
VERDICT = {**{k: "block" for k in KINDS}, "adversarial-suffix": "alert", "classifier": "alert", "classifier-block": "block", "guard": "alert",
           "model": "alert", "model-block": "block"}
EXTRA = {"jailbreak_classifier": 1, "jailbreak_guard": 2, "injection_model": 2}          # 규칙 외 검사 수(분류기·안전 분류 모델)


def detect(req, engine):
    return decide("D1-03", engine.scan(req), VERDICT, rules=len(KINDS) + 1 + EXTRA.get(engine.id, 0))
