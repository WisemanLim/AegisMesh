"""D6-02 재귀 행동 — 깊이·팬아웃·순환은 차단, 생성 예산 소진은 승인."""
from aegis.decide import decide

RULES = {"D6-02.depth": "호출 깊이 상한(maxDepth) 도달. 차단.", "D6-02.fanout": "하위 에이전트 생성 수가 팬아웃 상한. 차단.",
         "D6-02.cycle": "계보에 이미 있는 에이전트를 다시 생성(순환). 차단.", "D6-02.budget": "생성 예산 소진. 사람 승인.",
         "D6-02.pass": "깊이·팬아웃·계보 검사 통과."}


def detect(req, engine):
    return decide("D6-02", engine.scan(req), {"depth": "block", "fanout": "block", "cycle": "block", "budget": "require_approval"}, rules=4)
