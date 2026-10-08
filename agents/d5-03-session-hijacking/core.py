"""D5-03 세션 탈취 — 소유 증명 없는 바인딩 토큰 재사용·장치 지문 불일치는 차단, 불가능한 이동·IP 변경은 경보."""
from aegis.decide import decide

RULES = {
    "D5-03.token-replay": "소유 증명(DPoP·mTLS)에 묶인 토큰을 증명 없이·다른 키로 사용. 탈취 토큰 재사용 → 차단·세션 전체 폐기.",
    "D5-03.fingerprint-mismatch": "세션 발급 장치 지문과 현재 지문이 다르다. 탈취 의심 → 차단·재인증.",
    "D5-03.impossible-travel": "마지막으로 본 위치에서 지금 위치까지 물리적으로 갈 수 없는 속도(지오 IP). 자격 증명 공유·탈취 의심 → 재인증·경보.",
    "D5-03.ip-change": "같은 장치, 다른 IP. 망 전환일 수 있어 경보.",
    "D5-03.pass": "세션 결속 유지.",
}


def detect(req, engine):
    return decide("D5-03", engine.scan(req), {"token-replay": "block", "fingerprint-mismatch": "block", "impossible-travel": "alert",
                                                   "ip-change": "alert"}, rules=4)
