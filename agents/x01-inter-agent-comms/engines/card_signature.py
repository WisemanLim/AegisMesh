"""기본 엔진: 에이전트 간 통신 신뢰 (FR-X01) — A2A AgentCard Ed25519 서명 실검증 + MCP 서버 인증서 지문 고정.
params.peer = {kind: a2a|mcp, card, signature, keyId, pinnedFingerprint, presentedFingerprint, tls}
params.trustedKeys = {keyId: base64 공개키}"""
import base64
import json

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from aegis.engine import Signal
from aegis.schemas import EvidenceItem, JudgeRequest

id = "card_signature"


def canonical(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def scan(req: JudgeRequest) -> list[Signal]:
    peer = req.params.get("peer")
    if not peer:
        return []
    out: list[Signal] = []

    def sig(rule, score, note, loc="params.peer"):
        out.append(Signal(rule=rule, score=score, severity="critical", evidence=EvidenceItem(kind="peer", location=loc, note=note)))

    if peer.get("tls") is False:
        sig("plaintext", 0.94, "에이전트 간 평문 통신(상호 TLS 없음)")
    if peer.get("kind", "a2a") == "a2a" and isinstance(peer.get("card"), dict) and peer["card"].get("signatures"):
        # A2A v1.0 AgentCard — signatures[] 분리형 JWS(EdDSA) over 정규 JSON(카드 − signatures)
        from aegis.adapters.a2a import verify_card
        trusted = {k: Ed25519PublicKey.from_public_bytes(base64.b64decode(v)) for k, v in req.params.get("trustedKeys", {}).items()}
        v = verify_card(peer["card"], trusted)
        if not v["ok"]:
            rule = {"unsigned": "unsigned-card", "untrusted": "untrusted-key"}.get(v["reason"], "bad-signature")
            sig(rule, {"unsigned-card": 0.95, "untrusted-key": 0.94}.get(rule, 0.98), v["detail"], "params.peer.card.signatures")
    elif peer.get("kind", "a2a") == "a2a":
        card, s64, kid = peer.get("card"), peer.get("signature"), peer.get("keyId")
        if not card or not s64:
            sig("unsigned-card", 0.95, "AgentCard 서명 없음")
        else:
            pub = req.params.get("trustedKeys", {}).get(kid)
            if not pub:
                sig("untrusted-key", 0.94, f"신뢰 저장소에 없는 서명키 {kid}")
            else:
                try:
                    Ed25519PublicKey.from_public_bytes(base64.b64decode(pub)).verify(base64.b64decode(s64), canonical(card))
                except (InvalidSignature, ValueError):
                    sig("bad-signature", 0.98, "AgentCard 서명 검증 실패(변조)")
    if peer.get("pinnedFingerprint") and peer.get("presentedFingerprint") != peer["pinnedFingerprint"]:
        sig("pin-mismatch", 0.97, "서버 인증서 지문이 고정값과 다르다(중간자 의심)", "params.peer.presentedFingerprint")
    return out
