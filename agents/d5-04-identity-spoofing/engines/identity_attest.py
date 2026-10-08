"""기본 엔진: 워크로드 신원 증명 대조 + 입력 속 신원 사칭 (FR-D5-04)."""
import re

from aegis.engine import Signal
from aegis.schemas import EvidenceItem, JudgeRequest

id = "identity_attest"

CLAIM = re.compile(r"(\bi am (the |an? )?(admin(istrator)?|ceo|cto|owner|security team|system|developer of this)\b|"
                   r"\bthis is (the )?(ceo|cfo|it department|security team|administrator)\b|"
                   r"(저는|나는|여기는)\s*(관리자|대표|사장|보안팀|시스템|개발자)(입니다|이다|야|임))", re.I)


def scan(req: JudgeRequest) -> list[Signal]:
    out: list[Signal] = []
    a, sub = req.auth, req.subject
    for who, p in (("principal", sub.principal), ("onBehalfOf", sub.on_behalf_of)):
        if p is None or not p.spiffe_id:
            continue
        attested = a.attested_spiffe_id if a else None
        if attested != p.spiffe_id:
            out.append(Signal(rule="spiffe-mismatch", score=0.96, severity="critical", evidence=EvidenceItem(
                kind="identity", location=f"subject.{who}.spiffeId",
                note="주장한 SPIFFE ID 가 증명(SVID)과 다르다" if attested else "SPIFFE ID 주장에 증명(SVID) 없음")))
    p = sub.principal
    if p is not None and p.type == "agent" and not (a and (a.signed_identity or a.attested_spiffe_id)):
        out.append(Signal(rule="unsigned-agent", score=0.86, severity="high", evidence=EvidenceItem(
            kind="identity", location="subject.principal", note="서명·증명 없는 에이전트 신원")))
    roles = set(p.roles) if p else set()
    for loc, text in req.texts("text"):
        if (m := CLAIM.search(text)) and not roles & {"admin", "owner", "security"}:
            out.append(Signal(rule="claimed-authority", score=0.66, severity="medium", evidence=EvidenceItem(
                kind="span", location=loc, offset=m.start(), length=m.end() - m.start(), note="입력에서 권한자 사칭(역할 불일치)")))
    return out


def explain(req: JudgeRequest) -> dict:
    a, sub = req.auth, req.subject
    rows = [{"who": who, "id": p.id, "type": p.type, "claimed": p.spiffe_id, "attested": a.attested_spiffe_id if a else None,
             "match": (a.attested_spiffe_id if a else None) == p.spiffe_id if p.spiffe_id else None}
            for who, p in (("principal", sub.principal), ("onBehalfOf", sub.on_behalf_of)) if p is not None]
    return {"kind": "identity", "subjects": rows, "signedIdentity": bool(a and a.signed_identity),
            "claimedAuthority": [loc for loc, t in req.texts("text") if CLAIM.search(t)]}
