"""D2-01 민감정보 노출 — 고유식별·카드는 마스킹, 연락처는 가명화, 건강정보는 경보. regulated-kr 은 정책으로 차단 상향.
신뢰 구역별 노출 정책(SCR-F02): params.zone(요청 상태) + 정책 zonePolicy {구역: {유형|*: raw|last4|mask|pseudo|block}}.
external_model(외부 모델·국외 이전)은 정책에 명시한 유형만 허용 — 없으면 차단(기본 금지)."""
import hashlib

from aegis.decide import decide
from aegis.engine import Signal

KINDS = {"rrn": "transform", "card": "transform", "passport": "transform", "phone": "transform",
         "email": "transform", "health": "alert"}
RULES = {f"D2-01.{k}": f"출력에 {k} 형태 개인정보. 조치: {v} (값은 증적에 남기지 않음)." for k, v in KINDS.items()}
RULES["D2-01.zone-block"] = "신뢰 구역 노출 정책이 이 유형을 차단(외부 모델·국외 이전은 명시 허용만)."
RULES["D2-01.pass"] = "개인정보·건강정보 사전 검사 통과."
LABEL = {"rrn": "[주민번호]", "card": "[카드번호]", "passport": "[여권번호]", "phone": "[전화번호]", "email": "[이메일]"}
MODES = ("raw", "last4", "mask", "pseudo", "block")
DENY_BY_DEFAULT = ("external_model",)


def zone_modes(req) -> dict[str, str]:
    zone = req.params.get("zone")
    if not zone:
        return {}
    zp = (req.params.get("zonePolicy") or {}).get(zone)
    if zp is None:
        return {"*": "block"} if zone in DENY_BY_DEFAULT else {}
    return zp


def mode_of(rule: str, modes: dict[str, str]) -> str:
    return modes.get(rule, modes.get("*", "mask"))


def _replace(value: str, rule: str, mode: str) -> str:
    if mode == "last4":
        keep = sum(c.isalnum() for c in value) - 4
        out = []
        for c in value:
            if c.isalnum() and keep > 0:
                out.append("●")
                keep -= 1
            else:
                out.append(c)
        return "".join(out)
    if mode == "pseudo":
        return f"{LABEL[rule][:-1]}-{hashlib.sha256(value.encode()).hexdigest()[:6]}]"
    return LABEL[rule]


def mask(output: str, signals: list[Signal], modes: dict[str, str] | None = None) -> str:
    spans = sorted({(s.evidence.offset, s.evidence.length, s.rule) for s in signals
                    if s.evidence.location == "output" and s.rule in LABEL}, reverse=True)
    last = len(output) + 1
    for off, ln, rule in spans:
        if off + ln > last:           # 겹치는 구간은 앞선(뒤쪽) 치환만 유지
            continue
        output = output[:off] + _replace(output[off:off + ln], rule, mode_of(rule, modes or {})) + output[off + ln:]
        last = off
    return output


def apply_zone(signals: list[Signal], modes: dict[str, str]) -> list[Signal]:
    if not modes:
        return signals
    out = []
    for s in signals:
        m = mode_of(s.rule, modes)
        if m == "raw":
            continue
        if m == "block":
            ev = s.evidence.model_copy(update={"note": f"{s.evidence.note} — 신뢰 구역 정책 차단"})
            s = s.model_copy(update={"rule": "zone-block", "evidence": ev})
        out.append(s)
    return out


def detect(req, engine):
    modes = zone_modes(req)
    sig = apply_zone(engine.scan(req), modes)
    return decide("D2-01", sig, KINDS | {"zone-block": "block"}, rules=len(KINDS),
                  transform=lambda s: mask(req.output or "", s, modes))
