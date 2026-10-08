"""기본 엔진: 사람-에이전트 상호작용 — 자격증명 요구·승인 반복(피로)·유도 문구 (FR-X03, ASI09).
artifact = governance_snapshot.interactions 또는 {kind: interaction_log, interactions: [{agent, kind: approval|credential|exception, text, count}]}"""
import re

from aegis.engine import artifact_of, signal

id = "interaction_patterns"
PRESSURE = re.compile(r"(urgent|immediately|right now|asap|your (manager|boss|ceo) (already )?approved|just click approve|"
                      r"긴급|지금\s*바로|즉시\s*승인|대표님이?\s*(이미\s*)?승인|빨리\s*승인)", re.I)


def scan(req):
    a = artifact_of(req, "interaction_log", "governance_snapshot")
    if not a or "interactions" not in a:
        return []
    out = []
    reps: dict[tuple, int] = {}
    for i, it in enumerate(a["interactions"]):
        loc = f"interactions[{i}]:{it.get('agent')}"
        if it.get("kind") == "credential":
            out.append(signal("credential-request", 0.95, "critical", loc, "에이전트가 사람에게 자격증명 요구"))
        if PRESSURE.search(str(it.get("text", ""))):
            out.append(signal("pressure", 0.8, "medium", loc, "승인 유도·압박 문구"))
        k = (it.get("agent"), it.get("kind"), it.get("action"))
        reps[k] = reps.get(k, 0) + int(it.get("count", 1))
    for (agent, kind, action), n in reps.items():
        if kind == "approval" and n >= req.params.get("maxRepeatedRequests", 3):
            out.append(signal("approval-fatigue", 0.82, "medium", f"agent:{agent}", f"같은 행동({action}) 승인 요청 {n}회 반복"))
    return out
