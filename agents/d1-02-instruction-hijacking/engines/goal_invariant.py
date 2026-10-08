"""기본 엔진: 목표 불변식 — 원래 목표(goal)와 계획(plan)·입력 사이의 탈취 신호 (FR-D1-02)."""
import hashlib
import re

from aegis.engine import Signal
from aegis.schemas import EvidenceItem, JudgeRequest

id = "goal_invariant"

HIJACK = re.compile(r"(\b(your|the) (new|real|actual|true) (goal|task|objective|mission) is\b|\bforget (the|your) (task|goal)\b"
                    r"|\babandon (the|your) (current )?(task|goal)\b|\binstead of (summariz|answer|help)\w*|"
                    r"(새로운|진짜|실제)\s*(목표|임무|과업)는|원래\s*(작업|과업|목표)[은는을를]?\s*(잊|그만|중단))", re.I)
# 고위험 행동군 — 목표에 같은 군의 단어가 있으면 계획 단계의 동의어는 이탈로 보지 않는다
GROUPS = {
    "transmit": ("send", "email", "mail", "forward", "upload", "share", "post", "export", "전송", "공유", "업로드", "메일", "보내"),
    "money": ("transfer", "wire", "pay", "purchase", "buy", "송금", "이체", "결제", "구매"),
    "destroy": ("delete", "drop", "remove", "wipe", "삭제", "제거"),
}
WORD = re.compile(r"\w+", re.U)


def scan(req: JudgeRequest) -> list[Signal]:
    out: list[Signal] = []
    for loc, text in [*req.texts("text", "segments"), *[(f"plan[{i}]", p) for i, p in enumerate(req.plan)]]:
        if (m := HIJACK.search(text)):
            out.append(Signal(rule="goal-override", score=0.9, severity="high", evidence=EvidenceItem(
                kind="span", location=loc, offset=m.start(), length=m.end() - m.start(), note="목표 재정의·폐기 지시")))
    if req.goal and req.plan:
        goal = req.goal.lower()
        goal_groups = {g for g, ws in GROUPS.items() if any(w in goal for w in ws)}
        for i, step in enumerate(req.plan):
            st = step.lower()
            drift = sorted({g for g, ws in GROUPS.items() if g not in goal_groups and any(w in st for w in ws)})
            if drift:
                out.append(Signal(rule="plan-drift", score=0.78, severity="medium", evidence=EvidenceItem(
                    kind="plan", location=f"plan[{i}]",
                    note=f"목표에 없는 고위험 행동군 추가: {', '.join(drift)} — 계획 변경 감지")))
    return out


def explain(req: JudgeRequest) -> dict:
    """목표 불변식 서명(해시)과 계획 단계별 대조 타임라인 (SCR-E03). 서명 = sha256(목표) — 세션 시작 때 고정, 단계마다 대조."""
    goal = (req.goal or "").lower()
    goal_groups = sorted(g for g, ws in GROUPS.items() if any(w in goal for w in ws))
    steps = []
    for i, step in enumerate(req.plan):
        st = step.lower()
        drift = sorted(g for g, ws in GROUPS.items() if g not in goal_groups and any(w in st for w in ws))
        override = bool(HIJACK.search(step))
        steps.append({"i": i, "step": step[:120], "groups": sorted(g for g, ws in GROUPS.items() if any(w in st for w in ws)),
                      "drift": drift, "override": override,
                      "verdict": "block" if override else "require_approval" if drift else "allow"})
    return {"kind": "goal", "goalHash": hashlib.sha256((req.goal or "").encode()).hexdigest() if req.goal else None,
            "goalGroups": goal_groups, "steps": steps,
            "inputOverride": [loc for loc, t in req.texts("text", "segments") if HIJACK.search(t)],
            "note": "목표에 없는 고위험 행동군(전송·이체·삭제)이 계획에 생기면 계획 변경 — 사람 승인, 목표 재정의 지시는 차단"}
