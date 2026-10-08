"""삭제 전파·학습 데이터 재현 시험 (SCR-F04, FR-D2-05·D2-07) — 상태는 원장(추가 전용)에만 둔다.

삭제 요청: 정보주체 식별자는 테넌트 소금과 함께 해시만 남긴다(원문 미보존). 저장소별 삭제 결과 보고 → D2-07 잔존 재검사
(삭제 감사 대상으로 상시 점검 경로) → 잔존 0 이면 삭제 증적 발행. 학습 데이터 재현 시험: 모델 출력 표본을 D2-05 로 판정해
추출(정확 재현)률을 재고 멤버십 추론 AUC·차등 프라이버시 ε(외부 시험 결과, 선택)와 함께 배포 게이트를 판정한다. 출력 표본은 저장하지 않는다."""
from __future__ import annotations

import hashlib
import secrets
from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from aegis.schemas import JudgeRequest, Subject
from app import ledger, models, orchestrator, policy, registry, scanner

STORES = ("primary", "index", "cache", "memory", "backup")
STATUS = ("pending", "deleted", "failed", "scheduled")          # scheduled = 백업 보존 만료 시 삭제 예약


class PrivacyError(Exception):
    def __init__(self, status: int, msg: str):
        super().__init__(msg)
        self.status, self.msg = status, msg


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def subject_hash(tenant: str, subject: str) -> str:
    return hashlib.sha256(f"{tenant}:{subject.strip()}".encode()).hexdigest()[:24]


def _events(s: Session, tenant: str, rid: str | None = None) -> list[models.Evidence]:
    q = select(models.Evidence).where(models.Evidence.kind == "erasure", models.Evidence.tenant == tenant)
    if rid:
        q = q.where(models.Evidence.ref_id == rid)
    return list(s.scalars(q.order_by(models.Evidence.seq)))


def _fold(evs: list[models.Evidence]) -> dict[str, dict]:
    out: dict[str, dict] = {}
    for r in evs:
        b, rid = r.body, r.ref_id
        if b["event"] == "requested":
            out[rid] = {"id": rid, "subjectHash": b["subjectHash"], "basis": b["basis"], "requestedBy": b["by"],
                        "requestedAt": r.created_at, "deadline": b["deadline"], "stores": {k: {"status": "pending"} for k in STORES},
                        "verify": None, "certified": None, "events": 0}
        x = out.get(rid)
        if x is None:
            continue
        x["events"] += 1
        if b["event"] == "store_reported":
            x["stores"][b["store"]] = {"status": b["status"], "by": b["by"], "at": r.created_at, "note": b.get("note")}
        elif b["event"] == "verified":
            x["verify"] = {k: b.get(k) for k in ("verdict", "residual", "traceId", "by")} | {"at": r.created_at}
        elif b["event"] == "certified":
            x["certified"] = {"by": b["by"], "at": r.created_at, "seq": r.seq, "hash": r.hash}
    now = utcnow()
    for x in out.values():
        dl = datetime.fromisoformat(x["deadline"])
        x["daysLeft"] = (dl - now).days
        x["state"] = ("certified" if x["certified"] else "verified" if x["verify"] and x["verify"]["verdict"] != "block"
                      else "overdue" if dl < now else "open")
    return out


def requests(s: Session, tenant: str) -> list[dict]:
    return sorted(_fold(_events(s, tenant)).values(), key=lambda x: x["requestedAt"], reverse=True)


def get(s: Session, tenant: str, rid: str) -> dict:
    x = _fold(_events(s, tenant, rid)).get(rid)
    if x is None:
        raise PrivacyError(404, f"삭제 요청 {rid} 없음")
    return x


def create(s: Session, tenant: str, subject: str, basis: str, days: int, by: str) -> dict:
    if not subject.strip() or not basis.strip():
        raise PrivacyError(422, "정보주체 식별자·근거 필수 (MSG-003)")
    rid = f"era_{secrets.token_hex(5)}"
    deadline = (utcnow() + timedelta(days=days)).isoformat(timespec="seconds")
    ledger.append(s, "erasure", rid, {"event": "requested", "subjectHash": subject_hash(tenant, subject), "basis": basis.strip(),
                                      "deadline": deadline, "by": by}, tenant)
    s.flush()
    return get(s, tenant, rid)


def report(s: Session, tenant: str, rid: str, store: str, status: str, by: str, note: str = "") -> dict:
    x = get(s, tenant, rid)
    if x["certified"]:
        raise PrivacyError(409, "이미 삭제 증적 발행 — 변경 불가")
    if store not in STORES or status not in STATUS[1:]:
        raise PrivacyError(422, f"저장소 {STORES} · 상태 {STATUS[1:]}")
    ledger.append(s, "erasure", rid, {"event": "store_reported", "store": store, "status": status, "note": note[:200], "by": by}, tenant)
    s.flush()
    return get(s, tenant, rid)


def _artifact(x: dict, receipt: bool) -> dict:
    req_at = datetime.fromisoformat(x["requestedAt"].replace("Z", "+00:00")).timestamp()
    return {"kind": "deletion_audit", "subject": x["subjectHash"], "requestedAt": req_at, "receiptIssued": receipt,
            "stores": {k: v["status"] != "deleted" for k, v in x["stores"].items()}}


def verify(s: Session, tenant: str, rid: str, by: str) -> dict:
    """잔존 재검사 — D2-07 로 삭제 감사(상시 점검 경로, 판정·원장 기록). block = 사본 잔존(재전파 필요)."""
    x = get(s, tenant, rid)
    r = scanner.run_scan(s, _artifact(x, bool(x["certified"])), tenant, agent_ids=["d2-07"], by=by)
    residual = [h for h in r["hits"] if h["ruleId"] == "D2-07.residual-copy" and h["effective"] == "block"]
    ledger.append(s, "erasure", rid, {"event": "verified", "verdict": "block" if residual else r["verdict"],
                                      "residual": [k for k, v in x["stores"].items() if v["status"] != "deleted"],
                                      "traceId": r["traceId"], "by": by}, tenant)
    s.flush()
    return get(s, tenant, rid) | {"scan": {k: r[k] for k in ("traceId", "verdict", "hits")}}


def certify(s: Session, tenant: str, rid: str, by: str) -> dict:
    x = get(s, tenant, rid)
    if x["certified"]:
        raise PrivacyError(409, "이미 발행됨")
    if not x["verify"] or x["verify"]["verdict"] == "block":
        raise PrivacyError(409, "잔존 재검사 통과 후 발행 (MSG-028: 실패 저장소 재전파)")
    pending = [k for k, v in x["stores"].items() if v["status"] in ("pending", "failed")]
    if pending:
        raise PrivacyError(409, f"미완료 저장소 {pending}")
    ledger.append(s, "erasure", rid, {"event": "certified", "subjectHash": x["subjectHash"], "by": by,
                                      "stores": {k: v["status"] for k, v in x["stores"].items()}}, tenant)
    s.flush()
    scanner.run_scan(s, _artifact(get(s, tenant, rid), True), tenant, agent_ids=["d2-07"], by=by)   # 발행 후 감사 통과 기록
    return get(s, tenant, rid)


# ── 학습 데이터 재현 시험 (D2-05) ───────────────────────────────
def recall_test(s: Session, tenant: str, model: str, version: str, outputs: list[str], by: str,
                mia_auc: float | None = None, dp_epsilon: float | None = None, dedup_rate: float | None = None) -> dict:
    if not outputs:
        raise PrivacyError(422, "모델 출력 표본 1건 이상")
    rt = registry.runtime_agent("d2-05")
    params = policy.spec_of(policy.latest(s, "default", tenant)).agent_params
    p = params.get("d2-05", {})
    if not (p.get("trainingCanaries") or p.get("protectedCorpus")):
        raise PrivacyError(409, "d2-05 설정(학습 데이터 카나리·보호 코퍼스)이 정책에 없다 — 먼저 설정")
    flagged, rules = 0, {}
    for o in outputs:
        f = rt.judge(orchestrator.agent_request(rt, JudgeRequest(gate="output", output=o, subject=Subject(tenant=tenant)), params))
        if f.verdict != "allow":
            flagged += 1
            rules[f.rule_id] = rules.get(f.rule_id, 0) + 1
    rate = flagged / len(outputs)
    gate = rt.engines[rt.manifest.spec.engines.default].module.release_gate(rate, p, mia_auc, dp_epsilon)
    body = {"event": "recall_test", "model": model, "version": version, "samples": len(outputs), "flagged": flagged, "rules": rules,
            "extractionRate": round(rate, 6), "miaAuc": mia_auc, "dpEpsilon": dp_epsilon, "dedupRate": dedup_rate,
            "gate": "pass" if gate["pass"] else "block", "reasons": gate["reasons"], "limits": gate["limits"], "by": by}
    rec = ledger.append(s, "recall_test", f"{model}@{version}", body, tenant)
    return body | {"seq": rec.seq, "at": rec.created_at}


def recall_history(s: Session, tenant: str, limit: int = 50) -> list[dict]:
    q = select(models.Evidence).where(models.Evidence.kind == "recall_test", models.Evidence.tenant == tenant)
    return [r.body | {"seq": r.seq, "at": r.created_at} for r in s.scalars(q.order_by(models.Evidence.seq.desc()).limit(limit))]
