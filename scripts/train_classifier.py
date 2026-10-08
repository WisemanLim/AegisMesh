"""소형 분류기 학습 (OQ4 · FR-D1-01·D1-03) — 합성 학습셋(aegis/trainset) + 저장소 D1 에이전트 시험셋 + 골든셋 생성기(다른 seed)로
로지스틱 회귀를 학습해 `aegis/data/<name>.json` 에 쓴다. 공개 공격 코퍼스는 쓰지 않는다(평가 전용, Epic 43).

  python scripts/train_classifier.py [--name injection-clf-v1] [--seed 20261007] [--epochs 10] [--out 경로]

출력 마지막 줄의 sha256 을 엔진(MODEL_SHA256)에 고정한다 — 다르면 엔진이 모델 적재를 거부한다.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import random
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from aegis import classifier, goldenset, trainset  # noqa: E402

D1 = ["d1-01-malicious-instructions", "d1-02-instruction-hijacking", "d1-03-jailbreak-prompts", "d1-04-context-override"]
GOLDEN_REPLAY_SEED = 20260930          # quality.golden_replay 의 seed — 학습에는 다른 seed 를 쓴다


def repo_sets() -> list[dict]:
    out = []
    for d in D1:
        for kind in ("attacks", "golden"):
            for f in sorted((ROOT / "agents" / d / "tests" / kind).glob("*.jsonl")):
                for line in f.read_text(encoding="utf-8").splitlines():
                    if not line.strip():
                        continue
                    req = json.loads(line)["request"]
                    segs = [s["text"] for s in req.get("segments") or [] if s.get("trust") == "untrusted"]
                    if kind == "attacks":
                        for t in segs or ([req["text"]] if req.get("text") else []):
                            out.append({"text": t, "label": 1, "lang": "repo", "family": f"{d[:5]}-attack"})
                    else:
                        for t in segs + ([req["text"]] if req.get("text") else []):
                            out.append({"text": t, "label": 0, "lang": "repo", "family": f"{d[:5]}-golden"})
    return out


def golden_texts(n: int, seed: int) -> list[str]:
    texts = []
    for smp in goldenset.generate(n, seed):
        if smp["gate"] != "input":
            continue
        req = smp["request"]
        texts += [req["text"]] if req.get("text") else []
        texts += [s["text"] for s in req.get("segments") or []]
    return texts


def train(rows: list[dict], epochs: int, seed: int) -> tuple[dict[int, float], float]:
    r = random.Random(seed)
    data = [(classifier.features(x["text"]), x["label"]) for x in rows]
    pos = sum(y for _, y in data)
    cw = {1: len(data) / (2 * pos), 0: len(data) / (2 * (len(data) - pos))}
    w: dict[int, float] = {}
    b, l2 = 0.0, 1e-6
    for ep in range(epochs):
        r.shuffle(data)
        lr = 0.8 / (1 + 0.6 * ep)
        for f, y in data:
            z = b + sum(w.get(i, 0.0) * v for i, v in f.items())
            p = 1 / (1 + math.exp(-z)) if z > -60 else 0.0
            g = (p - y) * cw[y]
            for i, v in f.items():
                w[i] = w.get(i, 0.0) * (1 - lr * l2) - lr * g * v
            b -= lr * g
    return w, b


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--name", default="injection-clf-v1")
    ap.add_argument("--seed", type=int, default=20261007)
    ap.add_argument("--epochs", type=int, default=10)
    ap.add_argument("--out", help="출력 경로(기본 aegis/data/<name>.json) — 재현성 확인용")
    a = ap.parse_args()
    t0 = time.perf_counter()
    rows = trainset.generate(a.seed) + repo_sets()
    rows += [{"text": t, "label": 0, "lang": "golden", "family": "golden"} for t in golden_texts(3000, a.seed + 1)]
    seen, uniq = set(), []
    for x in rows:
        if x["text"] not in seen:
            seen.add(x["text"])
            uniq.append(x)
    r = random.Random(a.seed)
    r.shuffle(uniq)
    cut = int(len(uniq) * 0.85)
    tr, va = uniq[:cut], uniq[cut:]
    w, b = train(tr, a.epochs, a.seed)
    m = classifier.Model({"version": a.name, "bias": b, "weights": {str(k): v for k, v in w.items()}, "sha256": ""})
    vp = [(m.prob(x["text"]), x["label"]) for x in va]
    neg = [p for p, y in vp if y == 0]
    posv = [p for p, y in vp if y == 1]

    def fp(t: float) -> float:
        return sum(p >= t for p in neg) / len(neg)

    def recall(t: float) -> float:
        return sum(p >= t for p in posv) / len(posv)

    grid = [round(0.5 + i / 100, 2) for i in range(50)]
    block = next((t for t in grid if t >= 0.95 and fp(t) <= 0.0005), 0.99)       # 하한 = 분포 밖 오탐 여유(R01)
    alert = next((t for t in grid if t >= 0.8 and fp(t) <= 0.002), block)
    gold = golden_texts(10_000, GOLDEN_REPLAY_SEED)
    gold_fp = sum(m.prob(t) >= alert for t in gold) / len(gold)
    meta = {"trainedAt": datetime.now(timezone.utc).isoformat(timespec="seconds"), "seed": a.seed, "epochs": a.epochs,
            "features": "NFKC·소문자·leet 정규화 → 글자 3·4-gram + 단어 1·2-gram, CRC32 해시 2^18, L2 정규화",
            "train": {"n": len(tr), "pos": sum(x["label"] for x in tr)}, "validation": {"n": len(va), "pos": len(posv)},
            "trainSha256": hashlib.sha256(json.dumps([(x["text"], x["label"]) for x in tr], ensure_ascii=False).encode()).hexdigest(),
            "val": {"alert": {"threshold": alert, "fpRate": round(fp(alert), 5), "recall": round(recall(alert), 4)},
                    "block": {"threshold": block, "fpRate": round(fp(block), 5), "recall": round(recall(block), 4)}},
            "goldenReplayFpAtAlert": round(gold_fp, 5), "goldenTexts": len(gold), "publicCorpusUsed": False,
            "sources": ["aegis/trainset.py (합성)", "agents/d1-0[1-4]/tests (저장소 시험셋)", f"goldenset seed {a.seed + 1} (정상)"]}
    out = Path(a.out) if a.out else classifier.DATA / f"{a.name}.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    sha = classifier.save(out, a.name, w, b, {"alert": alert, "block": block}, meta)
    print(json.dumps(meta, ensure_ascii=False, indent=1))
    print(f"weights {sum(1 for v in w.values() if abs(v) >= 1e-4)} · {out.stat().st_size // 1024} KiB · {time.perf_counter() - t0:.1f}s")
    print(f"sha256 {sha}")


if __name__ == "__main__":
    main()
