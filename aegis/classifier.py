"""소형 분류기 (OQ4 결정 · FR-D1-01 "인젝션 분류기 이중 판정" · FR-D1-03 "전용 분류기") — 순수 파이썬, 결정적, 네트워크 없음.

특징 = 정규화한 글자 3·4-gram + 단어 1·2-gram 을 CRC32 로 2^18 칸에 해시(있음/없음) → L2 정규화.
모델 = 로지스틱 회귀 가중치(희소 JSON). 학습은 `scripts/train_classifier.py`(저장소 합성 학습셋만, 공개 코퍼스는 평가 전용).
가중치 파일은 무결성 해시를 품고, 엔진은 기대 해시를 고정해 불일치하면 적재를 거부한다(D7-06 과 같은 원칙).
"""
from __future__ import annotations

import hashlib
import json
import math
import re
import unicodedata
import zlib
from functools import lru_cache
from pathlib import Path

DIM = 1 << 18
MAX_CHARS = 3000                       # 지연 예산(NFR-L) — 긴 조각은 앞 2,000 + 뒤 1,000 자만 본다
LEET = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s"})
WORD = re.compile(r"[0-9a-z가-힣_]+")
DATA = Path(__file__).resolve().parent / "data"


class ModelIntegrityError(Exception):
    pass


def normalize(text: str) -> str:
    t = unicodedata.normalize("NFKC", text).lower()
    t = "".join(ch for ch in t if unicodedata.category(ch) not in ("Cf", "Mn"))   # 제로폭·결합 문자 제거
    if len(t) > MAX_CHARS:
        t = t[:2000] + " " + t[-1000:]
    return re.sub(r"\s+", " ", t.translate(LEET)).strip()


def grams(text: str) -> dict[str, str]:
    """특징 이름 → 원문 조각 (설명용). 이름은 해시 전 문자열."""
    t = f" {normalize(text)} "
    out: dict[str, str] = {}
    for n in (3, 4):
        for i in range(len(t) - n + 1):
            g = t[i:i + n]
            out.setdefault(f"c{n}:{g}", g)
    words = WORD.findall(t)
    for w in words:
        out.setdefault(f"w:{w}", w)
    for a, b in zip(words, words[1:]):
        out.setdefault(f"b:{a} {b}", f"{a} {b}")
    return out


def features(text: str) -> dict[int, float]:
    idx: dict[int, float] = {}
    for name in grams(text):
        idx[zlib.crc32(name.encode()) & (DIM - 1)] = 1.0
    if not idx:
        return {}
    norm = 1 / math.sqrt(len(idx))
    return {i: norm for i in idx}


def _sigmoid(z: float) -> float:
    return 1 / (1 + math.exp(-z)) if z > -60 else 0.0


def digest(weights: dict, bias: float) -> str:
    canon = json.dumps({"bias": round(bias, 6), "weights": {str(k): round(v, 6) for k, v in sorted(weights.items(), key=lambda kv: int(kv[0]))}},
                       sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canon.encode()).hexdigest()


class Model:
    def __init__(self, data: dict):
        self.version: str = data["version"]
        self.bias: float = float(data["bias"])
        self.weights: dict[int, float] = {int(k): float(v) for k, v in data["weights"].items()}
        self.sha256: str = data["sha256"]
        self.meta: dict = data.get("meta", {})
        self.thresholds: dict = data.get("thresholds", {"alert": 0.8, "block": 0.95})

    def prob(self, text: str) -> float:
        f = features(text)
        return _sigmoid(self.bias + sum(self.weights.get(i, 0.0) * v for i, v in f.items()))

    def top(self, text: str, k: int = 5) -> list[dict]:
        """점수를 올린 특징 상위 k (콘솔 설명용, 저장하지 않음)."""
        g = grams(text)
        n = 1 / math.sqrt(len(g)) if g else 0
        scored = sorted(((self.weights.get(zlib.crc32(name.encode()) & (DIM - 1), 0.0) * n, not name.startswith(("w:", "b:")), frag)
                         for name, frag in g.items()), key=lambda x: (x[1], -x[0]))   # 단어·두 단어 특징을 먼저(읽을 수 있게)
        seen, out = set(), []
        for w, _, frag in scored:
            if w <= 0 or frag in seen:
                continue
            seen.add(frag)
            out.append({"feature": frag.strip(), "weight": round(w, 3)})
            if len(out) == k:
                break
        return out


def save(path: Path, version: str, weights: dict[int, float], bias: float, thresholds: dict, meta: dict) -> str:
    w = {k: round(v, 6) for k, v in weights.items() if abs(v) >= 1e-4}
    sha = digest(w, bias)
    path.write_text(json.dumps({"version": version, "bias": round(bias, 6), "thresholds": thresholds, "meta": meta, "sha256": sha,
                                "weights": {str(k): v for k, v in sorted(w.items())}}, ensure_ascii=False, separators=(",", ":")))
    return sha


@lru_cache(maxsize=8)
def load(name: str, expect_sha256: str) -> Model:
    """aegis/data/<name>.json 적재 — 가중치 해시가 기대값과 다르면 거부(변조·교체 탐지)."""
    data = json.loads((DATA / f"{name}.json").read_text(encoding="utf-8"))
    actual = digest(data["weights"], float(data["bias"]))
    if actual != data.get("sha256") or actual != expect_sha256:
        raise ModelIntegrityError(f"분류기 {name} 해시 불일치 (기대 {expect_sha256[:12]}…, 실제 {actual[:12]}…)")
    return Model(data)
