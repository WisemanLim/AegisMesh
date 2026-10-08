"""observability/masking.yaml → infra/otel/collector.yaml (OTel Collector 설정 생성).

  python scripts/gen_otel_config.py          # 생성
  python scripts/gen_otel_config.py --check  # 최신인지 확인 (CI·pytest) — 다르면 exit 1
"""
from __future__ import annotations

import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
RULES = ROOT / "observability" / "masking.yaml"
OUT = ROOT / "infra" / "otel" / "collector.yaml"
HELM = ROOT / "deploy" / "helm" / "aegismesh" / "files" / "collector.yaml"      # 헬름 차트 사본(같은 내용)
HEADER = ("# 자동 생성 — 수정하지 말 것. 원천: observability/masking.yaml → python scripts/gen_otel_config.py\n"
          "# 파이프라인: 수신(OTLP) → 처리(메모리 한도·민감정보 마스킹·배치) → 내보내기(debug; 운영 백엔드는 exporters 에 추가)\n")


def _q(s: str) -> str:
    # 컬렉터 설정의 $ 는 환경변수 치환 — 정규식의 $ 는 $$ 로
    return s.replace("$", "$$").replace("\\", "\\\\").replace('"', '\\"')


def statements(rules: list[dict], targets: list[str]) -> list[str]:
    out = []
    for r in rules:
        for t in targets:
            fn = "replace_all_patterns" if t.endswith("attributes") else "replace_pattern"
            args = f'{t}, "value", "{_q(r["pattern"])}", "{r["replacement"]}"' if fn == "replace_all_patterns" \
                else f'{t}, "{_q(r["pattern"])}", "{r["replacement"]}"'
            out.append(f"{fn}({args})")
    return out


def build() -> str:
    rules = yaml.safe_load(RULES.read_text(encoding="utf-8"))["rules"]
    cfg = {
        "receivers": {"otlp": {"protocols": {"http": {"endpoint": "0.0.0.0:4318"}, "grpc": {"endpoint": "0.0.0.0:4317"}}}},
        "processors": {
            "memory_limiter": {"check_interval": "1s", "limit_mib": 256},
            "transform/mask": {
                "error_mode": "ignore",
                # OTTL 경로는 문맥 접두사를 명시한다(span.·spanevent.·log.·datapoint.) — 0.162 권장 형식
                "trace_statements": [{"context": "span", "statements": statements(rules, ["span.attributes", "span.name"])},
                                     {"context": "spanevent", "statements": statements(rules, ["spanevent.attributes"])}],
                "log_statements": [{"context": "log", "statements": statements(rules, ["log.attributes", "log.body"])}],
                "metric_statements": [{"context": "datapoint", "statements": statements(rules, ["datapoint.attributes"])}],
            },
            "batch": {"timeout": "2s"},
        },
        "exporters": {"debug": {"verbosity": "${env:OTEL_DEBUG_VERBOSITY:-basic}"}},
        "extensions": {"health_check": {"endpoint": "0.0.0.0:13133"}},
        "service": {
            "extensions": ["health_check"],
            "telemetry": {"logs": {"level": "info"}},
            "pipelines": {k: {"receivers": ["otlp"], "processors": ["memory_limiter", "transform/mask", "batch"], "exporters": ["debug"]}
                          for k in ("traces", "metrics", "logs")},
        },
    }
    return HEADER + yaml.safe_dump(cfg, allow_unicode=True, sort_keys=False, width=200)


def main() -> int:
    text = build()
    if "--check" in sys.argv:
        ok = all(o.exists() and o.read_text(encoding="utf-8") == text for o in (OUT, HELM))
        print("collector.yaml 최신" if ok else "collector.yaml 이 masking.yaml 과 다르다 — python scripts/gen_otel_config.py")
        return 0 if ok else 1
    for o in (OUT, HELM):
        o.parent.mkdir(parents=True, exist_ok=True)
        o.write_text(text, encoding="utf-8")
    print(f"생성: {OUT.relative_to(ROOT)} (규칙 {len(yaml.safe_load(RULES.read_text(encoding='utf-8'))['rules'])}종)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
