"""R4 재생 하위 프로세스 — 번들에서 풀어 둔 에이전트 디렉터리를 골든셋·공격셋으로 재생하고 JSON 한 줄을 출력한다."""
import json
import sys

from aegis.agent import load_agent
from aegis.harness import evaluate

if __name__ == "__main__":
    rep = evaluate(load_agent(sys.argv[1]), repeat=3)
    s = rep.summary()
    print(json.dumps({k: s[k] for k in ("golden", "attacks", "fpRate", "detectionRate", "p95Ms", "nondeterministic", "invalid")},
                     ensure_ascii=False))
