"""기본 엔진: 저장 시점 스캔 (FR-D8-04, 저장형 XSS 의 LLM 판) — 메모리·문서·DB 쓰기 도구 인자의 지시문·실행 표식."""
import re

from aegis.engine import signal, walk_strings
from aegis.patterns import find_directive
from aegis.schemas import JudgeRequest

id = "store_scan"
WRITE = re.compile(r"(save|store|write|insert|upsert|remember|add_memory|create_note|create_doc|index|put|append|memorize|기억|저장)", re.I)
EXEC_MARK = re.compile(r"(\{\{.*\}\}|<script\b|\$\{[^}]+\}|```(system|instructions))", re.I)


def scan(req: JudgeRequest):
    t = req.tool
    if t is None or not WRITE.search(t.name):
        return []
    out = []
    for loc, v in walk_strings(t.args):
        if (m := find_directive(v)):
            out.append(signal("directive-stored", 0.93, "critical", loc, "저장하려는 데이터에 모델 대상 지시", "span", m.start(), m.end() - m.start()))
        elif (m := EXEC_MARK.search(v)):
            out.append(signal("exec-marker", 0.85, "high", loc, "실행 가능 텍스트 표식(템플릿·스크립트)", "span", m.start(), m.end() - m.start()))
    return out
