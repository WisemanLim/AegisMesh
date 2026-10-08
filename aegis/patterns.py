"""에이전트 공통 지시문 패턴 — 메모리·검색 문서·첨부에 숨은 모델 대상 지시 (D1·D8·X06 공용)."""
import re

DIRECTIVE = re.compile(
    r"(\b(ignore|disregard|forget)\b.{0,30}\b(previous|prior|above|all|system)\b.{0,20}\b(instructions?|rules|prompts?)\b"
    r"|\byou are now\b|\bfrom now on\b,?\s+(you|always)|\bnew (system )?(instructions|prompt)\s*:|<\|im_start\|>|<\s*important\s*>"
    r"|\b(do not|don't) (tell|inform|reveal)\b.{0,20}\b(user|anyone)\b|\bsystem\s*:\s*\S"
    r"|(이전|위의|기존)\s*(지시|명령|규칙)[을를은는]?\s*(모두\s*)?(무시|잊어)|(지금부터|앞으로)\s*(너는|당신은|항상)|사용자에게\s*(알리지|말하지))",
    re.I | re.S)
INVISIBLE = re.compile(r"[\U000E0000-\U000E007F​‌⁠-⁤‪-‮⁦-⁩]")


def find_directive(text: str):
    return DIRECTIVE.search(text or "") or INVISIBLE.search(text or "")
