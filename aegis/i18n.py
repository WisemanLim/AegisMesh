"""aegis CLI 출력 한/영 (Epic 56 · NFR-C4) — 한국어 원문이 기준이고, en 이면 사람이 읽는 줄을 출력 직전에 바꾼다(웹 콘솔 lib/en.ts 와 같은 방식).

언어: --lang ko|en > AEGIS_LANG > LC_ALL·LC_MESSAGES·LANG(en* 이면 en) > ko. JSON 출력(판정·번들·키)은 기계용 데이터라 바꾸지 않는다.
"""
from __future__ import annotations

import os
import re
import sys

_lang = {"v": None}

# (원문 정규식, 영어) — 위에서부터 한 번씩. 원문 문구가 바뀌면 test_cli_i18n 이 한글 잔여로 알려 준다.
PATTERNS: list[tuple[re.Pattern, str]] = [(re.compile(p), r) for p, r in [
    # 증적 묶음 (aegis verify-bundle · ledger_verify)
    (r"레코드 (\d+)건 \(seq (\S+)–(\S+)\) 체인·서명 검증 통과, keyId (\S+)", r"\1 records (seq \2–\3) chain and signature verified, keyId \4"),
    (r"seq (\d+): prevHash 불일치 \(체인 단절\)", r"seq \1: prevHash mismatch (chain broken)"),
    (r"seq (\d+): 해시 불일치 \(내용 변조\)", r"seq \1: hash mismatch (content tampered)"),
    (r"체크포인트가 마지막 레코드와 다르다", "checkpoint does not match the last record"),
    (r"체크포인트 서명 검증 실패", "checkpoint signature verification failed"),
    (r"레코드 없음", "no records"),
    # 폐쇄망 번들 (aegis airgap · airgap)
    (r"번들 크기 (\d+) > (\d+)", r"bundle size \1 > \2"),
    (r"tar\.gz 아님: ", "not a tar.gz: "),
    (r"허용하지 않는 항목 ", "entry not allowed "),
    (r"bundle\.json 없음", "bundle.json missing"),
    (r"신뢰 저장소에 없는 키 (\S+) — 반입 거부 \(MSG-005\)", r"key \1 not in the trust store — import refused (MSG-005)"),
    (r"매니페스트 서명 불일치 — 반입 거부 \(MSG-005\)", "manifest signature mismatch — import refused (MSG-005)"),
    (r"keyId (\S+) \(내부 신뢰 저장소\)", r"keyId \1 (internal trust store)"),
    (r"매니페스트에 없는 파일 ", "files not in the manifest "),
    (r"구성요소 해시 불일치 (\S+) — 해당 구성요소 반입 거부", r"component hash mismatch \1 — component import refused"),
    (r"알 수 없는 구성요소 종류 ", "unknown component kind "),
    (r"구성요소 (\d+) \+ SBOM 해시 일치", r"\1 components + SBOM hashes match"),
    (r"CycloneDX SBOM 아님", "not a CycloneDX SBOM"),
    (r"SBOM 취약점 기준 초과 ", "SBOM vulnerabilities over the gate "),
    (r"CycloneDX (\d+)개 · 취약점 ", r"CycloneDX \1 components · vulnerabilities "),
    (r"알 수 없는 형식 ", "unknown format "),
    # 평가·도식 범위 (aegis eval · coverage)
    (r"골든셋·공격셋이 비어 있다", "golden and attack sets are empty"),
    (r"오탐률 ", "false-positive rate "),
    (r"미탐률 ", "miss rate "),
    (r"탐지율 회귀 (\S+) < 기준선 ", r"detection regression \1 < baseline "),
    (r"재현성 실패\(NFR-Q4\)", "non-deterministic (NFR-Q4)"),
    (r"무효 판정\(DP3\)", "invalid verdict (DP3)"),
    (r" \(기대 ", " (expected "),
    (r"coverage: 전체 (\S+) · 엄격 (\S+)", r"coverage: all \1 · strict \2"),
    (r"요구사항\(FR\) 없음", "no requirement (FR)"),
    (r"매니페스트 스키마 오류: ", "manifest schema error: "),
    (r"에이전트 매니페스트 없음", "no agent manifest"),
    (r"도식 추적 불일치: ", "diagram trace mismatch: "),
    (r"표준 매핑 없음", "no standards mapping"),
    (r"시험 자산 없음: ", "test asset missing: "),
    (r"core\.py 없음", "core.py missing"),
    # SBOM 게이트 (aegis sbom check · d7-02)
    (r" 영향 버전 ", " affects "),
    (r" · 수정 ", " · fixed in "),
    (r"SBOM 구성요소 없음 — 생성 누락", "SBOM has no components — generation step missing"),
    # A2A 클라이언트 (aegis a2a card|send)
    (r"AgentCard 서명 유효 \(kid (\S+)\)", r"AgentCard signature valid (kid \1)"),
    (r"AgentCard 서명 없음", "AgentCard is unsigned"),
    (r"AgentCard 서명 검증 실패\(변조\)", "AgentCard signature verification failed (tampered)"),
    (r"신뢰 저장소에 없는 서명키 ", "signing key not in the trust store "),
    (r"신뢰 키 없음", "no trusted key"),
    (r"protected 헤더 형식 오류", "malformed protected header"),
    (r"지원하지 않는 알고리즘 ", "unsupported algorithm "),
    (r"AgentCard 검증 실패 — (.*) \(호출 거부, FR-X01\)", r"AgentCard verification failed — \1 (call refused, FR-X01)"),
    (r"신뢰 고정\(--trust JWKS\) 없이 카드 자체 jku 만 확인됨 — 호출 거부 \(--allow-unpinned 로 무시\)",
     "only the card's own jku was checked, no pinned trust (--trust JWKS) — call refused (override with --allow-unpinned)"),
    (r"JSONRPC (\S+) 인터페이스 없음", r"no JSONRPC \1 interface"),
]]


def detect(argv: list[str] | None = None) -> str:
    argv = sys.argv[1:] if argv is None else argv
    for i, a in enumerate(argv):
        if a == "--lang" and i + 1 < len(argv):
            return "en" if argv[i + 1].lower().startswith("en") else "ko"
        if a.startswith("--lang="):
            return "en" if a.split("=", 1)[1].lower().startswith("en") else "ko"
    env = os.environ.get("AEGIS_LANG") or os.environ.get("LC_ALL") or os.environ.get("LC_MESSAGES") or os.environ.get("LANG") or ""
    return "en" if env.lower().startswith("en") else "ko"


def set_lang(v: str) -> None:
    _lang["v"] = v


def lang() -> str:
    return _lang["v"] or detect()


def T(ko: str, en: str) -> str:
    """CLI 자신의 문구 — 두 언어를 함께 둔다."""
    return en if lang() == "en" else ko


def tr(text: str) -> str:
    """다른 모듈이 만든 한국어 메시지 → en(패턴). ko 면 그대로."""
    if lang() != "en":
        return text
    for p, r in PATTERNS:
        text = p.sub(r, text)
    return text


def say(*parts, file=None) -> None:
    print(tr(" ".join(str(p) for p in parts)), file=file)
