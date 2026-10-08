// NFR-C4 본문 번역 — L(): 카탈로그 조회, 앞뒤 공백 보존, {n} 인자, 가변 문장 패턴, 없는 키는 원문.
import { describe, expect, it } from "vitest";
import { EN } from "@/lib/en";
import { L, nm } from "@/lib/i18n";

describe("L", () => {
  it("translates catalog keys and keeps Korean for ko", () => {
    expect(L("en", "다시 검증")).toBe("Verify again");
    expect(L("ko", "다시 검증")).toBe("다시 검증");
  });
  it("preserves surrounding whitespace of JSX fragments", () => {
    expect(L("en", " · 강등 ")).toBe(" · degraded ");
  });
  it("fills placeholders in both languages", () => {
    expect(L("en", "실패 {0}", "500: boom")).toBe("Failed 500: boom");
    expect(L("ko", "실패 {0}", "500: boom")).toBe("실패 500: boom");
  });
  it("translates server-built messages by pattern", () => {
    expect(L("en", "기본 테넌트 증적 보존 365일 — 원장 기록")).toBe("Default tenant evidence retention 365 days — recorded in the ledger");
  });
  it("translates engine evidence notes, including nested fragments (Epic 40)", () => {
    expect(L("en", "규칙 5종 검사 통과")).toBe("Passed 5 rule checks");
    expect(L("en", "허용 루트 /workspace 밖 쓰기")).toBe("write outside the allowed root /workspace");
    expect(L("en", "3시간째 봉쇄되지 않은 high 사건")).toBe("high incident not contained for 3 h");
    expect(L("en", "mcp_server 'files' 서명 없음")).toBe("mcp_server 'files' is unsigned");
    expect(L("en", "행동 등급 2(impact medium, 외부, 비가역) > 자율 레벨 1")).toBe("Action level 2 (impact medium, external, irreversible) > autonomy level 1");
  });
  it("falls back to the source for unknown text (data, API messages)", () => {
    expect(L("en", "d1-01 악성 지시 주입 탐지기")).toBe("d1-01 악성 지시 주입 탐지기");
  });
  it("catalog values keep placeholders and contain no Hangul", () => {
    for (const [ko, en] of Object.entries(EN)) {
      expect([...en.matchAll(/\{\d+\}/g)].map((m) => m[0]).sort()).toEqual([...new Set([...ko.matchAll(/\{\d+\}/g)].map((m) => m[0]))].sort());
      expect(/[가-힣]/.test(en)).toBe(false);
    }
  });
});

describe("nm", () => {
  it("picks the English name for en", () => {
    expect(nm("en", { id: "d1-01", name: "Malicious Instruction Detector", nameKo: "악성 지시 주입 탐지기" })).toBe("Malicious Instruction Detector");
    expect(nm("ko", { id: "d1-01", name: "Malicious Instruction Detector", nameKo: "악성 지시 주입 탐지기" })).toBe("악성 지시 주입 탐지기");
    expect(nm("en", { id: "chatbot-baseline", nameKo: "챗봇 기본" })).toBe("chatbot-baseline");
  });
});

describe("deep-check reasons (Epic 51)", () => {
  it("translates server-built quarantine and evidence notes", () => {
    const why = "깊은 검사(안전 분류 모델) 경보 — 추적 tr_ab12 · 안전 분류 모델 Unsafe · 위험 0.97 · 범주 Violent";
    expect(L("en", why)).toBe("Deep check (safety classification model) alert — trace tr_ab12 · safety classification model Unsafe · risk 0.97 · categories Violent");
    expect(L("en", "안전 분류 모델 Unsafe · 위험 0.62 · 범주 —")).toBe("Safety classification model Unsafe · risk 0.62 · categories —");
  });
});

describe("impossible travel and attestation reasons (Epics 54–55)", () => {
  it("translates the D5-03 note and security-key refusals", () => {
    expect(L("en", "불가능한 이동 9,080 km · 18,237,151 km/h")).toBe("Impossible travel 9,080 km · 18,237,151 km/h");
    expect(L("en", "테넌트 정책상 허용되지 않은 인증기 — MDS 에 없는 기종 (AAGUID 01020304050607080102030405060708)"))
      .toBe("Authenticator not allowed by the tenant policy — Model not in the FIDO MDS (AAGUID 01020304050607080102030405060708)");
    expect(L("en", "테넌트 정책상 허용되지 않은 인증기 — 신뢰 루트로 이어지지 않는 체인 — 발급자 CN=Batch"))
      .toBe("Authenticator not allowed by the tenant policy — Chain does not lead to a trusted root — issuer CN=Batch");
    expect(L("en", "패스키 등록 거부 — MDS 상태 REVOKED — TruU Windows Authenticator")).toBe("Passkey registration refused — MDS status REVOKED — TruU Windows Authenticator");
  });
});
