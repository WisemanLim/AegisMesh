// Epic 63 — 보조기술: 사용자 동작 뒤 제자리에 나타나는 오류 문구는 화면 낭독기가 알리도록 role="alert" (WCAG 4.1.3 상태 메시지).
// 클라이언트 컴포넌트(components/*.tsx)에서 `cond && <p|span|div … text-red-600>` 인데 role 이 없으면 실패.
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

const DIR = join(__dirname, "..", "components");

describe("live error messages (Epic 63)", () => {
  it("conditional error text in client components carries role=alert", () => {
    const missing: string[] = [];
    for (const f of readdirSync(DIR).filter((x) => x.endsWith(".tsx"))) {
      const src = readFileSync(join(DIR, f), "utf8");
      if (!src.includes('"use client"')) continue;
      src.split("\n").forEach((line, i) => {
        if (/&&\s*<(p|span|div)\s(?![^>]*role=)[^>]*text-red-600/.test(line)) missing.push(`${f}:${i + 1}`);
      });
    }
    expect(missing).toEqual([]);
  });
});
