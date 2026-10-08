// 코드모드 2단계 (Epic 26) — API 값을 그대로 보여 주는 JSX 자식 {a.b}·{a[b]}·{a.b ?? c} 를 LX(lang, …) 로 감싼다.
// LX 는 문자열만 카탈로그로 번역하고(없으면 그대로), 숫자·요소·ID 는 손대지 않는다. lang 은 1단계에서 확보된 범위를 쓴다.
import fs from "node:fs";
import path from "node:path";
import ts from "typescript";

const files = [];
for (const d of ["app", "components"]) (function walk(p) {
  for (const e of fs.readdirSync(p, { withFileTypes: true })) {
    const f = path.join(p, e.name);
    if (e.isDirectory()) walk(f); else if (f.endsWith(".tsx")) files.push(f);
  }
})(d);
let total = 0, nfiles = 0;
const skipped = [];
for (const f of files) {
  const src = fs.readFileSync(f, "utf8");
  if (!/\bL\(lang,|\bconst \{ lang \}|const lang = useLang\(\)/.test(src)) continue;     // lang 범위가 있는 파일만
  const sf = ts.createSourceFile(f, src, ts.ScriptTarget.Latest, true, ts.ScriptKind.TSX);
  const edits = [];
  const isAccess = (e) => ts.isPropertyAccessExpression(e) || ts.isElementAccessExpression(e) ||
    (ts.isBinaryExpression(e) && e.operatorToken.kind === ts.SyntaxKind.QuestionQuestionToken && (ts.isPropertyAccessExpression(e.left) || ts.isElementAccessExpression(e.left)));
  const hasLang = (n) => { for (let p = n.parent; p; p = p.parent) if (ts.isFunctionLike(p) && /\blang\b/.test(p.getText().slice(0, 4000))) return true; return false; };
  (function visit(node) {
    if (ts.isJsxExpression(node) && node.expression && (ts.isJsxElement(node.parent) || ts.isJsxFragment(node.parent)) && isAccess(node.expression)) {
      const txt = node.expression.getText();
      if (/^(children|props\.|L\(|LX\()/.test(txt) || /\.(length|size|id|seq|n|count|total)$/.test(txt)) return;
      if (hasLang(node)) edits.push([node.expression.getStart(), node.expression.getEnd(), `LX(lang, ${txt})`]);
      else skipped.push(`${f}:${sf.getLineAndCharacterOfPosition(node.getStart()).line + 1} ${txt}`);
      return;
    }
    ts.forEachChild(node, visit);
  })(sf);
  if (!edits.length) continue;
  edits.sort((a, b) => b[0] - a[0]);
  let out = src;
  for (const [s, e, t] of edits) out = out.slice(0, s) + t + out.slice(e);
  if (!/import \{[^}]*\bLX\b[^}]*\} from "@\/lib\/i18n"/.test(out)) {
    const m = out.match(/import \{([^}]*)\} from "@\/lib\/i18n";/);
    out = m ? out.replace(m[0], `import {${m[1].trimEnd()}, LX } from "@/lib/i18n";`) : out.replace(/^(import [^\n]+\n)(?![\s\S]*^import )/m, `$1import { LX } from "@/lib/i18n";\n`);
  }
  fs.writeFileSync(f, out);
  total += edits.length; nfiles++;
}
console.log(`files ${nfiles} · wrapped ${total} · skipped(no lang) ${skipped.length}`);
if (skipped.length) console.log(skipped.slice(0, 30).join("\n"));
