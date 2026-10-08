// 콘솔 본문 영어화 코드모드 (Epic 26, NFR-C4) — 한국어 원문을 메시지 ID 로 쓰는 L(lang, "원문", ...인자) 호출로 바꾼다.
//   대상: JSX 텍스트 · 표시용 JSX 속성 · JSX 자식 위치의 문자열·템플릿 · "use server" 액션의 메시지 문자열·템플릿
//   lang 이 없는 함수: async 서버 컴포넌트·액션 → `const { lang } = await prefs();`, 클라이언트 컴포넌트 → `const lang = useLang();`
//   결과: 파일 수정 + scripts/i18n-msgids.json(카탈로그에 넣을 원문 전부 — 손으로 감쌀 상수 포함) + 수동 처리 목록
//   node scripts/i18n-codemod.mjs [--dry]
import fs from "node:fs";
import path from "node:path";
import ts from "typescript";

const DRY = process.argv.includes("--dry");
const HAN = /[가-힣]/;
const NON_DISPLAY_ATTR = new Set(["value", "name", "href", "key", "id", "className", "defaultValue", "type", "pattern", "accept", "action", "method", "src", "style", "data-testid"]);
const ENT = { "&lt;": "<", "&gt;": ">", "&amp;": "&", "&quot;": '"', "&#39;": "'", "&apos;": "'", "&nbsp;": " " };
const files = [];
for (const d of ["app", "components", "lib"]) (function walk(p) {
  for (const e of fs.readdirSync(p, { withFileTypes: true })) {
    const f = path.join(p, e.name);
    if (e.isDirectory()) walk(f); else if (/\.tsx?$/.test(f) && !/lib\/(en|i18n)\.ts$/.test(f)) files.push(f);
  }
})(d);

function collapse(text) {                                            // React/Babel JSX 공백 규칙
  const lines = text.split(/\r\n|\n|\r/);
  let last = -1;
  lines.forEach((l, i) => { if (/[^ \t]/.test(l)) last = i; });
  let out = "";
  lines.forEach((line, i) => {
    let t = line.replace(/\t/g, " ");
    if (i !== 0) t = t.replace(/^[ ]+/, "");
    if (i !== lines.length - 1) t = t.replace(/[ ]+$/, "");
    if (t) { if (i !== last) t += " "; out += t; }
  });
  return out.replace(/&(lt|gt|amp|quot|#39|apos|nbsp);/g, (m) => ENT[m]).replace(/&#(\d+);/g, (_, n) => String.fromCharCode(Number(n)));
}

function template(node) {                                           // `a ${x} b` → ["a {0} b", ["x"]]
  let s = node.head.text, args = [];
  node.templateSpans.forEach((sp, i) => { s += `{${i}}` + sp.literal.text; args.push(sp.expression.getText()); });
  return [s, args];
}

const msgids = new Set();
const manual = [];
let changed = 0, sites = 0;

for (const f of files) {
  const src = fs.readFileSync(f, "utf8");
  if (!HAN.test(src.replace(/\/\/.*$/gm, "").replace(/\/\*[\s\S]*?\*\//g, ""))) continue;
  const sf = ts.createSourceFile(f, src, ts.ScriptTarget.Latest, true, f.endsWith("x") ? ts.ScriptKind.TSX : ts.ScriptKind.TS);
  const isClient = src.startsWith('"use client"');
  const isAction = src.startsWith('"use server"');
  const edits = [];                                                  // [start, end, text, fnNode]

  const enclosingFn = (n) => { for (let p = n.parent; p; p = p.parent) if (ts.isFunctionLike(p)) return p; return null; };
  const call = (s, args) => `L(lang, ${JSON.stringify(s)}${args.map((a) => `, ${a}`).join("")})`;
  const inNoTranslateCall = (n) => {                                  // API 본문·로그·비교 인자는 그대로
    for (let p = n.parent; p && !ts.isFunctionLike(p); p = p.parent) {
      if (ts.isCallExpression(p)) {
        const c = p.expression.getText();
        if (/^(api|JSON\.stringify|fetch|console\.\w+|new URLSearchParams|encodeURIComponent)$/.test(c) || /\.(startsWith|endsWith|includes|split|replace|get|has)$/.test(c)) return true;
      }
      if (ts.isPropertyAssignment(p) && p.name.getText() === "body") return true;
    }
    return false;
  };
  const displayCtx = (n) => {                                          // JSX 자식·속성 위치까지 조건식만 거쳐 올라가는가
    let c = n;
    for (let p = n.parent; p; c = p, p = p.parent) {
      if (ts.isParenthesizedExpression(p)) continue;
      if (ts.isConditionalExpression(p) && (p.whenTrue === c || p.whenFalse === c)) continue;
      if (ts.isBinaryExpression(p) && p.right === c && [ts.SyntaxKind.AmpersandAmpersandToken, ts.SyntaxKind.BarBarToken, ts.SyntaxKind.QuestionQuestionToken].includes(p.operatorToken.kind)) continue;
      if (ts.isJsxExpression(p)) {
        const q = p.parent;
        if (ts.isJsxElement(q) || ts.isJsxFragment(q)) return true;
        if (ts.isJsxAttribute(q)) return !NON_DISPLAY_ATTR.has(q.name.getText());
        return false;
      }
      return false;
    }
    return false;
  };

  (function visit(node) {
    if (ts.isJsxText(node) && HAN.test(node.text)) {
      const s = collapse(node.getFullText());
      if (s.trim()) { msgids.add(s.trim()); edits.push([node.pos, node.end, `{${call(s, [])}}`, enclosingFn(node)]); }
      return;
    }
    if (ts.isJsxAttribute(node) && node.initializer && ts.isStringLiteral(node.initializer) && HAN.test(node.initializer.text)) {
      msgids.add(node.initializer.text.trim());
      if (!NON_DISPLAY_ATTR.has(node.name.getText())) edits.push([node.initializer.getStart(), node.initializer.getEnd(), `{${call(node.initializer.text, [])}}`, enclosingFn(node)]);
      return;
    }
    if (ts.isCallExpression(node) && node.expression.getText() === "tr") return;   // 이미 한·영 병기(tr)
    if (ts.isCallExpression(node) && node.expression.getText() === "L") {          // 이미 변환됨 — 원문만 모은다(재실행 안전)
      const a = node.arguments[1];
      if (a && (ts.isStringLiteral(a) || ts.isNoSubstitutionTemplateLiteral(a))) msgids.add(a.text.trim());
      node.arguments.slice(2).forEach(visit);
      return;
    }
    if ((ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node)) && HAN.test(node.text)) {
      if (ts.isImportDeclaration(node.parent) || (ts.isPropertyAssignment(node.parent) && node.parent.name === node)) return;
      msgids.add(node.text.trim());
      const fn = enclosingFn(node);
      if (fn && (displayCtx(node) || (isAction && !inNoTranslateCall(node)))) edits.push([node.getStart(), node.getEnd(), call(node.text, []), fn]);
      else manual.push(`${f}:${sf.getLineAndCharacterOfPosition(node.getStart()).line + 1} ${node.text.slice(0, 60)}`);
      return;
    }
    if (ts.isTemplateExpression(node) && HAN.test(node.head.text + node.templateSpans.map((s) => s.literal.text).join(""))) {
      const [s, args] = template(node);
      msgids.add(s.trim());
      const fn = enclosingFn(node);
      if (fn && (displayCtx(node) || (isAction && !inNoTranslateCall(node)))) { edits.push([node.getStart(), node.getEnd(), call(s, args), fn]); return; }
      manual.push(`${f}:${sf.getLineAndCharacterOfPosition(node.getStart()).line + 1} \`${s.slice(0, 60)}\``);
    }
    ts.forEachChild(node, visit);
  })(sf);

  if (!edits.length) continue;
  // lang 범위 확보 — 함수(또는 그 바깥 함수)에 lang 선언·매개변수가 없으면 넣는다
  const declaresLang = (fn) => /\blang\b/.test((fn.parameters || []).map((p) => p.getText()).join(",")) ||
    (fn.body && ts.isBlock(fn.body) && fn.body.statements.some((st) => /\b(const|let)\s*(\{[^}]*\blang\b[^}]*\}|lang)\s*=/.test(st.getText())));
  const inserts = new Map();
  let needPrefs = false, needUseLang = false;
  for (const [, , , fn] of edits) {
    let ok = false, top = fn;
    for (let p = fn; p; p = p.parent) { if (ts.isFunctionLike(p)) { top = p; if (declaresLang(p)) { ok = true; break; } } }
    if (ok || inserts.has(top)) continue;
    const isAsync = top.modifiers?.some((m) => m.kind === ts.SyntaxKind.AsyncKeyword);
    if (!top.body || !ts.isBlock(top.body)) { manual.push(`${f}: lang 범위 없음(식 본문 함수) ${top.name?.getText() ?? "(익명)"}`); inserts.set(top, null); continue; }
    if (isClient) { inserts.set(top, "\n  const lang = useLang();"); needUseLang = true; }
    else if (isAsync) { inserts.set(top, "\n  const { lang } = await prefs();"); needPrefs = true; }
    else { manual.push(`${f}: lang 범위 없음(동기 서버 함수) ${top.name?.getText() ?? "(익명)"}`); inserts.set(top, null); }
  }
  for (const [fn, text] of inserts) if (text) edits.push([fn.body.getStart() + 1, fn.body.getStart() + 1, text, null]);
  edits.sort((a, b) => b[0] - a[0]);
  let out = src;
  for (const [s, e, t] of edits) out = out.slice(0, s) + t + out.slice(e);
  const imports = [];
  if (!/\bimport\s*\{[^}]*\bL\b[^}]*\}\s*from\s*"@\/lib\/i18n"/.test(out)) imports.push('import { L } from "@/lib/i18n";');
  if (needPrefs && !/\bprefs\b[^;]*from\s*"@\/lib\/session"/.test(out)) imports.push('import { prefs } from "@/lib/session";');
  if (needUseLang) imports.push('import { useLang } from "@/lib/lang";');
  if (imports.length) {
    const lastImport = [...out.matchAll(/^import [^;]+;\s*$/gm)].pop();
    const at = lastImport ? lastImport.index + lastImport[0].length : (out.startsWith('"use') ? out.indexOf("\n") + 1 : 0);
    out = out.slice(0, at) + (lastImport ? "\n" : "") + imports.join("\n") + (lastImport ? "" : "\n") + out.slice(at);
  }
  sites += edits.length - [...inserts.values()].filter(Boolean).length;
  changed++;
  if (!DRY) fs.writeFileSync(f, out);
}
fs.writeFileSync("scripts/i18n-msgids.json", JSON.stringify([...msgids].sort(), null, 1));
fs.writeFileSync("scripts/i18n-manual.txt", manual.join("\n") + "\n");
console.log(`files ${changed} · sites ${sites} · msgids ${msgids.size} · manual ${manual.length}${DRY ? " (dry)" : ""}`);
