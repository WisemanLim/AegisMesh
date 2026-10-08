"""Epic 39 — 접근성 자동 점검 (WCAG 2.2 AA · KWCAG 2.2): Playwright Chromium + axe-core 4.10.

`make e2e-a11y OUT=test/impl/<N>/logs` — 콘솔 경로 전부(apps/web/app/**/page.tsx, 읽기 전용 마운트)를 ko·en 으로 연다.
동적 경로는 목록 화면의 링크에서 실제 ID 를 찾아 경로 틀마다 1개(도메인·확장·관문은 몇 개 더)만 점검한다.
판정: axe 위반 중 serious·critical 0 + 키보드(본문 바로가기·초점 표시·초점 가림) + 로그인 입력 목적(autocomplete).
OUT/e2e-credentials.env(비커밋)의 ADMIN_PW·ADMIN_TOTP 로 로그인하고, 등록·재인증 화면용 시험 사용자를 만든 뒤 끝에 비활성화한다.
"""
import base64
import hashlib
import hmac
import json
import os
import re
import struct
import time
import urllib.error
import urllib.request
from urllib.parse import urlparse

from playwright.sync_api import Error as PWError
from playwright.sync_api import TimeoutError as PWTimeout
from playwright.sync_api import sync_playwright

W, A = "http://localhost:3000", "http://api:8000"
OUT = os.environ.get("E2E_OUT", "/out")
ROUTES = os.environ.get("E2E_ROUTES", "/routes")
AXE = open("/opt/axe/axe.min.js", encoding="utf-8").read()
TAGS = ["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "wcag22aa"]
GATE = ("serious", "critical")
MORE = {"/domains/[d]": 10, "/domains/[d]/[view]": 40, "/extended/[x]": 4, "/gates/[gate]": 3, "/findings/[id]": 8, "/incidents/[id]": 4, "/incidents/[id]/response": 2, "/catalog/[id]": 6}   # 도메인 화면은 영역마다 다르다 — 전부
SEPARATE = {"/login", "/login/mfa", "/enroll", "/reauth"}               # 로그인 흐름에서 따로 점검
KEYBOARD = ["/overview", "/incidents", "/catalog", "/approvals", "/policies"]
# Epic 40 (NFR-C4) — en 모드에서 이 화면들은 한글 0 (사용자 데이터는 data-user 로 표시해 제외)
HANGUL_GATE = {"/incidents", "/incidents/[id]", "/incidents/[id]/response", "/catalog", "/catalog/[id]", "/findings", "/findings/[id]", "/extended/[x]",
               "/domains/[d]", "/domains/[d]/[view]", "/domains/[d]/calls/[cid]", "/domains/[d]/grounding/[fid]", "/domains/[d]/inspect/[fid]",
               "/domains/[d]/lineage/[trace]"}                                    # 44차: 도메인 상세까지
HANGUL_JS = """() => {
  const out = [], HAN = /[가-힣]/, w = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
  while (w.nextNode()) {
    const t = w.currentNode.nodeValue.trim(), el = w.currentNode.parentElement;
    if (!t || !HAN.test(t) || !el || el.closest('[data-user], script, style, noscript, option')) continue;
    const tid = el.closest('[data-testid]');
    out.push({text: t.slice(0, 90), tag: el.tagName.toLowerCase(), testid: tid ? tid.getAttribute('data-testid') : null});
  }
  return out;
}"""
# Epic 45 — 1.4.10 재배치(320 CSS px, 표·코드처럼 스크롤 영역 안은 예외) · 1.4.12 글자 간격 · 1.4.4 글자 200% — ko 회차에서 쪽마다
LAYOUT = os.environ.get("E2E_LAYOUT", "1") == "1"
REFLOW_JS = """(vw) => {
  const docW = document.documentElement.scrollWidth;
  const inScroller = (el) => { for (let p = el.parentElement; p && p !== document.body; p = p.parentElement) {
    const cs = getComputedStyle(p); if (/(auto|scroll)/.test(cs.overflowX)) return true; } return false; };
  const off = [];
  if (docW > vw + 1) for (const el of document.querySelectorAll('body *')) {
    const r = el.getBoundingClientRect();
    if (r.width > 0 && r.right > vw + 1 && !inScroller(el)) off.push(el);
  }
  const name = (e) => e.tagName.toLowerCase() + (e.dataset.testid ? '[' + e.dataset.testid + ']' : '') + ([...e.classList].slice(0, 3).map(c => '.' + c).join(''));
  // 가로 스크롤 영역은 표·코드·2차원 배치를 담을 때만 예외 — 그 밖의 내용이 넘쳐 스크롤되면 실패
  const stray = [];
  for (const el of document.querySelectorAll('main *, header *')) {
    const cs = getComputedStyle(el);
    if (!/(auto|scroll)/.test(cs.overflowX) || el.scrollWidth <= el.clientWidth + 1) continue;
    const wide = [...el.querySelectorAll('*')].filter(c => c.getBoundingClientRect().right > el.getBoundingClientRect().right + 1);
    if (wide.some(c => !c.closest('table, pre, code, [data-2d], textarea'))) stray.push(name(el));
  }
  return {docW, ok: docW <= vw + 1 && stray.length === 0, offenders: off.filter(e => !off.includes(e.parentElement)).slice(0, 5).map(name), stray: stray.slice(0, 5)};
}"""
CLIP_JS = """(css) => {
  const st = document.createElement('style'); st.textContent = css; document.head.appendChild(st);
  const bad = [], warn = [];
  for (const el of document.querySelectorAll('header *, main *, aside *')) {
    const cs = getComputedStyle(el);
    if (!/(hidden|clip)/.test(cs.overflowX + cs.overflowY) || !el.textContent.trim() || el.offsetParent === null) continue;
    if (el.scrollWidth > el.clientWidth + 2 || el.scrollHeight > el.clientHeight + 2) {
      const n = el.tagName.toLowerCase() + (el.dataset.testid ? '[' + el.dataset.testid + ']' : '') + [...el.classList].slice(0, 3).map(c => '.' + c).join('');
      (cs.textOverflow === 'ellipsis' && el.title ? warn : bad).push(n + ' «' + el.textContent.trim().slice(0, 30) + '»');
    }
  }
  st.remove();
  return {bad: bad.slice(0, 5), badCount: bad.length, warnCount: warn.length};
}"""
SPACING_CSS = "* { line-height: 1.5 !important; letter-spacing: 0.12em !important; word-spacing: 0.16em !important; } p { margin-bottom: 2em !important; }"
ZOOM_CSS = "html { font-size: 200% !important; } html, body { font-size: 28px !important; }"


def layout(page, label: str) -> dict:
    vp = page.viewport_size
    page.set_viewport_size({"width": 320, "height": 800})
    page.wait_for_timeout(150)
    reflow = page.evaluate(REFLOW_JS, 320)
    page.set_viewport_size(vp)
    page.wait_for_timeout(100)
    spacing = page.evaluate(CLIP_JS, SPACING_CSS)
    zoom = page.evaluate(CLIP_JS, ZOOM_CSS)
    out = {"reflow": reflow, "spacing": spacing, "zoom": zoom}
    bad = [k for k, v in (("reflow", not reflow["ok"]), ("spacing", spacing["badCount"]), ("zoom", zoom["badCount"])) if v]
    if bad:
        say(f"     layout {label}: " + " · ".join(
            f"reflow {reflow['docW']}px {reflow['offenders'][:2]} stray {reflow.get('stray', [])[:3]}" if k == "reflow" else f"{k} {out[k]['badCount']} {out[k]['bad'][:2]}" for k in bad))
    return out


ONLY = [x for x in os.environ.get("E2E_ONLY", "").split(",") if x]       # 반복 수정용 — 이 경로에서 시작(동적 링크만 따라간다)
CREDS = {}
for line in open(os.path.join(OUT, "e2e-credentials.env"), encoding="utf-8"):
    if "=" in line and not line.startswith("#"):
        k, v = line.rstrip("\n").split("=", 1)
        CREDS[k] = v
log = open(os.path.join(OUT, "a11y-e2e.txt"), "w", encoding="utf-8")
report: list[dict] = []
checks: list[tuple[str, bool, str]] = []


def say(*a):
    s = " ".join(str(x) for x in a)
    print(s)
    log.write(s + "\n")
    log.flush()


def check(name, ok, detail=""):
    checks.append((name, bool(ok), detail))
    say(("PASS " if ok else "FAIL ") + name, "—", detail)


def api(method, path, token=None, body=None):
    r = urllib.request.Request(A + path, method=method, data=json.dumps(body).encode() if body is not None else None,
                               headers={"content-type": "application/json", **({"Authorization": f"Bearer {token}"} if token else {})})
    try:
        with urllib.request.urlopen(r) as res:
            return res.status, json.loads(res.read() or b"null")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()[:300]


def totp(secret, step):
    key = base64.b32decode(secret + "=" * (-len(secret) % 8))
    d = hmac.new(key, struct.pack(">Q", step), hashlib.sha1).digest()
    o = d[-1] & 0x0F
    return f"{(int.from_bytes(d[o:o + 4], 'big') & 0x7FFFFFFF) % 1_000_000:06d}"


def templates() -> list[str]:
    out = []
    for root, _, files in os.walk(ROUTES):
        if "page.tsx" in files:
            rel = os.path.relpath(root, ROUTES)
            out.append("/" if rel == "." else "/" + rel)
    return sorted(out)


TPL = templates()
# 정적 경로를 먼저, 동적은 [..] 적은 순 — /catalog/register 가 /catalog/[id] 보다 먼저 맞는다
ORDER = sorted(TPL, key=lambda t: (t.count("["), -t.count("/")))
RX = {t: re.compile("^" + "/".join(("[^/]+" if s.startswith("[") else re.escape(s)) for s in t.split("/")) + "$") for t in TPL}


def template_of(path: str) -> str | None:
    return next((t for t in ORDER if RX[t].match(path)), None)


def settle(page):
    """load 뒤 짧게 — 주기 갱신(알림·승인 트레이) 화면은 networkidle 이 오지 않는다."""
    page.wait_for_load_state("load")
    try:
        page.wait_for_load_state("networkidle", timeout=2500)
    except PWTimeout:
        pass


AT_JS = """() => {
  const vis = e => !!(e.offsetWidth || e.offsetHeight || e.getClientRects().length) && getComputedStyle(e).visibility !== 'hidden';
  const q = s => [...document.querySelectorAll(s)].filter(vis);
  const hs = q('h1,h2,h3,h4,h5,h6,[role=heading]').map(h => +(h.getAttribute('aria-level') || h.tagName.slice(1)) || 2);
  const skips = []; hs.forEach((l, i) => { if (i && l > hs[i - 1] + 1) skips.push(`h${hs[i - 1]}→h${l}`); });
  return {main: q('main,[role=main]').length, banner: q('header:not(main header):not(section header):not(article header),[role=banner]').length,
          nav: q('nav,[role=navigation]').length, h1: hs.filter(l => l === 1).length, skips, title: document.title.trim(), lang: document.documentElement.lang};
}"""
SHELLLESS = {"/login", "/login/mfa", "/enroll", "/reauth", "/onboarding", "/setup"}   # 셸 밖 화면 — 배너·탐색 없음이 정상(main 은 필수)
UNNAMED = re.compile(r"^\s*- (button|textbox|combobox|checkbox|radio|searchbox|spinbutton|slider|switch|link|tab|menuitem)(?: \[[^\]]*\])?\s*:?\s*$")


def assistive(page) -> dict:
    """보조기술 트리(Epic 63) — 랜드마크·제목 구조·쪽 제목(DOM) + 이름 없는 컨트롤(Chromium 접근성 트리, aria_snapshot)."""
    at = page.evaluate(AT_JS)
    try:
        snap = page.locator("body").aria_snapshot(timeout=5000)
    except PWError:
        snap = ""
    at["unnamed"] = [ln.strip() for ln in snap.splitlines() if UNNAMED.match(ln)][:8]
    return at


def axe(page, label: str, lang: str, tpl: str | None) -> list[dict]:
    if not page.evaluate("() => !!window.axe"):
        page.add_script_tag(content=AXE)
    res = page.evaluate("""async (tags) => {
        const r = await axe.run(document, {runOnly: {type: 'tag', values: tags}, resultTypes: ['violations']});
        return r.violations.map(v => ({id: v.id, impact: v.impact, help: v.help, count: v.nodes.length,
            nodes: v.nodes.slice(0, 4).map(n => ({target: n.target.join(' '), html: n.html.slice(0, 160), summary: (n.failureSummary || '').slice(0, 300)}))}));
    }""", TAGS)
    path = urlparse(page.url).path
    han = page.evaluate(HANGUL_JS) if lang == "en" else []
    lay = layout(page, label) if LAYOUT and lang == "ko" else None
    at = assistive(page)
    report.append({"label": label, "lang": lang, "template": tpl, "path": path, "violations": res, "hangul": han, "layout": lay, "at": at})
    shell = (tpl or path) not in SHELLLESS
    at["shell"] = shell
    at_bad = [k for k, v in (("main", at["main"] != 1), ("banner", shell and at["banner"] < 1), ("nav", shell and at["nav"] < 1), ("h1", at["h1"] != 1),
                             ("skips", at["skips"]), ("unnamed", at["unnamed"]), ("title", not at["title"])) if v]
    if at_bad:
        say(f"     AT {' '.join(at_bad)}: h1 {at['h1']} skips {at['skips'][:3]} unnamed {at['unnamed'][:3]} main {at['main']} nav {at['nav']}")
    if han:
        say(f"     hangul {len(han)}: " + " | ".join(h["text"][:40] for h in han[:4]))
    bad = [f"{v['id']}({v['impact']}×{v['count']})" for v in res if v["impact"] in GATE]
    minor = [f"{v['id']}({v['impact']}×{v['count']})" for v in res if v["impact"] not in GATE]
    say(f"[{lang}] {label:<44} {'OK ' if not bad else 'BAD'} {' '.join(bad)}{('  · ' + ' '.join(minor)) if minor else ''}")
    return res


def goto(page, url: str) -> None:
    """dev 서버가 메모리 임계로 재시작하는 동안의 시간 초과·연결 끊김 — 쉬었다가 1회 재시도."""
    try:
        page.goto(url, wait_until="domcontentloaded")
    except PWError:
        page.wait_for_timeout(8000)
        page.goto(url, wait_until="domcontentloaded")


def links(page) -> list[str]:
    hrefs = page.eval_on_selector_all("a[href]", "els => els.map(e => e.getAttribute('href'))")
    out = []
    for h in hrefs:
        if h and h.startswith("/") and not h.startswith("//"):
            out.append(h.split("#", 1)[0])
    return out


def crawl(page, lang: str):
    seen_paths, counts = set(), {}
    queue = list(ONLY) or [t for t in TPL if "[" not in t and t not in SEPARATE]
    while queue:
        url = queue.pop(0)
        path = urlparse(url).path
        if path in seen_paths:
            continue
        seen_paths.add(path)
        tpl = template_of(path)
        try:
            try:
                page.goto(W + url, wait_until="domcontentloaded")
            except PWError:                                             # dev 서버 메모리 임계 재시작(시간 초과·연결 끊김) — 1회 재시도
                page.wait_for_timeout(8000)
                page.goto(W + url, wait_until="domcontentloaded")
        except PWError as exc:
            check(f"[{lang}] {url} loads", False, str(exc).splitlines()[0][:120])
            continue
        settle(page)
        final = urlparse(page.url).path
        if final.startswith("/login"):
            raise SystemExit(f"session lost at {url} → {page.url}")
        axe(page, url if final == path else f"{url} → {final}", lang, tpl)
        for h in links(page):
            p = urlparse(h).path
            t = template_of(p)
            if t is None or "[" not in t or t in SEPARATE or p in seen_paths:
                continue
            if counts.get(t, 0) < MORE.get(t, 1):
                counts[t] = counts.get(t, 0) + 1
                queue.append(h)
    covered = {r["template"] for r in report if r["lang"] == lang}
    missing = [t for t in TPL if t not in covered and t not in SEPARATE]
    say(f"[{lang}] templates covered {len(covered)}/{len(TPL) - len(SEPARATE)} · not reached: {missing}")
    return missing


FOCUS_JS = """() => {
  const a = document.activeElement;
  if (!a || a === document.body) return null;
  const cs = getComputedStyle(a), r = a.getBoundingClientRect();
  const e = document.elementFromPoint(Math.min(innerWidth - 1, Math.max(0, r.left + r.width / 2)), Math.min(innerHeight - 1, Math.max(0, r.top + r.height / 2)));
  return {tag: a.tagName, name: (a.getAttribute('aria-label') || a.innerText || a.getAttribute('name') || '').trim().slice(0, 40), href: a.getAttribute('href'),
          visible: (cs.outlineStyle !== 'none' && parseFloat(cs.outlineWidth) > 0) || cs.boxShadow !== 'none',
          obscured: !!e && !(e === a || a.contains(e) || e.contains(a)) && !(e.closest('label') && e.closest('label').contains(a))};
}"""


def keyboard(page, lang: str):
    for path in KEYBOARD:
        goto(page, W + path)
        settle(page)
        page.evaluate("() => { document.activeElement && document.activeElement.blur(); window.scrollTo(0, 0); }")
        first, bad, hidden, stops = None, [], [], 0
        for i in range(30):
            page.keyboard.press("Tab")
            f = page.evaluate(FOCUS_JS)
            if f is None:
                continue
            stops += 1
            first = first or f
            if not f["visible"]:
                bad.append(f"{f['tag']}:{f['name'] or f['href']}")
            if f["obscured"]:
                hidden.append(f"{f['tag']}:{f['name'] or f['href']}")
        check(f"[{lang}] {path} skip link first", bool(first) and (first.get("href") or "") == "#main", str(first)[:120])
        check(f"[{lang}] {path} focus visible ({stops} stops)", not bad, ", ".join(bad[:6]))
        check(f"[{lang}] {path} focus not obscured", not hidden, ", ".join(hidden[:6]))
        if path == "/overview":
            goto(page, W + path)
            settle(page)
            page.evaluate("() => document.activeElement && document.activeElement.blur()")
            page.keyboard.press("Tab")
            page.keyboard.press("Enter")
            target = page.evaluate("() => document.activeElement && (document.activeElement.id || document.activeElement.tagName)")
            check(f"[{lang}] skip link moves focus to main", target in ("main", "MAIN"), str(target))


def set_lang(ctx, lang):
    ctx.add_cookies([{"name": "lang", "value": lang, "url": W}])


def login_form(page, user, pw):
    page.fill("form input[name=username]", user)
    page.fill("form input[name=password]", pw)
    page.click("form button.btn-primary")
    page.wait_for_load_state("networkidle")


def autocomplete(page, sel, want):
    got = page.get_attribute(sel, "autocomplete") or ""
    return want in got.split(), got


# 관리자 토큰(시험 사용자 생성·정리) — OTP 시간 단계 s0, 브라우저 로그인은 s0+1 (서버는 같은 단계 재사용 거부)
s0 = int(time.time() // 30)
st, adm = api("POST", "/v1/auth/login", body={"username": "plat.admin", "password": CREDS["ADMIN_PW"]})
if isinstance(adm, dict) and "mfa" in adm:
    st, adm = api("POST", "/v1/auth/mfa:verify", body={"ticket": adm["mfa"]["ticket"], "code": totp(CREDS["ADMIN_TOTP"], s0)})
USER, PW = f"a11y.e2e{int(time.time())}", "Ax-" + base64.urlsafe_b64encode(os.urandom(15)).decode()
st, made = api("POST", "/v1/users", adm["token"], {"username": USER, "displayName": "a11y e2e", "roles": ["approver"], "tenant": "garam", "password": PW})
say("routes", len(TPL), "· test user", USER, st)

missing = {}
try:
    with sync_playwright() as p:
        browser = p.chromium.launch()

        # 1) 로그인 화면 ko·en + 2단계 화면 (관리자 로그인 도중)
        ctx = browser.new_context(locale="ko-KR", viewport={"width": 1440, "height": 1000}, bypass_csp=True)
        ctx.set_default_navigation_timeout(90000)                       # dev 서버 첫 컴파일
        page = ctx.new_page()
        for lang in ("en", "ko"):
            set_lang(ctx, lang)
            page.goto(f"{W}/login")
            settle(page)
            axe(page, "/login", lang, "/login")
        check("login username autocomplete=username", *autocomplete(page, "form input[name=username]", "username"))
        check("login password autocomplete=current-password", *autocomplete(page, "form input[name=password]", "current-password"))
        login_form(page, "plat.admin", CREDS["ADMIN_PW"])
        axe(page, "/login/mfa", "ko", "/login/mfa")
        check("OTP autocomplete=one-time-code", *autocomplete(page, "[data-testid=otp-form] input[name=code]", "one-time-code"))
        page.fill("[data-testid=otp-form] input[name=code]", totp(CREDS["ADMIN_TOTP"], s0 + 1))
        page.click("[data-testid=otp-form] button")
        page.wait_for_url("**/overview")

        # 2) 전 경로 ko → en
        for lang in ("ko", "en"):
            set_lang(ctx, lang)
            missing[lang] = crawl(page, lang)
            keyboard(page, lang)

        # 3) 등록(강제)·재인증 화면 — 2단계 수단 없는 승인자
        ctx2 = browser.new_context(locale="ko-KR", viewport={"width": 1440, "height": 1000}, bypass_csp=True)
        pg = ctx2.new_page()
        pg.goto(f"{W}/login")
        set_lang(ctx2, "en")
        pg.goto(f"{W}/login")
        login_form(pg, USER, PW)
        pg.wait_for_url("**/enroll**")
        settle(pg)
        axe(pg, "/enroll", "en", "/enroll")
        set_lang(ctx2, "ko")
        pg.reload()
        settle(pg)
        axe(pg, "/enroll", "ko", "/enroll")
        pg.click("[data-testid=enroll-totp-start]")
        pg.wait_for_selector("[data-testid=enroll-totp-secret]")
        axe(pg, "/enroll (OTP setup)", "ko", "/enroll")
        check("enroll OTP autocomplete=one-time-code", *autocomplete(pg, "[data-testid=enroll-totp] input[name=code]", "one-time-code"))
        secret = pg.inner_text("[data-testid=enroll-totp-secret]").strip()
        pg.fill("[data-testid=enroll-totp] input[name=code]", totp(secret, int(time.time() // 30)))
        pg.click("[data-testid=enroll-totp] button")
        pg.wait_for_url("**/overview")
        ctx2.set_extra_http_headers({"X-Forwarded-For": "198.51.100.77"})      # 새 위치 → 재인증
        pg.goto(f"{W}/approvals")
        settle(pg)
        check("new location → /reauth", "/reauth" in pg.url, pg.url)
        axe(pg, "/reauth", "ko", "/reauth")
        check("reauth OTP autocomplete=one-time-code", *autocomplete(pg, "input[name=code]", "one-time-code"))
        set_lang(ctx2, "en")
        pg.reload()
        settle(pg)
        axe(pg, "/reauth", "en", "/reauth")
        browser.close()
finally:                                                                # 시험 사용자 정리 — 중간 실패에도
    api("PATCH", f"/v1/users/{made['id']}", adm["token"], {"active": False})
    api("POST", "/v1/auth/logout", adm["token"])
    with open(os.path.join(OUT, "a11y-report.json"), "w", encoding="utf-8") as f:
        json.dump({"axe": "4.10.3", "tags": TAGS, "pages": report, "checks": checks, "notReached": missing}, f, ensure_ascii=False, indent=1)


by_rule: dict[str, list] = {}
for r in report:
    for v in r["violations"]:
        by_rule.setdefault(f"{v['id']} ({v['impact']})", []).append(f"{r['lang']}:{r['path']}")
say("\n== rules")
for k, v in sorted(by_rule.items(), key=lambda kv: -len(kv[1])):
    say(f"{k:<40} {len(v):>3} pages  e.g. {', '.join(v[:4])}")
for t in sorted(HANGUL_GATE):
    pages = [r for r in report if r["lang"] == "en" and r["template"] == t]
    if pages:
        n = sum(len(r["hangul"]) for r in pages)
        check(f"[en] hangul 0 on {t} ({len(pages)} pages)", n == 0, "; ".join(h["text"][:40] for r in pages for h in r["hangul"][:3])[:300])
if LAYOUT:
    lays = [r for r in report if r.get("layout")]
    for key, test in (("reflow 320px (1.4.10)", lambda l: not l["reflow"]["ok"]), ("text spacing (1.4.12)", lambda l: l["spacing"]["badCount"] > 0),
                      ("text 200% (1.4.4)", lambda l: l["zoom"]["badCount"] > 0)):
        failing = [r["path"] for r in lays if test(r["layout"])]
        check(f"[ko] {key} — {len(lays) - len(failing)}/{len(lays)} pages", not failing, ", ".join(failing[:8]))
for lang in ("ko", "en"):                                              # 보조기술 트리(Epic 63) — 화면 낭독기가 쓰는 구조
    ats = [r for r in report if r["lang"] == lang and r.get("at")]
    for key, test in (("landmarks (main 1 · banner · navigation)", lambda a: a["main"] != 1 or (a["shell"] and (a["banner"] < 1 or a["nav"] < 1))),
                      ("headings (h1 1 · no skipped level)", lambda a: a["h1"] != 1 or bool(a["skips"])),
                      ("accessible names (controls)", lambda a: bool(a["unnamed"])),
                      ("page title + lang", lambda a: not a["title"] or a["lang"] != lang)):
        failing = [f"{r['path']}" for r in ats if test(r["at"])]
        check(f"[{lang}] AT {key} — {len(ats) - len(failing)}/{len(ats)} pages", not failing, ", ".join(failing[:8]))
serious = sum(v["count"] for r in report for v in r["violations"] if v["impact"] in GATE)
failed = [c for c in checks if not c[1]]
say(f"\npages {len(report)} · serious/critical nodes {serious} · keyboard/auth checks {len(checks) - len(failed)}/{len(checks)}")
with open(os.path.join(OUT, "a11y-report.json"), "w", encoding="utf-8") as f:                 # 한글 판정까지 포함해 다시 쓴다
    json.dump({"axe": "4.10.3", "tags": TAGS, "pages": report, "checks": checks, "notReached": missing}, f, ensure_ascii=False, indent=1)
say("RESULT", "PASS" if serious == 0 and not failed else "FAIL")
raise SystemExit(0 if serious == 0 and not failed else 1)
