"""Epic 34 — 패스키(WebAuthn) E2E: Playwright Chromium + CDP 가상 인증기 (SCR-B02 · FR-D5-01·03).

`make e2e-passkey OUT=test/impl/<N>/logs` — 콘솔 컨테이너 네트워크를 공유해 http://localhost:3000 (보안 컨텍스트·RP ID localhost)
으로 접속한다. OUT/e2e-credentials.env(비커밋)의 ADMIN_PW 로 실행마다 새 시험 사용자를 만들고 끝에 비활성화한다.
흐름: 비밀번호 로그인 → 패스키 등록(가상 인증기) → OTP 등록 → 로그아웃 → 비밀번호 + 패스키 2단계 → 새 위치(재인증·패스키)
→ OTP 2단계 → 탈취 토큰 재사용(쿠키 토큰을 증명 없이 API 에 직접) → 세션 전체 폐기·사건.
"""
import base64
import hashlib
import hmac
import json
import os
import struct
import sys
import time
import urllib.error
import urllib.request

from playwright.sync_api import sync_playwright

W, A = "http://localhost:3000", "http://api:8000"
OUT = os.environ.get("E2E_OUT", "/out")
CREDS = {}
for line in open(os.path.join(OUT, "e2e-credentials.env"), encoding="utf-8"):
    if "=" in line and not line.startswith("#"):
        k, v = line.rstrip("\n").split("=", 1)
        CREDS[k] = v
log = open(os.path.join(OUT, "passkey-e2e.txt"), "w", encoding="utf-8")
results: list[tuple[str, bool, str]] = []


def say(*a):
    s = " ".join(str(x) for x in a)
    print(s)
    log.write(s + "\n")
    log.flush()


def check(name, ok, detail=""):
    results.append((name, bool(ok), detail))
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


def text(page, sel):
    el = page.query_selector(sel)
    return el.inner_text() if el else ""


def login_pw(page):
    page.goto(f"{W}/login")
    page.fill("form input[name=username]", USER)
    page.fill("form input[name=password]", PW)
    page.click("form button.btn-primary")
    page.wait_for_load_state("networkidle")


# 실행마다 새 시험 사용자(2단계 수단 없음) — 관리자(ADMIN_PW)로 만들고 끝에 비활성화한다. 비밀번호는 이 실행 안에서만.
st, adm = api("POST", "/v1/auth/login", body={"username": "plat.admin", "password": CREDS["ADMIN_PW"]})
if isinstance(adm, dict) and "mfa" in adm:                              # 특권 역할 2단계 강제(OQ3) — 관리자 OTP(ADMIN_TOTP)
    st, adm = api("POST", "/v1/auth/mfa:verify", body={"ticket": adm["mfa"]["ticket"], "code": totp(CREDS["ADMIN_TOTP"], int(time.time() // 30))})
USER, PW = f"pk.e2e{int(time.time())}", "Pk-" + base64.urlsafe_b64encode(os.urandom(15)).decode()
st, made = api("POST", "/v1/users", adm["token"], {"username": USER, "displayName": "passkey e2e", "roles": ["security_engineer"], "tenant": "garam", "password": PW})
say("test user", USER, st)

with sync_playwright() as p:
    browser = p.chromium.launch()
    ctx = browser.new_context(locale="ko-KR", viewport={"width": 1440, "height": 1000})
    page = ctx.new_page()
    cdp = ctx.new_cdp_session(page)
    cdp.send("WebAuthn.enable")
    auth = cdp.send("WebAuthn.addVirtualAuthenticator", {"options": {"protocol": "ctap2", "transport": "internal", "hasResidentKey": True,
                                                                      "hasUserVerification": True, "isUserVerified": True,
                                                                      "automaticPresenceSimulation": True}})["authenticatorId"]
    say("virtual authenticator", auth)

    login_pw(page)
    check("password login (no factor yet) → overview", page.url.endswith("/overview"), page.url)
    page.goto(f"{W}/account")
    check("account warns no second factor", "2단계 인증 수단 없음" in page.inner_text("main"))
    page.click("[data-testid=passkey-add]")
    page.wait_for_selector("[data-testid=passkey-register]")
    page.fill("input[aria-label='passkey name']", "E2E virtual key")
    page.click("[data-testid=passkey-register]")
    page.wait_for_url("**/account?msg=*")
    check("register passkey via navigator.credentials.create", "패스키 등록" in text(page, "main [role=status],main [role=alert]"), text(page, "main [role=status]")[:120])
    creds = cdp.send("WebAuthn.getCredentials", {"authenticatorId": auth})["credentials"]
    check("authenticator holds 1 credential (rpId localhost)", len(creds) == 1 and creds[0]["rpId"] == "localhost", str([c["rpId"] for c in creds]))
    page.click("[data-testid=totp-start]")
    page.wait_for_selector("[data-testid=totp-secret]")
    secret = page.inner_text("[data-testid=totp-secret]").strip()
    page.fill("[data-testid=totp-setup] input[name=code]", totp(secret, int(time.time() // 30)))
    page.click("[data-testid=totp-setup] button")
    page.wait_for_url("**/account?msg=*")
    check("authenticator-app OTP enrolled", "인증 앱 OTP 사용" in text(page, "main [role=status],main [role=alert]"))
    page.screenshot(path=os.path.join(OUT, "b02-account-ko.png"), full_page=True)

    page.goto(f"{W}/logout")
    login_pw(page)
    check("password step → second-factor page", "/login/mfa" in page.url, page.url)
    page.screenshot(path=os.path.join(OUT, "b02-mfa-ko.png"), full_page=True)
    page.click("[data-testid=passkey-login]")
    page.wait_for_url("**/overview")
    check("passkey assertion → signed in", page.url.endswith("/overview"))
    page.goto(f"{W}/account")
    row = text(page, "[data-testid=sessions] tbody tr")
    check("session bound: DPoP + webauthn", "DPoP" in row and "webauthn" in row, row.replace("\n", " ")[:160])

    ctx.set_extra_http_headers({"X-Forwarded-For": "198.51.100.23"})       # 새 위치
    page.goto(f"{W}/approvals")
    page.wait_for_load_state("networkidle")
    check("new location → /reauth (MSG-030)", "/reauth" in page.url and "새 위치" in page.inner_text("main"), page.url)
    page.screenshot(path=os.path.join(OUT, "b02-reauth-ko.png"), full_page=True)
    page.click("[data-testid=passkey-reauth]")
    page.wait_for_url("**/approvals")
    check("passkey re-auth → back to /approvals", page.url.endswith("/approvals"))
    page.goto(f"{W}/account")
    check("session rebound to new location", "198.51.100.0/24" in text(page, "[data-testid=sessions]"))

    ctx.set_extra_http_headers({})
    page.goto(f"{W}/logout")
    login_pw(page)
    page.wait_for_selector("[data-testid=otp-form]")
    page.fill("[data-testid=otp-form] input[name=code]", totp(secret, int(time.time() // 30) + 1))
    page.click("[data-testid=otp-form] button")
    page.wait_for_url("**/overview")
    check("OTP fallback second step → signed in", page.url.endswith("/overview"))

    tok = next(c["value"] for c in ctx.cookies() if c["name"] == "aegis_session")
    st, body = api("GET", "/v1/auth/me", tok)                                 # 쿠키에서 빼낸 토큰을 증명 없이 직접 사용
    check("stolen token without DPoP proof → 401 (session theft)", st == 401 and "세션 탈취" in str(body), f"{st} {str(body)[:120]}")
    page.goto(f"{W}/overview")
    page.wait_for_load_state("networkidle")
    check("browser session revoked → login", "/login" in page.url, page.url)
    st, incs = api("GET", "/v1/incidents?limit=30", adm["token"])
    hit = [i for i in incs["items"] if "D5-03.token-replay" in json.dumps(i)]
    check("incident opened for D5-03.token-replay", bool(hit), hit[0]["id"] if hit else "")
    api("PATCH", f"/v1/users/{made['id']}", adm["token"], {"active": False})       # 시험 사용자 정리
    api("POST", "/v1/auth/logout", adm["token"])
    browser.close()

passed = sum(ok for _, ok, _ in results)
say(f"\nRESULT {passed}/{len(results)} passed")
sys.exit(0 if passed == len(results) else 1)
