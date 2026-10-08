// 재인증·2단계 등록 관문으로 가는 경유지 — RSC 가 아닌 HTML 을 돌려줘 클라이언트 라우터가 전체 페이지 로드로 넘어가게 한다.
// 같은 루트 레이아웃 안에서 셸 ↔ 관문(맨 화면) 전환을 소프트 내비게이션으로 하면 RSC 재요청이 반복되고, 주소가 경유지에 남으면
// 서버 액션이 경유지로 POST 된다 → 문서 로드로 주소를 관문 화면으로 바꾼다.
import { type NextRequest } from "next/server";

const ALLOWED = ["/enroll", "/reauth"];

export function GET(req: NextRequest) {
  const to = req.nextUrl.searchParams.get("to") ?? "/overview";
  const dest = to.startsWith("/") && !to.startsWith("//") && ALLOWED.some((p) => to === p || to.startsWith(`${p}?`)) ? to : "/overview";
  const js = JSON.stringify(dest);
  const html = `<!doctype html><meta charset="utf-8"><meta http-equiv="refresh" content="0;url=${dest.replace(/"/g, "&quot;")}"><script>location.replace(${js})</script>`;
  return new Response(html, { headers: { "content-type": "text/html; charset=utf-8", "cache-control": "no-store" } });
}
