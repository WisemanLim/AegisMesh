import { L } from "@/lib/i18n";
import { prefs } from "@/lib/session";

export default async function NotFound() {
  const { lang } = await prefs();
  return <div className="card p-8 text-center"><h1 className="text-lg font-bold">404</h1><p className="text-muted">{L(lang, "찾을 수 없는 항목입니다.")}</p></div>;
}
