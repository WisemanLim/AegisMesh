// 도메인 상세 화면 디스패처 — /domains/{d}/{view} → 화면 컴포넌트 (SCR-E03·E04·F02~F04 …). 목록은 lib/domainScreens.
import { notFound } from "next/navigation";
import { screenOf } from "@/lib/domainScreens";
import { me, prefs } from "@/lib/session";
import type { ScreenProps } from "../../_screens/common";
import { Exfil, GoalJailbreak } from "../../_screens/d1";
import { Erasure, Isolation, Pii } from "../../_screens/d2";
import { Calls, Registry, Sandbox } from "../../_screens/d3";
import { Decisions, GroundingList, Propagation } from "../../_screens/d4";
import { Authz, Identity, Tokens } from "../../_screens/d5";
import { Autonomy, Budgets, Lineage } from "../../_screens/d6";
import { Integrity, Review, Sbom } from "../../_screens/d7";
import { Bias, Context, Memory } from "../../_screens/d8";
import { Network, Posture, Runtime } from "../../_screens/d9";

const SCREENS: Record<string, (p: ScreenProps) => Promise<React.ReactNode>> = {
  "D1/goal-jailbreak": GoalJailbreak, "D1/exfil": Exfil,
  "D2/pii": Pii, "D2/isolation": Isolation, "D2/erasure": Erasure,
  "D3/calls": Calls, "D3/sandbox": Sandbox, "D3/registry": Registry,
  "D4/grounding": GroundingList, "D4/decisions": Decisions, "D4/propagation": Propagation,
  "D5/identity": Identity, "D5/tokens": Tokens, "D5/authz": Authz,
  "D6/autonomy": Autonomy, "D6/lineage": Lineage, "D6/budgets": Budgets,
  "D7/review": Review, "D7/sbom": Sbom, "D7/integrity": Integrity,
  "D8/memory": Memory, "D8/context": Context, "D8/bias": Bias,
  "D9/posture": Posture, "D9/runtime": Runtime, "D9/network": Network,
};

export default async function DomainDetail({ params, searchParams }: { params: Promise<{ d: string; view: string }>; searchParams: Promise<Record<string, string | undefined>> }) {
  const { d, view } = await params;
  const screen = screenOf(d, view);
  const Screen = SCREENS[`${d.toUpperCase()}/${view}`];
  if (!screen || !Screen) notFound();
  const [{ lang }, user, sp] = await Promise.all([prefs(), me(), searchParams]);
  return <Screen lang={lang} user={user} d={d} screen={screen} sp={sp} />;
}
