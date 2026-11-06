import type { JSX } from "react";
import {
  IconChart,
  IconGlobe,
  IconSearch,
  IconSend,
  IconShield,
  IconUnlock,
} from "../Icons";

export type PageId = "bypass" | "hosts" | "check" | "logs" | "dns" | "telegram";

export interface NavPage {
  id: PageId;
  title: string;
  icon: (props: { size?: number }) => JSX.Element;
}

export const NAV_PAGES: NavPage[] = [
  { id: "bypass", title: "Обход", icon: IconShield },
  { id: "hosts", title: "Разблокировка", icon: IconUnlock },
  { id: "check", title: "Проверка", icon: IconSearch },
  { id: "logs", title: "Анализ лога", icon: IconChart },
  { id: "dns", title: "DNS", icon: IconGlobe },
  { id: "telegram", title: "Telegram", icon: IconSend },
];
