import type { ReactNode } from "react";
import { IconCheck, IconClose, IconInfo, IconWarning } from "../Icons";

type NoticeTone = "error" | "warn" | "ok" | "hint";

const ICONS = {
  error: IconClose,
  warn: IconWarning,
  ok: IconCheck,
  hint: IconInfo,
};

interface NoticeProps {
  tone: NoticeTone;
  children: ReactNode;
  actions?: ReactNode;
}

export function Notice({ tone, children, actions }: NoticeProps) {
  const Icon = ICONS[tone];
  return (
    <div
      className={`notice notice--${tone}`}
      role={tone === "error" ? "alert" : "status"}
    >
      <Icon size={16} />
      <div className="notice__body">{children}</div>
      {actions && <div className="notice__actions">{actions}</div>}
    </div>
  );
}
