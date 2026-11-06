import type { EngineSnapshot } from "../../hooks/useEngineStatus";
import { EngineIndicator } from "./EngineIndicator";
import { NavTabs } from "./NavTabs";
import { PageId } from "./pages";
import { PrimeMark } from "./PrimeMark";
import { WindowButtons } from "./WindowButtons";

interface TopBarProps {
  current: PageId;
  engine: EngineSnapshot;
  onNavigate: (page: PageId) => void;
}

export function TopBar({ current, engine, onNavigate }: TopBarProps) {
  return (
    <header className="topbar">
      <div className="brand">
        <PrimeMark />
        <span className="brand__name">
          <b>Prime</b>Bypass
        </span>
      </div>
      <NavTabs current={current} onNavigate={onNavigate} />
      <div className="topbar__end">
        <EngineIndicator engine={engine} onOpen={() => onNavigate("bypass")} />
        <WindowButtons />
      </div>
    </header>
  );
}
