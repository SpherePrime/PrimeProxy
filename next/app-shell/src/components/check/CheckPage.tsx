import { useMemo } from "react";
import { enableOnlyTargets, GROUP_ORDER, isUniversal, targetForDomain } from "../bypass/presetCatalog";
import type { PageId } from "../shell/pages";
import { Notice } from "../ui/Notice";
import { PageHead } from "../ui/PageHead";
import { DomainPicker } from "./DomainPicker";
import { ResultsPanel } from "./ResultsPanel";
import { useSiteCheck } from "./useSiteCheck";
import "../../styles/pages/check.css";

export function CheckPage({ onNavigate }: { onNavigate: (page: PageId) => void }) {
  const model = useSiteCheck();

  const fixTargets = useMemo(() => {
    const targets = model.blocked
      .map((result) => targetForDomain(result.domain))
      .filter((target): target is string => Boolean(target));
    return [...new Set(targets)];
  }, [model.blocked]);

  const enableProfiles = () => {
    const allTargets = GROUP_ORDER.filter((target) => !isUniversal(target));
    enableOnlyTargets(fixTargets, [...allTargets]);
    onNavigate("bypass");
  };

  return (
    <div className="page">
      <PageHead
        eyebrow="Диагностика"
        title={
          <>
            Что <em>заблокировано</em>
          </>
        }
        lead="Прямая проверка доступности сервисов из вашей сети. Заблокированные можно сразу отправить в профили обхода."
      />

      <div className="notices">{model.error && <Notice tone="error">{model.error}</Notice>}</div>

      <div className="layout">
        <div className="layout__main">
          <DomainPicker model={model} />
        </div>
        <aside className="layout__side layout__side--sticky">
          <ResultsPanel model={model} fixableCount={fixTargets.length} onFix={enableProfiles} />
        </aside>
      </div>
    </div>
  );
}
