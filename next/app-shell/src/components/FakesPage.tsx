import { useEffect, useMemo, useState } from "react";
import { fetchFakes, FakeInfo } from "../api";
import { IconClose, IconLayers, IconSearch } from "./Icons";
import { PageHeader } from "./PageHeader";

// Размер в человекочитаемом виде (КБ/Б).
function sizeLabel(bytes: number): string {
  if (bytes >= 1024) return `${(bytes / 1024).toFixed(1)} КБ`;
  return `${bytes} Б`;
}

export function FakesPage() {
  const [fakes, setFakes] = useState<FakeInfo[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState("");
  const [kind, setKind] = useState("все");

  useEffect(() => {
    let cancelled = false;
    fetchFakes()
      .then((data) => {
        if (!cancelled) {
          setFakes(data.fakes);
          setLoading(false);
        }
      })
      .catch((e) => {
        if (!cancelled) {
          setError(String(e instanceof Error ? e.message : e));
          setLoading(false);
        }
      });
    return () => {
      cancelled = true;
    };
  }, []);

  const kinds = useMemo(
    () => Array.from(new Set(fakes.map((fake) => fake.kind))).sort(),
    [fakes],
  );

  const visible = useMemo(() => {
    const query = search.trim().toLowerCase();
    return fakes.filter(
      (fake) =>
        (kind === "все" || fake.kind === kind) &&
        (query === "" ||
          fake.name.toLowerCase().includes(query) ||
          fake.description.toLowerCase().includes(query)),
    );
  }, [fakes, kind, search]);

  return (
    <div className="page">
      <PageHeader
        index="07"
        group="Библиотека"
        title="Фейки"
        description="Заготовки пакетов для стратегий DESYNC — каталог fakes_catalog.sqlite3."
        actions={
          <span className="chip tone-neutral">
            {visible.length} из {fakes.length}
          </span>
        }
      />

      {error && (
        <div className="infobar error with-icon" role="alert">
          <IconClose />
          <span>{error}</span>
        </div>
      )}

      <section className="card">
        <div className="card-head">
          <div>
            <span className="section-kicker">
              <b>01</b> Каталог
            </span>
            <h2 className="card-title">Фейки DESYNC</h2>
            <p className="card-note">
              Используются пресетами автоматически; здесь — для справки и
              отладки стратегий.
            </p>
          </div>
        </div>

        <div className="launch-row">
          <label className="search-box">
            <IconSearch size={16} />
            <span className="sr-only">Поиск фейка</span>
            <input
              className="input"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Имя или описание фейка…"
              aria-label="Поиск фейка"
            />
            {search && (
              <button
                type="button"
                className="btn icon sm ghost"
                onClick={() => setSearch("")}
                aria-label="Очистить поиск"
              >
                <IconClose size={14} />
              </button>
            )}
          </label>
          <label className="field">
            <span className="field-label">Тип</span>
            <select value={kind} onChange={(e) => setKind(e.target.value)}>
              <option value="все">все</option>
              {kinds.map((option) => (
                <option value={option} key={option}>
                  {option}
                </option>
              ))}
            </select>
          </label>
        </div>

        {loading ? (
          <div className="empty-state" role="status">
            <span className="spinner" />
            <span>Загружаю каталог…</span>
          </div>
        ) : fakes.length === 0 ? (
          <div className="empty-state">
            <IconLayers />
            <strong>Каталог пуст</strong>
            <span>Проверьте, что база fakes_catalog.sqlite3 доступна ядру.</span>
          </div>
        ) : visible.length === 0 ? (
          <div className="empty-state">
            <strong>Ничего не найдено</strong>
            <span>Измените запрос или выберите другой тип.</span>
          </div>
        ) : (
          <div className="table-wrap">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Имя</th>
                  <th>Тип</th>
                  <th>SNI / размер</th>
                  <th>SHA-256</th>
                </tr>
              </thead>
              <tbody>
                {visible.map((fake) => (
                  <tr key={fake.name} title={fake.sha256 ?? ""}>
                    <td className="mono cell-strong">{fake.name}</td>
                    <td>
                      <span className="chip static">{fake.kind}</span>
                    </td>
                    <td className="cell-nowrap">
                      {fake.sni ? <span className="mono">{fake.sni}</span> : "—"}
                      <span className="fake-size">{sizeLabel(fake.size)}</span>
                    </td>
                    <td className="mono" title={fake.sha256}>
                      {(fake.sha256 ?? "").slice(0, 16) || "—"}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </div>
  );
}
