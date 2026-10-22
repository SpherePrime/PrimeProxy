import { useEffect, useMemo, useState } from "react";
import { fetchFakes, FakeInfo } from "../api";

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
      <div className="page-header">
        <h1>Фейки</h1>
        <p className="subtitle">
          Фейки — заготовки пакетов для стратегий DESYNC, используются
          пресетами автоматически (каталог fakes_catalog.sqlite3).
        </p>
      </div>

      {error && <div className="infobar error">{error}</div>}

      <div className="card">
        <div className="card-head">
          <h2>Каталог</h2>
          <span className="preset-count">{visible.length} из {fakes.length}</span>
        </div>
        <div className="launch-row" style={{ marginBottom: 12 }}>
          <div className="field" style={{ flex: 1 }}>
            <span className="field-label">Поиск</span>
            <input
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="имя или описание фейка"
              style={{ width: "100%" }}
            />
          </div>
          <div className="field">
            <span className="field-label">Тип</span>
            <select value={kind} onChange={(e) => setKind(e.target.value)}>
              <option value="все">все</option>
              {kinds.map((option) => (
                <option value={option} key={option}>
                  {option}
                </option>
              ))}
            </select>
          </div>
        </div>

        {loading ? (
          <div className="preset-empty">Загружаю каталог…</div>
        ) : visible.length === 0 ? (
          <div className="preset-empty">Ничего не найдено.</div>
        ) : (
          <div className="fake-list">
            {visible.map((fake) => (
              <div className="fake-row" key={fake.name} title={fake.sha256 ?? ""}>
                <span className="fake-name">{fake.name}</span>
                <span className="chip">{fake.kind}</span>
                <span className="preset-desc">
                  {fake.sni ? `SNI: ${fake.sni} · ` : ""}
                  {sizeLabel(fake.size)}
                </span>
                <span className="fake-hash" title={fake.sha256}>
                  {(fake.sha256 ?? "").slice(0, 12)}
                </span>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
