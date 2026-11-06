import { useState } from "react";
import { DnsSetError, setDns } from "../../api";
import { IconCheck } from "../Icons";
import { Notice } from "../ui/Notice";
import { Panel } from "../ui/Panel";

export function DnsSet() {
  const [ifname, setIfname] = useState("");
  const [server1, setServer1] = useState("");
  const [server2, setServer2] = useState("");
  const [saving, setSaving] = useState(false);
  const [done, setDone] = useState(false);
  const [noRights, setNoRights] = useState(false);
  const [error, setError] = useState("");

  async function apply() {
    const iface = ifname.trim();
    const servers = [server1.trim(), server2.trim()].filter(Boolean);
    if (!iface) {
      setError("Укажите имя интерфейса, например Ethernet или eth0");
      return;
    }
    if (servers.length === 0) {
      setError("Укажите хотя бы один DNS-сервер");
      return;
    }
    setSaving(true);
    setError("");
    setNoRights(false);
    setDone(false);
    try {
      await setDns(servers, iface);
      setDone(true);
    } catch (e) {
      if (e instanceof DnsSetError && e.status === 409) setNoRights(true);
      else setError(String((e as Error).message));
    } finally {
      setSaving(false);
    }
  }

  return (
    <Panel title="Установить DNS" note="Два сервера на сетевой интерфейс. Нужны права администратора.">
      <div className="dns-set">
        <label className="field">
          <span className="field__label">Интерфейс</span>
          <input
            className="input input--mono"
            value={ifname}
            onChange={(event) => setIfname(event.target.value)}
            placeholder="Ethernet"
            disabled={saving}
            spellCheck={false}
          />
        </label>
        <label className="field">
          <span className="field__label">Основной</span>
          <input
            className="input input--mono"
            value={server1}
            onChange={(event) => setServer1(event.target.value)}
            placeholder="1.1.1.1"
            disabled={saving}
            spellCheck={false}
          />
        </label>
        <label className="field">
          <span className="field__label">Запасной</span>
          <input
            className="input input--mono"
            value={server2}
            onChange={(event) => setServer2(event.target.value)}
            placeholder="8.8.8.8"
            disabled={saving}
            spellCheck={false}
          />
        </label>
      </div>
      <button type="button" className="btn btn--accent btn--block dns-set__btn" onClick={() => void apply()} disabled={saving}>
        {saving ? <span className="spinner" /> : <IconCheck size={16} />}
        {saving ? "Применяю…" : "Установить"}
      </button>
      {done && <Notice tone="ok">DNS установлен</Notice>}
      {noRights && <Notice tone="warn">Нет прав администратора — перезапустите приложение с правами.</Notice>}
      {error && <Notice tone="error">{error}</Notice>}
    </Panel>
  );
}
