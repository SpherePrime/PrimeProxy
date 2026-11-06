import { useState } from "react";
import { IconFile, IconTerminal } from "../Icons";
import { Panel } from "../ui/Panel";
import { Segmented } from "../ui/Segmented";

type SourceKind = "file" | "text";

interface LogSourceProps {
  busy: boolean;
  onFile: (path: string) => void;
  onText: (text: string) => void;
}

export function LogSource({ busy, onFile, onText }: LogSourceProps) {
  const [kind, setKind] = useState<SourceKind>("text");
  const [path, setPath] = useState("");
  const [text, setText] = useState("");

  const ready = kind === "file" ? path.trim() !== "" : text.trim() !== "";
  const submit = () => (kind === "file" ? onFile(path.trim()) : onText(text));

  return (
    <Panel title="Источник" note="Debug-лог winws2: файл на машине ядра или вставленный фрагмент.">
      <div className="toolbar">
        <Segmented<SourceKind>
          label="Источник лога"
          value={kind}
          onChange={setKind}
          options={[
            { value: "text", label: "Текст" },
            { value: "file", label: "Файл" },
          ]}
        />
      </div>

      {kind === "file" ? (
        <label className="field">
          <span className="field__label">Путь к файлу</span>
          <input
            className="input input--mono"
            value={path}
            onChange={(event) => setPath(event.target.value)}
            placeholder="C:\\logs\\winws2-debug.log"
            spellCheck={false}
          />
        </label>
      ) : (
        <label className="field">
          <span className="field__label">Фрагмент лога</span>
          <textarea
            className="textarea"
            value={text}
            onChange={(event) => setText(event.target.value)}
            rows={9}
            placeholder="Вставьте кусок лога winws2…"
            spellCheck={false}
          />
        </label>
      )}

      <button
        type="button"
        className="btn btn--accent btn--block logs-run"
        disabled={busy || !ready}
        onClick={submit}
      >
        {busy ? <span className="spinner" /> : kind === "file" ? <IconFile size={16} /> : <IconTerminal size={16} />}
        {busy ? "Разбираю…" : "Разобрать лог"}
      </button>
    </Panel>
  );
}
