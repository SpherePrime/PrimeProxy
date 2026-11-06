import { useState } from "react";
import { fileName, filesBridge } from "../../electronBridge";
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
  const [kind, setKind] = useState<SourceKind>("file");
  const [path, setPath] = useState("");
  const [text, setText] = useState("");
  const files = filesBridge();

  const pickFile = async () => {
    const chosen = await files?.pick({
      title: "Лог winws2",
      filters: [
        { name: "Логи", extensions: ["log", "txt"] },
        { name: "Все файлы", extensions: ["*"] },
      ],
    });
    if (chosen) {
      setPath(chosen);
      onFile(chosen);
    }
  };

  return (
    <Panel title="Источник" note="Debug-лог winws2: выберите файл или вставьте фрагмент текста.">
      <div className="toolbar">
        <Segmented<SourceKind>
          label="Источник лога"
          value={kind}
          onChange={setKind}
          options={[
            { value: "file", label: "Файл" },
            { value: "text", label: "Текст" },
          ]}
        />
      </div>

      {kind === "file" ? (
        files ? (
          <button type="button" className="file-drop" onClick={() => void pickFile()} disabled={busy}>
            <span className="file-drop__icon" aria-hidden="true">
              {busy ? <span className="spinner" /> : <IconFile size={22} />}
            </span>
            <span className="file-drop__text">
              <b>{path ? fileName(path) : "Выбрать файл лога"}</b>
              <small>{path ? "Нажмите, чтобы выбрать другой" : ".log или .txt — разбор начнётся сразу"}</small>
            </span>
          </button>
        ) : (
          <>
            <label className="field">
              <span className="field__label">Путь к файлу на машине ядра</span>
              <input
                className="input input--mono"
                value={path}
                onChange={(event) => setPath(event.target.value)}
                placeholder="C:\logs\winws2-debug.log"
                spellCheck={false}
              />
            </label>
            <button
              type="button"
              className="btn btn--accent btn--block logs-run"
              disabled={busy || path.trim() === ""}
              onClick={() => onFile(path.trim())}
            >
              {busy ? <span className="spinner" /> : <IconFile size={16} />}
              Разобрать файл
            </button>
          </>
        )
      ) : (
        <>
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
          <button
            type="button"
            className="btn btn--accent btn--block logs-run"
            disabled={busy || text.trim() === ""}
            onClick={() => onText(text)}
          >
            {busy ? <span className="spinner" /> : <IconTerminal size={16} />}
            {busy ? "Разбираю…" : "Разобрать текст"}
          </button>
        </>
      )}
    </Panel>
  );
}
