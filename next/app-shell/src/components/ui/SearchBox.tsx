import { IconClose, IconSearch } from "../Icons";

interface SearchBoxProps {
  value: string;
  onChange: (value: string) => void;
  placeholder: string;
}

export function SearchBox({ value, onChange, placeholder }: SearchBoxProps) {
  return (
    <label className="search">
      <IconSearch size={16} />
      <input
        className="input"
        value={value}
        onChange={(event) => onChange(event.target.value)}
        placeholder={placeholder}
        aria-label={placeholder}
      />
      {value && (
        <button
          type="button"
          className="btn btn--ghost btn--icon"
          onClick={() => onChange("")}
          aria-label="Очистить поиск"
        >
          <IconClose size={14} />
        </button>
      )}
    </label>
  );
}
