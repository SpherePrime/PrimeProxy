"""
Парсер/сериализатор профилей winws (текст пресета ``--key=value`` ...).
Content lines: ``# комментарий``, пустые строки, ``--option``, ``--option=value``,
``--option value``. Значения могут быть числом, списком, @ссылкой на файл
или строкой опций вида ``name:opt=val:...``.
"""
from __future__ import annotations

import copy
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

VALUE_TYPE_INT = "int"
VALUE_TYPE_STR = "str"
VALUE_TYPE_VECTOR = "vector"
VALUE_TYPE_AT = "at"
VALUE_TYPE_OPTIONS = "options"
VALUE_TYPE_FLAG = "flag"

VALUE_TYPE_CODES = {
    VALUE_TYPE_INT: "целое число",
    VALUE_TYPE_STR: "строка",
    VALUE_TYPE_VECTOR: "список значений через запятую",
    VALUE_TYPE_AT: "@флаг (ссылка на файл/ресурс)",
    VALUE_TYPE_OPTIONS: "опции name:opt=val:...",
    VALUE_TYPE_FLAG: "параметр без значения",
}

GROUP_CONFIG = "config"
GROUP_FILTER = "filter"
GROUP_LUA = "lua"
GROUP_HOSTLIST = "hostlist"
GROUP_PARAMS = "params"

GROUP_CODES = {
    GROUP_CONFIG: "глобальные параметры движка",
    GROUP_FILTER: "фильтры трафика (--filter-*)",
    GROUP_LUA: "lua-стратегии и инициализация (--lua-*)",
    GROUP_HOSTLIST: "списки хостов (--hostlist/--ipset)",
    GROUP_PARAMS: "прочие параметры",
}

_KIND_BLANK = "blank"
_KIND_COMMENT = "comment"
_KIND_PARAM = "param"
_KIND_TEXT = "text"

_INT_PARAMS = {
    "--ctrack-disable", "--ipcache-lifetime", "--ipcache-hostname",
    "--ipcache-tolerance", "--wssize", "--wscap",
}
_FLAG_KEYS = {"--new", "--skip"}
_MULTI_KEYS = {
    "--lua-init", "--lua-desync", "--blob", "--hostlist", "--hostlist-exclude",
    "--ipset", "--ipset-exclude", "--wf-raw-part", "--payload",
    "--in-range", "--out-range", "--filter-tcp", "--filter-udp", "--filter-l7",
    "--name", "--dpi-desync", "--dpi-desync-fake-heredoc",
}

_OPTION_START = re.compile(r"^--[A-Za-z0-9][A-Za-z0-9_.-]*")
_DEC_INT = re.compile(r"^-?\d+$")
_HEX_INT = re.compile(r"^0x[0-9a-fA-F]+$")
_WS = re.compile(r"\s")


@dataclass
class Param:
    key: str
    value: str
    value_type: str
    group: str


@dataclass
class Line:
    kind: str
    raw: str
    key: str = ""
    value: str = ""

    @property
    def value_type(self) -> str:
        if self.kind != _KIND_PARAM:
            return ""
        return detect_value_type(self.value, self.key)

    @property
    def group(self) -> str:
        if self.kind != _KIND_PARAM:
            return ""
        return classify_group(self.key)

    @property
    def param(self) -> Optional[Param]:
        if self.kind != _KIND_PARAM:
            return None
        return Param(self.key, self.value, self.value_type, self.group)


@dataclass
class ProfileModel:
    lines: List[Line] = field(default_factory=list)

    @property
    def text(self) -> str:
        return "\n".join(line.raw for line in self.lines)

    @property
    def parameters(self) -> Dict[str, List[str]]:
        out: Dict[str, List[str]] = {}
        for line in self.lines:
            if line.kind == _KIND_PARAM:
                out.setdefault(line.key, []).append(line.value)
        return out

    @property
    def params(self) -> List[Param]:
        return [line.param for line in self.lines if line.kind == _KIND_PARAM]

    def get_values(self, name: str) -> List[str]:
        return [line.value for line in self.lines if line.kind == _KIND_PARAM and line.key == name]

    def get(self, name: str) -> Optional[str]:
        values = self.get_values(name)
        return values[0] if values else None

    def set(self, name: str, value: str, index: int = 0) -> bool:
        hits = 0
        for i, line in enumerate(self.lines):
            if line.kind == _KIND_PARAM and line.key == name:
                if hits == index:
                    raw = _canonical(name, value)
                    self.lines[i] = Line(_KIND_PARAM, raw, name, value)
                    return line.raw != raw or line.value != value
                hits += 1
        self.add(name, value)
        return True

    def add(self, name: str, value: str = "", after: Optional[str] = None) -> bool:
        line = Line(_KIND_PARAM, _canonical(name, value), name, value)
        if after is not None:
            for i, item in enumerate(self.lines):
                if item.kind == _KIND_PARAM and item.key == after:
                    self.lines.insert(i + 1, line)
                    return True
        self._append(line)
        return True

    def remove(self, name: str, index: Optional[int] = None) -> int:
        hits = 0
        removed = 0
        remaining: List[Line] = []
        for line in self.lines:
            match = line.kind == _KIND_PARAM and line.key == name
            if match and (index is None or hits == index):
                removed += 1
                hits += 1
                continue
            if match:
                hits += 1
            remaining.append(line)
        self.lines = remaining
        return removed

    def _append(self, line: Line) -> None:
        if self.lines and self.lines[-1].kind == _KIND_BLANK and self.lines[-1].raw == "":
            self.lines.insert(len(self.lines) - 1, line)
        else:
            self.lines.append(line)


def detect_value_type(value: str, key: str = "") -> str:
    v = value or ""
    if v == "":
        return VALUE_TYPE_FLAG
    if ":" in v:
        return VALUE_TYPE_OPTIONS
    if "," in v:
        return VALUE_TYPE_VECTOR
    if v.startswith("@"):
        return VALUE_TYPE_AT
    if _DEC_INT.match(v) or _HEX_INT.match(v):
        return VALUE_TYPE_INT
    return VALUE_TYPE_STR


def classify_group(key: str) -> str:
    k = key or ""
    if k.startswith("--hostlist") or k.startswith("--ipset"):
        return GROUP_HOSTLIST
    if k.startswith("--filter-"):
        return GROUP_FILTER
    if k.startswith("--lua-"):
        return GROUP_LUA
    if k.startswith(
        ("--wf-", "--ctrack-", "--ipcache-", "--blob", "--name", "--payload",
         "--wssize", "--wscap")
    ):
        return GROUP_CONFIG
    return GROUP_PARAMS


def _split_option(stripped: str) -> Optional[tuple]:
    match = _OPTION_START.match(stripped)
    if not match:
        return None
    head = match.group(0)
    rest = stripped[match.end():]
    if rest.startswith("="):
        return head, rest[1:]
    if rest.startswith(":") or rest.startswith(" ") or rest.startswith("\t"):
        return head, rest[1:].strip()
    if rest == "":
        return head, ""
    return None


def _classify_raw(raw: str) -> Line:
    stripped = raw.strip()
    if not stripped:
        return Line(_KIND_BLANK, raw)
    if stripped.startswith("#") or stripped.startswith(";"):
        return Line(_KIND_COMMENT, raw)
    split = _split_option(stripped)
    if split is None:
        return Line(_KIND_TEXT, raw)
    key, value = split
    return Line(_KIND_PARAM, raw, key, value)


def _canonical(key: str, value: str) -> str:
    v = "" if value is None else str(value)
    return f"{key}={v}" if v != "" else key


def parse_profile_text(text: Any = "") -> ProfileModel:
    text = "" if text is None else str(text)
    return ProfileModel([_classify_raw(raw) for raw in text.split("\n")])


def serialize_profile(model: ProfileModel) -> str:
    return model.text


def round_trip(text: Any) -> str:
    return serialize_profile(parse_profile_text(text))


def _check_int(key, value, line_no) -> Optional[Dict[str, Any]]:
    if key in _INT_PARAMS and not (_DEC_INT.match(value) or _HEX_INT.match(value)):
        return {"message": "bad_int_value", "line": line_no, "key": key}
    return None


def _check_vector(key, value, line_no) -> Optional[Dict[str, Any]]:
    if key.startswith(("--filter-", "--wf-")) and _WS.search(value):
        return {"message": "bad_vector_value", "line": line_no, "key": key}
    return None


def _check_ref(value, line_no, key) -> Optional[Dict[str, Any]]:
    if value.startswith("@") and (len(value) < 2 or value[1] in "\\/"):
        return {"message": "bad_ref", "line": line_no, "key": key}
    return None


def validate_profile(text: Any = "") -> Dict[str, Any]:
    text = "" if text is None else str(text)
    model = parse_profile_text(text)
    counts: Dict[str, int] = {}
    errors: List[Dict[str, Any]] = []
    warnings: List[Dict[str, Any]] = []
    param_count = 0
    for i, line in enumerate(model.lines, start=1):
        if line.kind == _KIND_TEXT:
            warnings.append({"message": "not_an_option", "line": i, "key": ""})
        elif line.kind == _KIND_PARAM:
            param_count += 1
            counts[line.key] = counts.get(line.key, 0) + 1
            if line.key in _FLAG_KEYS:
                continue
            for check in (_check_int, _check_vector):
                issue = check(line.key, line.value, i)
                if issue:
                    errors.append(issue)
            ref = _check_ref(line.value, i, line.key)
            if ref:
                errors.append(ref)
    for name, seen in counts.items():
        if name in _FLAG_KEYS or name in _MULTI_KEYS:
            continue
        if seen > 1:
            warnings.append({"message": "duplicate_param", "line": 0, "key": name})
    if "\x00" in text or "\ufffd" in text:
        errors.insert(0, {"message": "broken_encoding", "line": 0, "key": ""})
    if param_count == 0:
        errors.append({"message": "profile_empty", "line": 0, "key": ""})
    return {
        "ok": not errors,
        "errors": errors,
        "warnings": warnings,
        "parameters": model.parameters,
        "param_count": param_count,
    }


def describe(model: ProfileModel) -> Dict[str, List[Dict[str, Any]]]:
    out: Dict[str, List[Dict[str, Any]]] = {
        GROUP_CONFIG: [], GROUP_FILTER: [], GROUP_LUA: [],
        GROUP_HOSTLIST: [], GROUP_PARAMS: [],
    }
    for p in model.params:
        out[p.group].append({"key": p.key, "value": p.value, "type": p.value_type})
    return out


def apply_strategy(model: ProfileModel, strategy: dict) -> ProfileModel:
    m = copy.deepcopy(model)
    for key, value in (strategy or {}).get("set", {}).items():
        m.set(key, value, 0)
    for key, value in (strategy or {}).get("add", {}).items():
        m.add(key, value)
    for key in (strategy or {}).get("remove", []):
        m.remove(key)
    return m