from __future__ import annotations

import re
from typing import Tuple

Version = Tuple[Tuple[int, ...], str]


def parse_version(value) -> Version:
    raw = str(value or "").strip()
    if not raw:
        return ((0,), "")
    raw = raw[1:] if raw[0] in "vV" else raw
    segments = raw.split(".")
    numbers = []
    suffix = ""
    for index, segment in enumerate(segments):
        match = re.match(r"^(\d*)(.*)$", segment)
        head, tail = match.group(1), match.group(2)
        numbers.append(int(head) if head else 0)
        if tail and index == len(segments) - 1:
            suffix = tail.strip()
    while len(numbers) > 1 and numbers[-1] == 0:
        numbers.pop()
    return (tuple(numbers), suffix)


def _padded(tuple_a: Tuple[int, ...], tuple_b: Tuple[int, ...]):
    width = max(len(tuple_a), len(tuple_b))
    return tuple_a + (0,) * (width - len(tuple_a)), tuple_b + (0,) * (width - len(tuple_b))


def compare_versions(a: str, b: str) -> int:
    raw_a, suffix_a = parse_version(a)
    raw_b, suffix_b = parse_version(b)
    padded_a, padded_b = _padded(raw_a, raw_b)
    for left, right in zip(padded_a, padded_b):
        if left != right:
            return -1 if left < right else 1
    if suffix_a == suffix_b:
        return 0
    if not suffix_a and suffix_b:
        return 1
    if suffix_a and not suffix_b:
        return -1
    return -1 if suffix_a < suffix_b else 1


def is_newer(a: str, b: str) -> bool:
    return compare_versions(a, b) > 0