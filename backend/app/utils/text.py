from __future__ import annotations

import re
from typing import Iterable, List


def clean_text(text: str) -> str:
    text = text.replace("\x00", " ")
    text = re.sub(r"\r\n?", "\n", text)
    text = re.sub(r"[ \t]+", " ", text)
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text.strip()


def safe_excerpt(text: str, start: int | None = None, window: int = 140, max_chars: int | None = None) -> str:
    cleaned = clean_text(text)
    if max_chars is not None and start is None:
        return cleaned if len(cleaned) <= max_chars else cleaned[: max_chars - 3].rstrip() + "..."
    if start is None:
        return cleaned if len(cleaned) <= 280 else cleaned[:277].rstrip() + "..."
    start = max(0, min(start, len(text)))
    left = max(0, start - window)
    right = min(len(text), start + window)
    excerpt = clean_text(text[left:right])
    return ("..." if left > 0 else "") + excerpt + ("..." if right < len(text) else "")


def keyword_hits(text: str, patterns: Iterable[str]) -> List[str]:
    hits: List[str] = []
    lower = text.lower()
    for pattern in patterns:
        if pattern.startswith("re:"):
            rx = pattern[3:]
            if re.search(rx, lower, flags=re.IGNORECASE):
                hits.append(rx)
        elif pattern.lower() in lower:
            hits.append(pattern)
    return hits
