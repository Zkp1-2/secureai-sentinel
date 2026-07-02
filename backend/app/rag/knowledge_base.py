from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Dict, List, Tuple

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

from app.utils.text import clean_text, safe_excerpt


DEFAULT_KB_DIR = Path(__file__).resolve().parents[2] / "data" / "knowledge_base"


class LocalRAGKnowledgeBase:
    """A lightweight local RAG layer using TF-IDF retrieval.

    This is intentionally local and deterministic so the project works without API keys.
    It can later be swapped with ChromaDB or FAISS without changing the API response shape.
    """

    def __init__(self, kb_dir: str | None = None) -> None:
        self.kb_dir = Path(kb_dir or os.getenv("KNOWLEDGE_BASE_DIR", DEFAULT_KB_DIR))
        self.documents: List[Dict[str, str]] = []
        self.vectorizer = TfidfVectorizer(stop_words="english", ngram_range=(1, 2), max_features=6000)
        self.matrix = None
        self.load()

    def load(self) -> None:
        self.documents = []
        if not self.kb_dir.exists():
            return
        for path in sorted(self.kb_dir.glob("**/*")):
            if path.suffix.lower() not in {".md", ".txt", ".log"} or not path.is_file():
                continue
            raw = path.read_text(encoding="utf-8", errors="ignore")
            for section_title, section_body in self._split_markdown(raw):
                content = clean_text(section_body)
                if len(content) < 30:
                    continue
                self.documents.append(
                    {
                        "source": path.name,
                        "section": section_title,
                        "content": content,
                    }
                )
        if self.documents:
            self.matrix = self.vectorizer.fit_transform([doc["content"] for doc in self.documents])
        else:
            self.matrix = None

    def _split_markdown(self, raw: str) -> List[Tuple[str, str]]:
        parts = re.split(r"(?m)^#{1,3}\s+", raw)
        headings = re.findall(r"(?m)^#{1,3}\s+(.+)$", raw)
        if len(parts) <= 1:
            return [("General", raw)]
        chunks: List[Tuple[str, str]] = []
        # parts[0] is text before first heading
        for idx, body in enumerate(parts[1:]):
            title = headings[idx] if idx < len(headings) else "General"
            chunks.append((title.strip(), body.strip()))
        return chunks

    def search(self, query: str, top_k: int = 5) -> List[Dict[str, object]]:
        if not self.documents or self.matrix is None:
            return []
        query_vec = self.vectorizer.transform([clean_text(query)])
        scores = cosine_similarity(query_vec, self.matrix)[0]
        ranked = sorted(enumerate(scores), key=lambda pair: pair[1], reverse=True)[:top_k]
        results: List[Dict[str, object]] = []
        for idx, score in ranked:
            doc = self.documents[idx]
            if score <= 0:
                continue
            results.append(
                {
                    "source": doc["source"],
                    "section": doc["section"],
                    "score": round(float(score), 4),
                    "content": safe_excerpt(doc["content"], 420),
                }
            )
        return results
