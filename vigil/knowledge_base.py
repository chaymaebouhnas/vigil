"""Small local knowledge base with TF-IDF retrieval. Nothing leaves the machine."""
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import linear_kernel

KB_DIR = Path(__file__).parent / "knowledge"


@dataclass
class Doc:
    key: str
    title: str
    text: str
    summary: str
    actions: list


class KnowledgeBase:
    def __init__(self, folder: Path = KB_DIR) -> None:
        self.docs = [self._parse(p) for p in sorted(folder.glob("*.md"))]
        self.vec = TfidfVectorizer(stop_words="english", ngram_range=(1, 2))
        self.matrix = self.vec.fit_transform(d.text for d in self.docs)

    @staticmethod
    def _parse(p: Path) -> Doc:
        text = p.read_text(encoding="utf-8")
        lines = text.splitlines()
        return Doc(p.stem, lines[0].lstrip("# ").strip(), text, lines[1].strip(),
                   [m[2:].strip() for m in lines if m.startswith("- ")])

    def get(self, key: str) -> Doc | None:
        return next((d for d in self.docs if d.key == key), None)

    def search(self, query: str, k: int = 3) -> list[tuple[Doc, float]]:
        scores = linear_kernel(self.vec.transform([query]), self.matrix)[0]
        ranked = sorted(zip(self.docs, scores), key=lambda p: -p[1])
        return [(d, float(s)) for d, s in ranked[:k] if s > 0]
