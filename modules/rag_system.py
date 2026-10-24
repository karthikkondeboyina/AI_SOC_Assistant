"""
AI SOC Assistant - RAG (Retrieval-Augmented Generation) System
Chunks cybersecurity documents (MITRE ATT&CK, NIST SP 800-61, OWASP Top 10),
indexes vector representations into FAISS, performs cosine similarity retrieval,
and provides grounded context for Gemini AI investigations.
"""

from pathlib import Path
from typing import List, Dict, Any, Tuple, Optional
import json
import re
import joblib
import numpy as np
import faiss
import warnings
warnings.filterwarnings("ignore", category=UserWarning)
from sklearn.feature_extraction.text import TfidfVectorizer

from config.settings import KB_DOCS_DIR, KB_INDEX_DIR

INDEX_FILE = KB_INDEX_DIR / "faiss.index"
VECTORIZER_FILE = KB_INDEX_DIR / "vectorizer.joblib"
METADATA_FILE = KB_INDEX_DIR / "chunks_metadata.json"

class SOCKnowledgeRAG:
    """Manages document chunking, FAISS vector indexing, and grounded retrieval."""

    def __init__(self):
        self.index: Optional[faiss.IndexFlatIP] = None
        self.vectorizer: Optional[TfidfVectorizer] = None
        self.chunks_metadata: List[Dict[str, Any]] = []
        self._load_or_build_index()

    def _chunk_markdown_file(self, file_path: Path) -> List[Dict[str, Any]]:
        """Splits markdown file into meaningful sections based on headers."""
        with open(file_path, "r", encoding="utf-8") as f:
            content = f.read()

        sections = re.split(r'\n(?=##?\s)', content)
        chunks = []

        for sec in sections:
            clean_sec = sec.strip()
            if not clean_sec:
                continue

            # Extract header as section title
            lines = clean_sec.splitlines()
            first_line = lines[0].strip()
            title = first_line.lstrip("#").strip() if first_line.startswith("#") else "General Guidance"
            body = "\n".join(lines[1:]).strip() if len(lines) > 1 else clean_sec

            if len(body) > 40:
                chunks.append({
                    "source": file_path.name,
                    "title": title,
                    "text": clean_sec,
                    "summary": body[:200]
                })

        return chunks

    def build_index(self) -> Dict[str, Any]:
        """Loads all documents from knowledge_base/documents, vectorizes, and indexes in FAISS."""
        KB_INDEX_DIR.mkdir(parents=True, exist_ok=True)
        doc_files = list(KB_DOCS_DIR.glob("*.md")) + list(KB_DOCS_DIR.glob("*.txt"))

        if not doc_files:
            return {"success": False, "message": f"No knowledge base documents found in {KB_DOCS_DIR}"}

        all_chunks = []
        for doc in doc_files:
            chunks = self._chunk_markdown_file(doc)
            all_chunks.extend(chunks)

        if not all_chunks:
            return {"success": False, "message": "No valid text sections extracted from documents."}

        corpus = [c["text"] for c in all_chunks]

        # Vectorizer configured for cybersecurity vocabulary
        vectorizer = TfidfVectorizer(
            max_features=768,
            stop_words="english",
            ngram_range=(1, 2)
        )
        tfidf_matrix = vectorizer.fit_transform(corpus).toarray().astype(np.float32)

        # Normalize L2 for Cosine Similarity via Inner Product (IndexFlatIP)
        faiss.normalize_L2(tfidf_matrix)
        dim = tfidf_matrix.shape[1]

        index = faiss.IndexFlatIP(dim)
        index.add(tfidf_matrix)

        # Save artifacts
        faiss.write_index(index, str(INDEX_FILE))
        joblib.dump(vectorizer, VECTORIZER_FILE)
        with open(METADATA_FILE, "w", encoding="utf-8") as f:
            json.dump(all_chunks, f, indent=4)

        self.index = index
        self.vectorizer = vectorizer
        self.chunks_metadata = all_chunks

        return {
            "success": True,
            "total_documents": len(doc_files),
            "total_chunks": len(all_chunks),
            "vector_dimension": dim
        }

    def _load_or_build_index(self):
        """Loads saved FAISS index from disk or builds automatically."""
        if INDEX_FILE.exists() and VECTORIZER_FILE.exists() and METADATA_FILE.exists():
            try:
                self.index = faiss.read_index(str(INDEX_FILE))
                self.vectorizer = joblib.load(VECTORIZER_FILE)
                with open(METADATA_FILE, "r", encoding="utf-8") as f:
                    self.chunks_metadata = json.load(f)
                return
            except Exception as e:
                print(f"[-] Error loading FAISS index: {e}. Rebuilding...")

        # Build index if not available
        self.build_index()

    def retrieve(self, query: str, top_k: int = 3, similarity_threshold: float = 0.15) -> List[Dict[str, Any]]:
        """
        Retrieves top_k relevant cybersecurity knowledge chunks for a query.
        Returns matching chunks with sources, titles, text, and cosine score.
        """
        if self.index is None or self.vectorizer is None or not self.chunks_metadata:
            self._load_or_build_index()
            if self.index is None:
                return []

        clean_query = query.strip()
        if not clean_query:
            return []

        q_vec = self.vectorizer.transform([clean_query]).toarray().astype(np.float32)
        faiss.normalize_L2(q_vec)

        distances, indices = self.index.search(q_vec, top_k)

        results = []
        for score, idx in zip(distances[0], indices[0]):
            if idx != -1 and score >= similarity_threshold and idx < len(self.chunks_metadata):
                match = dict(self.chunks_metadata[idx])
                match["similarity_score"] = float(round(score, 4))
                results.append(match)

        return results

    def format_retrieved_context(self, matches: List[Dict[str, Any]]) -> str:
        """Formats retrieved chunks into a clean, cited context string."""
        if not matches:
            return "No directly relevant cybersecurity documents found in the local knowledge base."

        context_lines = []
        for i, m in enumerate(matches, 1):
            context_lines.append(
                f"[Source {i}: {m['source']} - {m['title']} (Relevance: {m['similarity_score']:.2f})]\n{m['text']}\n"
            )
        return "\n".join(context_lines)

# Singleton instance
_RAG_INSTANCE = None

def get_rag_system() -> SOCKnowledgeRAG:
    """Returns singleton instance of SOCKnowledgeRAG."""
    global _RAG_INSTANCE
    if _RAG_INSTANCE is None:
        _RAG_INSTANCE = SOCKnowledgeRAG()
    return _RAG_INSTANCE
