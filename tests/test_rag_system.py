"""
Tests for RAG System Module (modules/rag_system.py)
"""

import pytest
from modules.rag_system import get_rag_system

def test_rag_system_initialization():
    rag = get_rag_system()
    assert rag is not None
    assert rag.index is not None
    assert rag.vectorizer is not None
    assert len(rag.chunks_metadata) > 0

def test_rag_retrieval_ddos():
    rag = get_rag_system()
    results = rag.retrieve("Network Denial of Service DDoS mitigation", top_k=2)
    assert len(results) > 0
    top_result = results[0]
    assert "source" in top_result
    assert "title" in top_result
    assert "similarity_score" in top_result
    assert top_result["similarity_score"] > 0.0

def test_rag_empty_query():
    rag = get_rag_system()
    assert rag.retrieve("") == []
    assert rag.retrieve("   ") == []

def test_rag_context_formatting():
    rag = get_rag_system()
    results = rag.retrieve("Brute Force password spraying", top_k=2)
    formatted = rag.format_retrieved_context(results)
    assert isinstance(formatted, str)
    if results:
        assert "Source 1:" in formatted
