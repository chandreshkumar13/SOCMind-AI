"""Whole-term keyword matching shared by the triage, investigation and response agents.

A plain substring test lets a short keyword fire inside a longer word: 'c2' inside 'ec2', 'iam' inside 'william'. A term is
matched only where it is not glued to a letter, digit or underscore on either side. A term that starts or ends with a
non-word character (for example '-e ' or 'reg.exe add') keeps that edge as a plain substring, so such terms still match
where the separator is present.
"""
import re
from typing import Iterable

_cache: dict = {}


def _pattern(term: str) -> "re.Pattern[str]":
    compiled = _cache.get(term)
    if compiled is None:
        body = re.escape(term)
        if term[:1].isalnum() or term[:1] == "_":
            body = r"(?<!\w)" + body
        if term[-1:].isalnum() or term[-1:] == "_":
            body = body + r"(?!\w)"
        compiled = re.compile(body, re.IGNORECASE)
        _cache[term] = compiled
    return compiled


def contains_term(text: str, term: str) -> bool:
    """True when the term occurs in the text as a whole term (case-insensitive)."""
    return bool(term) and _pattern(term).search(text or "") is not None


def contains_any(text: str, terms: Iterable[str]) -> bool:
    return any(contains_term(text, term) for term in terms)
