"""
MITRE ATT&CK-based threat actor enrichment.

Extracts threat actor names from IOC descriptions by matching malware
family names in the text against a curated MITRE ATT&CK Group/Software
relationship mapping (data/mitre_attack_actor_mapping.json).
"""

from __future__ import annotations

import json
import logging
import re
from functools import lru_cache
from pathlib import Path
from typing import Dict, List, Set

logger = logging.getLogger(__name__)

_AI_SERVICE_ROOT = Path(__file__).resolve().parents[1]
_MAPPING_PATH = _AI_SERVICE_ROOT / "data" / "mitre_attack_actor_mapping.json"

# Token splitter — handles AV signature formats:
#   "Win64:Emotet-Z" → ["Win64", "Emotet", "Z"]
#   "Backdoor:Win32/Lazarus.A" → ["Backdoor", "Win32", "Lazarus", "A"]
#   "Trojan.GenericKDZ.113354" → ["Trojan", "GenericKDZ", "113354"]
_TOKEN_SPLIT_RE = re.compile(r"[\s.:/\\\[\]\(\)\-_,;|!]+")

# Minimum token length to consider — avoids false matches on short tokens
_MIN_TOKEN_LEN = 4


def _load_mapping() -> Dict[str, List[str]]:
    """Load MITRE mapping JSON. Returns empty dict on any error."""
    try:
        with open(_MAPPING_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data.get("malware_to_actors", {})
    except (FileNotFoundError, json.JSONDecodeError, OSError) as exc:
        logger.warning("Failed to load MITRE actor mapping: %s", exc)
        return {}


# Module-level: load once
_MALWARE_TO_ACTORS: Dict[str, List[str]] = _load_mapping()


def _normalize_token(token: str) -> str:
    """Lowercase + remove non-alphanumeric for fuzzy matching."""
    return re.sub(r"[^a-z0-9]", "", token.lower())


def _extract_tokens(text: str) -> List[str]:
    """Split description into tokens; return only tokens meeting min length."""
    if not text:
        return []
    raw_tokens = _TOKEN_SPLIT_RE.split(text)
    return [
        _normalize_token(t)
        for t in raw_tokens
        if len(_normalize_token(t)) >= _MIN_TOKEN_LEN
    ]


def lookup_actors_from_description(description: str) -> List[str]:
    """Extract threat actor names from description by matching malware family tokens.

    Args:
        description: Free-text IOC description (e.g. cyberint description, sandbox verdict)

    Returns:
        List of unique actor names found via MITRE mapping. Empty if no matches.
    """
    if not description or not _MALWARE_TO_ACTORS:
        return []

    tokens = _extract_tokens(description)
    if not tokens:
        return []

    actors: List[str] = []
    seen: Set[str] = set()

    for token in tokens:
        # Direct lookup — token must match malware family name exactly
        # (mapping keys are lowercase + alphanumeric only)
        matched_actors = _MALWARE_TO_ACTORS.get(token)
        if not matched_actors:
            continue
        for actor in matched_actors:
            if actor not in seen:
                actors.append(actor)
                seen.add(actor)

    return actors


@lru_cache(maxsize=4096)
def lookup_actors_from_description_cached(description: str) -> tuple:
    """Cached version — returns tuple (lru_cache requires hashable)."""
    return tuple(lookup_actors_from_description(description))


def get_known_malware_families() -> List[str]:
    """Return all known malware family keys (for debugging/inspection)."""
    return sorted(_MALWARE_TO_ACTORS.keys())
