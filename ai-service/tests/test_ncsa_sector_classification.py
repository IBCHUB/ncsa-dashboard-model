"""
Tests for Phase 1.18 — NCSA official sector + agency mapping integration.

Verifies that:

1. The two NCSA sectors added to ``config.SECTORS`` (``state_security`` and
   ``transportation``) are reachable from the classifier.
2. ``data.ncsa_agencies.match_ncsa_agency`` resolves official Thai agency
   names to the correct sector at the full-name layer.
3. Distinctive sector tokens (e.g. "กองทัพ", "การไฟฟ้า") fall through to
   the token layer when the full agency name is absent.
4. ``classify_sector`` returns the NCSA sector with high confidence when
   the IOC context contains an NCSA agency reference.
5. Conflict resolution honours the documented priority order — agencies
   appearing in multiple NCSA CSVs land in the most-specific sector.
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config import SECTORS, SECTOR_RISK_BONUS  # noqa: E402
from models.ncsa_agencies import (  # noqa: E402
    NCSA_AGENCY_INDEX,
    NCSA_SECTOR_AGENCIES,
    NCSA_SECTOR_TOKENS,
    NCSA_TOKEN_INDEX,
    match_ncsa_agency,
)
from models.sector_classifier import classify_sector  # noqa: E402


# ---------------------------------------------------------------------------
# Config invariants
# ---------------------------------------------------------------------------


def test_state_security_sector_present_in_config():
    assert "state_security" in SECTORS
    cfg = SECTORS["state_security"]
    assert cfg["name_th"] == "ด้านความมั่นคงของรัฐ"
    assert cfg["weight"] >= 1.4  # state security is high-impact
    assert SECTOR_RISK_BONUS["state_security"] >= 12


def test_transportation_sector_present_in_config():
    assert "transportation" in SECTORS
    cfg = SECTORS["transportation"]
    assert cfg["name_th"] == "ด้านการขนส่งและโลจิสติกส์"
    assert SECTOR_RISK_BONUS["transportation"] >= 8


def test_existing_sectors_still_present():
    """Adding new sectors must not remove any existing key."""
    required = {
        "financial", "government", "healthcare", "education",
        "critical_infrastructure", "technology", "general",
    }
    assert required.issubset(SECTORS.keys())


# ---------------------------------------------------------------------------
# NCSA data module
# ---------------------------------------------------------------------------


def test_ncsa_agency_index_sorted_longest_first():
    """Greedy substring scan needs longest-first ordering."""
    lengths = [len(needle) for needle, _ in NCSA_AGENCY_INDEX]
    assert lengths == sorted(lengths, reverse=True)


def test_ncsa_token_index_sorted_longest_first():
    lengths = [len(needle) for needle, _ in NCSA_TOKEN_INDEX]
    assert lengths == sorted(lengths, reverse=True)


def test_no_agency_appears_in_multiple_sectors():
    """Conflict resolution must produce a strict partition of agencies."""
    seen: dict[str, str] = {}
    for sector, names in NCSA_SECTOR_AGENCIES.items():
        for raw in names:
            cleaned = raw.strip().lower()
            assert cleaned not in seen or seen[cleaned] == sector, (
                f"agency {raw!r} appears in both {seen.get(cleaned)} and {sector}"
            )
            seen[cleaned] = sector


# ---------------------------------------------------------------------------
# match_ncsa_agency()
# ---------------------------------------------------------------------------


def test_match_full_agency_state_security_army():
    hit = match_ncsa_agency("ผู้ไม่หวังดีเจาะเครือข่าย กองทัพบก เมื่อสัปดาห์ที่ผ่านมา")
    assert hit is not None
    sector, needle, kind = hit
    assert sector == "state_security"
    assert "กองทัพบก" in needle
    assert kind == "agency"


def test_match_full_agency_transport_airline():
    hit = match_ncsa_agency("Phishing campaign impersonates บริษัท การบินไทย จำกัด (มหาชน)")
    assert hit is not None
    sector, _, kind = hit
    assert sector == "transportation"
    assert kind == "agency"


def test_match_full_agency_critical_infra_egat():
    hit = match_ncsa_agency("ransomware ที่โจมตี การไฟฟ้าฝ่ายผลิตแห่งประเทศไทย")
    assert hit is not None
    sector, _, kind = hit
    assert sector == "critical_infrastructure"
    assert kind == "agency"


def test_match_full_agency_healthcare_moph_office():
    hit = match_ncsa_agency(
        "ข้อมูลผู้ป่วยรั่วจาก ศูนย์เทคโนโลยีสารสนเทศและการสื่อสาร "
        "สำนักงานปลัดกระทรวงสาธารณสุข"
    )
    assert hit is not None
    sector, _, _ = hit
    assert sector == "healthcare"


def test_match_token_falls_back_when_full_name_absent():
    # "กรมสรรพากร" is not in our NCSA CSV but generic "กองทัพ" still matches.
    hit = match_ncsa_agency("รายงานข่าว: กองทัพ ตอบโต้การโจมตี")
    assert hit is not None
    sector, needle, kind = hit
    assert sector == "state_security"
    assert kind == "token"
    assert "กองทัพ" in needle


def test_match_returns_none_for_unrelated_text():
    assert match_ncsa_agency("Generic phishing kit detected") is None
    assert match_ncsa_agency("") is None


def test_match_is_case_insensitive_for_english_tokens():
    hit = match_ncsa_agency("Incident at NOKAIR baggage system")
    assert hit is not None
    sector, _, _ = hit
    assert sector == "transportation"


# ---------------------------------------------------------------------------
# classify_sector() integration
# ---------------------------------------------------------------------------


def test_classify_sector_uses_ncsa_match_for_state_security():
    result = classify_sector(
        description="เว็บฟิชชิงปลอมระบบของ สำนักงานตำรวจแห่งชาติ",
        title="Phishing targets RTP",
        ioc_value="rtp-login.example.com",
        ioc_type="domain",
    )
    assert result["sector"] == "state_security"
    # NCSA agency match → high confidence (>= 0.75).
    assert result["confidence"] >= 0.75
    assert result["matched_keywords"], "should expose what matched"


def test_classify_sector_uses_ncsa_match_for_transportation():
    result = classify_sector(
        description="Credential theft against การรถไฟแห่งประเทศไทย booking portal",
        ioc_value="srt-tickets.example.com",
        ioc_type="domain",
    )
    assert result["sector"] == "transportation"
    assert result["confidence"] >= 0.75


def test_classify_sector_ncsa_beats_keyword_fallback():
    """NCSA agency hit must short-circuit the keyword-scoring fallback."""
    # "bank" keyword would normally push toward financial; but "กองทัพอากาศ"
    # is a full agency match for state_security and runs first.
    result = classify_sector(
        description="กองทัพอากาศ alerts staff to bank-themed phishing",
        ioc_value="airforce-payroll.example.com",
        ioc_type="domain",
    )
    assert result["sector"] == "state_security"


def test_classify_sector_state_security_risk_bonus_applied():
    result = classify_sector(
        description="malware traced to สำนักข่าวกรองแห่งชาติ internal subnet",
        ioc_value="nia-internal.example.com",
        ioc_type="domain",
    )
    assert result["sector"] == "state_security"
    assert result["risk_bonus"] == SECTOR_RISK_BONUS["state_security"]
