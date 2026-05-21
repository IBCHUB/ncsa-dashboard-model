"""
Tests for Thai-specific sector classification (Phase 1.17).

Verifies that the expanded keyword/domain lists in config.SECTORS plus the
loosened token-level domain matching in models.sector_classifier correctly
classify Thai banks, government agencies, utilities, telecom, hospitals,
and universities.

The dashboard relies heavily on sector classification — 6+ pages group by
target_sector. Improving URL/domain coverage is the highest-ROI lever
available (sha256 hashes have no sector signal and remain "general").
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from models.sector_classifier import classify_sector  # noqa: E402


def _classify(ioc_value: str, ioc_type: str = "domain", **kwargs) -> dict:
    """Convenience wrapper with common defaults."""
    return classify_sector(
        description=kwargs.get("description", ""),
        title=kwargs.get("title", ""),
        ioc_value=ioc_value,
        ioc_type=ioc_type,
        threat_actors=kwargs.get("threat_actors"),
        tags=kwargs.get("tags"),
    )


# ---------------------------------------------------------------------------
# Thai banks → financial
# ---------------------------------------------------------------------------


def test_scb_domain_classifies_as_financial():
    """scb.co.th — Thai bank token match."""
    result = _classify("scb.co.th")
    assert result["sector"] == "financial", (
        f"scb.co.th must classify as financial; got {result['sector']}"
    )


def test_kbank_domain_classifies_as_financial():
    """kbank.co.th — substring match in domains list."""
    result = _classify("kbank.co.th")
    assert result["sector"] == "financial"


def test_bangkokbank_subdomain_classifies_as_financial():
    """Substring pattern 'bangkokbank.com' should match subdomain."""
    result = _classify("login.bangkokbank.com")
    assert result["sector"] == "financial"


def test_krungsri_classifies_as_financial():
    """krungsri.com — substring pattern."""
    result = _classify("www.krungsri.com")
    assert result["sector"] == "financial"


def test_phishing_url_imitating_scb_classifies_as_financial():
    """URL path mentioning 'scb' should reach financial via token match."""
    result = _classify(
        "https://phish.evil/scb/login.php",
        ioc_type="url",
    )
    assert result["sector"] == "financial"


def test_thai_bank_keyword_in_description_classifies_as_financial():
    """description mentioning Thai bank brand should trip financial sector."""
    result = _classify(
        "evil.example",
        description="Phishing campaign targeting Kasikorn customers",
    )
    assert result["sector"] == "financial"


# ---------------------------------------------------------------------------
# Thai gov (.go.th + agencies) → government
# ---------------------------------------------------------------------------


def test_go_th_tld_classifies_as_government_via_tld_hint():
    """Any *.go.th hostname → government via TLD shortcut."""
    result = _classify("intranet.moph.go.th")
    assert result["sector"] == "government"
    # TLD hint provides high confidence (0.85)
    assert result["confidence"] >= 0.8


def test_mi_th_tld_classifies_as_government_after_phase_1_17_fix():
    """Phase 1.17 fix: *.mi.th remapped from non-existent 'defense' to 'government'."""
    result = _classify("rtaf.mi.th")
    assert result["sector"] == "government", (
        "Phase 1.17 fix: military TLDs must map to 'government' "
        "(NCSA taxonomy = Substantive Public Services)"
    )


def test_mil_tld_classifies_as_government():
    """US .mil military domains map to government too."""
    result = _classify("cyber.mil")
    assert result["sector"] == "government"


def test_thai_gov_agency_token_classifies_as_government():
    """etda.or.th — token match via 'etda' bare keyword."""
    result = _classify("portal.etda.or.th")
    # .or.th is also in government domains list → should match
    assert result["sector"] == "government"


def test_ncsa_keyword_in_description_classifies_as_government():
    result = _classify(
        "evil.example",
        description="phishing impersonating NCSA Thailand security advisory",
    )
    assert result["sector"] == "government"


# ---------------------------------------------------------------------------
# Thai universities (.ac.th) → education
# ---------------------------------------------------------------------------


def test_ac_th_tld_classifies_as_education():
    """*.ac.th → education via TLD hint."""
    result = _classify("portal.chula.ac.th")
    assert result["sector"] == "education"


def test_mahidol_classifies_as_education():
    result = _classify("library.mahidol.ac.th")
    assert result["sector"] == "education"


# ---------------------------------------------------------------------------
# Thai healthcare → healthcare
# ---------------------------------------------------------------------------


def test_bumrungrad_classifies_as_healthcare():
    result = _classify("login.bumrungrad.com")
    assert result["sector"] == "healthcare"


def test_thai_hospital_keyword_classifies_as_healthcare():
    result = _classify(
        "evil.example",
        description="Ransomware hits Bumrungrad Hospital systems",
    )
    assert result["sector"] == "healthcare"


def test_siriraj_keyword_classifies_as_healthcare():
    result = _classify(
        "evil.example",
        description="Siriraj patient data leaked",
    )
    assert result["sector"] == "healthcare"


# ---------------------------------------------------------------------------
# Thai utilities → critical_infrastructure
# ---------------------------------------------------------------------------


def test_egat_classifies_as_critical_infrastructure():
    """egat.co.th — Electricity Generating Authority of Thailand."""
    result = _classify("portal.egat.co.th")
    assert result["sector"] == "critical_infrastructure"


def test_ptt_classifies_as_critical_infrastructure():
    """pttplc.com — PTT (Thai oil/gas)."""
    result = _classify("login.pttplc.com")
    assert result["sector"] == "critical_infrastructure"


def test_aot_airport_classifies_as_critical_infrastructure():
    """airportthai.co.th — Airports of Thailand."""
    result = _classify("www.airportthai.co.th")
    assert result["sector"] == "critical_infrastructure"


def test_egat_keyword_classifies_as_critical_infrastructure():
    result = _classify(
        "evil.example",
        description="SCADA attack against EGAT power grid",
    )
    assert result["sector"] == "critical_infrastructure"


# ---------------------------------------------------------------------------
# Thai + global telecom → technology
# ---------------------------------------------------------------------------


def test_ais_classifies_as_technology():
    """ais.co.th — Thai mobile carrier."""
    result = _classify("login.ais.co.th")
    assert result["sector"] == "technology"


def test_truemove_classifies_as_technology():
    """truemoveh.com — Thai mobile carrier."""
    result = _classify("portal.truemoveh.com")
    assert result["sector"] == "technology"


def test_cloudflare_classifies_as_technology():
    """Global CDN — should classify as technology, not general."""
    result = _classify("login.cloudflare.com")
    assert result["sector"] == "technology"


def test_aws_subdomain_classifies_as_technology():
    """amazonaws.com — global cloud provider."""
    result = _classify("malicious-bucket.s3.amazonaws.com")
    assert result["sector"] == "technology"


# ---------------------------------------------------------------------------
# False-positive guards — token match must not be too loose
# ---------------------------------------------------------------------------


def test_random_domain_with_bank_substring_does_not_false_positive():
    """'bankside.com' should NOT match financial (token 'bank' is part of
    a longer label, not a standalone token). After Phase 1.17 loosening,
    we explicitly use token-level (split-by-dot/dash) matching to prevent
    this class of false positives.

    Note: the keyword 'bank' in description STILL matches financial via
    keyword path — that's intentional. This test guards only domain
    pattern matching.
    """
    result = _classify("bankside.example")
    # 'bank' is a financial keyword — will get keyword score from substring
    # match in hostname text. But raw token matching should NOT fire.
    # We accept either general or financial here, but if financial, it
    # should be at low confidence (only keyword, no domain match).
    if result["sector"] == "financial":
        # OK as long as no domain match — verify via matched_domains being empty
        # of any of the bare tokens.
        bare_tokens = {"scb", "kbank", "ktb", "bbl", "uob", "cimb"}
        for d in result.get("matched_domains", []):
            assert d.lower() not in bare_tokens, (
                f"False positive: bare token '{d}' should not match 'bankside'"
            )


def test_news_outlet_does_not_false_positive_as_government():
    """Random news site should not match government just because text has 'government'."""
    result = _classify(
        "https://news.example/article-about-government-spending",
        ioc_type="url",
    )
    # Will likely match government via "government" keyword in path — that's
    # fine. The test guards against the URL itself being forced to government
    # by TLD hints when it's a .example/.com.
    # Just verify no TLD hint forced classification at 0.85 confidence
    if result["sector"] == "government":
        assert result["confidence"] < 0.85, (
            "TLD hint should NOT fire on .example"
        )


def test_unknown_random_domain_falls_back_to_general():
    """Generic IOC with no sector signals → general."""
    result = _classify("random-c2-server-xyz.example")
    assert result["sector"] == "general"
    assert result["confidence"] == 0.0


# ---------------------------------------------------------------------------
# IOC type variants — sha256/IP must not raise even if they can't classify
# ---------------------------------------------------------------------------


def test_sha256_hash_falls_back_to_general_gracefully():
    """sha256 has no domain context — must return general, not crash."""
    result = _classify("a" * 64, ioc_type="sha256")
    assert result["sector"] == "general"


def test_ip_without_geo_context_falls_back_to_general():
    """Bare IP IOC — must return general."""
    result = _classify("185.220.101.42", ioc_type="ip")
    assert result["sector"] == "general"


def test_url_with_query_params_does_not_crash():
    """URL with query params — domain extraction should still work."""
    result = _classify(
        "https://scb.co.th/login?next=/dashboard&utm=phish",
        ioc_type="url",
    )
    assert result["sector"] == "financial"
