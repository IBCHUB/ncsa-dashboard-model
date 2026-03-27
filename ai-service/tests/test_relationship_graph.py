"""
Unit tests for the Attack Relationship Graph Builder.

Covers node/link extraction, deduplication, weighting, immutability,
and meta-count accuracy.
"""

import copy
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from models.relationship_graph import build_relationship_graph  # noqa: E402


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_doc(**overrides):
    """Return a minimal warehouse document with sensible defaults."""
    base = {
        "ioc_value": "192.168.1.1",
        "ioc_type": "ip",
        "ai_threat_types": [],
        "ai_threat_actors": [],
        "enrichment": {},
        "cluster_label": None,
    }
    return {**base, **overrides}


def _find_nodes(graph, node_type=None, node_id=None):
    """Filter graph nodes by type and/or id."""
    results = graph["nodes"]
    if node_type is not None:
        results = [n for n in results if n["type"] == node_type]
    if node_id is not None:
        results = [n for n in results if n["id"] == node_id]
    return results


def _find_links(graph, link_type=None, source=None, target=None):
    """Filter graph links by type, source, and/or target."""
    results = graph["links"]
    if link_type is not None:
        results = [lk for lk in results if lk["type"] == link_type]
    if source is not None:
        results = [lk for lk in results if lk["source"] == source]
    if target is not None:
        results = [lk for lk in results if lk["target"] == target]
    return results


# ---------------------------------------------------------------------------
# 1. Empty input
# ---------------------------------------------------------------------------

def test_graph_empty_input():
    result = build_relationship_graph([])

    assert result["nodes"] == []
    assert result["links"] == []
    assert result["meta"]["node_count"] == 0
    assert result["meta"]["link_count"] == 0
    assert "generated_at" in result["meta"]


# ---------------------------------------------------------------------------
# 2. Actor -> Indicator link (uses)
# ---------------------------------------------------------------------------

def test_graph_actor_indicator_link():
    doc = _make_doc(
        ioc_value="163.44.198.62",
        ioc_type="ip",
        ai_threat_actors=["Lazarus"],
    )
    graph = build_relationship_graph([doc])

    actor_nodes = _find_nodes(graph, node_type="actor")
    assert len(actor_nodes) == 1
    assert actor_nodes[0]["id"] == "actor_Lazarus"
    assert actor_nodes[0]["label"] == "Lazarus"

    uses_links = _find_links(graph, link_type="uses")
    assert len(uses_links) == 1
    assert uses_links[0]["source"] == "actor_Lazarus"
    assert uses_links[0]["target"] == "ioc_163.44.198.62"


# ---------------------------------------------------------------------------
# 3. Indicator -> ThreatType link (classified_as)
# ---------------------------------------------------------------------------

def test_graph_indicator_threattype_link():
    doc = _make_doc(
        ioc_value="malicious.com",
        ioc_type="domain",
        ai_threat_types=["Ransomware"],
    )
    graph = build_relationship_graph([doc])

    tt_nodes = _find_nodes(graph, node_type="threattype")
    assert len(tt_nodes) == 1
    assert tt_nodes[0]["id"] == "threattype_Ransomware"

    classified_links = _find_links(graph, link_type="classified_as")
    assert len(classified_links) == 1
    assert classified_links[0]["source"] == "ioc_malicious.com"
    assert classified_links[0]["target"] == "threattype_Ransomware"


# ---------------------------------------------------------------------------
# 4. CVE exploits link
# ---------------------------------------------------------------------------

def test_graph_cve_exploits_link():
    doc = _make_doc(
        ioc_value="CVE-2025-1234",
        ioc_type="cve",
        ai_threat_actors=["APT28"],
    )
    graph = build_relationship_graph([doc])

    cve_nodes = _find_nodes(graph, node_type="cve")
    assert len(cve_nodes) == 1
    assert cve_nodes[0]["id"] == "ioc_CVE-2025-1234"

    exploits_links = _find_links(graph, link_type="exploits")
    assert len(exploits_links) == 1
    assert exploits_links[0]["source"] == "actor_APT28"
    assert exploits_links[0]["target"] == "ioc_CVE-2025-1234"

    uses_links = _find_links(graph, link_type="uses")
    assert len(uses_links) == 0


# ---------------------------------------------------------------------------
# 5. Infrastructure link (shares_infra via ASN)
# ---------------------------------------------------------------------------

def test_graph_infrastructure_link():
    doc = _make_doc(
        ioc_value="10.0.0.1",
        ioc_type="ip",
        enrichment={
            "ip_info": {"asn": "AS4134"},
        },
    )
    graph = build_relationship_graph([doc])

    infra_nodes = _find_nodes(graph, node_type="infrastructure")
    assert len(infra_nodes) == 1
    assert infra_nodes[0]["id"] == "infra_AS4134"
    assert infra_nodes[0]["label"] == "AS4134"

    infra_links = _find_links(graph, link_type="shares_infra")
    assert len(infra_links) == 1
    assert infra_links[0]["source"] == "ioc_10.0.0.1"
    assert infra_links[0]["target"] == "infra_AS4134"


# ---------------------------------------------------------------------------
# 6. Same-campaign link via cluster_label
# ---------------------------------------------------------------------------

def test_graph_same_campaign_link():
    doc_a = _make_doc(ioc_value="evil1.com", ioc_type="domain", cluster_label=5)
    doc_b = _make_doc(ioc_value="evil2.com", ioc_type="domain", cluster_label=5)

    graph = build_relationship_graph([doc_a, doc_b])

    campaign_links = _find_links(graph, link_type="same_campaign")
    assert len(campaign_links) == 1
    assert campaign_links[0]["source"] == "ioc_evil1.com"
    assert campaign_links[0]["target"] == "ioc_evil2.com"

    campaign_nodes = _find_nodes(graph, node_type="campaign")
    assert len(campaign_nodes) == 1
    assert campaign_nodes[0]["id"] == "campaign_cluster_5"


# ---------------------------------------------------------------------------
# 7. Deduplication: same actor across multiple docs => 1 node
# ---------------------------------------------------------------------------

def test_graph_deduplicates_nodes():
    docs = [
        _make_doc(ioc_value=f"ioc{i}.com", ioc_type="domain", ai_threat_actors=["Lazarus"])
        for i in range(3)
    ]
    graph = build_relationship_graph(docs)

    actor_nodes = _find_nodes(graph, node_type="actor")
    assert len(actor_nodes) == 1
    assert actor_nodes[0]["id"] == "actor_Lazarus"


# ---------------------------------------------------------------------------
# 8. Link weight reflects number of supporting documents
# ---------------------------------------------------------------------------

def test_graph_link_weight():
    docs = [
        _make_doc(
            ioc_value="evil.com",
            ioc_type="domain",
            ai_threat_actors=["Lazarus"],
        )
        for _ in range(3)
    ]
    graph = build_relationship_graph(docs)

    uses_links = _find_links(
        graph, link_type="uses", source="actor_Lazarus", target="ioc_evil.com"
    )
    assert len(uses_links) == 1
    assert uses_links[0]["weight"] == 3.0


# ---------------------------------------------------------------------------
# 9. Immutability: input documents must not be mutated
# ---------------------------------------------------------------------------

def test_graph_immutability():
    original_doc = _make_doc(
        ioc_value="safe.com",
        ioc_type="domain",
        ai_threat_actors=["APT29"],
        enrichment={"ip_info": {"asn": "AS1234"}},
    )
    frozen_copy = copy.deepcopy(original_doc)
    input_list = [original_doc]
    frozen_list_len = len(input_list)

    build_relationship_graph(input_list)

    assert len(input_list) == frozen_list_len
    assert original_doc == frozen_copy


# ---------------------------------------------------------------------------
# 10. Meta counts match actual node and link lists
# ---------------------------------------------------------------------------

def test_graph_meta_counts():
    docs = [
        _make_doc(
            ioc_value="c2.example.com",
            ioc_type="domain",
            ai_threat_actors=["Lazarus"],
            ai_threat_types=["Ransomware", "C2"],
            enrichment={"ip_info": {"asn": "AS9999"}},
        ),
        _make_doc(
            ioc_value="dropper.exe",
            ioc_type="hash",
            ai_threat_actors=["Lazarus"],
            ai_threat_types=["Malware"],
        ),
    ]
    graph = build_relationship_graph(docs)

    assert graph["meta"]["node_count"] == len(graph["nodes"])
    assert graph["meta"]["link_count"] == len(graph["links"])
    assert graph["meta"]["node_count"] > 0
    assert graph["meta"]["link_count"] > 0
