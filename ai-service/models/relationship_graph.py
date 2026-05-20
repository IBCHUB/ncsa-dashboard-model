"""
Attack Relationship Graph Builder

Constructs a node-link graph from warehouse documents showing relationships
between threat actors, IOCs, malware, CVEs, infrastructure, and campaigns.

Design reference: 03Attack-Relationship specification.

Graph Schema:
  Nodes: actor, malware, indicator, cve, vendor, threattype, infrastructure, campaign
  Links: uses, classified_as, hosts, shares_infra, exploits, affects, same_campaign, suggested_actor
"""

from __future__ import annotations

import copy
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Tuple


def _make_node_id(node_type: str, value: str) -> str:
    """Sanitize value for use as node ID.

    Replaces spaces with underscores, strips characters that are not
    alphanumeric, underscore, hyphen, or dot.
    """
    sanitized = str(value).strip()
    sanitized = sanitized.replace(" ", "_")
    sanitized = re.sub(r"[^A-Za-z0-9_\-\.]", "", sanitized)
    return f"{node_type}_{sanitized}"


def _safe_list(value: Any) -> List[Any]:
    """Return *value* as a list, falling back to empty list for None."""
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def _safe_str(value: Any) -> str:
    """Return a stripped string or empty string for None."""
    if value is None:
        return ""
    return str(value).strip()


def _add_node(
    nodes_by_id: Dict[str, Dict[str, Any]],
    node_id: str,
    node_type: str,
    label: str,
    properties: Dict[str, Any] | None = None,
) -> None:
    """Insert a node if its id is not already present."""
    if node_id in nodes_by_id:
        return
    nodes_by_id[node_id] = {
        "id": node_id,
        "type": node_type,
        "label": label,
        "properties": dict(properties) if properties else {},
    }


def _add_link(
    links_index: Dict[Tuple[str, str, str], float],
    source: str,
    target: str,
    link_type: str,
) -> None:
    """Increment weight for a (source, target, type) link tuple."""
    key = (source, target, link_type)
    links_index[key] = links_index.get(key, 0.0) + 1.0


def _extract_actor_links(
    doc: Dict[str, Any],
    indicator_id: str,
    nodes_by_id: Dict[str, Dict[str, Any]],
    links_index: Dict[Tuple[str, str, str], float],
) -> None:
    """Create actor nodes and uses/exploits links from ai_threat_actors."""
    actors = _safe_list(doc.get("ai_threat_actors"))
    ioc_type = _safe_str(doc.get("ioc_type")).lower()

    for actor_name in actors:
        name = _safe_str(actor_name)
        if not name:
            continue
        actor_id = _make_node_id("actor", name)
        _add_node(nodes_by_id, actor_id, "actor", name)

        if ioc_type == "cve":
            _add_link(links_index, actor_id, indicator_id, "exploits")
        else:
            _add_link(links_index, actor_id, indicator_id, "uses")


def _extract_threattype_links(
    doc: Dict[str, Any],
    indicator_id: str,
    nodes_by_id: Dict[str, Dict[str, Any]],
    links_index: Dict[Tuple[str, str, str], float],
) -> None:
    """Create threattype nodes and classified_as links from ai_threat_types."""
    threat_types = _safe_list(doc.get("ai_threat_types"))

    for tt in threat_types:
        label = _safe_str(tt)
        if not label:
            continue
        tt_id = _make_node_id("threattype", label)
        _add_node(nodes_by_id, tt_id, "threattype", label)
        _add_link(links_index, indicator_id, tt_id, "classified_as")


def _extract_malware_links(
    doc: Dict[str, Any],
    indicator_id: str,
    nodes_by_id: Dict[str, Dict[str, Any]],
    links_index: Dict[Tuple[str, str, str], float],
) -> None:
    """Create malware nodes and hosts links from enrichment.related_entities and source_malware_family."""
    enrichment = doc.get("enrichment")
    if isinstance(enrichment, dict):
        related_entities = _safe_list(enrichment.get("related_entities"))
        for entity in related_entities:
            if not isinstance(entity, dict):
                continue
            entity_type = _safe_str(entity.get("entity_type")).lower()
            if "malware" in entity_type:
                name = _safe_str(entity.get("name") or entity.get("value"))
                if not name:
                    continue
                malware_id = _make_node_id("malware", name)
                _add_node(nodes_by_id, malware_id, "malware", name)
                _add_link(links_index, indicator_id, malware_id, "hosts")

        # enrichment.malware_family (may be set by some enrichment providers)
        malware_family = _safe_str(enrichment.get("malware_family"))
        if malware_family:
            malware_id = _make_node_id("malware", malware_family)
            _add_node(nodes_by_id, malware_id, "malware", malware_family)
            _add_link(links_index, indicator_id, malware_id, "hosts")

    # source_malware_family is the flat field set by pipeline_documents.py from
    # source evidence (e.g. cyberint.malware.name) — this is the primary path for
    # malware intelligence from the datalake adapters.
    source_malware = _safe_list(doc.get("source_malware_family"))
    if not source_malware:
        raw = doc.get("source_malware_family")
        if isinstance(raw, str) and raw.strip():
            source_malware = [raw.strip()]
    for malware_name in source_malware:
        name = _safe_str(malware_name)
        if not name:
            continue
        malware_id = _make_node_id("malware", name)
        _add_node(nodes_by_id, malware_id, "malware", name)
        _add_link(links_index, indicator_id, malware_id, "hosts")


def _extract_vendor_links(
    doc: Dict[str, Any],
    indicator_id: str,
    nodes_by_id: Dict[str, Dict[str, Any]],
    links_index: Dict[Tuple[str, str, str], float],
) -> None:
    """Create vendor nodes and affects links from CVE data."""
    ioc_type = _safe_str(doc.get("ioc_type")).lower()
    if ioc_type != "cve":
        return

    enrichment = doc.get("enrichment")
    vendor = None

    if isinstance(enrichment, dict):
        cve_info = enrichment.get("cve_info")
        if isinstance(cve_info, dict):
            vendor = _safe_str(cve_info.get("vendor"))
        if not vendor:
            vendor = _safe_str(enrichment.get("affected_vendor"))

    if not vendor:
        vendor = _safe_str(doc.get("affected_vendor"))

    if not vendor:
        return

    vendor_id = _make_node_id("vendor", vendor)
    _add_node(nodes_by_id, vendor_id, "vendor", vendor)
    _add_link(links_index, indicator_id, vendor_id, "affects")


def _extract_infrastructure_links(
    doc: Dict[str, Any],
    indicator_id: str,
    nodes_by_id: Dict[str, Dict[str, Any]],
    links_index: Dict[Tuple[str, str, str], float],
) -> None:
    """Create infrastructure nodes from enrichment data (ASN, nameservers, registrant email, ASN org)."""
    enrichment = doc.get("enrichment")
    if not isinstance(enrichment, dict):
        return

    ip_info = enrichment.get("ip_info")
    if isinstance(ip_info, dict):
        asn = _safe_str(ip_info.get("asn"))
        if asn:
            infra_id = _make_node_id("infra", asn)
            _add_node(nodes_by_id, infra_id, "infrastructure", asn)
            _add_link(links_index, indicator_id, infra_id, "shares_infra")

    asn_data = enrichment.get("asn_data")
    if isinstance(asn_data, dict):
        asn_org = _safe_str(asn_data.get("org"))
        if asn_org:
            org_id = _make_node_id("infra", f"org_{asn_org}")
            _add_node(nodes_by_id, org_id, "infrastructure", asn_org, {"source": "asn_data.org"})
            _add_link(links_index, indicator_id, org_id, "shares_infra")

    whois = enrichment.get("whois")
    if isinstance(whois, dict):
        name_servers = _safe_list(whois.get("name_server"))
        for ns in name_servers:
            ns_val = _safe_str(ns)
            if not ns_val:
                continue
            ns_id = _make_node_id("ns", ns_val)
            _add_node(nodes_by_id, ns_id, "infrastructure", ns_val)
            _add_link(links_index, indicator_id, ns_id, "shares_infra")

        registrant_email = _safe_str(whois.get("registrant_email"))
        if registrant_email:
            email_id = _make_node_id("infra", f"reg_{registrant_email}")
            _add_node(
                nodes_by_id, email_id, "infrastructure", registrant_email,
                {"source": "whois.registrant_email"},
            )
            _add_link(links_index, indicator_id, email_id, "shares_infra")


def _extract_campaign_links(
    doc: Dict[str, Any],
    indicator_id: str,
    campaign_members: Dict[Any, List[str]],
) -> None:
    """Track cluster_label membership for same_campaign links."""
    cluster = doc.get("cluster_label")
    if cluster is None:
        return
    campaign_members.setdefault(cluster, []).append(indicator_id)


def _build_campaign_nodes_and_links(
    campaign_members: Dict[Any, List[str]],
    nodes_by_id: Dict[str, Dict[str, Any]],
    links_index: Dict[Tuple[str, str, str], float],
) -> None:
    """Create same_campaign links between all IOCs sharing a cluster_label."""
    for cluster_label, member_ids in campaign_members.items():
        unique_members = list(dict.fromkeys(member_ids))
        if len(unique_members) < 2:
            continue

        campaign_id = _make_node_id("campaign", f"cluster_{cluster_label}")
        _add_node(
            nodes_by_id,
            campaign_id,
            "campaign",
            f"cluster_{cluster_label}",
        )

        for i in range(len(unique_members)):
            for j in range(i + 1, len(unique_members)):
                _add_link(
                    links_index,
                    unique_members[i],
                    unique_members[j],
                    "same_campaign",
                )


def _build_suggested_actor_links(
    campaign_members: Dict[Any, List[str]],
    links_index: Dict[Tuple[str, str, str], float],
) -> None:
    """For IOCs in a cluster without an actor, inherit actors from cluster peers.

    If IOC-A in cluster X is linked to Actor-Z via 'uses', and IOC-B is in the
    same cluster but has no actor link, create a suggested_actor link from IOC-B
    to Actor-Z.
    """
    # Build a lookup: ioc_id -> set of actors already linked
    # Include both "uses" (non-CVE) and "exploits" (CVE) link types
    ioc_actors: Dict[str, set] = {}
    for (src, tgt, lt) in links_index:
        if lt in ("uses", "exploits"):
            # actor -> ioc (both link types have actor as source, ioc as target)
            ioc_actors.setdefault(tgt, set()).add(src)

    for _cluster_label, member_ids in campaign_members.items():
        unique_members = list(dict.fromkeys(member_ids))
        if len(unique_members) < 2:
            continue

        # Collect all actors in this cluster
        cluster_actors: set = set()
        for ioc_id in unique_members:
            cluster_actors.update(ioc_actors.get(ioc_id, set()))

        if not cluster_actors:
            continue

        # For IOCs without an actor, suggest the cluster actors
        for ioc_id in unique_members:
            if ioc_id in ioc_actors:
                continue
            for actor_id in cluster_actors:
                _add_link(links_index, ioc_id, actor_id, "suggested_actor")


def build_relationship_graph(documents: list[dict]) -> dict:
    """Build a node-link graph from a list of warehouse documents.

    Returns a dict with ``nodes``, ``links``, and ``meta`` keys.
    Input documents are never mutated.
    """
    docs = copy.deepcopy(documents)

    nodes_by_id: Dict[str, Dict[str, Any]] = {}
    links_index: Dict[Tuple[str, str, str], float] = {}
    campaign_members: Dict[Any, List[str]] = {}

    for doc in docs:
        ioc_value = _safe_str(doc.get("ioc_value"))
        ioc_type = _safe_str(doc.get("ioc_type")).lower()

        if not ioc_value:
            continue

        if ioc_type == "cve":
            indicator_id = _make_node_id("ioc", ioc_value)
            node_type = "cve"
        else:
            indicator_id = _make_node_id("ioc", ioc_value)
            node_type = "indicator"

        _add_node(
            nodes_by_id,
            indicator_id,
            node_type,
            ioc_value,
            {"ioc_type": ioc_type} if ioc_type else {},
        )

        _extract_actor_links(doc, indicator_id, nodes_by_id, links_index)
        _extract_threattype_links(doc, indicator_id, nodes_by_id, links_index)
        _extract_malware_links(doc, indicator_id, nodes_by_id, links_index)
        _extract_vendor_links(doc, indicator_id, nodes_by_id, links_index)
        _extract_infrastructure_links(doc, indicator_id, nodes_by_id, links_index)
        _extract_campaign_links(doc, indicator_id, campaign_members)

    _build_campaign_nodes_and_links(campaign_members, nodes_by_id, links_index)
    _build_suggested_actor_links(campaign_members, links_index)

    nodes = list(nodes_by_id.values())
    links = [
        {"source": src, "target": tgt, "type": lt, "weight": w}
        for (src, tgt, lt), w in links_index.items()
    ]

    return {
        "nodes": nodes,
        "links": links,
        "meta": {
            "node_count": len(nodes),
            "link_count": len(links),
            "generated_at": datetime.now(timezone.utc).isoformat(),
        },
    }
