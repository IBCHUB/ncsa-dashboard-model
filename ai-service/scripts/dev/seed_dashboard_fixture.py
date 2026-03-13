#!/usr/bin/env python
"""Seed or clean synthetic dashboard UAT fixtures in remote ELK indices."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import random
from collections import Counter
from datetime import date, datetime, timedelta, timezone
from typing import Any, Dict, Iterable, Iterator, List, Sequence, Tuple

import requests


ELASTICSEARCH_URL = os.getenv("ELASTICSEARCH_URL", "https://pluto-elk.ibusiness.co.th").rstrip("/")
DATALAKE_INDEX = os.getenv("DATALAKE_INDEX", "cyber-logs-datalake")
WAREHOUSE_INDEX = os.getenv("WAREHOUSE_INDEX", "cyber-logs-datawarehouse")
DATALAKE_API_KEY = os.getenv("DATALAKE_API_KEY", "")
WAREHOUSE_API_KEY = os.getenv("WAREHOUSE_API_KEY", "")

BANGKOK_TZ = timezone(timedelta(hours=7))
UTC = timezone.utc

SEED_TAG = "synthetic-dashboard-uat"
SEED_SERIES = "synthetic-dashboard-uat-v4"
DEFAULT_RANDOM_SEED = 20260313
DEFAULT_CHUNK_SIZE = 500
DEFAULT_SMALL_WAREHOUSE_TARGET = 36
DEFAULT_LARGE_WAREHOUSE_TARGET = 12000
DEFAULT_SMALL_DATE_SPAN_DAYS = 1
DEFAULT_LARGE_DATE_SPAN_DAYS = 13

LEGACY_FIXTURE_DOCS = (
    (WAREHOUSE_INDEX, "fixture-action-review-20260205", WAREHOUSE_API_KEY),
    (DATALAKE_INDEX, "fixture-dl-action-review-20260205", DATALAKE_API_KEY),
)

SECTOR_PROFILES: Dict[str, Dict[str, str]] = {
    "government": {"sector": "government", "sector_name": "Government", "sector_name_th": "ภาครัฐ", "icon": "🏛️"},
    "financial": {"sector": "financial", "sector_name": "Financial", "sector_name_th": "การเงิน", "icon": "🏦"},
    "healthcare": {"sector": "healthcare", "sector_name": "Healthcare", "sector_name_th": "สาธารณสุข", "icon": "🏥"},
    "critical_infrastructure": {
        "sector": "critical_infrastructure",
        "sector_name": "Critical Infrastructure",
        "sector_name_th": "โครงสร้างพื้นฐานสำคัญ",
        "icon": "⚡",
    },
    "education": {"sector": "education", "sector_name": "Education", "sector_name_th": "การศึกษา", "icon": "🎓"},
    "technology": {"sector": "technology", "sector_name": "Technology", "sector_name_th": "เทคโนโลยี", "icon": "💻"},
    "manufacturing": {"sector": "manufacturing", "sector_name": "Manufacturing", "sector_name_th": "อุตสาหกรรม", "icon": "🏭"},
    "retail": {"sector": "retail", "sector_name": "Retail", "sector_name_th": "ค้าปลีก", "icon": "🛒"},
    "telecom": {"sector": "telecom", "sector_name": "Telecom", "sector_name_th": "โทรคมนาคม", "icon": "📡"},
    "energy": {"sector": "energy", "sector_name": "Energy", "sector_name_th": "พลังงาน", "icon": "⛽"},
}

COUNTRY_PROFILES: Dict[str, Dict[str, Any]] = {
    "Russia": {"city": "Moscow", "latitude": 55.7558, "longitude": 37.6173, "asn": "AS64500", "org": "Synthetic RU Hosting"},
    "Singapore": {"city": "Singapore", "latitude": 1.3521, "longitude": 103.8198, "asn": "AS64510", "org": "Synthetic SG Transit"},
    "United States": {"city": "Ashburn", "latitude": 39.0438, "longitude": -77.4874, "asn": "AS64520", "org": "Synthetic US Cloud"},
    "Netherlands": {"city": "Amsterdam", "latitude": 52.3676, "longitude": 4.9041, "asn": "AS64530", "org": "Synthetic NL Hosting"},
    "Germany": {"city": "Frankfurt", "latitude": 50.1109, "longitude": 8.6821, "asn": "AS64540", "org": "Synthetic DE Exchange"},
    "China": {"city": "Beijing", "latitude": 39.9042, "longitude": 116.4074, "asn": "AS64550", "org": "Synthetic CN ISP"},
    "India": {"city": "Mumbai", "latitude": 19.0760, "longitude": 72.8777, "asn": "AS64551", "org": "Synthetic IN Transit"},
    "Indonesia": {"city": "Jakarta", "latitude": -6.2088, "longitude": 106.8456, "asn": "AS64552", "org": "Synthetic ID Exchange"},
    "Thailand": {"city": "Bangkok", "latitude": 13.7563, "longitude": 100.5018, "asn": "AS64560", "org": "Synthetic TH Broadband"},
    "Poland": {"city": "Warsaw", "latitude": 52.2297, "longitude": 21.0122, "asn": "AS64570", "org": "Synthetic PL Datacenter"},
    "France": {"city": "Paris", "latitude": 48.8566, "longitude": 2.3522, "asn": "AS64580", "org": "Synthetic FR Network"},
    "Iran": {"city": "Tehran", "latitude": 35.6892, "longitude": 51.3890, "asn": "AS64590", "org": "Synthetic IR Backbone"},
    "Japan": {"city": "Tokyo", "latitude": 35.6762, "longitude": 139.6503, "asn": "AS64600", "org": "Synthetic JP Carrier"},
    "South Korea": {"city": "Seoul", "latitude": 37.5665, "longitude": 126.9780, "asn": "AS64610", "org": "Synthetic KR ISP"},
    "United Kingdom": {"city": "London", "latitude": 51.5072, "longitude": -0.1276, "asn": "AS64620", "org": "Synthetic UK Exchange"},
}

SOURCE_CATALOG: Dict[str, Dict[str, Any]] = {
    "VirusTotal": {"kind": "threat_intel", "category": "trusted", "score": 96},
    "AbuseIPDB": {"kind": "threat_intel", "category": "trusted", "score": 94},
    "MITRE": {"kind": "threat_intel", "category": "trusted", "score": 92},
    "AlienVault": {"kind": "threat_intel", "category": "trusted", "score": 90},
    "ThreatFox": {"kind": "threat_intel", "category": "trusted", "score": 95},
    "URLhaus": {"kind": "threat_intel", "category": "trusted", "score": 93},
    "MalwareBazaar": {"kind": "threat_intel", "category": "trusted", "score": 92},
    "PhishTank": {"kind": "threat_intel", "category": "trusted", "score": 89},
    "Suricata": {"kind": "sensor", "category": "sensor", "score": 91},
    "Snort": {"kind": "sensor", "category": "sensor", "score": 89},
    "Zeek": {"kind": "sensor", "category": "sensor", "score": 88},
    "YARA": {"kind": "sensor", "category": "sensor", "score": 87},
    "Cyberint": {"kind": "threat_intel", "category": "trusted", "score": 90},
    "Recorded Future": {"kind": "threat_intel", "category": "trusted", "score": 95},
    "Sandbox": {"kind": "internal", "category": "internal", "score": 94},
    "BleepingComputer": {"kind": "news", "category": "news", "score": 84},
    "DarkReading": {"kind": "news", "category": "news", "score": 85},
    "TheHackerNews": {"kind": "news", "category": "news", "score": 86},
    "Cyber News": {"kind": "news", "category": "news", "score": 82},
    "SecurityWeek": {"kind": "news", "category": "news", "score": 85},
    "KrebsOnSecurity": {"kind": "news", "category": "news", "score": 83},
    "Zone-H": {"kind": "feed", "category": "feed", "score": 81},
}

ALL_SOURCES: Sequence[str] = tuple(SOURCE_CATALOG.keys())
NEWS_SOURCES: Sequence[str] = tuple(name for name, meta in SOURCE_CATALOG.items() if meta["category"] == "news")

SOURCE_BUNDLES: Dict[str, Dict[str, Sequence[str]]] = {
    "phishing": {
        "intel": ("PhishTank", "URLhaus", "ThreatFox", "AbuseIPDB", "VirusTotal"),
        "sensor": ("Suricata", "Snort"),
        "news": ("TheHackerNews", "BleepingComputer", "Cyber News"),
        "internal": ("Sandbox",),
    },
    "malware": {
        "intel": ("ThreatFox", "MalwareBazaar", "VirusTotal", "AbuseIPDB", "Recorded Future", "Cyberint"),
        "sensor": ("Suricata", "YARA"),
        "news": ("BleepingComputer", "SecurityWeek", "DarkReading"),
        "internal": ("Sandbox",),
    },
    "vulnerability": {
        "intel": ("MITRE", "Recorded Future", "AlienVault", "Cyberint", "VirusTotal"),
        "sensor": ("YARA",),
        "news": ("DarkReading", "SecurityWeek", "TheHackerNews", "KrebsOnSecurity"),
        "internal": ("Sandbox",),
    },
    "defacement": {
        "intel": ("Zone-H", "VirusTotal", "AbuseIPDB"),
        "sensor": ("Suricata",),
        "news": ("Cyber News", "BleepingComputer"),
        "internal": ("Sandbox",),
    },
    "ddos": {
        "intel": ("AbuseIPDB", "VirusTotal", "Recorded Future"),
        "sensor": ("Suricata", "Snort", "Zeek"),
        "news": ("Cyber News",),
        "internal": ("Sandbox",),
    },
    "breach": {
        "intel": ("Recorded Future", "Cyberint", "AbuseIPDB", "AlienVault", "VirusTotal"),
        "sensor": ("Zeek",),
        "news": ("SecurityWeek", "DarkReading", "BleepingComputer"),
        "internal": ("Sandbox",),
    },
    "c2": {
        "intel": ("ThreatFox", "AbuseIPDB", "VirusTotal", "Cyberint", "Recorded Future"),
        "sensor": ("Suricata", "YARA"),
        "news": ("TheHackerNews", "SecurityWeek"),
        "internal": ("Sandbox",),
    },
    "supply_chain": {
        "intel": ("Recorded Future", "MITRE", "AlienVault", "Cyberint"),
        "sensor": ("YARA", "Zeek"),
        "news": ("DarkReading", "SecurityWeek", "KrebsOnSecurity"),
        "internal": ("Sandbox",),
    },
}

ARCHETYPES: Sequence[Dict[str, Any]] = (
    {
        "slug": "gov-phishing-domain",
        "ioc_type": "domain",
        "severity": "critical",
        "risk_base": 94,
        "threat_types": ("Phishing Website",),
        "threat_actor": "Lazarus",
        "sector": "government",
        "country_pool": ("China", "India", "Indonesia"),
        "source_profile": "phishing",
        "malware": "AgentTesla",
        "headline": "Government credential harvesting campaign targets Thai agencies",
        "description": "Credential phishing kit impersonates Thai government portals and captures passwords.",
    },
    {
        "slug": "bank-malware-ip",
        "ioc_type": "ip",
        "severity": "high",
        "risk_base": 86,
        "threat_types": ("Malware",),
        "threat_actor": "APT28",
        "sector": "financial",
        "country_pool": ("India", "Russia", "China"),
        "source_profile": "malware",
        "malware": "Qakbot",
        "headline": "Banking malware callback infrastructure observed in regional hosting provider",
        "description": "Callback IP linked to banking malware beaconing into Thai financial infrastructure.",
    },
    {
        "slug": "health-zero-day-cve",
        "ioc_type": "cve",
        "severity": "critical",
        "risk_base": 91,
        "threat_types": ("Vulnerability",),
        "threat_actor": "Cl0p",
        "sector": "healthcare",
        "country_pool": ("United States", "Germany", "Singapore"),
        "source_profile": "vulnerability",
        "malware": "ExploitKit",
        "headline": "Healthcare VPN zero-day under active exploitation",
        "description": "Unpatched remote access product exploited against hospital networks and partner portals.",
    },
    {
        "slug": "energy-defacement-domain",
        "ioc_type": "domain",
        "severity": "high",
        "risk_base": 79,
        "threat_types": ("Web Defacement",),
        "threat_actor": "Anonymous",
        "sector": "energy",
        "country_pool": ("Indonesia", "China", "Iran"),
        "source_profile": "defacement",
        "malware": "WebShell",
        "headline": "Utility customer portal defaced and mirrored on threat channels",
        "description": "Website defacement indicator associated with public mirror listings and follow-on reconnaissance.",
    },
    {
        "slug": "education-ddos-ip",
        "ioc_type": "ip",
        "severity": "medium",
        "risk_base": 63,
        "threat_types": ("DDoS",),
        "threat_actor": "Anonymous",
        "sector": "education",
        "country_pool": ("Indonesia", "Thailand", "Singapore"),
        "source_profile": "ddos",
        "malware": "Botnet",
        "headline": "Volumetric probes against university edge services intensify",
        "description": "Sensor telemetry captured coordinated DDoS bursts against public-facing education services.",
    },
    {
        "slug": "telecom-breach-url",
        "ioc_type": "url",
        "severity": "high",
        "risk_base": 84,
        "threat_types": ("Compromised",),
        "threat_actor": "APT29",
        "sector": "telecom",
        "country_pool": ("China", "India", "United States"),
        "source_profile": "breach",
        "malware": "StealerX",
        "headline": "Leaked telecom credentials surfaced with exfiltration URL",
        "description": "Credential package references exfiltration endpoint used in telecom data breach disclosures.",
    },
    {
        "slug": "manufacturing-ransomware-hash",
        "ioc_type": "sha256",
        "severity": "critical",
        "risk_base": 96,
        "threat_types": ("Network Intrusion",),
        "threat_actor": "LockBit",
        "sector": "manufacturing",
        "country_pool": ("India", "Russia", "Poland"),
        "source_profile": "malware",
        "malware": "LockBit",
        "headline": "Manufacturing ransomware sample linked to lateral movement toolkit",
        "description": "Payload hash associated with ransomware deployment observed in industrial environments.",
    },
    {
        "slug": "gov-supply-chain-domain",
        "ioc_type": "domain",
        "severity": "critical",
        "risk_base": 89,
        "threat_types": ("Payload Delivery",),
        "threat_actor": "APT41",
        "sector": "government",
        "country_pool": ("China", "South Korea", "Japan"),
        "source_profile": "supply_chain",
        "malware": "BackdoorLoader",
        "headline": "Compromised package repository references staged update domain",
        "description": "Supply-chain compromise indicator points to update domain serving tampered application bundles.",
    },
    {
        "slug": "health-credential-url",
        "ioc_type": "url",
        "severity": "high",
        "risk_base": 82,
        "threat_types": ("C2 Server",),
        "threat_actor": "FIN7",
        "sector": "healthcare",
        "country_pool": ("India", "United States", "Singapore"),
        "source_profile": "c2",
        "malware": "InfoStealer",
        "headline": "Healthcare credential harvesting pages mimic appointment workflows",
        "description": "Credential theft landing pages imitate hospital appointment flows and insurance renewal portals.",
    },
    {
        "slug": "tech-vuln-cve",
        "ioc_type": "cve",
        "severity": "medium",
        "risk_base": 68,
        "threat_types": ("Vulnerability",),
        "threat_actor": "OilRig",
        "sector": "technology",
        "country_pool": ("France", "United Kingdom", "United States"),
        "source_profile": "vulnerability",
        "malware": "ExploitChain",
        "headline": "Public cloud panel vulnerability discussed across editorial feeds",
        "description": "Editorial reporting highlights exploitation risk for newly disclosed control-panel vulnerability.",
    },
    {
        "slug": "financial-phishing-url",
        "ioc_type": "url",
        "severity": "critical",
        "risk_base": 90,
        "threat_types": ("Phishing Website",),
        "threat_actor": "MuddyWater",
        "sector": "financial",
        "country_pool": ("Indonesia", "Thailand", "India"),
        "source_profile": "phishing",
        "malware": "BrowserStealer",
        "headline": "Financial alert phishing workflow abuses cloned banking login pages",
        "description": "Credential capture URL ties into finance-themed lure set targeting Thai banking customers.",
    },
    {
        "slug": "retail-botnet-ip",
        "ioc_type": "ip",
        "severity": "high",
        "risk_base": 79,
        "threat_types": ("Other",),
        "threat_actor": "Emotet",
        "sector": "retail",
        "country_pool": ("China", "India", "Russia"),
        "source_profile": "malware",
        "malware": "Emotet",
        "headline": "Retail botnet relay infrastructure observed in recurring malware sessions",
        "description": "Botnet relay IP shows repeat malware beaconing patterns across captured sandbox sessions.",
    },
    {
        "slug": "telecom-c2-domain",
        "ioc_type": "domain",
        "severity": "high",
        "risk_base": 83,
        "threat_types": ("C2 Server",),
        "threat_actor": "APT29",
        "sector": "telecom",
        "country_pool": ("Netherlands", "Germany", "France"),
        "source_profile": "c2",
        "malware": "BeaconX",
        "headline": "Regional telecom beacons connect to rotating command infrastructure",
        "description": "Domain infrastructure rotates through European hosting to manage beacon traffic and tasking.",
    },
    {
        "slug": "public-sector-malware-hash",
        "ioc_type": "md5",
        "severity": "high",
        "risk_base": 81,
        "threat_types": ("Malware",),
        "threat_actor": "APT41",
        "sector": "government",
        "country_pool": ("China", "Russia", "Iran"),
        "source_profile": "malware",
        "malware": "LoaderX",
        "headline": "Public-sector malware sample linked to loader reuse",
        "description": "Malware sample shares code lineage with previously observed loader activity against government networks.",
    },
    {
        "slug": "retail-carding-domain",
        "ioc_type": "domain",
        "severity": "medium",
        "risk_base": 71,
        "threat_types": ("Compromised",),
        "threat_actor": "FIN7",
        "sector": "retail",
        "country_pool": ("United States", "Netherlands", "Singapore"),
        "source_profile": "breach",
        "malware": "CardSkimmer",
        "headline": "Retail storefront skimmer domain appears in breach telemetry",
        "description": "Compromised e-commerce assets reference skimmer collection infrastructure and shared drop endpoints.",
    },
    {
        "slug": "university-scan-ip",
        "ioc_type": "ip",
        "severity": "low",
        "risk_base": 44,
        "threat_types": ("Other",),
        "threat_actor": "Anonymous",
        "sector": "education",
        "country_pool": ("Thailand", "Singapore", "Indonesia"),
        "source_profile": "ddos",
        "malware": "Scanner",
        "headline": "Automated reconnaissance continues against university perimeter services",
        "description": "Internet-facing academic services receive recurring scan activity and credential spray attempts.",
    },
    {
        "slug": "critical-supply-cve",
        "ioc_type": "cve",
        "severity": "critical",
        "risk_base": 93,
        "threat_types": ("Vulnerability",),
        "threat_actor": "APT41",
        "sector": "critical_infrastructure",
        "country_pool": ("United States", "Germany", "Japan"),
        "source_profile": "supply_chain",
        "malware": "ExploitKit",
        "headline": "Critical infrastructure vendor patch advisory tied to active exploitation",
        "description": "Exploit chain against industrial software package observed before patch adoption reached operators.",
    },
)


def _headers(api_key: str, content_type: str = "application/json") -> Dict[str, str]:
    headers = {"Content-Type": content_type}
    if api_key:
        headers["Authorization"] = f"ApiKey {api_key}"
    return headers


def _parse_json(response: requests.Response) -> Dict[str, Any]:
    if not response.content:
        return {}
    try:
        return response.json()
    except ValueError:
        return {"text": response.text}


def _post(path: str, payload: Dict[str, Any], api_key: str) -> Tuple[int, Dict[str, Any]]:
    response = requests.post(
        f"{ELASTICSEARCH_URL}/{path.lstrip('/')}",
        headers=_headers(api_key),
        json=payload,
        timeout=120,
    )
    return response.status_code, _parse_json(response)


def _bulk_index(index: str, docs: Sequence[Tuple[str, Dict[str, Any]]], api_key: str, chunk_size: int) -> Dict[str, Any]:
    ok = 0
    errors = 0
    for start in range(0, len(docs), chunk_size):
        chunk = docs[start : start + chunk_size]
        lines: List[str] = []
        for doc_id, payload in chunk:
            lines.append(json.dumps({"index": {"_index": index, "_id": doc_id}}, ensure_ascii=False))
            lines.append(json.dumps(payload, ensure_ascii=False))
        body = "\n".join(lines) + "\n"
        response = requests.post(
            f"{ELASTICSEARCH_URL}/_bulk",
            headers=_headers(api_key, content_type="application/x-ndjson"),
            data=body.encode("utf-8"),
            timeout=180,
        )
        parsed = _parse_json(response)
        if response.status_code >= 400:
            raise RuntimeError(f"bulk index failed for {index}: {response.status_code} {parsed}")
        items = parsed.get("items") or []
        for item in items:
            result = (item.get("index") or {})
            if result.get("status") in {200, 201}:
                ok += 1
            else:
                errors += 1
        if parsed.get("errors"):
            errors += sum(1 for item in items if (item.get("index") or {}).get("error"))
    _refresh(index, api_key)
    return {"count": len(docs), "ok": ok, "errors": errors}


def _refresh(index: str, api_key: str) -> None:
    requests.post(
        f"{ELASTICSEARCH_URL}/{index}/_refresh",
        headers=_headers(api_key),
        timeout=60,
    )


def _delete(index: str, doc_id: str, api_key: str) -> Tuple[int, Dict[str, Any]]:
    response = requests.delete(
        f"{ELASTICSEARCH_URL}/{index}/_doc/{doc_id}",
        headers=_headers(api_key),
        timeout=60,
    )
    return response.status_code, _parse_json(response)


def _delete_by_query(index: str, query: Dict[str, Any], api_key: str) -> Tuple[int, Dict[str, Any]]:
    response = requests.post(
        f"{ELASTICSEARCH_URL}/{index}/_delete_by_query?refresh=true&conflicts=proceed&wait_for_completion=true",
        headers=_headers(api_key),
        json={"query": query},
        timeout=300,
    )
    return response.status_code, _parse_json(response)


def _count_by_query(index: str, query: Dict[str, Any], api_key: str) -> int:
    response = requests.post(
        f"{ELASTICSEARCH_URL}/{index}/_count",
        headers=_headers(api_key),
        json={"query": query},
        timeout=120,
    )
    parsed = _parse_json(response)
    if response.status_code >= 400:
        raise RuntimeError(f"count failed for {index}: {response.status_code} {parsed}")
    return int(parsed.get("count", 0) or 0)


def _parse_seed_date(value: str) -> date:
    return datetime.strptime(value, "%Y-%m-%d").date()


def _today_bangkok() -> date:
    return datetime.now(BANGKOK_TZ).date()


def _default_window(profile: str) -> Tuple[date, date]:
    end = _today_bangkok()
    if profile == "large":
        start = end - timedelta(days=DEFAULT_LARGE_DATE_SPAN_DAYS - 1)
    else:
        start = end - timedelta(days=DEFAULT_SMALL_DATE_SPAN_DAYS - 1)
    return start, end


def _build_date_window(start: date, end: date) -> List[date]:
    if end < start:
        raise ValueError("end_date must not be earlier than start_date")
    dates: List[date] = []
    cursor = start
    while cursor <= end:
        dates.append(cursor)
        cursor += timedelta(days=1)
    return dates


def _to_utc_z(value: datetime) -> str:
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _source_kind(source_name: str) -> str:
    return str(SOURCE_CATALOG[source_name]["kind"])


def _source_score(source_name: str) -> int:
    return int(SOURCE_CATALOG[source_name]["score"])


def _severity_th(severity: str) -> str:
    return {
        "critical": "วิกฤต",
        "high": "สูง",
        "medium": "ปานกลาง",
        "low": "ต่ำ",
        "clean": "สะอาด",
    }.get(severity, "ต่ำ")


def _slugify(value: str) -> str:
    return "".join(char.lower() if char.isalnum() else "-" for char in value).strip("-")


def _hash_hex(prefix: str, length: int = 64) -> str:
    digest = hashlib.sha256(prefix.encode("utf-8")).hexdigest()
    while len(digest) < length:
        digest += hashlib.sha256(digest.encode("utf-8")).hexdigest()
    return digest[:length]


def _article_id(source_name: str, reference: str, published_at: str) -> str:
    day = datetime.fromisoformat(published_at.replace("Z", "+00:00")).astimezone(BANGKOK_TZ).strftime("%Y-%m-%d")
    payload = f"{source_name}|{reference}|{day}".encode("utf-8")
    return hashlib.sha1(payload).hexdigest()[:16]


def _batch_name(profile: str, start: date, end: date, warehouse_target: int) -> str:
    return f"{SEED_SERIES}-{profile}-{start.strftime('%Y%m%d')}-{end.strftime('%Y%m%d')}-{warehouse_target}"


def _synthetic_query(batch: str | None = None) -> Dict[str, Any]:
    filters: List[Dict[str, Any]] = [
        {
            "bool": {
                "minimum_should_match": 1,
                "should": [
                    {"term": {"synthetic_tag.keyword": SEED_TAG}},
                    {"term": {"tags": SEED_TAG}},
                ],
            }
        }
    ]
    if batch:
        filters.append(
            {
                "bool": {
                "minimum_should_match": 1,
                "should": [
                        {"term": {"synthetic_batch.keyword": batch}},
                        {"term": {"tags": batch}},
                    ],
                }
            }
        )
    return {"bool": {"filter": filters}}


def _weighted_choice(rng: random.Random, items: Sequence[Any], weights: Sequence[float]) -> Any:
    return rng.choices(list(items), weights=list(weights), k=1)[0]


def _weighted_date(rng: random.Random, dates: Sequence[date]) -> date:
    weights = [index + 1 for index, _ in enumerate(dates)]
    return _weighted_choice(rng, dates, weights)


def _choose_country(archetype: Dict[str, Any], rng: random.Random) -> str:
    return rng.choice(list(archetype["country_pool"]))


def _choose_sources(archetype: Dict[str, Any], rng: random.Random, doc_index: int) -> List[str]:
    bundle = SOURCE_BUNDLES[archetype["source_profile"]]
    selected: List[str] = []

    intel_count = rng.randint(2, 3)
    sensor_count = 1 if rng.random() < 0.4 else 0
    news_count = 1 if rng.random() < 0.65 else 0
    internal_count = 1 if rng.random() < 0.35 else 0

    selected.extend(rng.sample(list(bundle["intel"]), k=min(intel_count, len(bundle["intel"]))))
    if sensor_count:
        selected.extend(rng.sample(list(bundle["sensor"]), k=min(sensor_count, len(bundle["sensor"]))))
    if news_count:
        selected.extend(rng.sample(list(bundle["news"]), k=min(news_count, len(bundle["news"]))))
    if internal_count:
        selected.extend(rng.sample(list(bundle["internal"]), k=min(internal_count, len(bundle["internal"]))))

    coverage_source = ALL_SOURCES[doc_index % len(ALL_SOURCES)]
    if coverage_source not in selected:
        selected.append(coverage_source)

    if not any(SOURCE_CATALOG[source]["category"] == "news" for source in selected) and rng.random() < 0.45:
        selected.append(rng.choice(list(bundle["news"])))

    unique_sources = list(dict.fromkeys(source for source in selected if source))
    return unique_sources[:5]


def _build_domain_label(archetype: Dict[str, Any], serial: int) -> str:
    sector = _slugify(SECTOR_PROFILES[archetype["sector"]]["sector_name"])
    slug = archetype["slug"].replace("_", "-")
    return f"{sector}-{slug}-{serial:05d}.synthetic-uat.example"


def _build_ip_value(serial: int) -> str:
    block = 18 + ((serial // 65025) % 2)
    third = (serial // 255) % 255
    fourth = (serial % 255) + 1
    return f"198.{block}.{third}.{fourth}"


def _ioc_value(archetype: Dict[str, Any], serial: int) -> str:
    ioc_type = archetype["ioc_type"]
    if ioc_type == "domain":
        return _build_domain_label(archetype, serial)
    if ioc_type == "url":
        domain = _build_domain_label(archetype, serial)
        return f"https://{domain}/portal/{serial:05d}"
    if ioc_type == "ip":
        return _build_ip_value(serial)
    if ioc_type == "cve":
        return f"CVE-2026-{40000 + serial}"
    if ioc_type == "sha256":
        return _hash_hex(f"{archetype['slug']}-{serial}", 64)
    if ioc_type == "sha1":
        return _hash_hex(f"{archetype['slug']}-{serial}", 40)
    if ioc_type == "md5":
        return _hash_hex(f"{archetype['slug']}-{serial}", 32)
    return _hash_hex(f"{archetype['slug']}-{serial}", 64)


def _event_times(target_date: date, rng: random.Random, event_count: int) -> List[datetime]:
    peak_hour = rng.choice([1, 3, 5, 8, 10, 12, 14, 16, 18, 20, 22])
    times: List[datetime] = []
    for index in range(event_count):
        hour = (peak_hour + index * rng.choice([1, 2, 3])) % 24
        minute = (7 + (index * 13) + rng.randint(0, 18)) % 60
        second = rng.randint(0, 50)
        times.append(
            datetime(
                target_date.year,
                target_date.month,
                target_date.day,
                hour,
                minute,
                second,
                tzinfo=BANGKOK_TZ,
            )
        )
    return sorted(times)


def _source_objects(source_names: Iterable[str]) -> List[Dict[str, Any]]:
    output: List[Dict[str, Any]] = []
    for source_name in source_names:
        output.append({"name": source_name, "type": _source_kind(source_name), "score": _source_score(source_name)})
    return output


def _top_factors(archetype: Dict[str, Any], source_count: int) -> List[Dict[str, Any]]:
    return [
        {
            "factor": "cross_source",
            "score": min(35, 12 + (source_count * 5)),
            "weighted_score": min(35, 12 + (source_count * 5)),
            "label": f"{source_count} sources",
        },
        {
            "factor": "threat_type_severity",
            "score": 20,
            "weighted_score": 20,
            "label": archetype["threat_types"][0],
        },
        {
            "factor": "threat_actor",
            "score": 15,
            "weighted_score": 15,
            "label": archetype["threat_actor"],
        },
    ]


def _action_fields(severity: str, risk_score: int, source_count: int, processed_at: datetime, rng: random.Random) -> Dict[str, Any]:
    actionable = severity in {"critical", "high"} or risk_score >= 80 or source_count >= 4
    if not actionable:
        return {
            "action_required": False,
            "action_status": None,
            "action_title": None,
            "action_reason": None,
            "action_opened_at": None,
            "action_updated_at": None,
            "action_closed_at": None,
            "action_closed_reason": None,
            "reviewed_by": None,
            "reviewed_at": None,
            "review_notes": None,
        }

    roll = rng.random()
    if roll < 0.56:
        status = "open"
    elif roll < 0.82:
        status = "in_progress"
    else:
        status = "closed"

    title = "Review Critical Threat" if severity == "critical" else "Investigate High-Risk IOC"
    reason = "critical_threat" if severity == "critical" else "high_risk_ioc"
    opened_at = processed_at + timedelta(minutes=5)
    updated_at = opened_at + timedelta(minutes=rng.randint(20, 180))
    analysts = ("Nattakarn Sudjai", "Mint Ibusiness", "Tier 2 SOC", "Blue Team Analyst")

    fields: Dict[str, Any] = {
        "action_required": status != "closed",
        "action_status": status,
        "action_title": title,
        "action_reason": reason,
        "action_opened_at": _to_utc_z(opened_at),
        "action_updated_at": _to_utc_z(updated_at),
        "action_closed_at": None,
        "action_closed_reason": None,
        "reviewed_by": None,
        "reviewed_at": None,
        "review_notes": None,
    }
    if status in {"in_progress", "closed"}:
        reviewed_at = updated_at - timedelta(minutes=rng.randint(5, 30))
        fields["reviewed_by"] = analysts[rng.randrange(len(analysts))]
        fields["reviewed_at"] = _to_utc_z(reviewed_at)
        fields["review_notes"] = "Containment and validation in progress."
    if status == "closed":
        closed_at = updated_at + timedelta(minutes=rng.randint(30, 240))
        fields["action_closed_at"] = _to_utc_z(closed_at)
        fields["action_closed_reason"] = rng.choice(["mitigated", "blocked", "false_positive"])
        fields["review_notes"] = "Case closed after evidence review and mitigation."
    return fields


def _severity_mix(archetype: Dict[str, Any], rng: random.Random) -> str:
    roll = rng.random()
    base = archetype["severity"]
    if base == "critical":
        return "high" if roll < 0.08 else "critical"
    if base == "high":
        if roll < 0.08:
            return "critical"
        if roll < 0.22:
            return "medium"
        return "high"
    if base == "medium":
        if roll < 0.1:
            return "high"
        if roll < 0.18:
            return "low"
        return "medium"
    if base == "low":
        return "medium" if roll < 0.14 else "low"
    return base


def _risk_score(archetype: Dict[str, Any], severity: str, source_count: int, rng: random.Random) -> int:
    base = int(archetype["risk_base"])
    severity_delta = {"critical": 6, "high": 0, "medium": -12, "low": -24, "clean": -36}[severity]
    score = base + severity_delta + (source_count - 2) * 2 + rng.randint(-6, 6)
    return max(8, min(99, score))


def _reference(base_slug: str, serial: int, source_name: str) -> str:
    return f"https://synthetic-uat.example/{base_slug}/{serial:05d}/{_slugify(source_name)}"


def _headline(archetype: Dict[str, Any], serial: int, country: str) -> str:
    return f"{archetype['headline']} #{serial} ({country})"


def _description(archetype: Dict[str, Any], sector_name: str, country: str) -> str:
    return f"{archetype['description']} Target sector: {sector_name}. Origin telemetry: {country}."


def _ioc_age_days(target_date: date, first_seen: datetime) -> int:
    return max(0, (target_date - first_seen.astimezone(BANGKOK_TZ).date()).days)


def _warehouse_doc(
    batch: str,
    archetype: Dict[str, Any],
    doc_index: int,
    serial: int,
    target_date: date,
    rng: random.Random,
) -> Tuple[str, Dict[str, Any], List[str], List[datetime], str, str]:
    ioc_value = _ioc_value(archetype, serial)
    sources = _choose_sources(archetype, rng, doc_index)
    event_times = _event_times(target_date, rng, len(sources))
    severity = _severity_mix(archetype, rng)
    risk_score = _risk_score(archetype, severity, len(sources), rng)
    country_name = _choose_country(archetype, rng)
    country = COUNTRY_PROFILES[country_name]
    sector = SECTOR_PROFILES[archetype["sector"]]
    description = _description(archetype, sector["sector_name"], country_name)
    first_seen = event_times[0]
    last_seen = event_times[-1]
    processed_at = last_seen + timedelta(minutes=rng.randint(8, 30))
    action_fields = _action_fields(severity, risk_score, len(sources), processed_at, rng)
    threat_types = list(archetype["threat_types"])
    if severity == "critical" and "Other" not in threat_types and rng.random() < 0.18:
        threat_types.append("Other")
    warehouse_id = f"seed-wh-{batch}-{serial:06d}"
    payload = {
        "synthetic_tag": SEED_TAG,
        "synthetic_series": SEED_SERIES,
        "synthetic_batch": batch,
        "synthetic_profile": "large" if "large" in batch else "small",
        "synthetic_serial": serial,
        "ioc_value": ioc_value,
        "ioc_type": archetype["ioc_type"],
        "description": description,
        "source_name": ", ".join(sources),
        "source_type": "multi" if len(sources) > 1 else _source_kind(sources[0]),
        "sources": list(sources),
        "source_count": len(sources),
        "source_types": sorted({_source_kind(source) for source in sources}),
        "reference": _reference(archetype["slug"], serial, sources[0]),
        "threat_type": threat_types,
        "tags": [SEED_TAG, batch, archetype["slug"], f"serial-{serial:06d}"],
        "collect_time": _to_utc_z(last_seen + timedelta(minutes=5)),
        "event_time": _to_utc_z(first_seen),
        "first_seen": _to_utc_z(first_seen),
        "last_seen": _to_utc_z(last_seen),
        "ioc_age_days": _ioc_age_days(target_date, first_seen),
        "geo_country": country_name,
        "ai_risk_score": risk_score,
        "ai_severity": severity,
        "ai_severity_th": _severity_th(severity),
        "ai_threat_types": threat_types,
        "ai_threat_actors": [archetype["threat_actor"]],
        "ai_mitre_techniques": _mitre_by_profile(archetype["source_profile"]),
        "ai_classification_confidence": round(max(0.72, min(0.99, 0.82 + (len(sources) * 0.03) + rng.random() * 0.08)), 2),
        "ai_score_breakdown": {"target_sector": sector},
        "ai_top_factors": _top_factors(archetype, len(sources)),
        "score_model_version": "synthetic-uat-v4",
        "score_config_version": "synthetic-uat-v4",
        "credibility_score": max(60, min(99, 74 + len(sources) * 4 + rng.randint(-3, 6))),
        "impact_score": max(55, min(99, 68 + {"critical": 20, "high": 12, "medium": 4, "low": -4, "clean": -10}[severity] + rng.randint(-4, 4))),
        "validation_status": "validated_auto",
        "validation_reasons": [],
        "warehouse_eligible": True,
        "review_required": False,
        "review_state": "not_required",
        "cleaning_flags": [],
        "processed_at": _to_utc_z(processed_at),
        "created_at": _to_utc_z(datetime.now(UTC)),
        **action_fields,
    }
    return warehouse_id, payload, sources, event_times, country_name, ioc_value


def _mitre_by_profile(profile: str) -> List[str]:
    mapping = {
        "phishing": ["T1566", "T1056"],
        "malware": ["T1105", "T1071"],
        "vulnerability": ["T1190", "T1068"],
        "defacement": ["T1491"],
        "ddos": ["T1498"],
        "breach": ["T1537", "T1567"],
        "c2": ["T1071", "T1105"],
        "supply_chain": ["T1195", "T1553"],
    }
    return mapping.get(profile, ["T1071"])


def _build_news_title(archetype: Dict[str, Any], serial: int, source_name: str, country_name: str) -> str:
    return f"{source_name}: {_headline(archetype, serial, country_name)}"


def _datalake_docs(
    batch: str,
    archetype: Dict[str, Any],
    serial: int,
    sources: Sequence[str],
    event_times: Sequence[datetime],
    country_name: str,
    ioc_value: str,
    rng: random.Random,
) -> List[Tuple[str, Dict[str, Any]]]:
    country = COUNTRY_PROFILES[country_name]
    source_ip = _build_ip_value(serial * 2)
    target_ip = _build_ip_value(serial * 2 + 1)
    docs: List[Tuple[str, Dict[str, Any]]] = []
    for event_index, source_name in enumerate(sources, start=1):
        event_time = event_times[min(event_index - 1, len(event_times) - 1)]
        source_type = _source_kind(source_name)
        reference = _reference(archetype["slug"], serial, source_name)
        description = archetype["description"]
        payload: Dict[str, Any] = {
            "synthetic_tag": SEED_TAG,
            "synthetic_series": SEED_SERIES,
            "synthetic_batch": batch,
            "synthetic_profile": "large" if "large" in batch else "small",
            "synthetic_serial": serial,
            "ioc_value": ioc_value,
            "ioc_type": archetype["ioc_type"],
            "source_name": source_name,
            "source_type": source_type,
            "source_url": reference,
            "collect_time": _to_utc_z(event_time + timedelta(minutes=5)),
            "event_time": _to_utc_z(event_time),
            "threat_type": list(archetype["threat_types"]),
            "severity": archetype["severity"],
            "confidence": min(10, max(6, round((_source_score(source_name) / 10) + rng.random(), 1))),
            "description": description,
            "reference": reference,
            "tags": [SEED_TAG, batch, archetype["slug"], f"serial-{serial:06d}"],
            "geo_country": country_name,
            "geo_info": {
                "city": country["city"],
                "country": country_name,
                "latitude": country["latitude"],
                "longitude": country["longitude"],
            },
            "source_ip": source_ip,
            "target_ip": target_ip,
            "enrichment": {
                "ip_info": {"country": country_name},
                "related_entities": {"malware_family": [archetype["malware"]]},
            },
            "whois": {"org": country["org"], "registrant_email": f"abuse@{_slugify(archetype['slug'])}.synthetic-uat.example"},
            "asn_data": {"asn": country["asn"], "org": country["org"], "country_code": country_name},
            "cluster_label": (serial % 750) + 1000,
            "ai_processed": True,
            "created_at": _to_utc_z(datetime.now(UTC)),
        }
        if source_type == "news":
            payload["title"] = _build_news_title(archetype, serial, source_name, country_name)
            payload["description"] = f"{source_name} coverage: {description}"
        doc_id = f"seed-dl-{batch}-{serial:06d}-{event_index:02d}"
        docs.append((doc_id, payload))
    return docs


def _iter_seed_documents(
    profile: str,
    start: date,
    end: date,
    warehouse_target: int,
    random_seed: int,
) -> Tuple[str, List[Tuple[str, Dict[str, Any]]], List[Tuple[str, Dict[str, Any]]]]:
    batch = _batch_name(profile, start, end, warehouse_target)
    rng = random.Random(random_seed)
    dates = _build_date_window(start, end)
    warehouse_docs: List[Tuple[str, Dict[str, Any]]] = []
    datalake_docs: List[Tuple[str, Dict[str, Any]]] = []

    for doc_index in range(warehouse_target):
        serial = doc_index + 1
        archetype = ARCHETYPES[doc_index % len(ARCHETYPES)]
        target_date = _weighted_date(rng, dates)
        warehouse_id, warehouse_payload, sources, event_times, country_name, ioc_value = _warehouse_doc(
            batch=batch,
            archetype=archetype,
            doc_index=doc_index,
            serial=serial,
            target_date=target_date,
            rng=rng,
        )
        warehouse_docs.append((warehouse_id, warehouse_payload))
        datalake_docs.extend(
            _datalake_docs(
                batch=batch,
                archetype=archetype,
                serial=serial,
                sources=sources,
                event_times=event_times,
                country_name=country_name,
                ioc_value=ioc_value,
                rng=rng,
            )
        )
    return batch, warehouse_docs, datalake_docs


def _seed_summary(batch: str, warehouse_docs: Sequence[Tuple[str, Dict[str, Any]]], datalake_docs: Sequence[Tuple[str, Dict[str, Any]]]) -> Dict[str, Any]:
    warehouse_payloads = [doc for _, doc in warehouse_docs]
    datalake_payloads = [doc for _, doc in datalake_docs]
    action_counts = Counter(
        str(doc.get("action_status"))
        for doc in warehouse_payloads
        if doc.get("action_status")
    )
    source_counts = Counter(
        source.strip()
        for doc in warehouse_payloads
        for source in str(doc.get("source_name", "")).split(",")
        if source.strip()
    )
    source_coverage = sorted(source_counts)
    missing_sources = sorted(set(ALL_SOURCES) - set(source_coverage))
    sample_action = next((doc_id for doc_id, doc in warehouse_docs if doc.get("action_status") == "open"), None)
    sample_ioc = next(
        (
            f"{doc.get('ioc_type')}::{doc.get('ioc_value')}"
            for _, doc in warehouse_docs
            if doc.get("ioc_type") and doc.get("ioc_value")
        ),
        None,
    )
    sample_article = next(
        (
            _article_id(doc["source_name"], doc["reference"], doc["event_time"])
            for doc in datalake_payloads
            if doc.get("source_type") == "news" and doc.get("reference") and doc.get("event_time")
        ),
        None,
    )
    return {
        "seed_tag": SEED_TAG,
        "seed_series": SEED_SERIES,
        "seed_batch": batch,
        "warehouse_docs": len(warehouse_docs),
        "datalake_events": len(datalake_docs),
        "news_articles": sum(1 for doc in datalake_payloads if doc.get("source_type") == "news"),
        "severity_counts": Counter(str(doc.get("ai_severity")) for doc in warehouse_payloads),
        "action_counts": dict(action_counts),
        "sectors": Counter(doc["ai_score_breakdown"]["target_sector"]["sector_name"] for doc in warehouse_payloads),
        "ioc_types": Counter(str(doc.get("ioc_type")) for doc in warehouse_payloads),
        "source_coverage_count": len(source_coverage),
        "source_coverage_complete": not missing_sources,
        "missing_sources": missing_sources,
        "top_sources": source_counts.most_common(10),
        "sample_ids": {
            "action_id": sample_action,
            "ioc_id": sample_ioc,
            "article_id": sample_article,
        },
    }


def cleanup_all_synthetic() -> Dict[str, Any]:
    query = _synthetic_query()
    warehouse_status, warehouse_body = _delete_by_query(WAREHOUSE_INDEX, query, WAREHOUSE_API_KEY)
    datalake_status, datalake_body = _delete_by_query(DATALAKE_INDEX, query, DATALAKE_API_KEY)

    legacy = []
    for index, doc_id, api_key in LEGACY_FIXTURE_DOCS:
        status_code, body = _delete(index, doc_id, api_key)
        legacy.append({"index": index, "doc_id": doc_id, "status_code": status_code, "result": body.get("result")})

    if warehouse_status >= 400:
        raise RuntimeError(f"warehouse cleanup failed: {warehouse_status} {warehouse_body}")
    if datalake_status >= 400:
        raise RuntimeError(f"datalake cleanup failed: {datalake_status} {datalake_body}")

    return {
        "warehouse_deleted": warehouse_body.get("deleted", 0),
        "datalake_deleted": datalake_body.get("deleted", 0),
        "legacy_cleanup": legacy,
    }


def seed(profile: str, start: date, end: date, warehouse_target: int, random_seed: int, chunk_size: int, purge_all_synthetic: bool) -> None:
    cleanup_result = None
    if purge_all_synthetic:
        cleanup_result = cleanup_all_synthetic()

    batch, warehouse_docs, datalake_docs = _iter_seed_documents(
        profile=profile,
        start=start,
        end=end,
        warehouse_target=warehouse_target,
        random_seed=random_seed,
    )

    warehouse_result = _bulk_index(WAREHOUSE_INDEX, warehouse_docs, WAREHOUSE_API_KEY, chunk_size)
    datalake_result = _bulk_index(DATALAKE_INDEX, datalake_docs, DATALAKE_API_KEY, chunk_size)

    print(
        json.dumps(
            {
                "action": "seed",
                "summary": _seed_summary(batch, warehouse_docs, datalake_docs),
                "cleanup": cleanup_result,
                "warehouse": warehouse_result,
                "datalake": datalake_result,
            },
            ensure_ascii=False,
            indent=2,
            default=lambda value: dict(value),
        )
    )


def cleanup() -> None:
    print(
        json.dumps(
            {
                "action": "cleanup",
                **cleanup_all_synthetic(),
            },
            ensure_ascii=False,
            indent=2,
        )
    )


def status(profile: str, start: date, end: date, warehouse_target: int) -> None:
    batch = _batch_name(profile, start, end, warehouse_target)
    all_query = _synthetic_query()
    batch_query = _synthetic_query(batch)
    print(
        json.dumps(
            {
                "action": "status",
                "checked_at": _to_utc_z(datetime.now(UTC)),
                "all_synthetic": {
                    "warehouse": _count_by_query(WAREHOUSE_INDEX, all_query, WAREHOUSE_API_KEY),
                    "datalake": _count_by_query(DATALAKE_INDEX, all_query, DATALAKE_API_KEY),
                },
                "current_batch": {
                    "seed_batch": batch,
                    "warehouse": _count_by_query(WAREHOUSE_INDEX, batch_query, WAREHOUSE_API_KEY),
                    "datalake": _count_by_query(DATALAKE_INDEX, batch_query, DATALAKE_API_KEY),
                },
            },
            ensure_ascii=False,
            indent=2,
        )
    )


def main() -> int:
    parser = argparse.ArgumentParser(description="Seed or clean synthetic dashboard UAT fixtures.")
    parser.add_argument("command", choices=["seed", "cleanup", "status"])
    parser.add_argument("--profile", choices=["small", "large"], default="small")
    parser.add_argument("--start-date", dest="start_date")
    parser.add_argument("--end-date", dest="end_date")
    parser.add_argument("--warehouse-target", type=int)
    parser.add_argument("--random-seed", type=int, default=DEFAULT_RANDOM_SEED)
    parser.add_argument("--chunk-size", type=int, default=DEFAULT_CHUNK_SIZE)
    parser.add_argument("--purge-all-synthetic", action="store_true")
    args = parser.parse_args()

    default_start, default_end = _default_window(args.profile)
    start = _parse_seed_date(args.start_date) if args.start_date else default_start
    end = _parse_seed_date(args.end_date) if args.end_date else default_end
    warehouse_target = args.warehouse_target or (
        DEFAULT_LARGE_WAREHOUSE_TARGET if args.profile == "large" else DEFAULT_SMALL_WAREHOUSE_TARGET
    )

    if args.command == "seed":
        seed(
            profile=args.profile,
            start=start,
            end=end,
            warehouse_target=warehouse_target,
            random_seed=args.random_seed,
            chunk_size=max(50, args.chunk_size),
            purge_all_synthetic=args.purge_all_synthetic,
        )
    elif args.command == "cleanup":
        cleanup()
    else:
        status(profile=args.profile, start=start, end=end, warehouse_target=warehouse_target)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
