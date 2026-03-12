import type { GraphData } from '@/lib/types/graph-types';

export type AnalyticsSeverity = 'critical' | 'high' | 'medium' | 'low' | 'clean';

export interface BreakdownSector {
    sector: string;
    sector_name?: string;
    sector_name_th?: string;
    icon?: string;
    confidence?: number;
    matched_keywords?: string[];
    matched_actors?: string[];
    matched_domains?: string[];
    risk_bonus?: number;
    risk_bonus_original?: number;
    multiplier_used?: number;
    score?: number;
    maxScore?: number;
    reason?: string;
    reasonEn?: string;
}

export interface WarehouseScoreBreakdown {
    target_sector?: BreakdownSector;
    [key: string]: unknown;
}

export interface WarehouseIOCDocument {
    ioc_value: string;
    ioc_type: string;
    source_name: string;
    source_type: string;
    sources: Array<string | { name: string; confidence?: number; type?: string }>;
    source_types?: string[];
    source_count?: number;
    description: string;
    threat_type?: string[];
    severity?: string;
    tags?: string[];
    reference?: string;
    collect_time?: string;
    event_time?: string;
    first_seen?: string;
    last_seen?: string;
    ioc_age_days?: number;
    geo_country?: string | null;
    ai_risk_score?: number;
    ai_severity?: AnalyticsSeverity;
    ai_severity_th?: string;
    ai_threat_types?: string[];
    ai_threat_actors?: string[];
    ai_mitre_techniques?: string[];
    ai_classification_confidence?: number;
    ai_score_breakdown?: WarehouseScoreBreakdown;
    ai_top_factors?: Array<{ factor: string; score: number; weighted_score?: number; label: string }>;
    score_model_version?: string;
    score_config_version?: string;
    credibility_score?: number;
    impact_score?: number;
    processed_at?: string;
    created_at?: string;
}

export interface DataLakeRelatedEntities {
    threat_actor?: string[];
    malware_family?: string[];
    campaign?: string[];
    vulnerability?: string[];
    vendor?: string[];
}

export interface DataLakeDocument {
    ioc_value: string;
    ioc_type: string;
    source_name?: string;
    source_type?: string;
    source_url?: string;
    collect_time?: string;
    event_time?: string;
    description?: string;
    reference?: string;
    threat_type?: string[];
    severity?: string;
    tags?: string[];
    geo_country?: string | null;
    geo_info?: {
        country?: string;
        city?: string;
        region?: string;
    };
    ai_processed?: boolean;
    enrichment?: {
        ip_info?: {
            country?: string;
            asn_data?: {
                asn?: string;
                org?: string;
                country_code?: string;
            };
        };
        related_entities?: DataLakeRelatedEntities;
    };
    ip_info?: {
        country?: string;
        asn_data?: {
            asn?: string;
            org?: string;
            country_code?: string;
        };
    };
    asn_data?: {
        asn?: string;
        org?: string;
        country_code?: string;
    };
    whois?: {
        registrant_email?: string;
        name_server?: string | string[];
        name_servers?: string[];
        org?: string;
    };
    cluster_label?: string | number;
    created_at?: string;
}

export interface ThreatLevelFactor {
    score: number;
    input: number;
    label: string;
    description: string;
}

export interface ThreatLevelResponse {
    date: string;
    timezone: string;
    score: number;
    level: 'low' | 'guarded' | 'elevated' | 'critical';
    level_th: 'ต่ำ' | 'เฝ้าระวัง' | 'ยกระดับ' | 'วิกฤต';
    factors: {
        volume: ThreatLevelFactor;
        severity: ThreatLevelFactor;
        sector: ThreatLevelFactor;
        actor: ThreatLevelFactor;
    };
    inputs: {
        total_iocs: number;
        baseline_avg_14d: number;
        spike_ratio: number;
        critical_high_ratio: number;
        high_critical_sector_count: number;
        cii_sector_present: boolean;
        named_actor_count: number;
    };
    top_sectors: Array<{ sector: string; sector_name: string; sector_name_th: string; count: number }>;
    named_actors: Array<{ name: string; count: number }>;
}

export interface HourlySeverityPoint {
    hour: string;
    label: string;
    total: number;
    critical: number;
    high: number;
}

export interface ComparisonSeries {
    key: string;
    label: string;
    points: number[];
    total: number;
    direction: 'up' | 'down' | 'flat';
    change_percent: number;
}

export interface TrendComparisonChart {
    title: string;
    dimension: 'sources' | 'threat_types' | 'sectors' | 'countries';
    buckets: string[];
    series: ComparisonSeries[];
}

export interface AttackVolumeForecast {
    model: 'holt_winters' | 'seasonal_average_fallback';
    historical: HourlySeverityPoint[];
    forecast: HourlySeverityPoint[];
}

export interface TrendInsight {
    key: string;
    label: string;
    change_percent: number;
    total: number;
}

export interface TrendAnalyticsResponse {
    meta: {
        generated_at: string;
        timezone: string;
        window_hours: number;
        forecast_hours: number;
        training_window_hours: number;
    };
    summary: {
        total_events: number;
        critical_events: number;
        high_events: number;
        forecast_total: number;
        forecast_critical: number;
        forecast_high: number;
        top_rising_threat_types: TrendInsight[];
    };
    comparison_charts: {
        sources: TrendComparisonChart;
        threat_types: TrendComparisonChart;
        sectors: TrendComparisonChart;
        countries: TrendComparisonChart;
    };
    threat_volume_trend: HourlySeverityPoint[];
    attack_volume_trend: AttackVolumeForecast;
}

export interface AttackGraphResponse {
    generated_at: string;
    timezone: string;
    stats: {
        iocs: number;
        actors: number;
        threat_types: number;
        sectors: number;
        countries: number;
        infrastructures: number;
        campaigns: number;
        links: number;
    };
    capabilities: {
        campaigns: boolean;
        infrastructure: boolean;
        malware: boolean;
        whois: boolean;
        asn: boolean;
        countries: boolean;
    };
    data: GraphData;
}
