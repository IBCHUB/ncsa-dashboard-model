/**
 * Thailand Cyber Threat Intelligence - TypeScript Type Definitions
 * Based on JSON data lake analysis
 */

// IOC Types from data lake
export type IOCType = 'domain' | 'ip' | 'sha256' | 'sha1' | 'md5' | 'cve' | 'url';

// Severity levels (from TOR requirements)
export type SeverityLevel = 'critical' | 'high' | 'medium' | 'low' | 'clean' | 'info';

// Source types from data lake
export type SourceType = 'news' | 'feed' | 'sandbox' | 'suricata';

// Threat types from Zone-H data
export type ThreatType =
    | 'cnc_server'
    | 'payload_delivery'
    | 'phishing_website'
    | 'compromised_website'
    | 'malware'
    | 'ransomware'
    | 'credential_theft'
    | '';

// Status from data lake
export type IOCStatus = 'new' | 'open' | 'acknowledged' | 'resolved';

/**
 * Core IOC Interface
 */
export interface IOC {
    type: IOCType;
    value: string;
    related_hash?: string[];
    related_domain?: string[];
}

/**
 * WHOIS Enrichment Data
 */
export interface WhoisData {
    creation_date?: string;
    domain_name?: string;
    emails?: string;
    expiration_date?: string;
    name?: string;
    name_servers?: string[];
    org?: string;
    registrar?: string;
    state?: string;
    status?: string | string[];
    updated_date?: string;
    whois_server?: string;
}

/**
 * IP Information Enrichment
 */
export interface IPInfo {
    asn_data?: {
        asn?: string;
        city?: string;
        country_code?: string;
        org?: string;
        region?: string;
        timezone?: string;
    };
    status?: 'active' | 'inactive';
}

/**
 * File Information (for hash IOCs)
 */
export interface FileInfo {
    md5?: string;
    sha1?: string;
    sha256?: string;
    filename?: string;
    size?: number;
}

/**
 * Related Threat Entities
 */
export interface RelatedEntities {
    threat_actor?: string[];
    malware_family?: string[];
    campaign?: string[];
}

/**
 * Enrichment Data Container
 */
export interface Enrichment {
    events?: {
        registration?: string;
        expiration?: string;
        last_changed?: string;
    };
    status?: string | string[];
    whois?: WhoisData;
    ip_info?: IPInfo;
    categories?: { [key: string]: string };
    related_entities?: RelatedEntities;
    file?: FileInfo;
    tags?: string[];
    type_tags?: string[];
    first_seen?: string;
    last_seen?: string;
    souce?: string; // Note: typo in original data
    source?: string;
}

/**
 * Main Threat Event Interface
 * Matches the structure of JSON data lake entries
 */
export interface ThreatEvent {
    // Source information
    source_type: SourceType;
    source_name: string;
    source_url?: string;

    // Timing
    collect_time: string;
    event_time: string;
    insert_datetime?: string;
    last_seen?: string;

    // Classification
    threat_type: ThreatType[];
    severity: SeverityLevel | '';
    confidence: number;

    // Indicator
    ioc: IOC;

    // Context
    geo_info?: {
        country?: string;
        city?: string;
        region?: string;
    };
    description: string;
    reference?: string;
    tags: string[];
    status: IOCStatus;

    // Internal tracking
    source_index?: string;
    source_id?: string;
    misp_event_id?: string | null;

    // Enrichment data
    enrichment?: Enrichment;

    // ========================================
    // AI Risk Score (Pre-computed)
    // ========================================
    aiRiskScore?: number;          // 0-100 total score
    aiSeverity?: SeverityLevel;    // Calculated from AI score
    aiSeverityTH?: string;         // Thai severity label

    // AI Classification Results
    aiThreatTypes?: string[];      // Classified threat categories
    aiThreatActors?: string[];     // Identified threat actors
    aiMitreTechniques?: string[];  // MITRE ATT&CK techniques
    aiClassificationConfidence?: number; // 0-1 confidence

    // Detailed Score Breakdown
    aiScoreBreakdown?: {
        // Traditional Factors
        cross_source?: {
            score: number;
            count: number;
            description: string;
        };
        source_quality?: {
            score: number;
            trusted: number;
            news: number;
            other: number;
            description: string;
        };
        keywords?: {
            score: number;
            keywords: string[];
            description: string;
        };
        entropy?: {
            value: number;
            score: number;
            description: string;
        };
        geo_risk?: {
            score: number;
            country: string | null;
            is_high_risk: boolean;
            description: string;
        };
        domain_age?: {
            score: number;
            days: number | null;
            description: string;
        };

        // AI Classification Factors
        threat_type_severity?: {
            score: number;
            types: string[];
            max_severity_level: number | null;
            details: Array<{
                type: string;
                score: number;
                level: number;
                description: string;
            }>;
            description: string;
        };
        threat_actor?: {
            score: number;
            actors: string[];
            matched: Array<{
                name: string;
                score: number;
                origin: string;
                aliases: string[];
                targets: string[];
            }>;
            attribution_level: string;
            description: string;
        };
        mitre_techniques?: {
            score: number;
            techniques: string[];
            matched_tactics: Array<{
                name: string;
                id: string;
                score: number;
            }>;
            sophistication: string;
            description: string;
        };
        ai_confidence?: {
            score: number;
            confidence: number;
            level: string;
            description: string;
        };
    };

    // Top contributing factors
    aiTopFactors?: Array<{
        factor: string;
        score: number;
        label: string;
    }>;

    // Score summary
    aiScoreSummary?: {
        traditional_score: number;
        ai_score: number;
        has_threat_actor: boolean;
        has_mitre: boolean;
        primary_threat: string | null;
    };
}

/**
 * Elasticsearch-style response wrapper
 */
export interface DataLakeResponse {
    hits: {
        _index: string;
        _id: string;
        _score: number;
        _source: ThreatEvent;
    }[];
}

/**
 * Threat Score (Rule-based from MoM)
 * 1 source = 50 points
 * 2+ sources = 100 points
 */
export interface ThreatScore {
    value: number;
    level: SeverityLevel;
    sources: string[];
    explanation: string;
}

/**
 * Dashboard Statistics
 */
export interface DashboardStats {
    totalIOCs: number;
    byType: Record<IOCType, number>;
    bySeverity: Record<SeverityLevel, number>;
    bySource: Record<string, number>;
    byThreatType: Record<string, number>;
    recentAlerts: ThreatEvent[];
    lastUpdated: string;
}

/**
 * Top 10 Item
 */
export interface TopItem {
    value: string;
    count: number;
    severity?: SeverityLevel;
    type?: IOCType;
}

/**
 * Filter Options
 */
export interface FilterOptions {
    type?: IOCType | IOCType[];
    severity?: SeverityLevel | SeverityLevel[];
    source?: string | string[];
    dateFrom?: string;
    dateTo?: string;
    searchQuery?: string;
    limit?: number;
    offset?: number;
}

/**
 * API Response Wrapper
 */
export interface APIResponse<T> {
    success: boolean;
    data: T;
    meta?: {
        total: number;
        limit: number;
        offset: number;
        timestamp: string;
    };
    error?: string;
}

/**
 * Navigation Item
 */
export interface NavItem {
    id: string;
    label: string;
    labelTh?: string;
    href: string;
    icon: string;
    children?: NavItem[];
    badge?: number;
}

/**
 * User (Mock Authentication)
 */
export interface User {
    id: string;
    name: string;
    email: string;
    role: 'public' | 'internal' | 'admin';
    avatar?: string;
}

/**
 * Authentication Context
 */
export interface AuthContext {
    user: User | null;
    isAuthenticated: boolean;
    isInternal: boolean;
    login: (email: string, password: string) => Promise<void>;
    logout: () => void;
}
