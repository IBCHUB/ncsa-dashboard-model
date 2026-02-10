/**
 * Data Normalization Script
 * 
 * Reads raw threat data from data_lake/, computes AI Risk Scores,
 * and outputs normalized data to public/data/normalized_iocs.json
 * 
 * Run with: npx ts-node src/scripts/normalize-data.ts
 */

import * as fs from 'fs';
import * as path from 'path';

// ============================================
// Types (inline to avoid import issues)
// ============================================

type SeverityLevel = 'critical' | 'high' | 'medium' | 'low' | 'clean' | 'info';

interface ThreatEvent {
    source_type: string;
    source_name: string;
    source_url?: string;
    collect_time: string;
    event_time: string;
    threat_type: string[];
    severity: SeverityLevel | '';
    confidence: number;
    ioc: {
        type: string;
        value: string;
        related_hash?: string[];
        related_domain?: string[];
    };
    geo_info?: {
        country?: string;
        city?: string;
        region?: string;
    };
    description: string;
    reference?: string;
    tags: string[];
    status: string;
    enrichment?: any;
    // Normalized fields
    aiRiskScore?: number;
    aiSeverity?: SeverityLevel;
    aiSeverityTH?: string;
    // Full breakdown from new scorer
    aiScoreBreakdown?: Record<string, any>;
    // Top factors
    aiTopFactors?: Array<{ factor: string; score: number; label: string }>;
    // Score summary
    aiScoreSummary?: {
        traditional_score: number;
        ai_score: number;
        has_threat_actor: boolean;
        has_mitre: boolean;
        primary_threat: string | null;
    };
    // AI Service fields (from Python)
    aiThreatTypes?: string[];
    aiThreatActors?: string[];
    aiMitreTechniques?: string[];
    aiClassificationConfidence?: number;
}

interface NormalizedIOC {
    iocValue: string;
    iocType: string;
    events: ThreatEvent[];
    aiRiskScore: number;
    aiSeverity: SeverityLevel;
    aiSeverityTH: string;
    aiScoreBreakdown: Record<string, any>;
    aiTopFactors: Array<{ factor: string; score: number; label: string }>;
    aiScoreSummary: {
        traditional_score: number;
        ai_score: number;
        has_threat_actor: boolean;
        has_mitre: boolean;
        primary_threat: string | null;
    };
    // AI Service fields
    aiThreatTypes: string[];
    aiThreatActors: string[];
    aiMitreTechniques: string[];
    aiClassificationConfidence: number;
    sources: string[];
    firstSeen: string;
    lastSeen: string;
}

// AI Service Response Interface (Enhanced)
interface AIServiceResponse {
    ioc_value: string;
    ioc_type: string;
    ai_threat_types: string[];
    ai_threat_actors: string[];
    ai_mitre_techniques: string[];
    ai_classification_confidence: number;
    ai_risk_score: number;
    ai_severity: string;
    ai_score_breakdown: Record<string, any>;
    ai_top_factors: Array<{ factor: string; score: number; label: string }>;
    processing_time_ms: number;
    // New fields from enhanced scorer
    severity_th?: string;
    summary?: {
        traditional_score: number;
        ai_score: number;
        has_threat_actor: boolean;
        has_mitre: boolean;
        primary_threat: string | null;
    };
}

// ============================================
// Constants
// ============================================

const DATA_LAKE_DIR = path.join(__dirname, '../../../data_lake');
const OUTPUT_FILE = path.join(__dirname, '../../public/data/normalized_iocs.json');
const URL_CLASSIFICATIONS_FILE = path.join(__dirname, '../../../data_lake/url_classifications.json');

const HIGH_RISK_KEYWORDS = [
    'ransomware', 'zero-day', '0day', 'critical', 'exploit', 'active',
    'lazarus', 'apt', 'backdoor', 'c2', 'cnc', 'botnet', 'credential',
    'phishing', 'malware', 'trojan', 'wiper', 'encryption'
];

const HIGH_RISK_COUNTRIES = ['RU', 'CN', 'KP', 'IR', 'BY', 'SY', 'VE'];

// AI Service Configuration
const AI_SERVICE_URL = process.env.AI_SERVICE_URL || 'http://localhost:8000';
const AI_SERVICE_API_KEY = process.env.AI_SERVICE_API_KEY || 'tcti-dashboard-key';
const ENABLE_AI_SERVICE = process.env.ENABLE_AI_SERVICE !== 'false';
const AI_BATCH_SIZE = 10; // Process IOCs in batches

// URL Classifications Cache (loaded from enrichment script output)
interface URLClassification {
    url: string;
    title?: string;
    threat_types?: string[];
    threat_actors?: string[];
    status: string;
    error?: string;
}

let urlClassificationsCache: Record<string, URLClassification> = {};

function loadURLClassifications(): Record<string, URLClassification> {
    try {
        if (fs.existsSync(URL_CLASSIFICATIONS_FILE)) {
            const data = fs.readFileSync(URL_CLASSIFICATIONS_FILE, 'utf-8');
            const parsed = JSON.parse(data);
            console.log(`📋 Loaded ${Object.keys(parsed).length} URL classifications`);
            return parsed;
        }
    } catch (error) {
        console.warn('⚠️ Could not load URL classifications:', error);
    }
    return {};
}

function getURLClassification(referenceUrl: string | undefined): URLClassification | null {
    if (!referenceUrl) return null;
    return urlClassificationsCache[referenceUrl] || null;
}

// ============================================
// AI Service Functions
// ============================================

async function callAIService(
    iocValue: string,
    iocType: string,
    description: string,
    title: string,
    sources: string[],
    countryCode?: string,
    domainAgeDays?: number
): Promise<AIServiceResponse | null> {
    if (!ENABLE_AI_SERVICE) return null;

    try {
        const response = await fetch(`${AI_SERVICE_URL}/enrich`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-API-Key': AI_SERVICE_API_KEY
            },
            body: JSON.stringify({
                ioc_value: iocValue,
                ioc_type: iocType,
                description,
                title,
                sources,
                country_code: countryCode,
                domain_age_days: domainAgeDays
            })
        });

        if (!response.ok) {
            console.warn(`AI Service error for ${iocValue}: ${response.status}`);
            return null;
        }

        return await response.json() as AIServiceResponse;
    } catch (error) {
        // AI Service not available - fail silently
        return null;
    }
}

async function checkAIServiceHealth(): Promise<boolean> {
    try {
        const response = await fetch(`${AI_SERVICE_URL}/health`);
        if (response.ok) {
            const data = await response.json();
            return data.status === 'healthy' && data.classifier_loaded;
        }
        return false;
    } catch {
        return false;
    }
}

// ============================================
// Helper Functions
// ============================================

function normalizeSeverity(severity: string | undefined): SeverityLevel {
    if (!severity) return 'low';
    const normalized = severity.toLowerCase().trim();
    switch (normalized) {
        case 'critical':
        case 'very high':
            return 'critical';
        case 'high':
            return 'high';
        case 'medium':
            return 'medium';
        case 'low':
            return 'low';
        case 'clean':
        case 'info':
            return 'clean';
        default:
            return 'low';
    }
}

function detectIOCType(value: string): string {
    if (/^CVE-\d{4}-\d+$/i.test(value)) return 'cve';
    if (/^[a-f0-9]{64}$/i.test(value)) return 'sha256';
    if (/^[a-f0-9]{40}$/i.test(value)) return 'sha1';
    if (/^[a-f0-9]{32}$/i.test(value)) return 'md5';
    if (/^(\d{1,3}\.){3}\d{1,3}$/.test(value)) return 'ip';
    if (/^https?:\/\//.test(value)) return 'url';
    return 'domain';
}

function calculateEntropy(str: string): number {
    if (!str || str.length === 0) return 0;
    const freq: { [char: string]: number } = {};
    for (const char of str.toLowerCase()) {
        freq[char] = (freq[char] || 0) + 1;
    }
    let entropy = 0;
    const len = str.length;
    for (const char in freq) {
        const p = freq[char] / len;
        entropy -= p * Math.log2(p);
    }
    return Math.round(entropy * 100) / 100;
}

function getDomainAgeDays(creationDate: string | undefined): number | null {
    if (!creationDate) return null;
    try {
        const created = new Date(creationDate);
        const now = new Date();
        const diffMs = now.getTime() - created.getTime();
        return Math.floor(diffMs / (1000 * 60 * 60 * 24));
    } catch {
        return null;
    }
}

function containsHighRiskKeywords(text: string): string[] {
    if (!text) return [];
    const lowerText = text.toLowerCase();
    return HIGH_RISK_KEYWORDS.filter(keyword => lowerText.includes(keyword));
}

// ============================================
// Source Type Classification
// ============================================

const THREAT_INTEL_SOURCES = [
    'VirusTotal', 'AbuseIPDB', 'MITRE', 'AlienVault',
    'ThreatFox', 'URLhaus', 'MalwareBazaar', 'PhishTank'
];

const SANDBOX_SOURCES = [
    'ANY.RUN', 'Joe Sandbox', 'Hybrid Analysis', 'Triage', 'Sandbox'
];

const SECURITY_TOOLS = [
    'Suricata', 'Snort', 'Zeek', 'YARA'
];

// News sources - don't count for cross-source validation
const NEWS_SOURCES = [
    'BleepingComputer', 'DarkReading', 'TheHackerNews',
    'Cyber News', 'SecurityWeek', 'KrebsOnSecurity'
];

function classifySource(sourceName: string): 'threat_intel' | 'sandbox' | 'security_tool' | 'news' | 'other' {
    const lowerName = sourceName.toLowerCase();

    if (THREAT_INTEL_SOURCES.some(s => lowerName.includes(s.toLowerCase()))) {
        return 'threat_intel';
    }
    if (SANDBOX_SOURCES.some(s => lowerName.includes(s.toLowerCase()))) {
        return 'sandbox';
    }
    if (SECURITY_TOOLS.some(s => lowerName.includes(s.toLowerCase()))) {
        return 'security_tool';
    }
    if (NEWS_SOURCES.some(s => lowerName.includes(s.toLowerCase()))) {
        return 'news';
    }
    return 'other';
}

// ============================================
// AI Risk Score Calculation (Refactored)
// ============================================

function calculateAIRiskScore(
    iocValue: string,
    iocType: string,
    events: ThreatEvent[]
): {
    totalScore: number;
    severity: SeverityLevel;
    breakdown: Record<string, any>;  // Changed to match AI Service format
} {
    let totalScore = 0;

    // 1. Cross-Source Validation (max 40 points)
    // Only count Threat Intel, Sandbox, and Security Tools - NOT news
    const sources = [...new Set(events.map(e => e.source_name))];

    let threatIntelCount = 0;
    let sandboxCount = 0;
    let securityToolCount = 0;
    let evidenceCount = 0;
    let otherValidCount = 0; // Non-news sources
    const threatIntelSources: string[] = [];
    const sandboxSources: string[] = [];
    const securityToolSources: string[] = [];
    const evidenceSources: string[] = [];
    const otherSources: string[] = [];

    for (const source of sources) {
        const sourceType = classifySource(source);
        if (sourceType === 'threat_intel') {
            threatIntelCount++;
            threatIntelSources.push(source);
        } else if (sourceType === 'sandbox') {
            sandboxCount++;
            sandboxSources.push(source);
        } else if (sourceType === 'security_tool') {
            securityToolCount++;
            securityToolSources.push(source);
        } else if (sourceType === 'other') {
            // Check if it's an evidence source like Zone-H
            const lowerSource = source.toLowerCase();
            if (lowerSource.includes('zone-h') || lowerSource.includes('zoneh') ||
                lowerSource.includes('defac') || lowerSource.includes('breach')) {
                evidenceCount++;
                evidenceSources.push(source);
            } else {
                otherValidCount++;
                otherSources.push(source);
            }
        }
        // news sources don't add any score
    }

    // Scoring:
    // - Each Threat Intel source: +15 points (max 2 = 30)
    // - Each Sandbox confirmation: +10 points
    // - Security tool detection: +10 points
    // - Evidence sources (Zone-H, etc): +8 points each
    // - Other non-news sources: +5 points each (base score)
    const crossSourceScore = Math.min(threatIntelCount * 15, 30) +
        Math.min(sandboxCount * 10, 10) +
        Math.min(securityToolCount * 10, 10) +
        Math.min(evidenceCount * 8, 16) +
        Math.min(otherValidCount * 5, 10);
    const crossSourceFinal = Math.min(crossSourceScore, 40);
    totalScore += crossSourceFinal;

    // Build cross_source reason
    const crossSourceParts: string[] = [];
    const crossSourcePartsEn: string[] = [];
    if (threatIntelSources.length > 0) {
        crossSourceParts.push(`Threat Intel: ${threatIntelSources.join(', ')}`);
        crossSourcePartsEn.push(`Threat Intel: ${threatIntelSources.join(', ')}`);
    }
    if (sandboxSources.length > 0) {
        crossSourceParts.push(`Sandbox: ${sandboxSources.join(', ')}`);
        crossSourcePartsEn.push(`Sandbox: ${sandboxSources.join(', ')}`);
    }
    if (securityToolSources.length > 0) {
        crossSourceParts.push(`เครื่องมือรักษาความปลอดภัย: ${securityToolSources.join(', ')}`);
        crossSourcePartsEn.push(`Security Tools: ${securityToolSources.join(', ')}`);
    }
    if (evidenceSources.length > 0) {
        crossSourceParts.push(`หลักฐาน: ${evidenceSources.join(', ')}`);
        crossSourcePartsEn.push(`Evidence: ${evidenceSources.join(', ')}`);
    }
    if (otherSources.length > 0) {
        crossSourceParts.push(`อื่นๆ: ${otherSources.join(', ')}`);
        crossSourcePartsEn.push(`Other: ${otherSources.join(', ')}`);
    }

    const crossSourceReason = crossSourceParts.length > 0
        ? `พบใน ${sources.length} แหล่ง: ${crossSourceParts.join(' | ')}`
        : 'ไม่พบการยืนยันจากแหล่งที่น่าเชื่อถือ';
    const crossSourceReasonEn = crossSourcePartsEn.length > 0
        ? `Found in ${sources.length} sources: ${crossSourcePartsEn.join(' | ')}`
        : 'No confirmation from trusted sources';

    // 2. Threat Type Bonus (max 10 points) - if has threat_type array
    const allThreatTypes = events.flatMap(e => e.threat_type || []);
    let threatTypeScore = 0;
    if (allThreatTypes.length > 0) {
        threatTypeScore += 5;
    }
    if (allThreatTypes.length >= 2) {
        threatTypeScore += 5;
    }
    totalScore += threatTypeScore;

    // Get first event for enrichment data
    const firstEvent = events[0];
    const enrichment = firstEvent?.enrichment;

    // 3. Type-Specific Analysis (max 20 points)
    let typeSpecificScore = 0;
    let typeSpecificReason = 'ไม่ได้วิเคราะห์เพิ่มเติม';
    let typeSpecificReasonEn = 'No additional analysis';

    if (iocType === 'domain' || iocType === 'url') {
        // Domain Age Analysis
        const creationDate = enrichment?.whois?.creation_date || enrichment?.events?.registration;
        const domainAgeDays = getDomainAgeDays(creationDate);
        if (domainAgeDays !== undefined && domainAgeDays !== null) {
            if (domainAgeDays <= 30) {
                typeSpecificScore = 20;
                typeSpecificReason = `โดเมนใหม่มาก (${domainAgeDays} วัน) - ความเสี่ยงสูง`;
                typeSpecificReasonEn = `Very new domain (${domainAgeDays} days) - high risk`;
            } else if (domainAgeDays <= 90) {
                typeSpecificScore = 15;
                typeSpecificReason = `โดเมนใหม่ (${domainAgeDays} วัน)`;
                typeSpecificReasonEn = `New domain (${domainAgeDays} days)`;
            } else if (domainAgeDays <= 180) {
                typeSpecificScore = 8;
                typeSpecificReason = `โดเมนอายุน้อย (${domainAgeDays} วัน)`;
                typeSpecificReasonEn = `Young domain (${domainAgeDays} days)`;
            } else {
                typeSpecificReason = `โดเมนอายุ ${domainAgeDays} วัน (ปกติ)`;
                typeSpecificReasonEn = `Domain age ${domainAgeDays} days (normal)`;
            }
        }

        // WHOIS Privacy bonus
        const registrant = enrichment?.whois?.registrant_name?.toLowerCase() || '';
        if (registrant.includes('privacy') || registrant.includes('protect') ||
            registrant.includes('whoisguard') || registrant.includes('domains by proxy')) {
            typeSpecificScore += 5;
            typeSpecificReason += ' | ใช้บริการซ่อนข้อมูล WHOIS';
            typeSpecificReasonEn += ' | Uses WHOIS privacy service';
        }
    } else if (iocType === 'ip') {
        // IP Analysis
        const asnData = enrichment?.asn || enrichment?.ip_info?.asn_data;
        if (asnData) {
            const asnOrg = (asnData.org || asnData.name || '').toLowerCase();
            if (asnOrg.includes('hosting') || asnOrg.includes('vps') || asnOrg.includes('cloud')) {
                typeSpecificScore = 10;
                typeSpecificReason = `ใช้บริการ VPS/Hosting: ${asnData.org || asnData.name}`;
                typeSpecificReasonEn = `VPS/Hosting provider: ${asnData.org || asnData.name}`;
            } else if (asnOrg.includes('bullet') || asnOrg.includes('vpn')) {
                typeSpecificScore = 15;
                typeSpecificReason = `VPN/Bulletproof hosting: ${asnData.org || asnData.name}`;
                typeSpecificReasonEn = `VPN/Bulletproof hosting: ${asnData.org || asnData.name}`;
            } else {
                typeSpecificReason = `ASN: ${asnData.org || asnData.name || 'Unknown'}`;
                typeSpecificReasonEn = `ASN: ${asnData.org || asnData.name || 'Unknown'}`;
            }
        }
    }
    totalScore += typeSpecificScore;

    // 4. Entropy Analysis for domains/URLs (max 12 points)
    let entropyScore = 0;
    let entropy = 0;
    let entropyReason = 'ไม่ได้วิเคราะห์ (ไม่ใช่โดเมน/URL)';
    let entropyReasonEn = 'Not analyzed (not a domain/URL)';

    if (iocType === 'domain' || iocType === 'url' || iocType === 'hostname') {
        const domainPart = iocValue.split('/')[0].split(':')[0];
        entropy = calculateEntropy(domainPart);
        if (entropy > 4.0) {
            entropyScore = 12;
            entropyReason = `Entropy = ${entropy.toFixed(2)} (สูงมาก) - อาจเป็น DGA`;
            entropyReasonEn = `Entropy = ${entropy.toFixed(2)} (very high) - possible DGA`;
        } else if (entropy > 3.5) {
            entropyScore = 8;
            entropyReason = `Entropy = ${entropy.toFixed(2)} (สูง) - อาจเป็นชื่อโดเมนสุ่ม`;
            entropyReasonEn = `Entropy = ${entropy.toFixed(2)} (high) - possibly random`;
        } else if (entropy > 3.0) {
            entropyScore = 4;
            entropyReason = `Entropy = ${entropy.toFixed(2)} (ปานกลาง)`;
            entropyReasonEn = `Entropy = ${entropy.toFixed(2)} (moderate)`;
        } else {
            entropyReason = `Entropy = ${entropy.toFixed(2)} (ปกติ) - ชื่อโดเมนดูปกติ`;
            entropyReasonEn = `Entropy = ${entropy.toFixed(2)} (normal) - domain name looks normal`;
        }
        totalScore += entropyScore;
    }

    // 5. Keyword Context Analysis (max 20 points)
    const allDescriptions = events.map(e => e.description).join(' ');
    const allTags = events.flatMap(e => e.tags || []).join(' ');
    const combinedText = allDescriptions + ' ' + allTags;
    const foundKeywords = containsHighRiskKeywords(combinedText);

    let keywordsScore = 0;
    if (foundKeywords.length >= 4) {
        keywordsScore = 20;
    } else if (foundKeywords.length >= 2) {
        keywordsScore = 12;
    } else if (foundKeywords.length >= 1) {
        keywordsScore = 6;
    }
    totalScore += keywordsScore;

    const keywordsReason = foundKeywords.length > 0
        ? `พบคำสำคัญ: ${foundKeywords.join(', ')}`
        : 'ไม่พบคำสำคัญที่น่าสงสัย';
    const keywordsReasonEn = foundKeywords.length > 0
        ? `Keywords found: ${foundKeywords.join(', ')}`
        : 'No suspicious keywords found';

    // 6. Source Severity Bonus (max 15 points)
    const sourceSeverities = events
        .map(e => e.severity)
        .filter(Boolean) as SeverityLevel[];

    const severityScores: Record<SeverityLevel, number> = {
        critical: 15,
        high: 10,
        medium: 5,
        low: 0,
        clean: 0,
        info: 0
    };

    const maxSourceSeverity = sourceSeverities.reduce((max, sev) => {
        return severityScores[sev] > severityScores[max] ? sev : max;
    }, 'low' as SeverityLevel);

    const sourceSeverityScore = severityScores[maxSourceSeverity];
    totalScore += sourceSeverityScore;

    // Determine severity
    // Thresholds adjusted for actual data:
    // - Zone-H (8 pts) should be Low
    // - Suricata + keywords (18 pts) should be Medium
    // - Multiple validations (30+ pts) should be High
    let severity: SeverityLevel;
    if (totalScore >= 45) {
        severity = 'critical';
    } else if (totalScore >= 30) {
        severity = 'high';
    } else if (totalScore >= 15) {
        severity = 'medium';
    } else if (totalScore >= 6) {
        severity = 'low';
    } else {
        severity = 'clean';
    }

    // Build enhanced breakdown matching AI Service format
    const breakdown: Record<string, any> = {
        cross_source: {
            score: crossSourceFinal,
            maxScore: 40,
            count: sources.length,
            sources_found: sources,
            description: `พบจาก ${sources.length} แหล่งข้อมูล`,
            reason: crossSourceReason,
            reasonEn: crossSourceReasonEn,
            methodology: 'นับจำนวนแหล่งข่าวกรองที่รายงาน IOC นี้ ยิ่งพบหลายแหล่งยิ่งน่าเชื่อถือ',
            methodologyEn: 'Count unique threat intelligence sources reporting this IOC. More sources = higher confidence.',
            scoringRules: 'Threat Intel = +15/แหล่ง (สูงสุด 30), Sandbox = +10, Security Tool = +10, หลักฐาน = +8/แหล่ง, อื่นๆ = +5/แหล่ง (รวมสูงสุด 40)'
        },
        source_quality: {
            score: threatIntelCount > 0 ? 15 : (sandboxCount > 0 || securityToolCount > 0 ? 10 : 5),
            maxScore: 40,
            trusted: threatIntelCount,
            news: 0, // News not counted
            other: otherValidCount,
            trusted_sources: threatIntelSources,
            description: `แหล่งน่าเชื่อถือ ${threatIntelCount} แห่ง`,
            reason: threatIntelSources.length > 0 ? `แหล่งเชื่อถือ: ${threatIntelSources.join(', ')}` : 'ไม่พบแหล่งที่เชื่อถือได้ในรายการ',
            reasonEn: threatIntelSources.length > 0 ? `Trusted sources: ${threatIntelSources.join(', ')}` : 'No sources from trusted list',
            methodology: 'ตรวจสอบว่าแหล่งข้อมูลอยู่ในรายการที่เชื่อถือได้หรือไม่ (เช่น VirusTotal, AbuseIPDB, MISP)',
            methodologyEn: 'Check if sources are in trusted list (e.g., VirusTotal, AbuseIPDB, MISP)',
            scoringRules: 'แหล่งเชื่อถือ = 15 คะแนน, แหล่งข่าว = 0 คะแนน, อื่นๆ = 5 คะแนน (สูงสุด 40)'
        },
        keywords: {
            score: keywordsScore,
            maxScore: 25,
            keywords: foundKeywords,
            description: `พบ ${foundKeywords.length} คำสำคัญ`,
            reason: keywordsReason,
            reasonEn: keywordsReasonEn,
            methodology: 'ค้นหาคำสำคัญที่บ่งชี้ภัยคุกคาม เช่น ransomware, zero-day, exploit, APT, backdoor',
            methodologyEn: 'Search for keywords indicating threats like ransomware, zero-day, exploit, APT, backdoor',
            scoringRules: '1 คำ = 6 คะแนน, 2-3 คำ = 12 คะแนน, 4+ คำ = 20 คะแนน'
        },
        entropy: {
            value: entropy,
            score: entropyScore,
            maxScore: 15,
            description: entropy > 3.5 ? 'สูง (น่าสงสัย DGA)' : 'ปกติ',
            reason: entropyReason,
            reasonEn: entropyReasonEn,
            methodology: 'คำนวณค่า Shannon Entropy ของชื่อโดเมน ค่าสูง = สุ่มมาก = อาจเป็น DGA (Domain Generation Algorithm)',
            methodologyEn: 'Calculate Shannon Entropy of domain name. High entropy = more random = likely DGA',
            scoringRules: 'Entropy > 4.0 = 12 คะแนน, > 3.5 = 8 คะแนน, > 3.0 = 4 คะแนน'
        },
        domain_age: {
            score: iocType === 'domain' || iocType === 'url' ? typeSpecificScore : 0,
            maxScore: 20,
            description: typeSpecificReason,
            reason: typeSpecificReason,
            reasonEn: typeSpecificReasonEn,
            methodology: 'วิเคราะห์อายุโดเมนจาก WHOIS โดเมนใหม่มากมีความเสี่ยงสูงกว่า',
            methodologyEn: 'Analyze domain age from WHOIS. Newer domains are riskier.',
            scoringRules: '< 30 วัน = 20 คะแนน, < 90 วัน = 15 คะแนน, < 180 วัน = 8 คะแนน'
        },
        threat_type_severity: {
            score: threatTypeScore,
            maxScore: 35,
            description: `ตรวจพบ ${allThreatTypes.length} ประเภทภัยคุกคาม`,
            reason: allThreatTypes.length > 0 ? `ประเภทที่พบ: ${allThreatTypes.join(', ')}` : 'ไม่พบประเภทภัยคุกคามที่รู้จัก (ใช้ข้อมูล AI เพื่อระบุ)',
            reasonEn: allThreatTypes.length > 0 ? `Types detected: ${allThreatTypes.join(', ')}` : 'No known threat types detected (use AI for identification)',
            methodology: 'วิเคราะห์ด้วย AI (NLP) เพื่อจัดประเภทภัยคุกคาม เช่น Ransomware, APT, Phishing, Malware',
            methodologyEn: 'AI (NLP) analysis to classify threat types like Ransomware, APT, Phishing, Malware',
            scoringRules: 'มีประเภท 1 ประเภท = 5 คะแนน, 2+ ประเภท = 10 คะแนน (Fallback scoring)'
        },
        geo_risk: {
            score: 0,
            maxScore: 15,
            disabled: true,
            description: 'ปิดใช้งาน - ไม่มีแหล่งข้อมูลที่ตรวจสอบได้',
            reason: 'ปัจจัยนี้ถูกปิดใช้งานเพราะข้อมูลประเทศต้นทางไม่สามารถ audit ได้',
            reasonEn: 'This factor is disabled - country data source is not auditable',
            methodology: 'ปิดใช้งานเพื่อความโปร่งใสและสามารถตรวจสอบได้',
            methodologyEn: 'Disabled for transparency and auditability',
            scoringRules: 'ปิดใช้งาน'
        }
    };

    return { totalScore, severity, breakdown };
}

// ============================================
// Main Normalization Logic
// ============================================

async function normalizeData() {
    console.log('🚀 Starting data normalization...\n');

    // Load URL classifications from enrichment script
    urlClassificationsCache = loadURLClassifications();

    // 1. Read all JSON files from data_lake
    const files = fs.readdirSync(DATA_LAKE_DIR).filter(f => f.endsWith('.json') && f !== 'url_classifications.json');
    console.log(`📂 Found ${files.length} data files in data_lake/`);

    const allEvents: ThreatEvent[] = [];

    for (const file of files) {
        try {
            const filePath = path.join(DATA_LAKE_DIR, file);
            const content = fs.readFileSync(filePath, 'utf-8');
            const data = JSON.parse(content);

            // Handle Elasticsearch nested format
            const hits = data.hits?.hits || (Array.isArray(data.hits) ? data.hits : []);

            for (const hit of hits) {
                const source = hit._source || hit;
                if (source && source.ioc) {
                    allEvents.push({
                        ...source,
                        severity: normalizeSeverity(source.severity as string),
                    });
                }
            }
            console.log(`  ✓ ${file}: ${hits.length} events`);
        } catch (error) {
            console.error(`  ✗ Error loading ${file}:`, error);
        }
    }

    console.log(`\n📊 Total events loaded: ${allEvents.length}`);

    // 2. Group events by IOC value
    const iocMap = new Map<string, ThreatEvent[]>();
    for (const event of allEvents) {
        const key = `${event.ioc.type}:${event.ioc.value}`;
        if (!iocMap.has(key)) {
            iocMap.set(key, []);
        }
        iocMap.get(key)!.push(event);
    }

    console.log(`🔗 Unique IOCs: ${iocMap.size}`);

    // 3. Check AI Service availability
    const aiServiceAvailable = ENABLE_AI_SERVICE && await checkAIServiceHealth();
    if (aiServiceAvailable) {
        console.log('🤖 AI Service: Connected (NLP Classification enabled)');
    } else if (ENABLE_AI_SERVICE) {
        console.log('⚠️  AI Service: Not available (using rule-based scoring only)');
    } else {
        console.log('ℹ️  AI Service: Disabled');
    }

    // 4. Calculate AI Risk Score for each IOC and normalize events
    const normalizedIOCs: NormalizedIOC[] = [];
    let processedCount = 0;
    let aiEnrichedCount = 0;

    for (const [key, events] of iocMap) {
        const [iocType, iocValue] = key.split(':');
        const detectedType = iocType || detectIOCType(iocValue);

        // Calculate local AI Risk Score (rule-based)
        const { totalScore, severity, breakdown } = calculateAIRiskScore(
            iocValue,
            detectedType,
            events
        );

        // Get sources and dates
        const sources = [...new Set(events.map(e => e.source_name))];
        const dates = events.map(e => e.event_time).filter(Boolean).sort();

        // Get description for AI Service
        const primaryEvent = events[0];
        let description = primaryEvent?.description || '';
        let title = (primaryEvent as any)?.title || '';
        const countryCode = primaryEvent?.geo_info?.country;
        const enrichment = primaryEvent?.enrichment;
        const creationDate = enrichment?.whois?.creation_date;
        const domainAgeDays = creationDate ? getDomainAgeDays(creationDate) : undefined;

        // Check URL classification for additional context
        const referenceUrl = primaryEvent?.reference;
        const urlClassification = getURLClassification(referenceUrl);
        let urlThreatTypes: string[] = [];
        let urlThreatActors: string[] = [];

        if (urlClassification && urlClassification.status === 'success') {
            // Use URL title if no direct title
            if (!title && urlClassification.title) {
                title = urlClassification.title;
            }
            // Use URL classification as description if no direct description
            if (!description && urlClassification.title) {
                description = urlClassification.title;
            }
            // Store pre-classified data from URL enrichment
            urlThreatTypes = urlClassification.threat_types || [];
            urlThreatActors = urlClassification.threat_actors || [];
        }

        // Initialize AI Service fields with defaults
        let aiThreatTypes: string[] = urlThreatTypes;  // Start with URL classification
        let aiThreatActors: string[] = urlThreatActors;  // Start with URL classification
        let aiMitreTechniques: string[] = [];
        let aiClassificationConfidence = urlThreatTypes.length > 0 ? 0.7 : 0;  // URL classification has medium confidence
        let finalScore = totalScore;
        let finalSeverity = severity;
        let finalSeverityTH = '';
        let finalBreakdown: Record<string, any> = breakdown;
        let finalTopFactors: Array<{ factor: string; score: number; label: string }> = [];
        let finalSummary = {
            traditional_score: totalScore,
            ai_score: 0,
            has_threat_actor: urlThreatActors.length > 0,
            has_mitre: false,
            primary_threat: urlThreatTypes[0] || null as string | null
        };

        // Call AI Service if available AND we have enough context
        const hasEnoughContext = description.length > 20 || title.length > 20;
        if (aiServiceAvailable && hasEnoughContext) {
            const aiResult = await callAIService(
                iocValue,
                detectedType,
                description,
                title,
                sources,
                countryCode,
                domainAgeDays ?? undefined
            );

            if (aiResult) {
                aiThreatTypes = aiResult.ai_threat_types;
                aiThreatActors = aiResult.ai_threat_actors;
                aiMitreTechniques = aiResult.ai_mitre_techniques;
                aiClassificationConfidence = aiResult.ai_classification_confidence;

                // Always use AI Service score when available (more accurate)
                finalScore = aiResult.ai_risk_score;
                finalSeverity = normalizeSeverity(aiResult.ai_severity);
                finalSeverityTH = aiResult.severity_th || '';
                finalBreakdown = aiResult.ai_score_breakdown;
                finalTopFactors = aiResult.ai_top_factors || [];

                // Extract summary from breakdown
                if (aiResult.summary) {
                    finalSummary = aiResult.summary;
                } else {
                    // Compute summary from breakdown
                    const bd = aiResult.ai_score_breakdown;
                    const getRaw = (key: string) => {
                        const v = (bd as any)?.[key];
                        if (!v) return 0;
                        // New format: score normalized 0-100 plus raw_score/raw_max for audit
                        if (typeof v.raw_score === 'number') return v.raw_score;
                        if (typeof v.score === 'number') return v.score;
                        return 0;
                    };
                    finalSummary = {
                        traditional_score: getRaw('cross_source') +
                            getRaw('source_quality') +
                            getRaw('keywords') +
                            getRaw('entropy') +
                            getRaw('geo_risk') +
                            getRaw('domain_age'),
                        ai_score: getRaw('threat_type_severity') +
                            getRaw('threat_actor') +
                            getRaw('mitre_techniques') +
                            getRaw('ai_confidence'),
                        has_threat_actor: aiThreatActors.length > 0,
                        has_mitre: aiMitreTechniques.length > 0,
                        primary_threat: aiThreatTypes[0] || null
                    };
                }

                aiEnrichedCount++;
            }
        }

        // Update each event with AI scores
        for (const event of events) {
            event.aiRiskScore = finalScore;
            event.aiSeverity = finalSeverity;
            event.aiSeverityTH = finalSeverityTH;
            event.aiScoreBreakdown = finalBreakdown;
            event.aiTopFactors = finalTopFactors;
            event.aiScoreSummary = finalSummary;
            event.aiThreatTypes = aiThreatTypes;
            event.aiThreatActors = aiThreatActors;
            event.aiMitreTechniques = aiMitreTechniques;
            event.aiClassificationConfidence = aiClassificationConfidence;
        }

        normalizedIOCs.push({
            iocValue,
            iocType: detectedType,
            events,
            aiRiskScore: finalScore,
            aiSeverity: finalSeverity,
            aiSeverityTH: finalSeverityTH,
            aiScoreBreakdown: finalBreakdown,
            aiTopFactors: finalTopFactors,
            aiScoreSummary: finalSummary,
            aiThreatTypes,
            aiThreatActors,
            aiMitreTechniques,
            aiClassificationConfidence,
            sources,
            firstSeen: dates[0] || '',
            lastSeen: dates[dates.length - 1] || ''
        });

        processedCount++;
        if (processedCount % 50 === 0) {
            process.stdout.write(`\r⚙️  Processing: ${processedCount}/${iocMap.size} (AI enriched: ${aiEnrichedCount})`);
        }
    }

    console.log(`\n\n✅ Processed ${processedCount} unique IOCs`);
    if (aiEnrichedCount > 0) {
        console.log(`🤖 AI-enriched: ${aiEnrichedCount} IOCs with NLP classification`);
    }

    // 4. Create flat events array for API output
    const normalizedEvents: ThreatEvent[] = [];
    for (const ioc of normalizedIOCs) {
        normalizedEvents.push(...ioc.events);
    }

    // 5. Calculate statistics
    const stats = {
        total: normalizedEvents.length,
        uniqueIOCs: normalizedIOCs.length,
        bySeverity: {
            critical: normalizedEvents.filter(e => e.aiSeverity === 'critical').length,
            high: normalizedEvents.filter(e => e.aiSeverity === 'high').length,
            medium: normalizedEvents.filter(e => e.aiSeverity === 'medium').length,
            low: normalizedEvents.filter(e => e.aiSeverity === 'low').length,
            clean: normalizedEvents.filter(e => e.aiSeverity === 'clean').length,
        },
        generatedAt: new Date().toISOString()
    };

    console.log('\n📈 Severity Distribution (AI-Calculated):');
    console.log(`   Critical: ${stats.bySeverity.critical}`);
    console.log(`   High: ${stats.bySeverity.high}`);
    console.log(`   Medium: ${stats.bySeverity.medium}`);
    console.log(`   Low: ${stats.bySeverity.low}`);
    console.log(`   Clean: ${stats.bySeverity.clean}`);

    // 6. Ensure output directory exists
    const outputDir = path.dirname(OUTPUT_FILE);
    if (!fs.existsSync(outputDir)) {
        fs.mkdirSync(outputDir, { recursive: true });
    }

    // 7. Write output
    const output = {
        stats,
        events: normalizedEvents
    };

    fs.writeFileSync(OUTPUT_FILE, JSON.stringify(output, null, 2));
    console.log(`\n💾 Output saved to: ${OUTPUT_FILE}`);
    console.log(`   File size: ${(fs.statSync(OUTPUT_FILE).size / 1024 / 1024).toFixed(2)} MB`);

    console.log('\n🎉 Normalization complete!');
}

// Run
normalizeData().catch(console.error);
