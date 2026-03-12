/**
 * Threat Scoring Logic
 * Based on Meeting Minutes requirements:
 * - 1 source = 50 points
 * - 2+ sources = 100 points (High)
 * 
 * Enhanced with AI-style multi-dimensional scoring:
 * - Domain Age Analysis
 * - Entropy Score (DGA Detection)
 * - Keyword Context Analysis
 * - Cross-Source Validation
 */

import type { ThreatEvent, ThreatScore, SeverityLevel, Enrichment } from '@/lib/types';

/**
 * Detailed score breakdown for tooltip display
 */
export interface ScoreBreakdown {
    totalScore: number;
    maxScore: number;
    breakdown: {
        category: string;
        categoryTh: string;
        score: number;
        maxScore: number;
        reason: string;
        reasonTh: string;
        methodology: string;
        methodologyTh: string;
    }[];
    severity: SeverityLevel;
}

/**
 * Enhanced Score Breakdown from Python AI Service
 */
export interface EnhancedScoreBreakdown {
    totalScore: number;
    severity: SeverityLevel;
    severityTH?: string;
    breakdown: Record<string, any>;
    topFactors?: Array<{ factor: string; score: number; weighted_score?: number; label: string }>;
    summary?: {
        traditional_score: number;
        ai_score: number;
        has_threat_actor: boolean;
        has_mitre: boolean;
        primary_threat: string | null;
    };
}

/**
 * Union type for score breakdown (legacy or enhanced)
 */
export type AnyScoreBreakdown = ScoreBreakdown | EnhancedScoreBreakdown;

/**
 * Type guard to check if breakdown is enhanced
 */
export function isEnhancedBreakdown(breakdown: AnyScoreBreakdown): breakdown is EnhancedScoreBreakdown {
    return 'topFactors' in breakdown || 'summary' in breakdown;
}


/**
 * HIGH RISK keywords in threat intelligence
 */
const HIGH_RISK_KEYWORDS = [
    'ransomware', 'zero-day', '0day', 'critical', 'exploit', 'active',
    'lazarus', 'apt', 'backdoor', 'c2', 'cnc', 'botnet', 'credential',
    'phishing', 'malware', 'trojan', 'wiper', 'encryption'
];

/**
 * Calculate Shannon Entropy for DGA detection
 * Higher entropy = more random = potentially DGA-generated
 */
export function calculateEntropy(str: string): number {
    if (!str || str.length === 0) return 0;

    const freq: Record<string, number> = {};
    for (const char of str.toLowerCase()) {
        freq[char] = (freq[char] || 0) + 1;
    }

    let entropy = 0;
    const len = str.length;
    for (const count of Object.values(freq)) {
        const p = count / len;
        entropy -= p * Math.log2(p);
    }

    return Math.round(entropy * 100) / 100;
}

/**
 * Calculate domain age in days from creation date
 */
export function getDomainAgeDays(creationDate: string | undefined): number | null {
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

/**
 * Check if text contains high-risk keywords
 */
export function containsHighRiskKeywords(text: string): string[] {
    if (!text) return [];
    const lowerText = text.toLowerCase();
    return HIGH_RISK_KEYWORDS.filter(kw => lowerText.includes(kw));
}

/**
 * HIGH RISK countries for IP geolocation analysis
 */
const HIGH_RISK_COUNTRIES = ['RU', 'CN', 'KP', 'IR', 'BY'];

/**
 * AI-Enhanced Threat Score Calculator
 * IOC-Type Aware: applies appropriate analysis per IOC type
 * Returns detailed breakdown for tooltip display
 */
export function calculateAIThreatScore(
    iocValue: string,
    events: ThreatEvent[],
    iocType?: string
): ScoreBreakdown {
    const breakdown: ScoreBreakdown['breakdown'] = [];
    let totalScore = 0;
    const maxPossibleScore = 100;

    // Find all events with this IOC value
    const relatedEvents = events.filter(
        e => e.ioc.value.toLowerCase() === iocValue.toLowerCase()
    );

    // Auto-detect IOC type from first event if not provided
    const detectedType = iocType || relatedEvents[0]?.ioc.type || detectIOCType(iocValue);
    const firstEvent = relatedEvents[0];
    const enrichment = firstEvent?.enrichment;

    // Get unique sources
    const sources = [...new Set(relatedEvents.map(e => e.source_name))];
    const sourceCount = sources.length;

    // ============================================
    // 1. Cross-Source Validation (max 40 points)
    // Applies to ALL IOC types
    // ============================================
    const sourceScore = sourceCount === 0 ? 0 : sourceCount === 1 ? 20 : Math.min(sourceCount * 15, 40);
    breakdown.push({
        category: 'Cross-Source Validation',
        categoryTh: 'การตรวจสอบข้ามแหล่งข้อมูล',
        score: sourceScore,
        maxScore: 40,
        reason: sourceCount === 0
            ? 'Not found in any source'
            : `Found in ${sourceCount} source(s): ${sources.join(', ')}`,
        reasonTh: sourceCount === 0
            ? 'ไม่พบในแหล่งข้อมูลใด'
            : `พบใน ${sourceCount} แหล่งข้อมูล: ${sources.join(', ')}`,
        methodology: 'Count unique threat intelligence sources (BleepingComputer, DarkReading, Suricata, etc.) that report this IOC. More sources = higher confidence. Scoring: 1 source = 20pts, 2+ sources = up to 40pts.',
        methodologyTh: 'นับจำนวนแหล่งข่าวกรอง (เช่น BleepingComputer, DarkReading, Suricata) ที่รายงาน IOC นี้ ยิ่งพบหลายแหล่งยิ่งน่าเชื่อถือ การให้คะแนน: 1 แหล่ง = 20 คะแนน, 2+ แหล่ง = สูงสุด 40 คะแนน'
    });
    totalScore += sourceScore;

    // ============================================
    // 2. Type-Specific Analysis (max 25 points)
    // ============================================
    if (detectedType === 'domain' || detectedType === 'url') {
        // DOMAIN/URL: Domain Age Analysis
        const creationDate = enrichment?.whois?.creation_date ||
            enrichment?.events?.registration;
        const domainAgeDays = getDomainAgeDays(creationDate);

        let ageScore = 0;
        let ageReason = 'N/A - No WHOIS data';
        let ageReasonTh = 'ไม่มีข้อมูล WHOIS';

        if (domainAgeDays !== null) {
            if (domainAgeDays < 30) {
                ageScore = 25;
                ageReason = `Very new domain (${domainAgeDays} days) - High risk`;
                ageReasonTh = `โดเมนใหม่มาก (${domainAgeDays} วัน) - ความเสี่ยงสูง`;
            } else if (domainAgeDays < 90) {
                ageScore = 15;
                ageReason = `New domain (${domainAgeDays} days) - Medium risk`;
                ageReasonTh = `โดเมนใหม่ (${domainAgeDays} วัน) - ความเสี่ยงปานกลาง`;
            } else if (domainAgeDays < 365) {
                ageScore = 5;
                ageReason = `Domain age: ${domainAgeDays} days - Low risk`;
                ageReasonTh = `อายุโดเมน: ${domainAgeDays} วัน - ความเสี่ยงต่ำ`;
            } else {
                ageScore = 0;
                ageReason = `Established domain (${Math.floor(domainAgeDays / 365)} years)`;
                ageReasonTh = `โดเมนเก่าแก่ (${Math.floor(domainAgeDays / 365)} ปี)`;
            }
        }
        breakdown.push({
            category: 'Domain Age Analysis',
            categoryTh: 'การวิเคราะห์อายุโดเมน',
            score: ageScore,
            maxScore: 25,
            reason: ageReason,
            reasonTh: ageReasonTh,
            methodology: 'Check domain registration date from WHOIS data. Newly registered domains (<30 days) are high risk as attackers often create fresh domains. Scoring: <30 days = 25pts, <90 days = 15pts, <1 year = 5pts, older = 0pts.',
            methodologyTh: 'ตรวจสอบวันที่จดทะเบียนโดเมนจากข้อมูล WHOIS โดเมนใหม่ (<30 วัน) ถือว่าเสี่ยงสูงเพราะผู้โจมตีมักสร้างโดเมนใหม่ การให้คะแนน: <30 วัน = 25 คะแนน, <90 วัน = 15 คะแนน, <1 ปี = 5 คะแนน, เก่ากว่า = 0 คะแนน'
        });
        totalScore += ageScore;

    } else if (detectedType === 'ip') {
        // IP: Geolocation Risk Analysis
        const countryCode = enrichment?.ip_info?.asn_data?.country_code || '';
        const asn = enrichment?.ip_info?.asn_data?.asn || '';
        const org = enrichment?.ip_info?.asn_data?.org || '';

        let geoScore = 0;
        let geoReason = 'N/A - No IP info';
        let geoReasonTh = 'ไม่มีข้อมูล IP';

        if (countryCode) {
            if (HIGH_RISK_COUNTRIES.includes(countryCode)) {
                geoScore = 25;
                geoReason = `High-risk country: ${countryCode} (${org || asn})`;
                geoReasonTh = `ประเทศเสี่ยงสูง: ${countryCode} (${org || asn})`;
            } else {
                geoScore = 0;
                geoReason = `Country: ${countryCode} - Normal risk`;
                geoReasonTh = `ประเทศ: ${countryCode} - ความเสี่ยงปกติ`;
            }
        }
        breakdown.push({
            category: 'Geolocation Risk',
            categoryTh: 'ความเสี่ยงตามภูมิศาสตร์',
            score: geoScore,
            maxScore: 25,
            reason: geoReason,
            reasonTh: geoReasonTh,
            methodology: 'Check IP country from ASN/GeoIP data. High-risk countries (RU, CN, KP, IR, BY) often host malicious infrastructure. Scoring: High-risk country = 25pts, Others = 0pts.',
            methodologyTh: 'ตรวจสอบประเทศของ IP จากข้อมูล ASN/GeoIP ประเทศเสี่ยงสูง (รัสเซีย, จีน, เกาหลีเหนือ, อิหร่าน, เบลารุส) มักเป็นแหล่งโครงสร้างพื้นฐานอันตราย การให้คะแนน: ประเทศเสี่ยงสูง = 25 คะแนน, อื่นๆ = 0 คะแนน'
        });
        totalScore += geoScore;

    } else if (['sha256', 'sha1', 'md5'].includes(detectedType)) {
        // HASH: Detection Count Analysis
        // For hashes, we check if multiple malware-related keywords appear
        const allDescriptions = relatedEvents.map(e => e.description).join(' ').toLowerCase();
        const malwareIndicators = ['malware', 'trojan', 'virus', 'ransomware', 'backdoor', 'worm', 'spyware'];
        const detectedIndicators = malwareIndicators.filter(ind => allDescriptions.includes(ind));

        let hashScore = 0;
        let hashReason = 'No malware associations detected';
        let hashReasonTh = 'ไม่พบความเชื่อมโยงกับมัลแวร์';

        if (detectedIndicators.length >= 2) {
            hashScore = 25;
            hashReason = `Multiple malware types: ${detectedIndicators.join(', ')}`;
            hashReasonTh = `เชื่อมโยงกับมัลแวร์หลายประเภท: ${detectedIndicators.join(', ')}`;
        } else if (detectedIndicators.length === 1) {
            hashScore = 15;
            hashReason = `Malware association: ${detectedIndicators[0]}`;
            hashReasonTh = `เชื่อมโยงกับ: ${detectedIndicators[0]}`;
        }
        breakdown.push({
            category: 'Malware Association',
            categoryTh: 'การเชื่อมโยงกับมัลแวร์',
            score: hashScore,
            maxScore: 25,
            reason: hashReason,
            reasonTh: hashReasonTh,
            methodology: 'Scan descriptions for malware-related keywords (malware, trojan, ransomware, backdoor, virus, worm, spyware). Multiple types indicate polymorphic or multi-stage threats. Scoring: 2+ types = 25pts, 1 type = 15pts.',
            methodologyTh: 'ค้นหาคีย์เวิร์ดมัลแวร์ใน description (malware, trojan, ransomware, backdoor, virus, worm, spyware) พบหลายประเภทบ่งบอกถึงภัยคุกคามที่ซับซ้อน การให้คะแนน: พบ 2+ ประเภท = 25 คะแนน, 1 ประเภท = 15 คะแนน'
        });
        totalScore += hashScore;

    } else if (detectedType === 'cve') {
        // CVE: Severity from description (looking for CVSS or severity keywords)
        const allDescriptions = relatedEvents.map(e => e.description).join(' ').toLowerCase();
        let cveScore = 0;
        let cveReason = 'Unknown severity';
        let cveReasonTh = 'ไม่ทราบระดับความรุนแรง';

        if (allDescriptions.includes('critical') || allDescriptions.includes('cvss 9') || allDescriptions.includes('cvss 10')) {
            cveScore = 25;
            cveReason = 'Critical severity CVE';
            cveReasonTh = 'CVE ระดับวิกฤต (Critical)';
        } else if (allDescriptions.includes('high') || allDescriptions.includes('cvss 7') || allDescriptions.includes('cvss 8')) {
            cveScore = 18;
            cveReason = 'High severity CVE';
            cveReasonTh = 'CVE ระดับสูง (High)';
        } else if (allDescriptions.includes('medium') || allDescriptions.includes('cvss 4') || allDescriptions.includes('cvss 5') || allDescriptions.includes('cvss 6')) {
            cveScore = 10;
            cveReason = 'Medium severity CVE';
            cveReasonTh = 'CVE ระดับปานกลาง (Medium)';
        }
        breakdown.push({
            category: 'CVE Severity',
            categoryTh: 'ระดับความรุนแรงของ CVE',
            score: cveScore,
            maxScore: 25,
            reason: cveReason,
            reasonTh: cveReasonTh,
            methodology: 'Extract severity from description keywords (critical, high, medium) or CVSS scores. Based on CVSS v3 rating system. Scoring: Critical/CVSS 9-10 = 25pts, High/CVSS 7-8 = 18pts, Medium/CVSS 4-6 = 10pts.',
            methodologyTh: 'วิเคราะห์ระดับความรุนแรงจากคีย์เวิร์ด (critical, high, medium) หรือคะแนน CVSS อ้างอิงมาตรฐาน CVSS v3 การให้คะแนน: Critical/CVSS 9-10 = 25 คะแนน, High/CVSS 7-8 = 18 คะแนน, Medium/CVSS 4-6 = 10 คะแนน'
        });
        totalScore += cveScore;

    } else {
        // Unknown type - no specific analysis
        breakdown.push({
            category: 'Type-Specific Analysis',
            categoryTh: 'การวิเคราะห์ตามประเภท',
            score: 0,
            maxScore: 25,
            reason: `No analysis available for type: ${detectedType}`,
            reasonTh: `ไม่มีการวิเคราะห์สำหรับประเภท: ${detectedType}`,
            methodology: 'This IOC type does not have a dedicated analysis method yet.',
            methodologyTh: 'IOC ประเภทนี้ยังไม่มีวิธีการวิเคราะห์เฉพาะ'
        });
    }

    // ============================================
    // 3. Entropy Analysis (max 20 points)
    // ONLY for domains - DGA detection
    // ============================================
    if (detectedType === 'domain') {
        const domainPart = iocValue.split('.')[0]; // First part of domain
        const entropy = calculateEntropy(domainPart);
        let entropyScore = 0;
        let entropyReason = '';
        let entropyReasonTh = '';

        if (entropy > 4.0) {
            entropyScore = 20;
            entropyReason = `Very high entropy (${entropy}) - Likely DGA generated`;
            entropyReasonTh = `ค่า Entropy สูงมาก (${entropy}) - น่าจะสร้างจากโปรแกรม (DGA)`;
        } else if (entropy > 3.5) {
            entropyScore = 10;
            entropyReason = `High entropy (${entropy}) - Possibly random`;
            entropyReasonTh = `ค่า Entropy สูง (${entropy}) - อาจเป็นชื่อสุ่ม`;
        } else if (entropy > 3.0) {
            entropyScore = 5;
            entropyReason = `Medium entropy (${entropy}) - Normal variation`;
            entropyReasonTh = `ค่า Entropy ปานกลาง (${entropy}) - ความผันแปรปกติ`;
        } else {
            entropyScore = 0;
            entropyReason = `Low entropy (${entropy}) - Appears legitimate`;
            entropyReasonTh = `ค่า Entropy ต่ำ (${entropy}) - ดูเป็นชื่อปกติ`;
        }
        breakdown.push({
            category: 'Entropy Analysis (DGA Detection)',
            categoryTh: 'การวิเคราะห์ความสุ่ม (ตรวจจับ DGA)',
            score: entropyScore,
            maxScore: 20,
            reason: entropyReason,
            reasonTh: entropyReasonTh,
            methodology: 'Calculate Shannon Entropy of domain name characters. DGA-generated domains (used by botnets) have high randomness >4.0. Legitimate domains like "google" have low entropy. Scoring: >4.0 = 20pts, >3.5 = 10pts, >3.0 = 5pts.',
            methodologyTh: 'คำนวณค่า Shannon Entropy ของตัวอักษรในชื่อโดเมน โดเมนที่สร้างจาก DGA (ใช้โดย botnet) จะมีความสุ่มสูง >4.0 โดเมนปกติเช่น "google" มีค่าต่ำ การให้คะแนน: >4.0 = 20 คะแนน, >3.5 = 10 คะแนน, >3.0 = 5 คะแนน'
        });
        totalScore += entropyScore;
    } else {
        // For non-domain types, show N/A
        breakdown.push({
            category: 'Entropy Analysis (DGA Detection)',
            categoryTh: 'การวิเคราะห์ความสุ่ม (ตรวจจับ DGA)',
            score: 0,
            maxScore: 20,
            reason: `N/A for ${detectedType} type`,
            reasonTh: `ไม่ใช้กับประเภท ${detectedType}`,
            methodology: 'Entropy analysis only applies to domain names. Hash values and IPs have inherently high/fixed entropy patterns.',
            methodologyTh: 'การวิเคราะห์ Entropy ใช้ได้กับโดเมนเท่านั้น Hash และ IP มีรูปแบบ entropy ที่แน่นอนอยู่แล้ว'
        });
    }

    // ============================================
    // 4. Keyword Context Analysis (max 15 points)
    // Applies to ALL IOC types
    // ============================================
    const allDescriptions = relatedEvents.map(e => e.description).join(' ');
    const foundKeywords = containsHighRiskKeywords(allDescriptions);
    let keywordScore = 0;
    let keywordReason = '';
    let keywordReasonTh = '';

    if (foundKeywords.length >= 3) {
        keywordScore = 15;
        keywordReason = `Multiple high-risk keywords: ${foundKeywords.slice(0, 3).join(', ')}`;
        keywordReasonTh = `พบคีย์เวิร์ดความเสี่ยงสูงหลายคำ: ${foundKeywords.slice(0, 3).join(', ')}`;
    } else if (foundKeywords.length >= 1) {
        keywordScore = 8;
        keywordReason = `High-risk keyword found: ${foundKeywords.join(', ')}`;
        keywordReasonTh = `พบคีย์เวิร์ดความเสี่ยงสูง: ${foundKeywords.join(', ')}`;
    } else {
        keywordScore = 0;
        keywordReason = 'No high-risk keywords detected';
        keywordReasonTh = 'ไม่พบคีย์เวิร์ดความเสี่ยงสูง';
    }
    breakdown.push({
        category: 'Keyword Context',
        categoryTh: 'การวิเคราะห์คีย์เวิร์ด',
        score: keywordScore,
        maxScore: 15,
        reason: keywordReason,
        reasonTh: keywordReasonTh,
        methodology: 'Scan descriptions for high-risk keywords: ransomware, zero-day, APT, backdoor, C2, botnet, phishing, malware, trojan, exploit, etc. Scoring: 3+ keywords = 15pts, 1-2 keywords = 8pts.',
        methodologyTh: 'ค้นหาคีย์เวิร์ดความเสี่ยงสูงใน description: ransomware, zero-day, APT, backdoor, C2, botnet, phishing, malware, trojan, exploit ฯลฯ การให้คะแนน: พบ 3+ คำ = 15 คะแนน, 1-2 คำ = 8 คะแนน'
    });
    totalScore += keywordScore;

    // Determine severity based on total score
    // Thresholds: Critical >= 45, High >= 30, Medium >= 15, Low >= 6
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

    return {
        totalScore,
        maxScore: maxPossibleScore,
        breakdown,
        severity
    };
}

/**
 * Auto-detect IOC type from value pattern
 */
function detectIOCType(value: string): string {
    if (/^CVE-\d{4}-\d+$/i.test(value)) return 'cve';
    if (/^[a-f0-9]{64}$/i.test(value)) return 'sha256';
    if (/^[a-f0-9]{40}$/i.test(value)) return 'sha1';
    if (/^[a-f0-9]{32}$/i.test(value)) return 'md5';
    if (/^(\d{1,3}\.){3}\d{1,3}$/.test(value)) return 'ip';
    if (/^https?:\/\//.test(value)) return 'url';
    return 'domain';
}

/**
 * Calculate threat score for an IOC based on number of sources
 * (Legacy function - kept for backwards compatibility)
 */
export function calculateThreatScore(
    iocValue: string,
    events: ThreatEvent[]
): ThreatScore {
    // Find all events with this IOC value
    const relatedEvents = events.filter(
        e => e.ioc.value.toLowerCase() === iocValue.toLowerCase()
    );

    // Get unique sources
    const sources = [...new Set(relatedEvents.map(e => e.source_name))];
    const sourceCount = sources.length;

    // Calculate score based on MoM requirements
    let score: number;
    let level: SeverityLevel;
    let explanation: string;

    if (sourceCount === 0) {
        score = 0;
        level = 'clean';
        explanation = 'IOC not found in any tracked sources';
    } else if (sourceCount === 1) {
        score = 50;
        level = 'medium';
        explanation = `Found in 1 source: ${sources[0]}`;
    } else {
        score = 100;
        level = 'high';
        explanation = `Found in ${sourceCount} sources: ${sources.join(', ')}`;
    }

    // Boost score based on severity of related events
    const maxSeverity = getMaxSeverity(relatedEvents);
    if (maxSeverity === 'critical' && score < 100) {
        score = Math.min(score + 25, 100);
        level = 'critical';
    } else if (maxSeverity === 'high' && score < 75) {
        score = Math.min(score + 15, 100);
    }

    return {
        value: score,
        level,
        sources,
        explanation,
    };
}

/**
 * Get the maximum severity from a list of events
 */
function getMaxSeverity(events: ThreatEvent[]): SeverityLevel {
    const severityOrder: SeverityLevel[] = ['clean', 'info', 'low', 'medium', 'high', 'critical'];

    let maxIndex = 0;
    for (const event of events) {
        const severity = event.severity as SeverityLevel || 'low';
        const index = severityOrder.indexOf(severity);
        if (index > maxIndex) {
            maxIndex = index;
        }
    }

    return severityOrder[maxIndex];
}

/**
 * Calculate confidence based on multiple factors
 */
export function calculateConfidence(events: ThreatEvent[]): number {
    if (events.length === 0) return 0;

    // Average confidence from events
    const avgConfidence = events.reduce((sum, e) => sum + (e.confidence || 0), 0) / events.length;

    // Boost for multiple sources
    const sources = new Set(events.map(e => e.source_name));
    const sourceBoost = Math.min(sources.size * 10, 30);

    // Boost for enrichment data
    const hasEnrichment = events.some(e => e.enrichment && Object.keys(e.enrichment).length > 0);
    const enrichmentBoost = hasEnrichment ? 10 : 0;

    return Math.min(avgConfidence + sourceBoost + enrichmentBoost, 100);
}

/**
 * Get severity color for display
 */
export function getSeverityColor(severity: SeverityLevel): string {
    const colors: Record<SeverityLevel, string> = {
        critical: 'var(--color-severity-critical)',
        high: 'var(--color-severity-high)',
        medium: 'var(--color-severity-medium)',
        low: 'var(--color-severity-low)',
        clean: 'var(--color-severity-clean)',
        info: 'var(--color-severity-info)',
    };
    return colors[severity] || colors.low;
}

/**
 * Get severity badge class
 */
export function getSeverityBadgeClass(severity: SeverityLevel): string {
    const classes: Record<SeverityLevel, string> = {
        critical: 'badge-critical',
        high: 'badge-high',
        medium: 'badge-medium',
        low: 'badge-low',
        clean: 'badge-low',
        info: 'badge-info',
    };
    return `badge ${classes[severity] || classes.low}`;
}

/**
 * Get IOC type badge class
 */
export function getIOCTypeBadgeClass(type: string): string {
    const classes: Record<string, string> = {
        ip: 'ioc-type ioc-type-ip',
        domain: 'ioc-type ioc-type-domain',
        sha256: 'ioc-type ioc-type-hash',
        sha1: 'ioc-type ioc-type-hash',
        md5: 'ioc-type ioc-type-hash',
        url: 'ioc-type ioc-type-url',
        cve: 'ioc-type ioc-type-cve',
    };
    return classes[type] || 'ioc-type';
}

/**
 * Format threat score for display
 */
export function formatThreatScore(score: number): string {
    if (score === 0) return 'N/A';
    return `${score}/100`;
}

/**
 * Get score color based on value
 */
export function getScoreColor(score: number): string {
    if (score >= 80) return 'var(--color-severity-critical)';
    if (score >= 60) return 'var(--color-severity-high)';
    if (score >= 40) return 'var(--color-severity-medium)';
    if (score >= 20) return 'var(--color-severity-low)';
    return 'var(--color-severity-clean)';
}

/**
 * Build EnhancedScoreBreakdown from ThreatEvent data (for consistent display in both Explorer and Detail pages)
 */
export function buildEnhancedBreakdown(event: {
    aiRiskScore?: number;
    aiSeverity?: string;
    aiSeverityTH?: string;
    aiScoreBreakdown?: Record<string, any>;
    aiTopFactors?: Array<{ factor: string; score: number; label: string }>;
    aiScoreSummary?: {
        traditional_score: number;
        ai_score: number;
        has_threat_actor: boolean;
        has_mitre: boolean;
        primary_threat: string | null;
    };
    severity?: string;
}): EnhancedScoreBreakdown {
    return {
        totalScore: event.aiRiskScore ?? 0,
        severity: (event.aiSeverity || event.severity || 'low') as SeverityLevel,
        severityTH: event.aiSeverityTH || '',
        breakdown: event.aiScoreBreakdown || {},
        topFactors: event.aiTopFactors || [],
        summary: event.aiScoreSummary || {
            traditional_score: 0,
            ai_score: 0,
            has_threat_actor: false,
            has_mitre: false,
            primary_threat: null
        }
    };
}

/**
 * Simple breakdown from normalized data
 */
export interface SimpleScoreBreakdown {
    crossSource: number;
    typeSpecific: number;
    entropy: number;
    keywords: number;
    sourceSeverity?: number;
}

/**
 * Convert simple aiScoreBreakdown from normalized data to full ScoreBreakdown for tooltip
 * Handles both flat format {crossSource: number} and nested format {cross_source: {score: number}}
 */
export function convertToScoreBreakdown(
    simpleBreakdown: SimpleScoreBreakdown | Record<string, any> | undefined,
    totalScore: number,
    severity: SeverityLevel
): ScoreBreakdown {
    const breakdown: ScoreBreakdown['breakdown'] = [];

    // Extract scores from either flat or nested format
    const getScore = (flatKey: string, nestedKey: string): number => {
        if (!simpleBreakdown) return 0;
        // Try flat format first (e.g., crossSource)
        if (typeof (simpleBreakdown as any)[flatKey] === 'number') {
            return (simpleBreakdown as any)[flatKey];
        }
        // Try nested format (e.g., cross_source: {score: 5})
        const nested = (simpleBreakdown as any)[nestedKey];
        if (nested && typeof nested === 'object' && typeof nested.score === 'number') {
            return nested.score;
        }
        return 0;
    };

    // Default values if no breakdown provided
    const bd = {
        crossSource: getScore('crossSource', 'cross_source'),
        typeSpecific: getScore('typeSpecific', 'type_specific') || getScore('typeSpecific', 'nlp'),
        entropy: getScore('entropy', 'entropy'),
        keywords: getScore('keywords', 'keywords'),
        sourceSeverity: getScore('sourceSeverity', 'source_severity') || getScore('sourceSeverity', 'source_quality'),
    };

    // 1. Cross-Source Validation
    breakdown.push({
        category: 'Cross-Source Validation',
        categoryTh: 'การตรวจสอบข้ามแหล่งข้อมูล',
        score: bd.crossSource,
        maxScore: 40,
        reason: bd.crossSource > 0
            ? `ได้รับคะแนนจากการพบในแหล่งข้อมูลที่น่าเชื่อถือ`
            : 'ไม่พบในแหล่งข้อมูล Threat Intelligence หรือ Security Tools',
        reasonTh: bd.crossSource > 0
            ? `ได้รับคะแนนจากการพบในแหล่งข้อมูลที่น่าเชื่อถือ`
            : 'ไม่พบในแหล่งข้อมูล Threat Intelligence หรือ Security Tools',
        methodology: 'Threat Intel sources (+15/source), Sandbox (+10), Security Tools (+10), Evidence like Zone-H (+8). News sources do not count.',
        methodologyTh: 'แหล่ง Threat Intel (+15/แหล่ง), Sandbox (+10), Security Tools (+10), หลักฐาน เช่น Zone-H (+8) แหล่งข่าวไม่นับคะแนน'
    });

    // 2. Type-Specific Analysis
    breakdown.push({
        category: 'IOC Characteristics',
        categoryTh: 'ลักษณะเฉพาะของ IOC',
        score: bd.typeSpecific,
        maxScore: 25,
        reason: bd.typeSpecific > 0
            ? `พบลักษณะที่น่าสงสัย หรือมี threat_type ระบุ`
            : 'ไม่พบลักษณะที่น่าสงสัยเป็นพิเศษ',
        reasonTh: bd.typeSpecific > 0
            ? `พบลักษณะที่น่าสงสัย หรือมี threat_type ระบุ`
            : 'ไม่พบลักษณะที่น่าสงสัยเป็นพิเศษ',
        methodology: 'For domains: domain age analysis. For IPs: geolocation risk. For hashes: malware associations. Threat type bonus (+5 per type).',
        methodologyTh: 'สำหรับ domain: วิเคราะห์อายุ สำหรับ IP: ความเสี่ยงทางภูมิศาสตร์ สำหรับ hash: ความเชื่อมโยงกับมัลแวร์ Bonus จาก threat_type (+5 ต่อประเภท)'
    });

    // 3. Entropy Analysis
    breakdown.push({
        category: 'Entropy (DGA Detection)',
        categoryTh: 'ความสุ่ม (ตรวจจับ DGA)',
        score: bd.entropy,
        maxScore: 20,
        reason: bd.entropy > 0
            ? `พบความสุ่มสูงในชื่อ อาจเป็น DGA-generated domain`
            : 'ความสุ่มปกติ ดูเป็นชื่อที่มนุษย์ตั้ง',
        reasonTh: bd.entropy > 0
            ? `พบความสุ่มสูงในชื่อ อาจเป็น DGA-generated domain`
            : 'ความสุ่มปกติ ดูเป็นชื่อที่มนุษย์ตั้ง',
        methodology: 'Shannon Entropy calculation. High entropy (>4.0) = DGA-generated. Only applies to domains.',
        methodologyTh: 'คำนวณ Shannon Entropy ค่าสูง (>4.0) = สร้างจาก DGA ใช้กับ domain เท่านั้น'
    });

    // 4. Keyword Analysis
    breakdown.push({
        category: 'Keyword Context',
        categoryTh: 'คำสำคัญที่พบ',
        score: bd.keywords,
        maxScore: 15,
        reason: bd.keywords > 0
            ? `พบคำสำคัญที่บ่งบอกถึงภัยคุกคาม`
            : 'ไม่พบคำสำคัญที่บ่งบอกถึงภัยคุกคาม',
        reasonTh: bd.keywords > 0
            ? `พบคำสำคัญที่บ่งบอกถึงภัยคุกคาม`
            : 'ไม่พบคำสำคัญที่บ่งบอกถึงภัยคุกคาม',
        methodology: 'Search for high-risk keywords: ransomware, malware, APT, backdoor, C2, botnet, phishing, trojan, exploit, etc.',
        methodologyTh: 'ค้นหาคำสำคัญ: ransomware, malware, APT, backdoor, C2, botnet, phishing, trojan, exploit ฯลฯ'
    });

    // 5. Source Severity (if available)
    if (bd.sourceSeverity !== undefined && bd.sourceSeverity > 0) {
        breakdown.push({
            category: 'Source Severity',
            categoryTh: 'Severity จากแหล่งต้นทาง',
            score: bd.sourceSeverity,
            maxScore: 15,
            reason: `แหล่งข้อมูลต้นทางให้ระดับความรุนแรงมาด้วย`,
            reasonTh: `แหล่งข้อมูลต้นทางให้ระดับความรุนแรงมาด้วย`,
            methodology: 'Bonus from source-provided severity: Critical (+15), High (+10), Medium (+5).',
            methodologyTh: 'คะแนนเพิ่มจาก severity ที่ source ให้มา: Critical (+15), High (+10), Medium (+5)'
        });
    }

    return {
        totalScore,
        maxScore: 100,
        breakdown,
        severity
    };
}
