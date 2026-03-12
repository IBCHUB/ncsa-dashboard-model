import { NextResponse } from 'next/server';
import type { DashboardStats, ThreatEvent, IOCType, SeverityLevel } from '@/lib/types';
import { checkElasticsearchHealth, searchWarehouse } from '@/lib/elastic';

const DATA_LAKE_FILES = [
    'bleeping-enrichment-15112025.json',
    'darkreading-enrichment-05012026.json',
    'darkreading-enrichment-15112025.json',
    'darkreading-enrichment-23012026.json',
    'sandbox-enrichment-16112025.json',
    'suricata-enrichment-16112025.json',
    'thehackernews-enrichment-23012026.json',
    'zoneh-enrichment-05012026.json',
    'zoneh-enrichment-17112025.json',
];

// Cache
let cachedStats: DashboardStats | null = null;
let cacheTime = 0;
const CACHE_TTL = 60000; // 1 minute

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

/**
 * Convert Warehouse document shape to ThreatEvent.
 */
function warehouseToThreatEvent(doc: any): ThreatEvent {
    return {
        source_type: doc.source_type || 'unknown',
        source_name: doc.source_name || 'unknown',
        collect_time: doc.last_seen || doc.processed_at || new Date().toISOString(),
        event_time: doc.first_seen || doc.event_time || doc.collect_time || new Date().toISOString(),
        threat_type: doc.threat_type || doc.ai_threat_types || [],
        severity: normalizeSeverity(doc.ai_severity || doc.severity || 'low'),
        confidence: doc.ai_classification_confidence || 0,
        ioc: {
            type: doc.ioc_type || 'ip',
            value: doc.ioc_value || ''
        },
        description: doc.description || '',
        tags: doc.tags || [],
        status: 'open' as any,
        aiRiskScore: doc.ai_risk_score,
        aiSeverity: doc.ai_severity,
        aiSeverityTH: doc.ai_severity_th,
        aiThreatTypes: doc.ai_threat_types || [],
        aiThreatActors: doc.ai_threat_actors || [],
        aiMitreTechniques: doc.ai_mitre_techniques || [],
        aiClassificationConfidence: doc.ai_classification_confidence,
        aiScoreBreakdown: doc.ai_score_breakdown,
        aiTopFactors: doc.ai_top_factors
    } as unknown as ThreatEvent;
}

/**
 * Load events from Data Warehouse first, then fallback to static files.
 */
async function loadAllEvents(baseUrl: string): Promise<ThreatEvent[]> {
    try {
        const health = await checkElasticsearchHealth();
        if (health.available) {
            const result = await searchWarehouse({ limit: 5000, sortBy: 'time' });
            return result.data.map(warehouseToThreatEvent);
        }
    } catch (error) {
        console.error('[Stats API] Elasticsearch unavailable, fallback to files', error);
    }

    // Try normalized data first
    try {
        const normalizedResponse = await fetch(`${baseUrl}/data/normalized_iocs.json`, { cache: 'no-store' });
        if (normalizedResponse.ok) {
            const data = await normalizedResponse.json();
            if (data.events && data.events.length > 0) {
                console.log(`[Stats API] Loaded ${data.events.length} events from normalized data`);
                return data.events as ThreatEvent[];
            }
        }
    } catch (error) {
        console.log('[Stats API] Normalized data not available, falling back to raw files');
    }

    // Fallback to raw data files
    const allEvents: ThreatEvent[] = [];

    for (const filename of DATA_LAKE_FILES) {
        try {
            const response = await fetch(`${baseUrl}/data/${filename}`, { cache: 'no-store' });
            if (!response.ok) continue;

            const data: any = await response.json();

            if (data.hits && Array.isArray(data.hits)) {
                for (const hit of data.hits) {
                    if (hit._source) {
                        allEvents.push({
                            ...hit._source,
                            severity: normalizeSeverity(hit._source.severity as string),
                        });
                    }
                }
            }
            // Handle Elasticsearch nested format: data.hits.hits
            else if (data.hits && data.hits.hits && Array.isArray(data.hits.hits)) {
                for (const hit of data.hits.hits) {
                    if (hit._source) {
                        allEvents.push({
                            ...hit._source,
                            severity: normalizeSeverity(hit._source.severity as string),
                        });
                    }
                }
            }
        } catch (error) {
            console.error(`Error loading ${filename}:`, error);
        }
    }

    return allEvents;
}

export async function GET(request: Request) {
    try {
        // Return cached stats if valid
        if (cachedStats && Date.now() - cacheTime < CACHE_TTL) {
            return NextResponse.json({
                success: true,
                data: cachedStats,
                cached: true,
            });
        }

        // Get base URL from request
        const url = new URL(request.url);
        const baseUrl = `${url.protocol}//${url.host}`;

        const events = await loadAllEvents(baseUrl);

        const byType: Record<string, number> = {};
        const bySeverity: Record<string, number> = {};
        const bySource: Record<string, number> = {};
        const byThreatType: Record<string, number> = {};

        for (const event of events) {
            // By IOC type
            const iocType = event.ioc?.type || 'unknown';
            byType[iocType] = (byType[iocType] || 0) + 1;

            // By severity (use AI severity if available)
            const severity = event.aiSeverity || event.severity || 'low';
            bySeverity[severity] = (bySeverity[severity] || 0) + 1;

            // By source
            const source = event.source_name || 'unknown';
            bySource[source] = (bySource[source] || 0) + 1;

            // By threat type (prefer AI threat types)
            const threatTypes = (event as any).aiThreatTypes || event.threat_type || [];
            if (Array.isArray(threatTypes)) {
                for (const threatType of threatTypes) {
                    if (threatType) {
                        byThreatType[threatType] = (byThreatType[threatType] || 0) + 1;
                    }
                }
            }
        }

        // Get recent alerts (last 10, sorted by event_time)
        const recentAlerts = [...events]
            .filter(e => e.event_time)
            .sort((a, b) => new Date(b.event_time).getTime() - new Date(a.event_time).getTime())
            .slice(0, 10);

        const stats: DashboardStats = {
            totalIOCs: events.length,
            byType: byType as Record<IOCType, number>,
            bySeverity: bySeverity as Record<SeverityLevel, number>,
            bySource,
            byThreatType,
            recentAlerts,
            lastUpdated: new Date().toISOString(),
        };

        // Cache the stats
        cachedStats = stats;
        cacheTime = Date.now();

        return NextResponse.json({
            success: true,
            data: stats,
        });
    } catch (error) {
        console.error('Error fetching stats:', error);
        return NextResponse.json(
            {
                success: false,
                error: error instanceof Error ? error.message : 'Unknown error',
            },
            { status: 500 }
        );
    }
}
