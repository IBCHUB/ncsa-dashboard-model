import { NextResponse } from 'next/server';
import type { DashboardStats, ThreatEvent, IOCType, SeverityLevel } from '@/lib/types';

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
 * Try to load pre-computed normalized data first
 * Falls back to raw data files if normalized data doesn't exist
 */
async function loadAllEvents(baseUrl: string): Promise<ThreatEvent[]> {
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

            // By threat type
            if (Array.isArray(event.threat_type)) {
                for (const threatType of event.threat_type) {
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
