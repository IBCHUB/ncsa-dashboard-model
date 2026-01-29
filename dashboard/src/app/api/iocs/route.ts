import { NextRequest, NextResponse } from 'next/server';
import type { ThreatEvent, SeverityLevel } from '@/lib/types';
import { checkElasticsearchHealth, searchWarehouse, getWarehouseStats } from '@/lib/elastic';

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

// Cache for fallback mode
let cachedEvents: ThreatEvent[] | null = null;
let cacheTime = 0;
const CACHE_TTL = 60000;

// Track if Elasticsearch is available
let esAvailable: boolean | null = null;
let esCheckTime = 0;
const ES_CHECK_TTL = 30000; // Re-check ES availability every 30 seconds

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
 * Check if Elasticsearch is available (with caching)
 */
async function isElasticsearchAvailable(): Promise<boolean> {
    if (esAvailable !== null && Date.now() - esCheckTime < ES_CHECK_TTL) {
        return esAvailable;
    }

    try {
        const health = await checkElasticsearchHealth();
        esAvailable = health.available;
        esCheckTime = Date.now();
        console.log(`[API] Elasticsearch status: ${health.status}`);
        return esAvailable;
    } catch (error) {
        esAvailable = false;
        esCheckTime = Date.now();
        return false;
    }
}

/**
 * Convert Elasticsearch warehouse document to ThreatEvent format
 */
function warehouseToThreatEvent(doc: any): ThreatEvent {
    return {
        source_type: doc.source_type || 'unknown',
        source_name: doc.source_name || 'unknown',
        collect_time: doc.last_seen || doc.processed_at,
        event_time: doc.first_seen || doc.event_time,
        threat_type: doc.threat_type || doc.ai_threat_types || [],
        severity: doc.ai_severity || doc.severity || 'low',
        confidence: doc.ai_classification_confidence || 0,
        ioc: {
            type: doc.ioc_type,
            value: doc.ioc_value
        },
        description: doc.description || '',
        tags: doc.tags || [],
        status: 'active' as any,
        // AI fields
        aiRiskScore: doc.ai_risk_score,
        aiSeverity: doc.ai_severity,
        aiSeverityTH: doc.ai_severity_th,
        aiThreatTypes: doc.ai_threat_types,
        aiThreatActors: doc.ai_threat_actors,
        aiMitreTechniques: doc.ai_mitre_techniques,
        aiClassificationConfidence: doc.ai_classification_confidence,
        aiScoreBreakdown: doc.ai_score_breakdown,
        aiTopFactors: doc.ai_top_factors
    } as unknown as ThreatEvent;
}

/**
 * Load events from Elasticsearch Data Warehouse
 * Falls back to JSON files if ES is unavailable
 */
async function loadAllEvents(baseUrl: string, params?: {
    query?: string;
    type?: string;
    severity?: string;
    limit?: number;
}): Promise<{ events: ThreatEvent[]; fromElasticsearch: boolean }> {
    // Try Elasticsearch first
    if (await isElasticsearchAvailable()) {
        try {
            const result = await searchWarehouse({
                query: params?.query,
                iocType: params?.type,
                severity: params?.severity,
                limit: params?.limit || 500
            });

            if (result.data.length > 0) {
                console.log(`[API] Loaded ${result.data.length} events from Elasticsearch`);
                return {
                    events: result.data.map(warehouseToThreatEvent),
                    fromElasticsearch: true
                };
            }
        } catch (error) {
            console.error('[API] Elasticsearch query failed:', error);
        }
    }

    // Fallback to cached data or JSON files
    if (cachedEvents && Date.now() - cacheTime < CACHE_TTL) {
        return { events: cachedEvents, fromElasticsearch: false };
    }

    // Try normalized data first
    try {
        const normalizedResponse = await fetch(`${baseUrl}/data/normalized_iocs.json`, { cache: 'no-store' });
        if (normalizedResponse.ok) {
            const data = await normalizedResponse.json();
            if (data.events && data.events.length > 0) {
                console.log(`[API] Loaded ${data.events.length} events from normalized JSON`);
                cachedEvents = data.events as ThreatEvent[];
                cacheTime = Date.now();
                return { events: data.events as ThreatEvent[], fromElasticsearch: false };
            }
        }
    } catch (error) {
        console.log('[API] Normalized data not available, falling back to raw files');
    }

    // Fallback to raw data files
    const allEvents: ThreatEvent[] = [];

    for (const filename of DATA_LAKE_FILES) {
        try {
            const response = await fetch(`${baseUrl}/data/${filename}`, { cache: 'no-store' });
            if (!response.ok) continue;

            const data: any = await response.json();
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
        } catch (error) {
            console.error(`Error loading ${filename}:`, error);
        }
    }

    cachedEvents = allEvents;
    cacheTime = Date.now();

    return { events: allEvents, fromElasticsearch: false };
}

export async function GET(request: NextRequest) {
    try {
        const { searchParams } = new URL(request.url);
        const query = searchParams.get('q') || '';
        const type = searchParams.get('type') || '';
        const severity = searchParams.get('severity') || '';
        const source = searchParams.get('source') || '';
        const threatType = searchParams.get('threatType') || '';
        const threatActor = searchParams.get('threatActor') || '';
        const limit = parseInt(searchParams.get('limit') || '100');

        // Get base URL from request
        const url = new URL(request.url);
        const baseUrl = `${url.protocol}//${url.host}`;

        // Load events (tries Elasticsearch first, falls back to JSON)
        const result = await loadAllEvents(baseUrl, { query, type, severity, limit });
        let events = result.events;

        // If we have Elasticsearch and filtered there, less filtering needed here
        // For JSON fallback, filter in-memory
        if (!result.fromElasticsearch) {
            // Filter by search query
            if (query) {
                const lowerQuery = query.toLowerCase();
                events = events.filter((e: ThreatEvent) =>
                    e.ioc.value.toLowerCase().includes(lowerQuery) ||
                    e.description?.toLowerCase().includes(lowerQuery) ||
                    e.tags?.some((t: string) => t.toLowerCase().includes(lowerQuery))
                );
            }

            // Filter by type
            if (type) {
                events = events.filter((e: ThreatEvent) => e.ioc.type === type);
            }

            // Filter by severity (use aiSeverity from normalized data)
            if (severity) {
                events = events.filter((e: ThreatEvent) => (e.aiSeverity || e.severity) === severity);
            }
        }

        // Additional filters always applied
        if (source) {
            events = events.filter((e: ThreatEvent) => e.source_name === source);
        }

        // Filter by threat type (from AI classification)
        if (threatType) {
            events = events.filter((e: ThreatEvent) => {
                const types = (e as any).aiThreatTypes || [];
                return types.includes(threatType);
            });
        }

        // Filter by threat actor
        if (threatActor) {
            events = events.filter((e: ThreatEvent) => {
                const actors = (e as any).aiThreatActors || [];
                return actors.includes(threatActor);
            });
        }

        // Get unique sources for filter dropdown
        const allEventsResult = await loadAllEvents(baseUrl);
        const allEvents = allEventsResult.events;
        const sources = [...new Set(allEvents.map((e: ThreatEvent) => e.source_name).filter(Boolean))].sort();

        // Get unique threat types for filter dropdown
        const threatTypes = [...new Set(
            allEvents
                .flatMap((e: any) => e.aiThreatTypes || [])
                .filter(Boolean)
        )].sort();

        // Get unique threat actors for filter dropdown
        const threatActors = [...new Set(
            allEvents
                .flatMap((e: any) => e.aiThreatActors || [])
                .filter(Boolean)
        )].sort();

        // Limit results
        const limitedEvents = events.slice(0, limit);

        return NextResponse.json({
            success: true,
            data: limitedEvents,
            total: events.length,
            sources,
            threatTypes,
            threatActors,
            fromElasticsearch: result.fromElasticsearch
        });
    } catch (error) {
        console.error('Error fetching IOCs:', error);
        return NextResponse.json(
            { success: false, error: 'Failed to fetch IOCs' },
            { status: 500 }
        );
    }
}

