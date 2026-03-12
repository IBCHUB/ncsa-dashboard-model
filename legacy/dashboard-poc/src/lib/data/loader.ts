/**
 * Data Loader - Load and normalize JSON data lake files
 */

import type {
    ThreatEvent,
    DataLakeResponse,
    DashboardStats,
    IOCType,
    SeverityLevel,
    TopItem,
    FilterOptions
} from '@/lib/types';

// Data lake file paths (relative to public folder)
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

// Cached data
let cachedEvents: ThreatEvent[] | null = null;
let cacheTimestamp: number = 0;
const CACHE_TTL = 5 * 60 * 1000; // 5 minutes

/**
 * Load all JSON data lake files
 */
export async function loadAllData(): Promise<ThreatEvent[]> {
    // Return cached data if valid
    if (cachedEvents && Date.now() - cacheTimestamp < CACHE_TTL) {
        return cachedEvents;
    }

    const allEvents: ThreatEvent[] = [];

    for (const filename of DATA_LAKE_FILES) {
        try {
            const response = await fetch(`/data_lake/${filename}`);
            if (!response.ok) continue;

            const data: DataLakeResponse = await response.json();

            if (data.hits && Array.isArray(data.hits)) {
                for (const hit of data.hits) {
                    if (hit._source) {
                        allEvents.push(normalizeEvent(hit._source));
                    }
                }
            }
        } catch (error) {
            console.error(`Error loading ${filename}:`, error);
        }
    }

    // Cache the results
    cachedEvents = allEvents;
    cacheTimestamp = Date.now();

    return allEvents;
}

/**
 * Normalize event data to standard format
 */
function normalizeEvent(event: ThreatEvent): ThreatEvent {
    return {
        ...event,
        // Normalize severity
        severity: normalizeSeverity(event.severity),
        // Normalize confidence (ensure 0-100)
        confidence: normalizeConfidence(event.confidence),
        // Ensure arrays
        threat_type: Array.isArray(event.threat_type) ? event.threat_type : [],
        tags: Array.isArray(event.tags) ? event.tags : [],
    };
}

/**
 * Normalize severity values
 */
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
 * Normalize confidence score (0-100)
 */
function normalizeConfidence(confidence: number | undefined): number {
    if (confidence === undefined || confidence === null) return 0;
    if (confidence > 100) return Math.min(confidence, 100);
    if (confidence < 0) return 0;
    return confidence;
}

/**
 * Filter events based on options
 */
export async function filterEvents(options: FilterOptions): Promise<ThreatEvent[]> {
    let events = await loadAllData();

    // Filter by type
    if (options.type) {
        const types = Array.isArray(options.type) ? options.type : [options.type];
        events = events.filter(e => types.includes(e.ioc.type));
    }

    // Filter by severity
    if (options.severity) {
        const severities = Array.isArray(options.severity) ? options.severity : [options.severity];
        events = events.filter(e => severities.includes(e.severity as SeverityLevel));
    }

    // Filter by source
    if (options.source) {
        const sources = Array.isArray(options.source) ? options.source : [options.source];
        events = events.filter(e => sources.includes(e.source_name));
    }

    // Filter by date range
    if (options.dateFrom) {
        const fromDate = new Date(options.dateFrom);
        events = events.filter(e => new Date(e.event_time) >= fromDate);
    }

    if (options.dateTo) {
        const toDate = new Date(options.dateTo);
        events = events.filter(e => new Date(e.event_time) <= toDate);
    }

    // Search query (searches IOC value, description, tags)
    if (options.searchQuery) {
        const query = options.searchQuery.toLowerCase();
        events = events.filter(e =>
            e.ioc.value.toLowerCase().includes(query) ||
            e.description?.toLowerCase().includes(query) ||
            e.tags?.some(t => t.toLowerCase().includes(query))
        );
    }

    // Pagination
    const offset = options.offset || 0;
    const limit = options.limit || 50;

    return events.slice(offset, offset + limit);
}

/**
 * Get single IOC by type and value
 */
export async function getIOC(type: IOCType, value: string): Promise<ThreatEvent | null> {
    const events = await loadAllData();
    return events.find(e => e.ioc.type === type && e.ioc.value === value) || null;
}

/**
 * Find all events related to an IOC value
 */
export async function findRelatedEvents(value: string): Promise<ThreatEvent[]> {
    const events = await loadAllData();
    const lowerValue = value.toLowerCase();

    return events.filter(e =>
        e.ioc.value.toLowerCase() === lowerValue ||
        e.ioc.related_domain?.some(d => d.toLowerCase() === lowerValue) ||
        e.ioc.related_hash?.some(h => h.toLowerCase() === lowerValue)
    );
}

/**
 * Calculate dashboard statistics
 */
export async function getDashboardStats(): Promise<DashboardStats> {
    const events = await loadAllData();

    const byType: Record<string, number> = {};
    const bySeverity: Record<string, number> = {};
    const bySource: Record<string, number> = {};
    const byThreatType: Record<string, number> = {};

    for (const event of events) {
        // By IOC type
        byType[event.ioc.type] = (byType[event.ioc.type] || 0) + 1;

        // By severity
        const severity = event.severity || 'low';
        bySeverity[severity] = (bySeverity[severity] || 0) + 1;

        // By source
        bySource[event.source_name] = (bySource[event.source_name] || 0) + 1;

        // By threat type
        for (const threatType of event.threat_type) {
            if (threatType) {
                byThreatType[threatType] = (byThreatType[threatType] || 0) + 1;
            }
        }
    }

    // Get recent alerts (last 10, sorted by event_time)
    const recentAlerts = [...events]
        .sort((a, b) => new Date(b.event_time).getTime() - new Date(a.event_time).getTime())
        .slice(0, 10);

    return {
        totalIOCs: events.length,
        byType: byType as Record<IOCType, number>,
        bySeverity: bySeverity as Record<SeverityLevel, number>,
        bySource,
        byThreatType,
        recentAlerts,
        lastUpdated: new Date().toISOString(),
    };
}

/**
 * Get Top N items by count
 */
export async function getTopItems(
    field: 'type' | 'source' | 'threat_type' | 'severity',
    limit: number = 10
): Promise<TopItem[]> {
    const events = await loadAllData();
    const counts: Record<string, number> = {};

    for (const event of events) {
        let value: string;

        switch (field) {
            case 'type':
                value = event.ioc.type;
                break;
            case 'source':
                value = event.source_name;
                break;
            case 'threat_type':
                for (const tt of event.threat_type) {
                    if (tt) {
                        counts[tt] = (counts[tt] || 0) + 1;
                    }
                }
                continue;
            case 'severity':
                value = event.severity || 'low';
                break;
            default:
                continue;
        }

        counts[value] = (counts[value] || 0) + 1;
    }

    return Object.entries(counts)
        .sort((a, b) => b[1] - a[1])
        .slice(0, limit)
        .map(([value, count]) => ({ value, count }));
}

/**
 * Get unique sources
 */
export async function getSources(): Promise<string[]> {
    const events = await loadAllData();
    return [...new Set(events.map(e => e.source_name))].sort();
}

/**
 * Get event counts grouped by date
 */
export async function getEventsByDate(days: number = 30): Promise<Record<string, number>> {
    const events = await loadAllData();
    const counts: Record<string, number> = {};

    const cutoffDate = new Date();
    cutoffDate.setDate(cutoffDate.getDate() - days);

    for (const event of events) {
        const eventDate = new Date(event.event_time);
        if (eventDate >= cutoffDate) {
            const dateKey = eventDate.toISOString().split('T')[0];
            counts[dateKey] = (counts[dateKey] || 0) + 1;
        }
    }

    return counts;
}
