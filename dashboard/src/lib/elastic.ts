/**
 * Elasticsearch Client for Dashboard
 * 
 * Provides connection to Data Warehouse for querying AI-processed IOCs.
 */

const ELASTICSEARCH_URL = process.env.ELASTICSEARCH_URL || 'http://localhost:9200';
const WAREHOUSE_INDEX = process.env.WAREHOUSE_INDEX || 'tcti-warehouse';

interface ESSearchHit<T> {
    _id: string;
    _source: T;
    _score: number;
}

interface ESSearchResponse<T> {
    hits: {
        total: { value: number };
        hits: ESSearchHit<T>[];
    };
    aggregations?: Record<string, any>;
}

interface WarehouseIOC {
    ioc_value: string;
    ioc_type: string;
    source_name: string;
    sources: string[];
    description: string;
    threat_type: string[];
    severity: string;
    tags: string[];
    first_seen: string;
    last_seen: string;
    geo_country: string;
    ai_risk_score: number;
    ai_severity: string;
    ai_severity_th: string;
    ai_threat_types: string[];
    ai_threat_actors: string[];
    ai_mitre_techniques: string[];
    ai_classification_confidence: number;
    ai_score_breakdown: Record<string, any>;
    ai_top_factors: Array<{ factor: string; score: number; label: string }>;
    processed_at: string;
}

export async function checkElasticsearchHealth(): Promise<{ status: string; available: boolean }> {
    try {
        const response = await fetch(`${ELASTICSEARCH_URL}/_cluster/health`, {
            method: 'GET',
            headers: { 'Content-Type': 'application/json' },
        });

        if (!response.ok) {
            return { status: 'unavailable', available: false };
        }

        const data = await response.json();
        return {
            status: data.status,
            available: data.status === 'green' || data.status === 'yellow'
        };
    } catch (error) {
        console.error('Elasticsearch health check failed:', error);
        return { status: 'error', available: false };
    }
}

export async function searchWarehouse(params: {
    query?: string;
    iocType?: string;
    severity?: string;
    limit?: number;
    offset?: number;
}): Promise<{ total: number; data: WarehouseIOC[] }> {
    const { query = '*', iocType, severity, limit = 100, offset = 0 } = params;

    const mustClauses: any[] = [];

    if (query && query !== '*') {
        mustClauses.push({
            multi_match: {
                query,
                fields: ['ioc_value^3', 'description', 'tags', 'ai_threat_types', 'ai_threat_actors']
            }
        });
    }

    if (iocType) {
        mustClauses.push({ term: { ioc_type: iocType } });
    }

    if (severity) {
        mustClauses.push({ term: { ai_severity: severity } });
    }

    const searchBody = {
        query: {
            bool: {
                must: mustClauses.length > 0 ? mustClauses : [{ match_all: {} }]
            }
        },
        sort: [
            { ai_risk_score: 'desc' },
            { processed_at: 'desc' }
        ],
        from: offset,
        size: limit
    };

    try {
        const response = await fetch(`${ELASTICSEARCH_URL}/${WAREHOUSE_INDEX}/_search`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(searchBody)
        });

        if (!response.ok) {
            console.error('Warehouse search failed:', response.status);
            return { total: 0, data: [] };
        }

        const result: ESSearchResponse<WarehouseIOC> = await response.json();

        return {
            total: result.hits.total.value,
            data: result.hits.hits.map(hit => hit._source)
        };
    } catch (error) {
        console.error('Warehouse search error:', error);
        return { total: 0, data: [] };
    }
}

export async function getWarehouseStats(): Promise<{
    totalIOCs: number;
    bySeverity: Record<string, number>;
    byType: Record<string, number>;
    avgScore: number;
    topThreatTypes: Array<{ type: string; count: number }>;
}> {
    const aggsBody = {
        size: 0,
        aggs: {
            by_severity: { terms: { field: 'ai_severity' } },
            by_type: { terms: { field: 'ioc_type' } },
            avg_score: { avg: { field: 'ai_risk_score' } },
            by_threat_type: { terms: { field: 'ai_threat_types', size: 20 } }
        }
    };

    try {
        const response = await fetch(`${ELASTICSEARCH_URL}/${WAREHOUSE_INDEX}/_search`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(aggsBody)
        });

        if (!response.ok) {
            return {
                totalIOCs: 0,
                bySeverity: {},
                byType: {},
                avgScore: 0,
                topThreatTypes: []
            };
        }

        const result = await response.json();

        const bySeverity: Record<string, number> = {};
        result.aggregations?.by_severity?.buckets?.forEach((b: any) => {
            bySeverity[b.key] = b.doc_count;
        });

        const byType: Record<string, number> = {};
        result.aggregations?.by_type?.buckets?.forEach((b: any) => {
            byType[b.key] = b.doc_count;
        });

        const topThreatTypes = (result.aggregations?.by_threat_type?.buckets || [])
            .map((b: any) => ({ type: b.key, count: b.doc_count }));

        return {
            totalIOCs: result.hits.total.value,
            bySeverity,
            byType,
            avgScore: result.aggregations?.avg_score?.value || 0,
            topThreatTypes
        };
    } catch (error) {
        console.error('Warehouse stats error:', error);
        return {
            totalIOCs: 0,
            bySeverity: {},
            byType: {},
            avgScore: 0,
            topThreatTypes: []
        };
    }
}

export async function getIOCFromWarehouse(
    iocValue: string,
    iocType: string
): Promise<WarehouseIOC | null> {
    const searchBody = {
        query: {
            bool: {
                must: [
                    { term: { ioc_value: iocValue } },
                    { term: { ioc_type: iocType } }
                ]
            }
        },
        size: 1
    };

    try {
        const response = await fetch(`${ELASTICSEARCH_URL}/${WAREHOUSE_INDEX}/_search`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(searchBody)
        });

        if (!response.ok) {
            return null;
        }

        const result: ESSearchResponse<WarehouseIOC> = await response.json();

        if (result.hits.hits.length > 0) {
            return result.hits.hits[0]._source;
        }

        return null;
    } catch (error) {
        console.error('Get IOC from warehouse error:', error);
        return null;
    }
}
