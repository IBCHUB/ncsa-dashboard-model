/**
 * Elasticsearch Client for Dashboard
 *
 * Provides connection to both Data Warehouse and Data Lake.
 */

import type { DataLakeDocument, WarehouseIOCDocument } from '@/lib/analytics/types';

const ELASTICSEARCH_URL = process.env.ELASTICSEARCH_URL || 'https://pluto-elk.ibusiness.co.th';
const WAREHOUSE_INDEX = process.env.WAREHOUSE_INDEX || 'cyber-logs-datawarehouse';
const DATALAKE_INDEX = process.env.DATALAKE_INDEX || 'cyber-logs-datalake';
const ELASTICSEARCH_API_KEY = process.env.ELASTICSEARCH_API_KEY || '';
const ELASTICSEARCH_DATALAKE_API_KEY = process.env.ELASTICSEARCH_DATALAKE_API_KEY || '';

type IndexKind = 'warehouse' | 'datalake';
type SearchQuery = Record<string, unknown>;

interface ESSearchHit<T> {
    _id: string;
    _source: T;
    _score: number | null;
}

interface ESSearchResponse<T> {
    hits: {
        total: { value: number };
        hits: ESSearchHit<T>[];
    };
    aggregations?: Record<string, unknown>;
}

type AggregationBucket = {
    key: string;
    doc_count: number;
};

export interface SearchParams {
    query?: string;
    iocTypes?: string[];
    severityLevels?: string[];
    dateFrom?: string;
    dateTo?: string;
    sortBy?: 'risk' | 'time';
    limit?: number;
    offset?: number;
}

function getIndexName(kind: IndexKind): string {
    return kind === 'warehouse' ? WAREHOUSE_INDEX : DATALAKE_INDEX;
}

function getApiKey(kind: IndexKind): string {
    if (kind === 'datalake') {
        return ELASTICSEARCH_DATALAKE_API_KEY || ELASTICSEARCH_API_KEY;
    }
    return ELASTICSEARCH_API_KEY;
}

function getHeaders(kind: IndexKind): Record<string, string> {
    const headers: Record<string, string> = {
        'Content-Type': 'application/json'
    };

    const apiKey = getApiKey(kind);
    if (apiKey) {
        headers.Authorization = `ApiKey ${apiKey}`;
    }

    return headers;
}

function buildDateFilter(dateFrom?: string, dateTo?: string): SearchQuery | null {
    if (!dateFrom && !dateTo) {
        return null;
    }

    const range: Record<string, string> = {};
    if (dateFrom) {
        range.gte = dateFrom.includes('T') ? dateFrom : `${dateFrom}T00:00:00+07:00`;
    }
    if (dateTo) {
        range.lte = dateTo.includes('T') ? dateTo : `${dateTo}T23:59:59+07:00`;
    }

    return {
        bool: {
            should: [
                { range: { event_time: range } },
                { range: { first_seen: range } },
                { range: { collect_time: range } }
            ],
            minimum_should_match: 1
        }
    };
}

async function runSearch<T>(kind: IndexKind, body: SearchQuery): Promise<ESSearchResponse<T>> {
    const response = await fetch(`${ELASTICSEARCH_URL}/${getIndexName(kind)}/_search`, {
        method: 'POST',
        headers: getHeaders(kind),
        body: JSON.stringify(body)
    });

    if (!response.ok) {
        const details = await response.text();
        throw new Error(`${kind} search failed: ${response.status} ${response.statusText} ${details}`);
    }

    return await response.json() as ESSearchResponse<T>;
}

function buildTimeSort(kind: IndexKind): SearchQuery[] {
    const sharedDateSort = { order: 'desc', missing: '_last', unmapped_type: 'date' as const };
    const sort: SearchQuery[] = [
        { event_time: sharedDateSort },
        { collect_time: sharedDateSort }
    ];

    if (kind === 'warehouse') {
        sort.push({ processed_at: sharedDateSort });
    } else {
        sort.push({ created_at: sharedDateSort });
    }

    return sort;
}

function buildSearchBody(kind: IndexKind, params: SearchParams): SearchQuery {
    const { query = '*', iocTypes, severityLevels, dateFrom, dateTo, sortBy = 'risk', limit = 100, offset = 0 } = params;

    const mustClauses: SearchQuery[] = [];
    const filterClauses: SearchQuery[] = [];

    if (query && query !== '*') {
        mustClauses.push({
            multi_match: {
                query,
                fields: kind === 'warehouse'
                    ? ['ioc_value^3', 'description', 'tags', 'ai_threat_types', 'ai_threat_actors', 'reference']
                    : ['ioc_value^3', 'description', 'reference', 'source_name']
            }
        });
    }

    if (iocTypes && iocTypes.length > 0) {
        filterClauses.push({ terms: { 'ioc_type.keyword': iocTypes } });
    }

    if (kind === 'warehouse' && severityLevels && severityLevels.length > 0) {
        filterClauses.push({ terms: { 'ai_severity.keyword': severityLevels } });
    }

    const dateFilter = buildDateFilter(dateFrom, dateTo);
    if (dateFilter) {
        filterClauses.push(dateFilter);
    }

    return {
        query: {
            bool: {
                must: mustClauses.length > 0 ? mustClauses : [{ match_all: {} }],
                filter: filterClauses
            }
        },
        sort: kind === 'warehouse' && sortBy === 'risk'
            ? [
                { ai_risk_score: { order: 'desc', missing: '_last', unmapped_type: 'long' } },
                { processed_at: { order: 'desc', missing: '_last', unmapped_type: 'date' } }
            ]
            : buildTimeSort(kind),
        from: offset,
        size: limit
    };
}

async function searchByIndicators<T>(
    kind: IndexKind,
    indicators: Array<{ ioc_type: string; ioc_value: string }>,
    limit = 500
): Promise<T[]> {
    const normalizedIndicators = Array.from(
        new Map(
            indicators
                .map((indicator) => ({
                    ioc_type: String(indicator.ioc_type || '').trim().toLowerCase(),
                    ioc_value: String(indicator.ioc_value || '').trim()
                }))
                .filter((indicator) => indicator.ioc_type && indicator.ioc_value)
                .map((indicator) => [`${indicator.ioc_type}::${indicator.ioc_value}`, indicator])
        ).values()
    );

    if (normalizedIndicators.length === 0) {
        return [];
    }

    const chunkSize = 100;
    const results: T[] = [];

    for (let index = 0; index < normalizedIndicators.length; index += chunkSize) {
        const batch = normalizedIndicators.slice(index, index + chunkSize);
        const should = batch.map((indicator) => ({
            bool: {
                must: [
                    { term: { 'ioc_type.keyword': indicator.ioc_type } },
                    { term: { 'ioc_value.keyword': indicator.ioc_value } }
                ]
            }
        }));

        const body: SearchQuery = {
            size: limit,
            query: {
                bool: {
                    should,
                    minimum_should_match: 1
                }
            },
            sort: buildTimeSort(kind)
        };

        try {
            const result = await runSearch<T>(kind, body);
            results.push(...result.hits.hits.map((hit) => hit._source));
        } catch (error) {
            console.error(`${kind} indicator search error:`, error);
            return results;
        }
    }

    return results.slice(0, limit);
}

export async function checkElasticsearchHealth(kind: IndexKind = 'warehouse'): Promise<{ status: string; available: boolean }> {
    try {
        await runSearch(kind, { size: 0, query: { match_all: {} } });
        return { status: 'green', available: true };
    } catch (error) {
        console.error(`[Elasticsearch] ${kind} health check failed:`, error);
        return { status: 'error', available: false };
    }
}

export async function searchWarehouse(params: SearchParams): Promise<{ total: number; data: WarehouseIOCDocument[] }> {
    try {
        const result = await runSearch<WarehouseIOCDocument>('warehouse', buildSearchBody('warehouse', params));
        return {
            total: result.hits.total.value,
            data: result.hits.hits.map((hit) => hit._source)
        };
    } catch (error) {
        console.error('Warehouse search error:', error);
        return { total: 0, data: [] };
    }
}

export async function searchDataLake(params: SearchParams): Promise<{ total: number; data: DataLakeDocument[] }> {
    try {
        const result = await runSearch<DataLakeDocument>('datalake', buildSearchBody('datalake', params));
        return {
            total: result.hits.total.value,
            data: result.hits.hits.map((hit) => hit._source)
        };
    } catch (error) {
        console.error('Data Lake search error:', error);
        return { total: 0, data: [] };
    }
}

export async function getWarehouseByIndicators(
    indicators: Array<{ ioc_type: string; ioc_value: string }>,
    limit = 500
): Promise<WarehouseIOCDocument[]> {
    return await searchByIndicators<WarehouseIOCDocument>('warehouse', indicators, limit);
}

export async function getDataLakeByIndicators(
    indicators: Array<{ ioc_type: string; ioc_value: string }>,
    limit = 500
): Promise<DataLakeDocument[]> {
    return await searchByIndicators<DataLakeDocument>('datalake', indicators, limit);
}

export async function getWarehouseStats(): Promise<{
    totalIOCs: number;
    bySeverity: Record<string, number>;
    byType: Record<string, number>;
    avgScore: number;
    topThreatTypes: Array<{ type: string; count: number }>;
}> {
    const aggsBody: SearchQuery = {
        size: 0,
        aggs: {
            by_severity: { terms: { field: 'ai_severity.keyword' } },
            by_type: { terms: { field: 'ioc_type.keyword' } },
            avg_score: { avg: { field: 'ai_risk_score' } },
            by_threat_type: { terms: { field: 'ai_threat_types.keyword', size: 20 } }
        }
    };

    try {
        const result = await runSearch<WarehouseIOCDocument>('warehouse', aggsBody);
        const aggregations = (result.aggregations || {}) as Record<string, { buckets?: AggregationBucket[]; value?: number }>;

        const bySeverity: Record<string, number> = {};
        aggregations.by_severity?.buckets?.forEach((bucket) => {
            bySeverity[bucket.key] = bucket.doc_count;
        });

        const byType: Record<string, number> = {};
        aggregations.by_type?.buckets?.forEach((bucket) => {
            byType[bucket.key] = bucket.doc_count;
        });

        const topThreatTypes = (aggregations.by_threat_type?.buckets || [])
            .map((bucket) => ({ type: bucket.key, count: bucket.doc_count }));

        return {
            totalIOCs: result.hits.total.value,
            bySeverity,
            byType,
            avgScore: aggregations.avg_score?.value || 0,
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
): Promise<WarehouseIOCDocument | null> {
    const searchBody: SearchQuery = {
        query: {
            bool: {
                must: [
                    { term: { 'ioc_value.keyword': iocValue } },
                    { term: { 'ioc_type.keyword': iocType } }
                ]
            }
        },
        size: 1
    };

    try {
        const result = await runSearch<WarehouseIOCDocument>('warehouse', searchBody);
        if (result.hits.hits.length > 0) {
            return result.hits.hits[0]._source;
        }
        return null;
    } catch (error) {
        console.error('Get IOC from warehouse error:', error);
        return null;
    }
}
