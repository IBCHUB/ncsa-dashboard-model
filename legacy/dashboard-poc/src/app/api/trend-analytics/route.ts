import { NextResponse } from 'next/server';
import { buildTrendAnalytics } from '@/lib/analytics/trend-analytics';
import type { TrendAnalyticsResponse } from '@/lib/analytics/types';
import { checkElasticsearchHealth, getDataLakeByIndicators, searchWarehouse } from '@/lib/elastic';

export async function GET() {
    try {
        const health = await checkElasticsearchHealth('warehouse');
        if (!health.available) {
            return NextResponse.json(
                { error: 'Warehouse Elasticsearch unavailable' },
                { status: 503 }
            );
        }

        const trainingWindowHours = 72;
        const now = new Date();
        const dateFrom = new Date(now.getTime() - trainingWindowHours * 60 * 60 * 1000).toISOString();
        const dateTo = now.toISOString();

        const warehouse = await searchWarehouse({
            dateFrom,
            dateTo,
            limit: 5000,
            sortBy: 'time'
        });

        const indicators = warehouse.data.map((doc) => ({
            ioc_type: doc.ioc_type,
            ioc_value: doc.ioc_value
        }));
        const datalake = await getDataLakeByIndicators(indicators, 5000);

        const response: TrendAnalyticsResponse = buildTrendAnalytics(warehouse.data, datalake, now);
        return NextResponse.json(response);
    } catch (error) {
        console.error('Error in /api/trend-analytics:', error);
        return NextResponse.json(
            { error: 'Failed to build trend analytics' },
            { status: 500 }
        );
    }
}
