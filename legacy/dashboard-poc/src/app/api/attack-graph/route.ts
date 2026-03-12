import { NextRequest, NextResponse } from 'next/server';
import { buildAttackGraphResponse } from '@/lib/analytics/attack-graph';
import type { AttackGraphResponse } from '@/lib/analytics/types';
import { checkElasticsearchHealth, getDataLakeByIndicators, searchWarehouse } from '@/lib/elastic';

type GraphMode = 'with_actors' | 'with_entities' | 'all';

export async function GET(request: NextRequest) {
    try {
        const health = await checkElasticsearchHealth('warehouse');
        if (!health.available) {
            return NextResponse.json(
                { error: 'Warehouse Elasticsearch unavailable' },
                { status: 503 }
            );
        }

        const url = new URL(request.url);
        const mode = (url.searchParams.get('mode') || 'with_actors') as GraphMode;
        const limit = Number(url.searchParams.get('limit') || 250);

        const warehouse = await searchWarehouse({
            limit,
            sortBy: 'risk'
        });

        const indicators = warehouse.data.map((doc) => ({
            ioc_type: doc.ioc_type,
            ioc_value: doc.ioc_value
        }));
        const datalake = await getDataLakeByIndicators(indicators, limit * 3);

        const response: AttackGraphResponse = buildAttackGraphResponse(warehouse.data, datalake, mode);
        return NextResponse.json(response);
    } catch (error) {
        console.error('Error in /api/attack-graph:', error);
        return NextResponse.json(
            { error: 'Failed to build attack graph' },
            { status: 500 }
        );
    }
}
