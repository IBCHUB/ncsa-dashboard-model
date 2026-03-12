import { NextResponse } from 'next/server';
import { buildThreatLevel } from '@/lib/analytics/threat-level';
import type { ThreatLevelResponse } from '@/lib/analytics/types';
import { checkElasticsearchHealth, searchWarehouse } from '@/lib/elastic';
import { addDays, formatBangkokDate, startOfBangkokDay } from '@/lib/analytics/shared';

export async function GET() {
    try {
        const health = await checkElasticsearchHealth('warehouse');
        if (!health.available) {
            return NextResponse.json(
                { error: 'Warehouse Elasticsearch unavailable' },
                { status: 503 }
            );
        }

        const today = startOfBangkokDay(new Date());
        const dateFrom = formatBangkokDate(addDays(today, -14));
        const dateTo = formatBangkokDate(today);

        const warehouse = await searchWarehouse({
            dateFrom,
            dateTo,
            limit: 5000,
            sortBy: 'time'
        });

        const response: ThreatLevelResponse = buildThreatLevel(warehouse.data);
        return NextResponse.json(response);
    } catch (error) {
        console.error('Error in /api/threat-level:', error);
        return NextResponse.json(
            { error: 'Failed to build threat level' },
            { status: 500 }
        );
    }
}
