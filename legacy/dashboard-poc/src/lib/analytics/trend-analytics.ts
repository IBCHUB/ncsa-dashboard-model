import type {
    AttackVolumeForecast,
    ComparisonSeries,
    DataLakeDocument,
    HourlySeverityPoint,
    TrendAnalyticsResponse,
    TrendComparisonChart,
    WarehouseIOCDocument
} from '@/lib/analytics/types';
import {
    ANALYTICS_TIMEZONE,
    addHours,
    formatBangkokHour,
    formatHourLabel,
    getCountry,
    getSectorInfo,
    getWarehouseSeverity,
    parseDate,
    startOfBangkokHour
} from '@/lib/analytics/shared';

const DEFAULT_WINDOW_HOURS = 24;
const DEFAULT_FORECAST_HOURS = 24;
const DEFAULT_TRAINING_WINDOW_HOURS = 72;

type Dimension = 'sources' | 'threat_types' | 'sectors' | 'countries';

function makeIndicatorKey(iocType: string, iocValue: string): string {
    return `${iocType.toLowerCase()}::${iocValue}`;
}

function createHourWindow(endHour: Date, hours: number): Date[] {
    return Array.from({ length: hours }, (_, index) => addHours(endHour, -(hours - index - 1)));
}

function getDocHourKey(doc: WarehouseIOCDocument): string | null {
    const timestamp = parseDate(doc.event_time || doc.first_seen || doc.collect_time);
    return timestamp ? formatBangkokHour(timestamp) : null;
}

function normalizeSources(doc: WarehouseIOCDocument): string[] {
    if (Array.isArray(doc.sources) && doc.sources.length > 0) {
        return doc.sources
            .map((source) => {
                if (typeof source === 'string') {
                    return source.trim();
                }
                return String(source.name || '').trim();
            })
            .filter(Boolean);
    }

    return String(doc.source_name || '')
        .split(',')
        .map((source) => source.trim())
        .filter(Boolean);
}

function calculateChange(points: number[]): { direction: 'up' | 'down' | 'flat'; change: number } {
    const half = Math.max(1, Math.floor(points.length / 2));
    const previous = points.slice(0, half);
    const recent = points.slice(half);
    const prevAvg = previous.reduce((sum, value) => sum + value, 0) / previous.length;
    const recentAvg = recent.reduce((sum, value) => sum + value, 0) / recent.length;

    if (prevAvg === 0 && recentAvg === 0) {
        return { direction: 'flat', change: 0 };
    }

    if (prevAvg === 0) {
        return { direction: 'up', change: 100 };
    }

    const change = ((recentAvg - prevAvg) / prevAvg) * 100;
    if (change >= 10) {
        return { direction: 'up', change };
    }
    if (change <= -10) {
        return { direction: 'down', change };
    }
    return { direction: 'flat', change };
}

function buildSeries(
    chartTitle: string,
    dimension: Dimension,
    labelsByKey: Map<string, string>,
    countsByKeyHour: Map<string, Map<string, number>>,
    bucketKeys: string[]
): TrendComparisonChart {
    const sorted = Array.from(countsByKeyHour.entries())
        .map(([key, counts]) => ({
            key,
            total: Array.from(counts.values()).reduce((sum, value) => sum + value, 0)
        }))
        .sort((a, b) => b.total - a.total)
        .slice(0, 5);

    const series: ComparisonSeries[] = sorted.map(({ key, total }) => {
        const counts = countsByKeyHour.get(key) || new Map<string, number>();
        const points = bucketKeys.map((bucket) => counts.get(bucket) || 0);
        const { direction, change } = calculateChange(points);
        return {
            key,
            label: labelsByKey.get(key) || key,
            points,
            total,
            direction,
            change_percent: Number(change.toFixed(2))
        };
    });

    return {
        title: chartTitle,
        dimension,
        buckets: bucketKeys.map((bucket) => bucket.slice(5)),
        series
    };
}

function seasonalAverageForecast(values: number[], horizon: number, seasonLength: number): number[] {
    if (values.length === 0) {
        return Array.from({ length: horizon }, () => 0);
    }

    if (values.length < seasonLength) {
        const lastValue = values[values.length - 1] || 0;
        return Array.from({ length: horizon }, () => Math.round(lastValue));
    }

    const season = values.slice(-seasonLength);
    return Array.from({ length: horizon }, (_, index) => Math.max(0, Math.round(season[index % season.length] || 0)));
}

function initialTrend(values: number[], seasonLength: number): number {
    let sum = 0;
    for (let index = 0; index < seasonLength; index += 1) {
        sum += (values[index + seasonLength] - values[index]) / seasonLength;
    }
    return sum / seasonLength;
}

function initialSeasonals(values: number[], seasonLength: number): number[] {
    const seasonCount = Math.floor(values.length / seasonLength);
    const averages = Array.from({ length: seasonCount }, (_, seasonIndex) => {
        const start = seasonIndex * seasonLength;
        const season = values.slice(start, start + seasonLength);
        return season.reduce((sum, value) => sum + value, 0) / season.length;
    });

    return Array.from({ length: seasonLength }, (_, offset) => {
        let sum = 0;
        for (let seasonIndex = 0; seasonIndex < seasonCount; seasonIndex += 1) {
            sum += values[seasonIndex * seasonLength + offset] - averages[seasonIndex];
        }
        return sum / seasonCount;
    });
}

function holtWintersForecast(values: number[], horizon: number): number[] {
    const seasonLength = 24;
    if (values.length < seasonLength * 2) {
        return seasonalAverageForecast(values, horizon, seasonLength);
    }

    const alpha = 0.4;
    const beta = 0.2;
    const gamma = 0.2;

    const seasonals = initialSeasonals(values, seasonLength);
    let level = values[0];
    let trend = initialTrend(values, seasonLength);

    for (let index = 1; index < values.length; index += 1) {
        const value = values[index];
        const seasonIndex = index % seasonLength;
        const lastLevel = level;
        level = alpha * (value - seasonals[seasonIndex]) + (1 - alpha) * (level + trend);
        trend = beta * (level - lastLevel) + (1 - beta) * trend;
        seasonals[seasonIndex] = gamma * (value - level) + (1 - gamma) * seasonals[seasonIndex];
    }

    return Array.from({ length: horizon }, (_, index) => {
        const seasonIndex = (values.length + index) % seasonLength;
        const forecastValue = level + (index + 1) * trend + seasonals[seasonIndex];
        return Math.max(0, Math.round(forecastValue));
    });
}

function makeForecastSeries(values: number[], horizon: number): { model: AttackVolumeForecast['model']; values: number[] } {
    const result = holtWintersForecast(values, horizon);
    return {
        model: values.length >= 48 ? 'holt_winters' : 'seasonal_average_fallback',
        values: result
    };
}

function buildVolumePoints(bucketKeys: string[], bucketCounts: Map<string, HourlySeverityPoint>): HourlySeverityPoint[] {
    return bucketKeys.map((bucket) => {
        const point = bucketCounts.get(bucket);
        return point || {
            hour: bucket,
            label: bucket.slice(5),
            total: 0,
            critical: 0,
            high: 0
        };
    });
}

export function buildTrendAnalytics(
    warehouseDocs: WarehouseIOCDocument[],
    datalakeDocs: DataLakeDocument[],
    now = new Date(),
    windowHours = DEFAULT_WINDOW_HOURS,
    forecastHours = DEFAULT_FORECAST_HOURS,
    trainingWindowHours = DEFAULT_TRAINING_WINDOW_HOURS
): TrendAnalyticsResponse {
    const currentHour = startOfBangkokHour(now);
    const visibleHours = createHourWindow(currentHour, windowHours);
    const trainingHours = createHourWindow(currentHour, trainingWindowHours);
    const visibleHourKeys = visibleHours.map((hour) => formatBangkokHour(hour));
    const trainingHourKeys = trainingHours.map((hour) => formatBangkokHour(hour));
    const visibleHourSet = new Set(visibleHourKeys);
    const trainingHourSet = new Set(trainingHourKeys);

    const datalakeByIndicator = new Map<string, DataLakeDocument[]>();
    for (const doc of datalakeDocs) {
        const key = makeIndicatorKey(doc.ioc_type, doc.ioc_value);
        const current = datalakeByIndicator.get(key);
        if (current) {
            current.push(doc);
        } else {
            datalakeByIndicator.set(key, [doc]);
        }
    }

    const sourceLabels = new Map<string, string>();
    const threatLabels = new Map<string, string>();
    const sectorLabels = new Map<string, string>();
    const countryLabels = new Map<string, string>();
    const sourceCounts = new Map<string, Map<string, number>>();
    const threatCounts = new Map<string, Map<string, number>>();
    const sectorCounts = new Map<string, Map<string, number>>();
    const countryCounts = new Map<string, Map<string, number>>();

    const visibleBuckets = new Map<string, HourlySeverityPoint>();
    const trainingBuckets = new Map<string, HourlySeverityPoint>();

    for (const doc of warehouseDocs) {
        const hourKey = getDocHourKey(doc);
        if (!hourKey || !trainingHourSet.has(hourKey)) {
            continue;
        }

        const severity = getWarehouseSeverity(doc);
        const trainingPoint = trainingBuckets.get(hourKey) || {
            hour: hourKey,
            label: hourKey.slice(5),
            total: 0,
            critical: 0,
            high: 0
        };
        trainingPoint.total += 1;
        if (severity === 'critical') {
            trainingPoint.critical += 1;
        }
        if (severity === 'critical' || severity === 'high') {
            trainingPoint.high += 1;
        }
        trainingBuckets.set(hourKey, trainingPoint);

        if (visibleHourSet.has(hourKey)) {
            const visiblePoint = visibleBuckets.get(hourKey) || {
                hour: hourKey,
                label: hourKey.slice(5),
                total: 0,
                critical: 0,
                high: 0
            };
            visiblePoint.total += 1;
            if (severity === 'critical') {
                visiblePoint.critical += 1;
            }
            if (severity === 'critical' || severity === 'high') {
                visiblePoint.high += 1;
            }
            visibleBuckets.set(hourKey, visiblePoint);

            for (const source of normalizeSources(doc)) {
                sourceLabels.set(source, source);
                const counts = sourceCounts.get(source) || new Map<string, number>();
                counts.set(hourKey, (counts.get(hourKey) || 0) + 1);
                sourceCounts.set(source, counts);
            }

            const threatTypes = doc.ai_threat_types?.length ? doc.ai_threat_types : (doc.threat_type || []);
            for (const threatType of threatTypes) {
                const key = threatType || 'Unknown';
                threatLabels.set(key, key);
                const counts = threatCounts.get(key) || new Map<string, number>();
                counts.set(hourKey, (counts.get(hourKey) || 0) + 1);
                threatCounts.set(key, counts);
            }

            const sectorInfo = getSectorInfo(doc);
            sectorLabels.set(sectorInfo.sector, sectorInfo.sector_name_th);
            const sectorSeries = sectorCounts.get(sectorInfo.sector) || new Map<string, number>();
            sectorSeries.set(hourKey, (sectorSeries.get(hourKey) || 0) + 1);
            sectorCounts.set(sectorInfo.sector, sectorSeries);

            const indicatorKey = makeIndicatorKey(doc.ioc_type, doc.ioc_value);
            const datalakeCandidates = datalakeByIndicator.get(indicatorKey) || [];
            const country = datalakeCandidates.map(getCountry).find(Boolean) || getCountry(doc);
            if (country) {
                countryLabels.set(country, country);
                const countrySeries = countryCounts.get(country) || new Map<string, number>();
                countrySeries.set(hourKey, (countrySeries.get(hourKey) || 0) + 1);
                countryCounts.set(country, countrySeries);
            }
        }
    }

    const threatVolumeTrend = buildVolumePoints(visibleHourKeys, visibleBuckets);
    const trainingVolumeTrend = buildVolumePoints(trainingHourKeys, trainingBuckets);

    const totalForecast = makeForecastSeries(trainingVolumeTrend.map((point) => point.total), forecastHours);
    const criticalForecast = makeForecastSeries(trainingVolumeTrend.map((point) => point.critical), forecastHours);
    const highForecast = makeForecastSeries(trainingVolumeTrend.map((point) => point.high), forecastHours);

    const forecastHoursList = Array.from({ length: forecastHours }, (_, index) => addHours(currentHour, index + 1));
    const attackVolumeForecast: AttackVolumeForecast = {
        model: totalForecast.model === 'holt_winters' ? 'holt_winters' : 'seasonal_average_fallback',
        historical: threatVolumeTrend,
        forecast: forecastHoursList.map((hour, index) => ({
            hour: formatBangkokHour(hour),
            label: formatHourLabel(hour),
            total: totalForecast.values[index] || 0,
            critical: criticalForecast.values[index] || 0,
            high: highForecast.values[index] || 0
        }))
    };

    const threatTypeChart = buildSeries('Top 5 Threat Types', 'threat_types', threatLabels, threatCounts, visibleHourKeys);

    return {
        meta: {
            generated_at: new Date().toISOString(),
            timezone: ANALYTICS_TIMEZONE,
            window_hours: windowHours,
            forecast_hours: forecastHours,
            training_window_hours: trainingWindowHours
        },
        summary: {
            total_events: threatVolumeTrend.reduce((sum, point) => sum + point.total, 0),
            critical_events: threatVolumeTrend.reduce((sum, point) => sum + point.critical, 0),
            high_events: threatVolumeTrend.reduce((sum, point) => sum + point.high, 0),
            forecast_total: attackVolumeForecast.forecast.reduce((sum, point) => sum + point.total, 0),
            forecast_critical: attackVolumeForecast.forecast.reduce((sum, point) => sum + point.critical, 0),
            forecast_high: attackVolumeForecast.forecast.reduce((sum, point) => sum + point.high, 0),
            top_rising_threat_types: [...threatTypeChart.series]
                .sort((a, b) => b.change_percent - a.change_percent)
                .slice(0, 4)
                .map((series) => ({
                    key: series.key,
                    label: series.label,
                    change_percent: series.change_percent,
                    total: series.total
                }))
        },
        comparison_charts: {
            sources: buildSeries('Top 5 Sources', 'sources', sourceLabels, sourceCounts, visibleHourKeys),
            threat_types: threatTypeChart,
            sectors: buildSeries('Top 5 Sectors', 'sectors', sectorLabels, sectorCounts, visibleHourKeys),
            countries: buildSeries('Top 5 Countries', 'countries', countryLabels, countryCounts, visibleHourKeys)
        },
        threat_volume_trend: threatVolumeTrend,
        attack_volume_trend: attackVolumeForecast
    };
}
