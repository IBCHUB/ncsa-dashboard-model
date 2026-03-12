import { NextResponse } from 'next/server';
import fs from 'fs';
import path from 'path';
import { checkElasticsearchHealth, searchWarehouse } from '@/lib/elastic';

const HISTORY_DAYS = 14;
const FORECAST_DAYS = 7;
const MAX_THREAT_TYPES = 5;

type Direction = 'increasing' | 'decreasing' | 'stable';
type AlertLevel = 'warning' | 'info' | 'success' | 'neutral';

interface TrendItem {
    threat_type: string;
    direction: Direction;
    change_percent: number;
    confidence: number;
    prediction_text: string;
    prediction_text_en: string;
    alert_level: AlertLevel;
    total_count: number;
}

interface TrendResponse {
    meta: {
        generated: string;
        date_range: {
            start: string;
            end: string;
            total_days: number;
        };
    };
    predictions: TrendItem[];
    top_increasing: TrendItem[];
    summary: {
        total_threat_types: number;
        increasing_count: number;
        decreasing_count: number;
        stable_count: number;
    };
    forecast_chart: {
        labels: string[];
        datasets: Record<string, { historical: number[]; forecast: number[] }>;
        forecast_start_index: number;
    };
}

function toIsoDate(date: Date): string {
    return date.toISOString().split('T')[0];
}

function avg(values: number[]): number {
    if (!values.length) return 0;
    return values.reduce((sum, value) => sum + value, 0) / values.length;
}

function normalizeDirection(changePercent: number): Direction {
    if (changePercent >= 10) return 'increasing';
    if (changePercent <= -10) return 'decreasing';
    return 'stable';
}

function buildPredictionText(type: string, direction: Direction, change: number): { th: string; en: string; level: AlertLevel } {
    if (direction === 'increasing') {
        const th = `${type} มีแนวโน้มเพิ่มขึ้นประมาณ ${Math.abs(change).toFixed(0)}%`;
        const en = `${type} is likely to increase by about ${Math.abs(change).toFixed(0)}%`;
        return { th, en, level: change >= 20 ? 'warning' : 'info' };
    }
    if (direction === 'decreasing') {
        const th = `${type} มีแนวโน้มลดลงประมาณ ${Math.abs(change).toFixed(0)}%`;
        const en = `${type} is likely to decrease by about ${Math.abs(change).toFixed(0)}%`;
        return { th, en, level: 'success' };
    }
    return {
        th: `${type} มีแนวโน้มทรงตัว`,
        en: `${type} is likely to remain stable`,
        level: 'neutral'
    };
}

function fallbackPredictions(): TrendResponse | null {
    try {
        const filePath = path.join(process.cwd(), 'public', 'data', 'predictions.json');
        if (!fs.existsSync(filePath)) {
            return null;
        }
        const raw = fs.readFileSync(filePath, 'utf-8');
        return JSON.parse(raw) as TrendResponse;
    } catch {
        return null;
    }
}

export async function GET() {
    try {
        const health = await checkElasticsearchHealth();
        if (!health.available) {
            const fallback = fallbackPredictions();
            if (fallback) {
                return NextResponse.json(fallback);
            }
            return NextResponse.json({
                meta: {
                    generated: new Date().toISOString(),
                    date_range: { start: '', end: '', total_days: 0 }
                },
                predictions: [],
                top_increasing: [],
                summary: {
                    total_threat_types: 0,
                    increasing_count: 0,
                    decreasing_count: 0,
                    stable_count: 0
                },
                forecast_chart: {
                    labels: [],
                    datasets: {},
                    forecast_start_index: 0
                }
            } satisfies TrendResponse);
        }

        const warehouse = await searchWarehouse({ limit: 5000, sortBy: 'time' });
        if (warehouse.data.length === 0) {
            return NextResponse.json({
                meta: {
                    generated: new Date().toISOString(),
                    date_range: {
                        start: '',
                        end: '',
                        total_days: HISTORY_DAYS
                    }
                },
                predictions: [],
                top_increasing: [],
                summary: {
                    total_threat_types: 0,
                    increasing_count: 0,
                    decreasing_count: 0,
                    stable_count: 0
                },
                forecast_chart: {
                    labels: [],
                    datasets: {},
                    forecast_start_index: 0
                }
            } satisfies TrendResponse);
        }

        const today = new Date();
        const historyLabels: string[] = [];
        for (let i = HISTORY_DAYS - 1; i >= 0; i--) {
            const d = new Date(today);
            d.setUTCDate(d.getUTCDate() - i);
            historyLabels.push(toIsoDate(d));
        }

        const forecastLabels: string[] = [];
        for (let i = 1; i <= FORECAST_DAYS; i++) {
            const d = new Date(today);
            d.setUTCDate(d.getUTCDate() + i);
            forecastLabels.push(toIsoDate(d));
        }

        const countByTypeDate: Record<string, Record<string, number>> = {};

        for (const doc of warehouse.data as any[]) {
            const rawDate = doc.event_time || doc.first_seen || doc.collect_time;
            const eventDate = rawDate ? toIsoDate(new Date(rawDate)) : '';
            if (!eventDate || !historyLabels.includes(eventDate)) continue;

            const aiTypes: unknown[] = Array.isArray(doc.ai_threat_types) ? doc.ai_threat_types : [];
            const fallbackTypes: unknown[] = Array.isArray(doc.threat_type) ? doc.threat_type : [];
            const selectedTypes: unknown[] = aiTypes.length > 0 ? aiTypes : fallbackTypes;
            const threatTypes: string[] = [
                ...new Set(
                    selectedTypes
                        .map((value: unknown) => String(value || '').trim())
                        .filter((value: string): value is string => value.length > 0)
                )
            ];
            const normalizedTypes: string[] = threatTypes.length > 0 ? threatTypes : ['Other'];

            for (const threatType of normalizedTypes) {
                if (!countByTypeDate[threatType]) {
                    countByTypeDate[threatType] = {};
                }
                countByTypeDate[threatType][eventDate] = (countByTypeDate[threatType][eventDate] || 0) + 1;
            }
        }

        const topTypes = Object.entries(countByTypeDate)
            .map(([type, byDate]) => ({
                type,
                total: Object.values(byDate).reduce((sum, n) => sum + n, 0)
            }))
            .sort((a, b) => b.total - a.total)
            .slice(0, MAX_THREAT_TYPES)
            .map(item => item.type);

        const predictions: TrendItem[] = [];
        const datasets: Record<string, { historical: number[]; forecast: number[] }> = {};

        for (const threatType of topTypes) {
            const perDate = countByTypeDate[threatType] || {};
            const historical = historyLabels.map(d => perDate[d] || 0);

            const firstHalf = historical.slice(0, Math.floor(HISTORY_DAYS / 2));
            const lastHalf = historical.slice(Math.floor(HISTORY_DAYS / 2));
            const previousAvg = avg(firstHalf);
            const recentAvg = avg(lastHalf);
            const changePercent = previousAvg > 0
                ? ((recentAvg - previousAvg) / previousAvg) * 100
                : (recentAvg > 0 ? 100 : 0);

            const direction = normalizeDirection(changePercent);
            const recentWindow = historical.slice(-7);
            const baseline = recentWindow[recentWindow.length - 1] || 0;
            const slope = recentWindow.length > 1
                ? (recentWindow[recentWindow.length - 1] - recentWindow[0]) / (recentWindow.length - 1)
                : 0;
            const forecast = Array.from({ length: FORECAST_DAYS }, (_, idx) =>
                Math.max(0, Math.round(baseline + slope * (idx + 1)))
            );

            const confidence = Math.min(
                0.95,
                0.45 +
                Math.min(Math.abs(changePercent), 80) / 200 +
                Math.min(historical.reduce((sum, n) => sum + n, 0), 50) / 100
            );
            const texts = buildPredictionText(threatType, direction, changePercent);

            datasets[threatType] = { historical, forecast };
            predictions.push({
                threat_type: threatType,
                direction,
                change_percent: Number(changePercent.toFixed(2)),
                confidence: Number(confidence.toFixed(2)),
                prediction_text: texts.th,
                prediction_text_en: texts.en,
                alert_level: texts.level,
                total_count: historical.reduce((sum, n) => sum + n, 0)
            });
        }

        const topIncreasing = predictions
            .filter(item => item.direction === 'increasing')
            .sort((a, b) => b.change_percent - a.change_percent)
            .slice(0, 5);

        const response: TrendResponse = {
            meta: {
                generated: new Date().toISOString(),
                date_range: {
                    start: historyLabels[0] || '',
                    end: historyLabels[historyLabels.length - 1] || '',
                    total_days: HISTORY_DAYS
                }
            },
            predictions,
            top_increasing: topIncreasing,
            summary: {
                total_threat_types: predictions.length,
                increasing_count: predictions.filter(p => p.direction === 'increasing').length,
                decreasing_count: predictions.filter(p => p.direction === 'decreasing').length,
                stable_count: predictions.filter(p => p.direction === 'stable').length
            },
            forecast_chart: {
                labels: [...historyLabels, ...forecastLabels],
                datasets,
                forecast_start_index: historyLabels.length
            }
        };

        return NextResponse.json(response);
    } catch (error) {
        console.error('Error in /api/trends:', error);
        const fallback = fallbackPredictions();
        if (fallback) {
            return NextResponse.json(fallback);
        }
        return NextResponse.json(
            { error: 'Failed to build trend data' },
            { status: 500 }
        );
    }
}
