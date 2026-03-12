import type { DataLakeDocument, WarehouseIOCDocument } from '@/lib/analytics/types';

export const ANALYTICS_TIMEZONE = 'Asia/Bangkok';
export const THREAT_LEVEL_CII_SECTORS = new Set([
    'critical_infrastructure',
    'government',
    'healthcare',
    'financial',
    'technology'
]);

const bangkokDateTime = new Intl.DateTimeFormat('sv-SE', {
    timeZone: ANALYTICS_TIMEZONE,
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    hourCycle: 'h23'
});

const bangkokDateOnly = new Intl.DateTimeFormat('sv-SE', {
    timeZone: ANALYTICS_TIMEZONE,
    year: 'numeric',
    month: '2-digit',
    day: '2-digit'
});

export function normalizeSeverity(input?: string | null): 'critical' | 'high' | 'medium' | 'low' | 'clean' {
    const value = String(input || '').trim().toLowerCase();
    switch (value) {
        case 'critical':
        case 'very high':
            return 'critical';
        case 'high':
            return 'high';
        case 'medium':
            return 'medium';
        case 'clean':
        case 'info':
            return 'clean';
        case 'low':
        default:
            return 'low';
    }
}

export function getWarehouseSeverity(doc: WarehouseIOCDocument): 'critical' | 'high' | 'medium' | 'low' | 'clean' {
    return normalizeSeverity(doc.ai_severity || doc.severity);
}

export function getEventTimestamp(
    doc: Pick<WarehouseIOCDocument, 'event_time' | 'first_seen' | 'collect_time'> |
        Pick<DataLakeDocument, 'event_time' | 'collect_time'>
): string | null {
    if (doc.event_time) {
        return doc.event_time;
    }
    if ('first_seen' in doc && doc.first_seen) {
        return doc.first_seen;
    }
    return doc.collect_time || null;
}

export function parseDate(value?: string | null): Date | null {
    if (!value) {
        return null;
    }

    const parsed = new Date(value);
    if (Number.isNaN(parsed.getTime())) {
        return null;
    }
    return parsed;
}

export function formatBangkokDate(value: Date): string {
    return bangkokDateOnly.format(value);
}

export function formatBangkokHour(value: Date): string {
    return `${bangkokDateTime.format(value).slice(0, 13)}:00`;
}

export function startOfBangkokDay(value: Date): Date {
    return new Date(`${formatBangkokDate(value)}T00:00:00+07:00`);
}

export function startOfBangkokHour(value: Date): Date {
    const hourKey = formatBangkokHour(value).replace(' ', 'T');
    return new Date(`${hourKey}:00+07:00`);
}

export function formatHourLabel(value: Date): string {
    return formatBangkokHour(value).slice(5);
}

export function addHours(value: Date, hours: number): Date {
    return new Date(value.getTime() + hours * 60 * 60 * 1000);
}

export function addDays(value: Date, days: number): Date {
    return new Date(value.getTime() + days * 24 * 60 * 60 * 1000);
}

export function getSectorInfo(doc: WarehouseIOCDocument): {
    sector: string;
    sector_name: string;
    sector_name_th: string;
    icon: string;
} {
    const sector = doc.ai_score_breakdown?.target_sector;
    return {
        sector: sector?.sector || 'general',
        sector_name: sector?.sector_name || 'General/Multiple',
        sector_name_th: sector?.sector_name_th || 'ทั่วไป',
        icon: sector?.icon || '🌐'
    };
}

export function getCountry(doc: DataLakeDocument | WarehouseIOCDocument): string | null {
    if ('enrichment' in doc) {
        return (
            doc.enrichment?.ip_info?.country ||
            doc.ip_info?.country ||
            doc.asn_data?.country_code ||
            doc.geo_info?.country ||
            doc.geo_country ||
            null
        );
    }

    return doc.geo_country || null;
}

export function clamp(value: number, min: number, max: number): number {
    return Math.min(Math.max(value, min), max);
}
