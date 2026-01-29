import { NextResponse } from 'next/server';
import { COUNTRY_DATA, getCountryName } from '@/lib/countries';

interface CountryThreat {
    code: string;
    name: string;
    count: number;
    lat: number;
    lng: number;
    severities: Record<string, number>;
    primarySeverity: string;
}

interface GeoData {
    whois?: {
        country?: string;
        registrant_country?: string;
        admin_country?: string;
        tech_country?: string;
    };
    ip_info?: {
        country?: string;
        asn_data?: {
            country?: string;
        };
    };
}

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

// Extract country code from various data sources
function extractCountryCode(enrichment: GeoData | undefined): string | null {
    if (!enrichment) return null;

    // Priority: IP info country > WHOIS registrant > admin > tech
    const sources = [
        enrichment.ip_info?.country,
        enrichment.ip_info?.asn_data?.country,
        enrichment.whois?.country,
        enrichment.whois?.registrant_country,
        enrichment.whois?.admin_country,
        enrichment.whois?.tech_country,
    ];

    for (const source of sources) {
        if (source && typeof source === 'string' && source.length === 2) {
            const code = source.toUpperCase();
            // Skip redacted/invalid values
            if (code !== 'TH' && !code.includes('REDACT') && COUNTRY_DATA[code]) {
                return code;
            }
        }
    }

    return null;
}

export async function GET(request: Request) {
    try {
        // Get base URL from request
        const url = new URL(request.url);
        const baseUrl = `${url.protocol}//${url.host}`;

        // Count threats by country
        const countryMap = new Map<string, {
            count: number;
            severities: Record<string, number>;
        }>();

        for (const filename of DATA_LAKE_FILES) {
            try {
                const response = await fetch(`${baseUrl}/data/${filename}`, { cache: 'no-store' });
                if (!response.ok) continue;

                const data = await response.json();

                // Handle Elasticsearch format
                let hits: any[] = [];
                if (data.hits?.hits) {
                    hits = data.hits.hits;
                } else if (Array.isArray(data.hits)) {
                    hits = data.hits;
                } else if (Array.isArray(data)) {
                    hits = data;
                }

                for (const hit of hits) {
                    const source = hit._source || hit;
                    const enrichment = source.enrichment as GeoData | undefined;
                    const countryCode = extractCountryCode(enrichment);

                    if (countryCode) {
                        const existing = countryMap.get(countryCode) || {
                            count: 0,
                            severities: {}
                        };
                        existing.count++;

                        const severity = source.severity || 'unknown';
                        existing.severities[severity] = (existing.severities[severity] || 0) + 1;

                        countryMap.set(countryCode, existing);
                    }
                }
            } catch (err) {
                console.error(`Error processing ${filename}:`, err);
            }
        }

        // Convert to array with country info
        const countries: CountryThreat[] = Array.from(countryMap.entries())
            .map(([code, data]) => {
                const countryInfo = COUNTRY_DATA[code];
                if (!countryInfo) return null;

                // Determine primary severity
                const severityOrder = ['critical', 'high', 'medium', 'low', 'clean'];
                let primarySeverity = 'unknown';
                for (const sev of severityOrder) {
                    if (data.severities[sev] && data.severities[sev] > 0) {
                        primarySeverity = sev;
                        break;
                    }
                }

                return {
                    code,
                    name: countryInfo.name,
                    count: data.count,
                    lat: countryInfo.lat,
                    lng: countryInfo.lng,
                    severities: data.severities,
                    primarySeverity,
                };
            })
            .filter((c): c is CountryThreat => c !== null)
            .sort((a, b) => b.count - a.count);

        const totalThreats = countries.reduce((sum, c) => sum + c.count, 0);

        return NextResponse.json({
            success: true,
            data: {
                countries,
                topCountries: countries.slice(0, 10),
                totalThreats,
                uniqueCountries: countries.length,
                target: {
                    code: 'TH',
                    name: 'Thailand',
                    lat: 15.8700,
                    lng: 100.9925,
                }
            }
        });

    } catch (error) {
        console.error('Error fetching geo threats:', error);
        return NextResponse.json({
            success: false,
            error: 'Failed to fetch geo threats'
        }, { status: 500 });
    }
}
