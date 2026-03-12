import { NextResponse } from 'next/server';

interface NewsArticle {
    id: string;
    title: string;
    url: string;
    source: string;
    date: string;
    relatedIOCs: Array<{ type: string; value: string }>;
    iocCount: number;
}

interface IOCData {
    type: string;
    value: string;
}

interface EventSource {
    source_type?: string;
    source_name: string;
    source_url: string;
    event_time: string;
    ioc: IOCData;
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

// Parse title from URL slug
function parseTitleFromUrl(url: string): string {
    try {
        const urlObj = new URL(url);
        const pathname = urlObj.pathname;

        // Get the last segment (filename)
        const segments = pathname.split('/').filter(Boolean);
        let slug = segments[segments.length - 1] || '';

        // Remove file extension
        slug = slug.replace(/\.(html|htm|php|aspx?)$/i, '');

        // Remove common patterns
        slug = slug.replace(/^index$/i, segments[segments.length - 2] || 'Article');

        // Replace hyphens/underscores with spaces
        slug = slug.replace(/[-_]/g, ' ');

        // Title case
        const title = slug
            .split(' ')
            .map(word => word.charAt(0).toUpperCase() + word.slice(1).toLowerCase())
            .join(' ');

        return title || 'Untitled Article';
    } catch {
        return 'Untitled Article';
    }
}

// Get source icon based on source name
function getSourceName(url: string, sourceName: string): string {
    if (url.includes('thehackernews.com')) return 'TheHackerNews';
    if (url.includes('darkreading.com')) return 'DarkReading';
    if (url.includes('bleepingcomputer.com')) return 'BleepingComputer';
    return sourceName;
}

// Check if URL is a valid news article
function isValidNewsUrl(url: string): boolean {
    if (!url || typeof url !== 'string') return false;

    // Only include major news sources
    const validDomains = [
        'thehackernews.com',
        'darkreading.com',
        'bleepingcomputer.com'
    ];

    return validDomains.some(domain => url.includes(domain));
}

export async function GET(request: Request) {
    try {
        // Get base URL from request
        const url = new URL(request.url);
        const baseUrl = `${url.protocol}//${url.host}`;

        // Map to group articles by URL
        const articleMap = new Map<string, {
            url: string;
            source: string;
            date: string;
            iocs: Array<{ type: string; value: string }>;
        }>();

        for (const filename of DATA_LAKE_FILES) {
            try {
                const response = await fetch(`${baseUrl}/data/${filename}`, { cache: 'no-store' });
                if (!response.ok) continue;

                const data = await response.json() as any;

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
                    const source: EventSource = hit._source || hit;

                    if (!source.source_url || !isValidNewsUrl(source.source_url)) continue;

                    const articleUrl = source.source_url;
                    const existing = articleMap.get(articleUrl);

                    if (existing) {
                        // Add IOC if not duplicate
                        if (source.ioc?.value) {
                            const isDuplicate = existing.iocs.some(
                                ioc => ioc.type === source.ioc.type && ioc.value === source.ioc.value
                            );
                            if (!isDuplicate) {
                                existing.iocs.push({
                                    type: source.ioc.type,
                                    value: source.ioc.value
                                });
                            }
                        }
                        // Use earliest date
                        if (source.event_time && source.event_time < existing.date) {
                            existing.date = source.event_time;
                        }
                    } else {
                        articleMap.set(articleUrl, {
                            url: articleUrl,
                            source: getSourceName(articleUrl, source.source_name),
                            date: source.event_time || new Date().toISOString(),
                            iocs: source.ioc?.value ? [{
                                type: source.ioc.type,
                                value: source.ioc.value
                            }] : []
                        });
                    }
                }
            } catch (err) {
                console.error(`Error processing ${filename}:`, err);
            }
        }

        // Convert to articles array
        const articles: NewsArticle[] = Array.from(articleMap.entries()).map(([url, data], idx) => ({
            id: `news-${idx}`,
            title: parseTitleFromUrl(url),
            url: data.url,
            source: data.source,
            date: data.date,
            relatedIOCs: data.iocs.slice(0, 5), // Limit to 5 IOCs shown
            iocCount: data.iocs.length
        }));

        // Sort by date (newest first)
        articles.sort((a, b) => new Date(b.date).getTime() - new Date(a.date).getTime());

        // Get unique sources for filtering
        const sources = [...new Set(articles.map(a => a.source))].sort();

        return NextResponse.json({
            success: true,
            data: articles,
            total: articles.length,
            sources
        });

    } catch (error) {
        console.error('Error fetching news:', error);
        return NextResponse.json({
            success: false,
            error: 'Failed to fetch news'
        }, { status: 500 });
    }
}
