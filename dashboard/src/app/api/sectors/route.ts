import { NextResponse } from 'next/server';
import fs from 'fs';
import path from 'path';
import { checkElasticsearchHealth, searchWarehouse } from '@/lib/elastic';

interface SectorData {
    name: string;
    name_th: string;
    icon: string;
    count: number;
    threat_level: string;
    threat_level_th: string;
    by_severity: {
        critical: number;
        high: number;
        medium: number;
        low: number;
    };
    top_threat_types: Record<string, number>;
    threat_actors: string[];
}

// Sector definitions matching AI service config
const SECTORS: Record<string, { name: string; name_th: string; icon: string; keywords: string[]; threat_actors: string[] }> = {
    financial: {
        name: "Financial Services",
        name_th: "ภาคการเงิน",
        icon: "🏦",
        keywords: ["bank", "banking", "financial", "payment", "credit", "fintech", "trading", "cryptocurrency", "crypto", "wallet", "swift", "atm"],
        threat_actors: ["Lazarus", "FIN7", "FIN8", "Carbanak", "Cobalt Group", "Qakbot", "TrickBot", "IcedID", "Emotet"]
    },
    government: {
        name: "Government",
        name_th: "ภาครัฐ",
        icon: "🏛️",
        keywords: ["government", "ministry", "agency", "federal", "military", "defense", "embassy", "diplomatic"],
        threat_actors: ["APT28", "APT29", "APT41", "Sandworm", "Turla", "Charming Kitten", "MuddyWater", "OilRig"]
    },
    healthcare: {
        name: "Healthcare",
        name_th: "ภาคสาธารณสุข",
        icon: "🏥",
        keywords: ["hospital", "health", "medical", "pharmaceutical", "clinic", "patient", "doctor", "medicine"],
        threat_actors: ["Conti", "Royal", "Ryuk", "Maze", "BlackCat"]
    },
    education: {
        name: "Education",
        name_th: "ภาคการศึกษา",
        icon: "🎓",
        keywords: ["university", "school", "college", "education", "academic", "research", "student"],
        threat_actors: ["Charming Kitten"]
    },
    critical_infrastructure: {
        name: "Critical Infrastructure",
        name_th: "โครงสร้างพื้นฐาน",
        icon: "⚡",
        keywords: ["power", "energy", "electricity", "water", "utility", "grid", "pipeline", "telecom", "scada", "ics"],
        threat_actors: ["Sandworm", "Xenotime", "Triton"]
    },
    technology: {
        name: "Technology",
        name_th: "ภาคเทคโนโลยี",
        icon: "💻",
        keywords: ["software", "hardware", "tech", "technology", "saas", "cloud", "developer"],
        threat_actors: ["APT41", "Winnti", "Barium"]
    },
    general: {
        name: "General/Multiple",
        name_th: "ทั่วไป",
        icon: "🌐",
        keywords: [],
        threat_actors: []
    }
};

function classifySector(description: string, threatActors: string[]): string {
    const text = description.toLowerCase();

    for (const [sectorKey, config] of Object.entries(SECTORS)) {
        if (sectorKey === 'general') continue;

        // Check keywords
        for (const keyword of config.keywords) {
            if (text.includes(keyword.toLowerCase())) {
                return sectorKey;
            }
        }

        // Check threat actors
        for (const actor of threatActors) {
            if (config.threat_actors.some(ta => ta.toLowerCase() === actor.toLowerCase())) {
                return sectorKey;
            }
        }
    }

    return 'general';
}

function determineThreatLevel(stats: { critical: number; high: number; medium: number; low: number }, total: number): { level: string; level_th: string } {
    if (total === 0) return { level: 'clean', level_th: 'ปลอดภัย' };

    const weighted = (stats.critical * 4 + stats.high * 3 + stats.medium * 2 + stats.low * 1) / total;

    if (weighted >= 3.5) return { level: 'critical', level_th: 'วิกฤต' };
    if (weighted >= 2.5) return { level: 'high', level_th: 'สูง' };
    if (weighted >= 1.5) return { level: 'medium', level_th: 'ปานกลาง' };
    if (weighted > 0) return { level: 'low', level_th: 'ต่ำ' };
    return { level: 'clean', level_th: 'ปลอดภัย' };
}

export async function GET() {
    try {
        let events: any[] = [];
        let usedElasticsearch = false;

        // Prefer Data Warehouse (real-time)
        try {
            const health = await checkElasticsearchHealth();
            if (health.available) {
                usedElasticsearch = true;
                const result = await searchWarehouse({ limit: 5000, sortBy: 'time' });
                events = result.data.map((doc: any) => ({
                    description: doc.description || '',
                    aiThreatActors: doc.ai_threat_actors || [],
                    aiThreatTypes: doc.ai_threat_types || [],
                    aiSeverity: doc.ai_severity,
                    severity: doc.severity,
                    aiScoreBreakdown: doc.ai_score_breakdown
                }));
            }
        } catch (error) {
            console.error('[Sectors API] Elasticsearch fallback to file', error);
        }

        // Fallback to normalized file
        if (!usedElasticsearch && events.length === 0) {
            const dataPath = path.join(process.cwd(), 'public', 'data', 'normalized_iocs.json');

            if (!fs.existsSync(dataPath)) {
                return NextResponse.json({
                    success: true,
                    data: {}
                });
            }

            const rawData = fs.readFileSync(dataPath, 'utf-8');
            const data = JSON.parse(rawData);
            events = data.events || data || [];
        }

        // Aggregate by sector
        const sectorStats: Record<string, SectorData> = {};

        for (const event of events) {
            const description = event.description || '';
            const threatActors = event.aiThreatActors || [];
            const sector = event.aiScoreBreakdown?.target_sector?.sector
                || classifySector(description, threatActors);

            if (!sectorStats[sector]) {
                const config = SECTORS[sector] || SECTORS.general;
                sectorStats[sector] = {
                    name: config.name,
                    name_th: config.name_th,
                    icon: config.icon,
                    count: 0,
                    threat_level: 'clean',
                    threat_level_th: 'ปลอดภัย',
                    by_severity: { critical: 0, high: 0, medium: 0, low: 0 },
                    top_threat_types: {},
                    threat_actors: []
                };
            }

            const stats = sectorStats[sector];
            stats.count++;

            // Count severity
            const severity = event.aiSeverity || event.severity || 'low';
            if (severity in stats.by_severity) {
                stats.by_severity[severity as keyof typeof stats.by_severity]++;
            }

            // Aggregate threat types
            const threatTypes = event.aiThreatTypes || [];
            for (const tt of threatTypes) {
                stats.top_threat_types[tt] = (stats.top_threat_types[tt] || 0) + 1;
            }

            // Collect threat actors
            for (const actor of threatActors) {
                if (!stats.threat_actors.includes(actor)) {
                    stats.threat_actors.push(actor);
                }
            }
        }

        // Calculate threat levels and sort threat types
        for (const sector of Object.keys(sectorStats)) {
            const stats = sectorStats[sector];
            const { level, level_th } = determineThreatLevel(stats.by_severity, stats.count);
            stats.threat_level = level;
            stats.threat_level_th = level_th;

            // Sort and limit threat types
            const sorted = Object.entries(stats.top_threat_types)
                .sort((a, b) => b[1] - a[1])
                .slice(0, 5);
            stats.top_threat_types = Object.fromEntries(sorted);

            // Limit threat actors
            stats.threat_actors = stats.threat_actors.slice(0, 5);
        }

        return NextResponse.json({
            success: true,
            data: sectorStats
        });

    } catch (error) {
        console.error('Error in sectors API:', error);
        return NextResponse.json({
            success: false,
            error: 'Failed to fetch sector data'
        }, { status: 500 });
    }
}
