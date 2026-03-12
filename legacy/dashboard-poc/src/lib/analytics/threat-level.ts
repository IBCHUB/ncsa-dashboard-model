import type { ThreatLevelFactor, ThreatLevelResponse, WarehouseIOCDocument } from '@/lib/analytics/types';
import { ANALYTICS_TIMEZONE, THREAT_LEVEL_CII_SECTORS, addDays, formatBangkokDate, getSectorInfo, getWarehouseSeverity, parseDate, startOfBangkokDay } from '@/lib/analytics/shared';

function scoreVolume(spikeRatio: number): ThreatLevelFactor {
    if (spikeRatio >= 3) {
        return { score: 100, input: Number(spikeRatio.toFixed(2)), label: 'IOC Volume Spike', description: 'ผิดปกติมาก' };
    }
    if (spikeRatio >= 2) {
        return { score: 80, input: Number(spikeRatio.toFixed(2)), label: 'IOC Volume Spike', description: 'สูงกว่าปกติชัดเจน' };
    }
    if (spikeRatio >= 1.5) {
        return { score: 60, input: Number(spikeRatio.toFixed(2)), label: 'IOC Volume Spike', description: 'เริ่มผิดปกติ' };
    }
    if (spikeRatio >= 1) {
        return { score: 40, input: Number(spikeRatio.toFixed(2)), label: 'IOC Volume Spike', description: 'ปกติ' };
    }
    return { score: 20, input: Number(spikeRatio.toFixed(2)), label: 'IOC Volume Spike', description: 'น้อยกว่าปกติ' };
}

function scoreSeverity(ratio: number): ThreatLevelFactor {
    if (ratio >= 0.5) {
        return { score: 100, input: Number(ratio.toFixed(2)), label: 'Severity Distribution', description: 'ครึ่งหนึ่งเป็นภัยรุนแรง' };
    }
    if (ratio >= 0.3) {
        return { score: 80, input: Number(ratio.toFixed(2)), label: 'Severity Distribution', description: 'สัดส่วนภัยรุนแรงสูง' };
    }
    if (ratio >= 0.15) {
        return { score: 60, input: Number(ratio.toFixed(2)), label: 'Severity Distribution', description: 'สัดส่วนปานกลาง' };
    }
    if (ratio >= 0.05) {
        return { score: 40, input: Number(ratio.toFixed(2)), label: 'Severity Distribution', description: 'สัดส่วนปกติ' };
    }
    return { score: 20, input: Number(ratio.toFixed(2)), label: 'Severity Distribution', description: 'ส่วนใหญ่เป็น Low' };
}

function scoreSector(weightedSectorCount: number): ThreatLevelFactor {
    if (weightedSectorCount >= 4) {
        return { score: 100, input: Number(weightedSectorCount.toFixed(2)), label: 'Sector Impact', description: 'กระทบหลายภาคส่วนรวม CII' };
    }
    if (weightedSectorCount >= 3) {
        return { score: 80, input: Number(weightedSectorCount.toFixed(2)), label: 'Sector Impact', description: 'กระทบหลายภาคส่วน' };
    }
    if (weightedSectorCount >= 2) {
        return { score: 60, input: Number(weightedSectorCount.toFixed(2)), label: 'Sector Impact', description: 'กระทบอย่างน้อย 2 ภาคส่วน' };
    }
    if (weightedSectorCount >= 1) {
        return { score: 40, input: Number(weightedSectorCount.toFixed(2)), label: 'Sector Impact', description: 'พบผลกระทบบางส่วน' };
    }
    return { score: 10, input: Number(weightedSectorCount.toFixed(2)), label: 'Sector Impact', description: 'ยังไม่พบผลกระทบภาคส่วนสำคัญ' };
}

function scoreActor(actorCount: number): ThreatLevelFactor {
    if (actorCount >= 5) {
        return { score: 100, input: actorCount, label: 'Threat Actor Activity', description: 'ตรวจพบ named actors หลายราย' };
    }
    if (actorCount >= 3) {
        return { score: 80, input: actorCount, label: 'Threat Actor Activity', description: 'ตรวจพบ actor activity ชัดเจน' };
    }
    if (actorCount === 2) {
        return { score: 60, input: actorCount, label: 'Threat Actor Activity', description: 'ตรวจพบ actor 2 ราย' };
    }
    if (actorCount === 1) {
        return { score: 40, input: actorCount, label: 'Threat Actor Activity', description: 'ตรวจพบ actor 1 ราย' };
    }
    return { score: 10, input: actorCount, label: 'Threat Actor Activity', description: 'ไม่พบ named actor' };
}

function resolveLevel(score: number): Pick<ThreatLevelResponse, 'level' | 'level_th'> {
    if (score >= 76) {
        return { level: 'critical', level_th: 'วิกฤต' };
    }
    if (score >= 51) {
        return { level: 'elevated', level_th: 'ยกระดับ' };
    }
    if (score >= 26) {
        return { level: 'guarded', level_th: 'เฝ้าระวัง' };
    }
    return { level: 'low', level_th: 'ต่ำ' };
}

export function buildThreatLevel(docs: WarehouseIOCDocument[], now = new Date()): ThreatLevelResponse {
    const today = startOfBangkokDay(now);
    const todayKey = formatBangkokDate(today);

    const countsByDay = new Map<string, number>();
    const previousDays = Array.from({ length: 14 }, (_, index) => formatBangkokDate(addDays(today, -(index + 1))));
    previousDays.forEach((day) => countsByDay.set(day, 0));

    const todaysDocs: WarehouseIOCDocument[] = [];
    for (const doc of docs) {
        const eventTime = parseDate(doc.event_time || doc.first_seen || doc.collect_time);
        if (!eventTime) {
            continue;
        }
        const eventKey = formatBangkokDate(eventTime);
        if (eventKey === todayKey) {
            todaysDocs.push(doc);
        } else if (countsByDay.has(eventKey)) {
            countsByDay.set(eventKey, (countsByDay.get(eventKey) || 0) + 1);
        }
    }

    const totalToday = todaysDocs.length;
    const baselineAvg = previousDays.reduce((sum, day) => sum + (countsByDay.get(day) || 0), 0) / previousDays.length;
    const spikeRatio = baselineAvg > 0 ? totalToday / baselineAvg : (totalToday > 0 ? 3 : 0);

    const highCriticalDocs = todaysDocs.filter((doc) => {
        const severity = getWarehouseSeverity(doc);
        return severity === 'critical' || severity === 'high';
    });

    const severityRatio = totalToday > 0 ? highCriticalDocs.length / totalToday : 0;

    const sectorCountMap = new Map<string, { sector_name: string; sector_name_th: string; count: number }>();
    let ciiPresent = false;
    for (const doc of highCriticalDocs) {
        const sector = getSectorInfo(doc);
        ciiPresent = ciiPresent || THREAT_LEVEL_CII_SECTORS.has(sector.sector);
        const current = sectorCountMap.get(sector.sector);
        if (current) {
            current.count += 1;
        } else {
            sectorCountMap.set(sector.sector, {
                sector_name: sector.sector_name,
                sector_name_th: sector.sector_name_th,
                count: 1
            });
        }
    }

    const highCriticalSectorCount = sectorCountMap.size;
    const weightedSectorCount = highCriticalSectorCount * (ciiPresent ? 1.5 : 1.0);

    const actorCounts = new Map<string, number>();
    for (const doc of todaysDocs) {
        for (const actor of doc.ai_threat_actors || []) {
            actorCounts.set(actor, (actorCounts.get(actor) || 0) + 1);
        }
    }
    const actorCount = actorCounts.size;

    const volume = scoreVolume(spikeRatio);
    const severity = scoreSeverity(severityRatio);
    const sector = scoreSector(weightedSectorCount);
    const actor = scoreActor(actorCount);

    const score = Math.round(
        volume.score * 0.30 +
        severity.score * 0.25 +
        sector.score * 0.25 +
        actor.score * 0.20
    );

    const topSectors = Array.from(sectorCountMap.entries())
        .map(([sectorKey, item]) => ({
            sector: sectorKey,
            sector_name: item.sector_name,
            sector_name_th: item.sector_name_th,
            count: item.count
        }))
        .sort((a, b) => b.count - a.count)
        .slice(0, 5);

    const namedActors = Array.from(actorCounts.entries())
        .map(([name, count]) => ({ name, count }))
        .sort((a, b) => b.count - a.count)
        .slice(0, 5);

    return {
        date: todayKey,
        timezone: ANALYTICS_TIMEZONE,
        score,
        ...resolveLevel(score),
        factors: { volume, severity, sector, actor },
        inputs: {
            total_iocs: totalToday,
            baseline_avg_14d: Number(baselineAvg.toFixed(2)),
            spike_ratio: Number(spikeRatio.toFixed(2)),
            critical_high_ratio: Number(severityRatio.toFixed(2)),
            high_critical_sector_count: highCriticalSectorCount,
            cii_sector_present: ciiPresent,
            named_actor_count: actorCount
        },
        top_sectors: topSectors,
        named_actors: namedActors
    };
}
