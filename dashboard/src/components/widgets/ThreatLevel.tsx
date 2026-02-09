'use client';

import { useEffect, useState } from 'react';
import styles from './ThreatLevel.module.css';

interface SectorData {
  id: string;
  name: string;
  nameEn: string;
  icon: string;
  criticalLevel: number;  // 1-5 scale
  attackCount: number;
  topThreat: string;
}

interface SectorApiData {
  name: string;
  name_th: string;
  icon: string;
  count: number;
  threat_level: 'clean' | 'low' | 'medium' | 'high' | 'critical';
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

interface SectorsResponse {
  success: boolean;
  data: Record<string, SectorApiData>;
}

interface ThreatLevelData {
  level: 'low' | 'medium' | 'high' | 'critical';
  score: number;
  description: string;
  topSector: SectorData | null;
  affectedSectors: number;
  totalSectors: number;
}

const LEVEL_CONFIG = {
  low: { color: '#4caf50', label: 'LOW', emoji: '🟢' },
  medium: { color: '#ffc107', label: 'MEDIUM', emoji: '🟡' },
  high: { color: '#ff9800', label: 'HIGH', emoji: '🟠' },
  critical: { color: '#e53935', label: 'CRITICAL', emoji: '🔴' },
};

export default function ThreatLevel() {
  const [data, setData] = useState<ThreatLevelData | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchThreatLevel();
  }, []);

  const fetchThreatLevel = async () => {
    try {
      const response = await fetch('/api/sectors');
      const sectorsData: SectorsResponse = await response.json();

      const sectorEntries = Object.entries(sectorsData?.data || {})
        .filter(([key]) => key !== 'general');

      if (sectorEntries.length === 0) {
        setLoading(false);
        return;
      }

      const severityLevelMap: Record<string, number> = {
        clean: 1,
        low: 2,
        medium: 3,
        high: 4,
        critical: 5,
      };

      const sectors: SectorData[] = sectorEntries.map(([key, sector]) => {
        const topThreat = Object.entries(sector.top_threat_types || {})
          .sort((a, b) => b[1] - a[1])[0]?.[0] || '-';
        return {
          id: key,
          name: sector.name_th,
          nameEn: sector.name,
          icon: sector.icon,
          criticalLevel: severityLevelMap[sector.threat_level] || 1,
          attackCount: sector.count || 0,
          topThreat
        };
      });

      // Find highest impacted sector
      const topSector = sectors.reduce((prev, curr) =>
        (curr.criticalLevel > prev.criticalLevel)
          ? curr
          : (curr.criticalLevel === prev.criticalLevel && curr.attackCount > prev.attackCount ? curr : prev)
      );

      // Count sectors with significant attacks (criticalLevel >= 3)
      const affectedSectors = sectors.filter(s => s.criticalLevel >= 3).length;
      const totalSectors = sectors.length;

      // Calculate score based on SECTOR IMPACT (as per MOM requirements)
      // Weight: criticalLevel of each sector, with higher weight for critical infrastructure
      const CRITICAL_INFRASTRUCTURE = ['financial', 'government', 'critical_infrastructure', 'healthcare'];
      
      let score = 0;
      for (const sector of sectors) {
        const multiplier = CRITICAL_INFRASTRUCTURE.includes(sector.id) ? 2 : 1;
        score += sector.criticalLevel * multiplier * 10 + Math.min(sector.attackCount, 20);
      }

      // Determine level based on SECTOR IMPACT
      let level: 'low' | 'medium' | 'high' | 'critical';
      let description: string;
      
      // Critical: Any critical infrastructure has criticalLevel >= 4 OR multiple sectors affected
      const hasHighCriticalInfra = sectors.some(
        s => CRITICAL_INFRASTRUCTURE.includes(s.id) && s.criticalLevel >= 4
      );
      const multipleSectorsAffected = affectedSectors >= 4;

      if (hasHighCriticalInfra || score >= 200) {
        level = 'critical';
        description = `ระดับภัยคุกคามวิกฤต - ${topSector.name} ถูกโจมตีอย่างหนัก`;
      } else if (multipleSectorsAffected || score >= 120) {
        level = 'high';
        description = `ระดับภัยคุกคามสูง - ${affectedSectors} ภาคส่วนได้รับผลกระทบ`;
      } else if (affectedSectors >= 2 || score >= 60) {
        level = 'medium';
        description = `ระดับภัยคุกคามปานกลาง - ${topSector.name} มีความเสี่ยง`;
      } else {
        level = 'low';
        description = 'ระดับภัยคุกคามต่ำ - สถานการณ์ปลอดภัย';
      }

      setData({
        level,
        score,
        description,
        topSector,
        affectedSectors,
        totalSectors,
      });
    } catch (error) {
      console.error('Error fetching threat level:', error);
    } finally {
      setLoading(false);
    }
  };

  if (loading) {
    return (
      <div className={styles.container}>
        <div className={styles.loading}>Loading threat level...</div>
      </div>
    );
  }

  if (!data) return null;

  const config = LEVEL_CONFIG[data.level];

  return (
    <div className={styles.container} style={{ '--level-color': config.color } as React.CSSProperties}>
      <div className={styles.header}>
        <h3>🇹🇭 Thailand Threat Level</h3>
        <span className={styles.lastUpdate}>Updated: Just now</span>
      </div>
      
      <div className={styles.content}>
        <div className={styles.indicator}>
          <div className={styles.levelBadge} style={{ backgroundColor: config.color }}>
            <span className={styles.emoji}>{config.emoji}</span>
            <span className={styles.levelText}>{config.label}</span>
          </div>
          <p className={styles.description}>{data.description}</p>
        </div>

        {/* Sector Impact Summary */}
        {data.topSector && (
          <div className={styles.sectorSummary}>
            <div className={styles.sectorInfo}>
              <span className={styles.sectorIcon}>{data.topSector.icon}</span>
              <div className={styles.sectorDetails}>
                <span className={styles.sectorName}>{data.topSector.name}</span>
                <span className={styles.sectorThreat}>Top: {data.topSector.topThreat}</span>
              </div>
            </div>
            <div className={styles.sectorStats}>
              <span className={styles.affectedCount}>{data.affectedSectors}/{data.totalSectors}</span>
              <span className={styles.affectedLabel}>ภาคส่วนที่ได้รับผลกระทบ</span>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
