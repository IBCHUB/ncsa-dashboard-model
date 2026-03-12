'use client';

import { useEffect, useState, type CSSProperties } from 'react';
import type { ThreatLevelResponse } from '@/lib/analytics/types';
import styles from './ThreatLevel.module.css';

const LEVEL_CONFIG = {
  low: { color: '#4caf50', label: 'LOW', emoji: '🟢' },
  guarded: { color: '#facc15', label: 'GUARDED', emoji: '🟡' },
  elevated: { color: '#fb923c', label: 'ELEVATED', emoji: '🟠' },
  critical: { color: '#ef4444', label: 'CRITICAL', emoji: '🔴' },
} as const;

export default function ThreatLevel() {
  const [data, setData] = useState<ThreatLevelResponse | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    async function fetchThreatLevel() {
      try {
        const response = await fetch('/api/threat-level');
        if (!response.ok) {
          throw new Error('Failed to fetch threat level');
        }
        const payload = await response.json() as ThreatLevelResponse;
        setData(payload);
      } catch (error) {
        console.error('Error fetching threat level:', error);
      } finally {
        setLoading(false);
      }
    }

    fetchThreatLevel();
  }, []);

  if (loading) {
    return (
      <div className={styles.container}>
        <div className={styles.loading}>Loading threat level...</div>
      </div>
    );
  }

  if (!data) {
    return null;
  }

  const config = LEVEL_CONFIG[data.level];
  const topSector = data.top_sectors[0];
  const topActor = data.named_actors[0];

  return (
    <div className={styles.container} style={{ '--level-color': config.color } as CSSProperties}>
      <div className={styles.header}>
        <h3>🇹🇭 Thailand Threat Level</h3>
        <span className={styles.lastUpdate}>{data.date} ({data.timezone})</span>
      </div>

      <div className={styles.content}>
        <div className={styles.indicator}>
          <div className={styles.levelBadge} style={{ backgroundColor: config.color }}>
            <span className={styles.emoji}>{config.emoji}</span>
            <span className={styles.levelText}>{config.label}</span>
          </div>
          <p className={styles.description}>
            คะแนนรวม {data.score}/100 จาก IOC วันนี้ {data.inputs.total_iocs} รายการ
          </p>
        </div>

        <div className={styles.breakdown}>
          <div className={styles.stat}>
            <span className={styles.statValue}>{data.factors.volume.score}</span>
            <span className={styles.statLabel}>Volume</span>
          </div>
          <div className={styles.stat}>
            <span className={styles.statValue}>{data.factors.severity.score}</span>
            <span className={styles.statLabel}>Severity</span>
          </div>
          <div className={styles.stat}>
            <span className={styles.statValue}>{data.factors.sector.score}</span>
            <span className={styles.statLabel}>Sector</span>
          </div>
          <div className={styles.stat}>
            <span className={styles.statValue}>{data.factors.actor.score}</span>
            <span className={styles.statLabel}>Actor</span>
          </div>
        </div>

        <div className={styles.sectorSummary}>
          <div className={styles.sectorInfo}>
            <span className={styles.sectorIcon}>{topSector ? '🏭' : '📡'}</span>
            <div className={styles.sectorDetails}>
              <span className={styles.sectorName}>{topSector?.sector_name_th || 'ยังไม่พบภาคส่วนเด่น'}</span>
              <span className={styles.sectorThreat}>
                {topActor ? `Named actor: ${topActor.name}` : 'No named actor today'}
              </span>
            </div>
          </div>
          <div className={styles.sectorStats}>
            <span className={styles.affectedCount}>{data.inputs.high_critical_sector_count}</span>
            <span className={styles.affectedLabel}>High/Critical sectors</span>
          </div>
        </div>
      </div>
    </div>
  );
}
