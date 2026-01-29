'use client';

import { useState, useEffect } from 'react';
import styles from './SectorThreatGrid.module.css';

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

interface SectorGridProps {
  compact?: boolean;
}

const SEVERITY_COLORS: Record<string, string> = {
  critical: '#e53935',
  high: '#ff9800',
  medium: '#ffc107',
  low: '#4caf50',
  clean: '#2196f3',
};

export default function SectorThreatGrid({ compact = false }: SectorGridProps) {
  const [sectors, setSectors] = useState<Record<string, SectorData>>({});
  const [loading, setLoading] = useState(true);
  const [expandedSector, setExpandedSector] = useState<string | null>(null);

  useEffect(() => {
    fetchSectorData();
  }, []);

  const fetchSectorData = async () => {
    try {
      const response = await fetch('/api/sectors');
      const result = await response.json();
      if (result.success) {
        setSectors(result.data);
      }
    } catch (error) {
      console.error('Error fetching sector data:', error);
    } finally {
      setLoading(false);
    }
  };

  if (loading) {
    return (
      <div className={styles.container}>
        <div className={styles.header}>
          <h3>🏢 ระดับภัยคุกคามตามเซกเตอร์</h3>
        </div>
        <div className={styles.loading}>
          <div className="loading-spinner" />
          <p>กำลังโหลด...</p>
        </div>
      </div>
    );
  }

  const sectorEntries = Object.entries(sectors)
    .filter(([key]) => key !== 'general')
    .sort((a, b) => b[1].count - a[1].count);

  if (sectorEntries.length === 0) {
    return (
      <div className={styles.container}>
        <div className={styles.header}>
          <h3>🏢 ระดับภัยคุกคามตามเซกเตอร์</h3>
        </div>
        <div className={styles.empty}>
          <p>ยังไม่มีข้อมูลเซกเตอร์</p>
        </div>
      </div>
    );
  }

  return (
    <div className={styles.container}>
      <div className={styles.header}>
        <h3>🏢 ระดับภัยคุกคามตามเซกเตอร์</h3>
        <span className={styles.subtitle}>Sector-based Threat Levels</span>
      </div>

      <div className={styles.grid}>
        {sectorEntries.map(([key, sector]) => {
          const isExpanded = expandedSector === key;
          const threatColor = SEVERITY_COLORS[sector.threat_level] || '#666';

          return (
            <div
              key={key}
              className={`${styles.sectorCard} ${isExpanded ? styles.expanded : ''}`}
              onClick={() => setExpandedSector(isExpanded ? null : key)}
            >
              {/* Header */}
              <div className={styles.cardHeader}>
                <span className={styles.sectorIcon}>{sector.icon}</span>
                <div className={styles.sectorInfo}>
                  <span className={styles.sectorName}>{sector.name_th}</span>
                  <span className={styles.sectorNameEn}>{sector.name}</span>
                </div>
                <div
                  className={styles.threatLevel}
                  style={{ backgroundColor: threatColor }}
                >
                  {sector.threat_level_th}
                </div>
              </div>

              {/* Stats */}
              <div className={styles.statsRow}>
                <div className={styles.stat}>
                  <span className={styles.statValue}>{sector.count}</span>
                  <span className={styles.statLabel}>ภัยคุกคาม</span>
                </div>
                {sector.by_severity.critical > 0 && (
                  <div className={styles.stat}>
                    <span className={styles.statValue} style={{ color: SEVERITY_COLORS.critical }}>
                      {sector.by_severity.critical}
                    </span>
                    <span className={styles.statLabel}>วิกฤต</span>
                  </div>
                )}
                {sector.by_severity.high > 0 && (
                  <div className={styles.stat}>
                    <span className={styles.statValue} style={{ color: SEVERITY_COLORS.high }}>
                      {sector.by_severity.high}
                    </span>
                    <span className={styles.statLabel}>สูง</span>
                  </div>
                )}
              </div>

              {/* Expanded Details */}
              {isExpanded && (
                <div className={styles.expandedContent}>
                  {/* Severity Breakdown */}
                  <div className={styles.severityBar}>
                    {Object.entries(sector.by_severity).map(([sev, count]) => {
                      if (count === 0) return null;
                      const width = (count / sector.count) * 100;
                      return (
                        <div
                          key={sev}
                          className={styles.severitySegment}
                          style={{
                            width: `${width}%`,
                            backgroundColor: SEVERITY_COLORS[sev] || '#666',
                          }}
                          title={`${sev}: ${count}`}
                        />
                      );
                    })}
                  </div>

                  {/* Top Threat Types */}
                  {Object.keys(sector.top_threat_types).length > 0 && (
                    <div className={styles.threatTypes}>
                      <span className={styles.label}>ประเภทภัยคุกคามหลัก:</span>
                      <div className={styles.tags}>
                        {Object.entries(sector.top_threat_types)
                          .slice(0, 3)
                          .map(([type, count]) => (
                            <span key={type} className={styles.tag}>
                              {type} ({count})
                            </span>
                          ))}
                      </div>
                    </div>
                  )}

                  {/* Threat Actors */}
                  {sector.threat_actors.length > 0 && (
                    <div className={styles.threatActors}>
                      <span className={styles.label}>กลุ่มผู้โจมตี:</span>
                      <div className={styles.tags}>
                        {sector.threat_actors.slice(0, 3).map((actor) => (
                          <span key={actor} className={styles.actorTag}>
                            {actor}
                          </span>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}
