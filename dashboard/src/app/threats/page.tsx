'use client';

import { useState, useEffect } from 'react';
import Header from '@/components/layout/Header';
import type { DashboardStats, TopItem } from '@/lib/types';
import styles from './page.module.css';

export default function ThreatLandscapePage() {
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    async function fetchStats() {
      try {
        const response = await fetch('/api/stats');
        if (!response.ok) throw new Error('Failed to fetch');
        const data = await response.json();
        setStats(data.data);
      } catch (error) {
        console.error('Error fetching stats:', error);
      } finally {
        setLoading(false);
      }
    }
    fetchStats();
  }, []);

  if (loading) {
    return (
      <>
        <Header title="Threat Landscape" />
        <div className="page-content">
          <div className={styles.loading}>
            <div className="loading-spinner" />
            <p>Loading threat landscape...</p>
          </div>
        </div>
      </>
    );
  }

  const topSources = Object.entries(stats?.bySource || {})
    .sort((a, b) => b[1] - a[1])
    .slice(0, 10);

  const topTypes = Object.entries(stats?.byType || {})
    .sort((a, b) => b[1] - a[1])
    .slice(0, 10);

  const topThreatTypes = Object.entries(stats?.byThreatType || {})
    .sort((a, b) => b[1] - a[1])
    .slice(0, 10);

  // Get max values for bar chart scaling
  const maxSource = topSources[0]?.[1] || 1;
  const maxType = topTypes[0]?.[1] || 1;

  return (
    <>
      <Header title="Threat Landscape" />
      <div className="page-content">
        {/* Overview Stats */}
        <div className={styles.overviewGrid}>
          <div className={styles.statCard}>
            <span className={styles.statValue}>{stats?.totalIOCs?.toLocaleString() || 0}</span>
            <span className={styles.statLabel}>Total IOCs</span>
          </div>
          <div className={`${styles.statCard} ${styles.critical}`}>
            <span className={styles.statValue}>{stats?.bySeverity?.critical || 0}</span>
            <span className={styles.statLabel}>Critical Threats</span>
          </div>
          <div className={`${styles.statCard} ${styles.high}`}>
            <span className={styles.statValue}>{stats?.bySeverity?.high || 0}</span>
            <span className={styles.statLabel}>High Severity</span>
          </div>
          <div className={`${styles.statCard} ${styles.medium}`}>
            <span className={styles.statValue}>{stats?.bySeverity?.medium || 0}</span>
            <span className={styles.statLabel}>Medium Severity</span>
          </div>
        </div>

        {/* Charts Grid */}
        <div className={styles.chartsGrid}>
          {/* Top Sources Bar Chart */}
          <div className={styles.chartCard}>
            <h2>Top 10 Intelligence Sources</h2>
            <div className={styles.barChart}>
              {topSources.map(([source, count], idx) => (
                <div key={source} className={styles.barRow}>
                  <span className={styles.barRank}>#{idx + 1}</span>
                  <span className={styles.barLabel}>{source}</span>
                  <div className={styles.barTrack}>
                    <div
                      className={styles.barFill}
                      style={{ width: `${(count / maxSource) * 100}%` }}
                    />
                  </div>
                  <span className={styles.barValue}>{count.toLocaleString()}</span>
                </div>
              ))}
            </div>
          </div>

          {/* Top IOC Types Bar Chart */}
          <div className={styles.chartCard}>
            <h2>IOC Type Distribution</h2>
            <div className={styles.barChart}>
              {topTypes.map(([type, count], idx) => (
                <div key={type} className={styles.barRow}>
                  <span className={styles.barRank}>#{idx + 1}</span>
                  <span className={`${styles.barLabel} ${styles.typeLabel}`}>
                    <span className={`ioc-type ioc-type-${type === 'sha256' || type === 'md5' || type === 'sha1' ? 'hash' : type}`}>
                      {type}
                    </span>
                  </span>
                  <div className={styles.barTrack}>
                    <div
                      className={`${styles.barFill} ${styles.typeFill}`}
                      style={{ width: `${(count / maxType) * 100}%` }}
                    />
                  </div>
                  <span className={styles.barValue}>{count.toLocaleString()}</span>
                </div>
              ))}
            </div>
          </div>

          {/* Threat Types */}
          {topThreatTypes.length > 0 && (
            <div className={styles.chartCard}>
              <h2>Threat Categories</h2>
              <div className={styles.threatGrid}>
                {topThreatTypes.map(([type, count]) => (
                  <div key={type} className={styles.threatItem}>
                    <span className={styles.threatName}>
                      {type.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase())}
                    </span>
                    <span className={styles.threatCount}>{count}</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Severity Breakdown */}
          <div className={styles.chartCard}>
            <h2>Severity Breakdown</h2>
            <div className={styles.severityBars}>
              {Object.entries(stats?.bySeverity || {})
                .filter(([, count]) => count > 0)
                .sort((a, b) => b[1] - a[1])
                .map(([severity, count]) => (
                  <div key={severity} className={styles.severityRow}>
                    <span className={`badge badge-${severity}`}>{severity}</span>
                    <div className={styles.severityTrack}>
                      <div
                        className={`${styles.severityFill} ${styles[severity]}`}
                        style={{ width: `${(count / (stats?.totalIOCs || 1)) * 100}%` }}
                      />
                    </div>
                    <span className={styles.severityPercent}>
                      {((count / (stats?.totalIOCs || 1)) * 100).toFixed(1)}%
                    </span>
                    <span className={styles.severityCount}>{count.toLocaleString()}</span>
                  </div>
                ))}
            </div>
          </div>
        </div>

        {/* Last Updated */}
        <div className={styles.footer}>
          <span>Last updated: {stats?.lastUpdated ? new Date(stats.lastUpdated).toLocaleString('th-TH') : '-'}</span>
        </div>
      </div>
    </>
  );
}
