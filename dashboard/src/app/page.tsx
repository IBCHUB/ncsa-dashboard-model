'use client';

import { useState, useEffect } from 'react';
import Header from '@/components/layout/Header';
import StatCard from '@/components/widgets/StatCard';
import SeverityChart from '@/components/widgets/SeverityChart';
import AlertTable from '@/components/widgets/AlertTable';
import ThreatLevel from '@/components/widgets/ThreatLevel';
import TrendPrediction from '@/components/widgets/TrendPrediction';
import TrendChart from '@/components/widgets/TrendChart';
import SectorThreatGrid from '@/components/widgets/SectorThreatGrid';
import type { DashboardStats, ThreatEvent } from '@/lib/types';
import styles from './page.module.css';

export default function DashboardPage() {
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    async function fetchData() {
      try {
        const response = await fetch('/api/stats');
        if (!response.ok) throw new Error('Failed to fetch stats');
        const data = await response.json();
        setStats(data.data);
      } catch (err) {
        setError(err instanceof Error ? err.message : 'An error occurred');
      } finally {
        setLoading(false);
      }
    }

    fetchData();
  }, []);

  if (loading) {
    return (
      <>
        <Header title="Operational Dashboard" />
        <div className="page-content">
          <div className={styles.loading}>
            <div className="loading-spinner" />
            <p>Loading threat intelligence...</p>
          </div>
        </div>
      </>
    );
  }

  if (error) {
    return (
      <>
        <Header title="Operational Dashboard" />
        <div className="page-content">
          <div className={styles.error}>
            <p>⚠️ Error: {error}</p>
            <button onClick={() => window.location.reload()} className="btn btn-primary">
              Retry
            </button>
          </div>
        </div>
      </>
    );
  }

  const severityData = {
    critical: stats?.bySeverity.critical || 0,
    high: stats?.bySeverity.high || 0,
    medium: stats?.bySeverity.medium || 0,
    low: (stats?.bySeverity.low || 0) + (stats?.bySeverity.clean || 0),
  };

  const topSources = Object.entries(stats?.bySource || {})
    .sort((a, b) => b[1] - a[1])
    .slice(0, 5);

  const topTypes = Object.entries(stats?.byType || {})
    .sort((a, b) => b[1] - a[1])
    .slice(0, 5);

  return (
    <>
      <Header title="Operational Dashboard" />
      <div className="page-content">
        {/* Thailand Threat Level & Trend Prediction */}
        <div className={styles.threatLevelRow}>
          <ThreatLevel />
          <TrendPrediction />
        </div>


        {/* Trend Chart */}
        <div className={styles.chartRow}>
          <TrendChart />
        </div>

        {/* Sector Threat Grid - NEW */}
        <div className={styles.sectorRow}>
          <SectorThreatGrid />
        </div>
        {/* Charts Row */}
        <div className={styles.chartsRow}>
          <SeverityChart data={severityData} title="Threats by Severity" />
          
          <div className={styles.topLists}>
            <div className={styles.topList}>
              <h4>Top Sources</h4>
              <ul>
                {topSources.map(([source, count]) => (
                  <li key={source}>
                    <span className={styles.listLabel}>{source}</span>
                    <span className={styles.listValue}>{count}</span>
                  </li>
                ))}
              </ul>
            </div>
            
            <div className={styles.topList}>
              <h4>Top IOC Types</h4>
              <ul>
                {topTypes.map(([type, count]) => (
                  <li key={type}>
                    <span className={`ioc-type ioc-type-${type === 'sha256' || type === 'md5' ? 'hash' : type}`}>
                      {type}
                    </span>
                    <span className={styles.listValue}>{count}</span>
                  </li>
                ))}
              </ul>
            </div>
          </div>
        </div>

        {/* Recent Alerts */}
        <div className={styles.alertsSection}>
          <AlertTable 
            alerts={stats?.recentAlerts || []} 
            title="Recent Threat Events"
            maxRows={10}
          />
        </div>

        {/* Last Updated */}
        <div className={styles.footer}>
          <span className={styles.lastUpdated}>
            Last updated: {stats?.lastUpdated ? new Date(stats.lastUpdated).toLocaleString('th-TH') : '-'}
          </span>
        </div>
      </div>
    </>
  );
}
