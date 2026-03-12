'use client';

import { useEffect, useState } from 'react';
import type { TrendAnalyticsResponse } from '@/lib/analytics/types';
import styles from './TrendPrediction.module.css';

export default function TrendPrediction() {
  const [analytics, setAnalytics] = useState<TrendAnalyticsResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    fetch('/api/trend-analytics')
      .then((res) => {
        if (!res.ok) {
          throw new Error('Failed to load analytics');
        }
        return res.json() as Promise<TrendAnalyticsResponse>;
      })
      .then((data) => {
        setAnalytics(data);
        setLoading(false);
      })
      .catch((err: Error) => {
        setError(err.message);
        setLoading(false);
      });
  }, []);

  if (loading) {
    return (
      <div className={styles.container}>
        <div className={styles.loading}>กำลังโหลดการพยากรณ์...</div>
      </div>
    );
  }

  if (error || !analytics) {
    return (
      <div className={styles.container}>
        <div className={styles.error}>ไม่สามารถโหลดข้อมูลพยากรณ์ได้</div>
      </div>
    );
  }

  const { summary, meta } = analytics;

  return (
    <div className={styles.container}>
      <div className={styles.header}>
        <h3 className={styles.title}>
          <span className={styles.icon}>🔮</span>
          Trend Analytics
        </h3>
        <span className={styles.subtitle}>ย้อนหลัง {meta.window_hours} ชม. | Forecast {meta.forecast_hours} ชม.</span>
      </div>

      {summary.top_rising_threat_types.length > 0 && (
        <div className={styles.alertSection}>
          <div className={styles.alertHeader}>
            <span className={styles.alertIcon}>⚠️</span>
            <span>Threat types ที่เร่งตัวขึ้น</span>
          </div>
          <div className={styles.trendList}>
            {summary.top_rising_threat_types.map((item) => (
              <div
                key={item.key}
                className={`${styles.trendItem} ${item.change_percent >= 20 ? styles.warning : styles.info}`}
              >
                <div className={styles.trendType}>
                  <span className={styles.arrow}>{item.change_percent >= 0 ? '↑' : '↓'}</span>
                  <span>{item.label}</span>
                </div>
                <div className={styles.trendStats}>
                  <span className={styles.changePercent}>
                    {item.change_percent >= 0 ? '+' : ''}{item.change_percent.toFixed(0)}%
                  </span>
                  <span className={styles.confidence}>{item.total} events</span>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      <div className={styles.summary}>
        <div className={styles.summaryItem}>
          <span className={styles.summaryValue}>{summary.total_events}</span>
          <span className={styles.summaryLabel}>Events</span>
        </div>
        <div className={styles.summaryItem}>
          <span className={styles.summaryValue}>{summary.high_events}</span>
          <span className={styles.summaryLabel}>High/Critical</span>
        </div>
        <div className={styles.summaryItem}>
          <span className={styles.summaryValue}>{summary.forecast_total}</span>
          <span className={styles.summaryLabel}>Forecast total</span>
        </div>
      </div>

      <div className={styles.footer}>
        <span>Timezone: {meta.timezone}</span>
        <span className={styles.dateRange}>{new Date(meta.generated_at).toLocaleString('th-TH')}</span>
      </div>
    </div>
  );
}
