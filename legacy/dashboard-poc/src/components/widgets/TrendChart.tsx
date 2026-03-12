'use client';

import { useEffect, useState } from 'react';
import {
  CartesianGrid,
  Line,
  LineChart,
  ReferenceLine,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis
} from 'recharts';
import type { TrendAnalyticsResponse } from '@/lib/analytics/types';
import styles from './TrendChart.module.css';

const SERIES = [
  { key: 'total', color: '#8b5cf6', label: 'Total' },
  { key: 'high', color: '#f59e0b', label: 'High+' },
  { key: 'critical', color: '#ef4444', label: 'Critical' },
] as const;

export default function TrendChart() {
  const [analytics, setAnalytics] = useState<TrendAnalyticsResponse | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetch('/api/trend-analytics')
      .then((res) => res.json())
      .then((data: TrendAnalyticsResponse) => {
        setAnalytics(data);
        setLoading(false);
      })
      .catch(() => setLoading(false));
  }, []);

  if (loading || !analytics) {
    return (
      <div className={styles.container}>
        <div className={styles.loading}>กำลังโหลดกราฟ...</div>
      </div>
    );
  }

  const historical = analytics.attack_volume_trend.historical;
  const forecast = analytics.attack_volume_trend.forecast;
  const historyCount = historical.length;

  const chartData = [
    ...historical.map((point) => ({
      label: point.label,
      fullLabel: point.hour,
      total: point.total,
      high: point.high,
      critical: point.critical,
      total_forecast: null,
      high_forecast: null,
      critical_forecast: null,
    })),
    ...forecast.map((point, index) => ({
      label: point.label,
      fullLabel: point.hour,
      total: index === 0 ? historical[historical.length - 1]?.total ?? 0 : null,
      high: index === 0 ? historical[historical.length - 1]?.high ?? 0 : null,
      critical: index === 0 ? historical[historical.length - 1]?.critical ?? 0 : null,
      total_forecast: point.total,
      high_forecast: point.high,
      critical_forecast: point.critical,
    })),
  ];

  return (
    <div className={styles.container}>
      <div className={styles.header}>
        <h3 className={styles.title}>
          <span className={styles.icon}>📈</span>
          Attack Volume Trend
        </h3>
        <div className={styles.legend}>
          <span className={styles.legendItem}>
            <span className={styles.solidLine}></span> Historical
          </span>
          <span className={styles.legendItem}>
            <span className={styles.dashedLine}></span> Forecast
          </span>
        </div>
      </div>

      <div className={styles.chartWrapper}>
        <ResponsiveContainer width="100%" height={300}>
          <LineChart data={chartData} margin={{ top: 10, right: 30, left: 0, bottom: 0 }}>
            <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.1)" />
            <XAxis
              dataKey="label"
              stroke="rgba(255,255,255,0.5)"
              tick={{ fill: 'rgba(255,255,255,0.6)', fontSize: 11 }}
            />
            <YAxis
              stroke="rgba(255,255,255,0.5)"
              tick={{ fill: 'rgba(255,255,255,0.6)', fontSize: 11 }}
            />
            <Tooltip
              contentStyle={{
                backgroundColor: 'rgba(30, 30, 46, 0.95)',
                border: '1px solid rgba(139, 92, 246, 0.3)',
                borderRadius: '8px',
                color: '#fff'
              }}
              labelStyle={{ color: '#fff' }}
            />
            <ReferenceLine
              x={chartData[historyCount]?.label}
              stroke="#fbbf24"
              strokeDasharray="5 5"
              label={{ value: 'พยากรณ์ →', fill: '#fbbf24', fontSize: 10 }}
            />

            {SERIES.map((series) => (
              <Line
                key={series.key}
                type="monotone"
                dataKey={series.key}
                name={series.label}
                stroke={series.color}
                strokeWidth={2}
                dot={{ r: 3 }}
                connectNulls={false}
              />
            ))}

            {SERIES.map((series) => (
              <Line
                key={`${series.key}_forecast`}
                type="monotone"
                dataKey={`${series.key}_forecast`}
                name={`${series.label} (forecast)`}
                stroke={series.color}
                strokeWidth={2}
                strokeDasharray="5 5"
                dot={{ r: 3, strokeDasharray: '0' }}
                connectNulls
                legendType="none"
              />
            ))}
          </LineChart>
        </ResponsiveContainer>
      </div>

      <div className={styles.footer}>
        <span>Historical: last {analytics.meta.window_hours} hours</span>
        <span>Model: {analytics.attack_volume_trend.model}</span>
      </div>
    </div>
  );
}
