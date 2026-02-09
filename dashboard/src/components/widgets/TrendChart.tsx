'use client';

import { useState, useEffect } from 'react';
import {
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Legend,
  ResponsiveContainer,
  ReferenceLine
} from 'recharts';
import styles from './TrendChart.module.css';

interface ForecastData {
  labels: string[];
  datasets: {
    [key: string]: {
      historical: number[];
      forecast: number[];
    };
  };
  forecast_start_index: number;
}

interface PredictionsData {
  meta: {
    generated: string;
    date_range: {
      start: string;
      end: string;
      total_days: number;
    };
  };
  forecast_chart: ForecastData;
}

const COLORS = [
  '#8b5cf6', // Purple - APT
  '#ef4444', // Red - Vulnerability
  '#f59e0b', // Orange - Data Breach
  '#10b981', // Green - Malware
  '#3b82f6', // Blue - Other
];

export default function TrendChart() {
  const [predictions, setPredictions] = useState<PredictionsData | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetch('/api/trends')
      .then(res => res.json())
      .then(data => {
        setPredictions(data);
        setLoading(false);
      })
      .catch(() => setLoading(false));
  }, []);

  if (loading || !predictions?.forecast_chart) {
    return (
      <div className={styles.container}>
        <div className={styles.loading}>กำลังโหลดกราฟ...</div>
      </div>
    );
  }

  const { forecast_chart } = predictions;
  const { labels, datasets, forecast_start_index } = forecast_chart;
  const historyCount = forecast_start_index;

  // Transform data for Recharts - dual line approach (solid historical + dashed forecast)
  const chartData = labels.map((label, idx) => {
    const dataPoint: Record<string, string | number | null> = {
      date: label.slice(5), // MM-DD format
      fullDate: label,
    };

    Object.entries(datasets).forEach(([type, values]) => {
      if (idx < historyCount) {
        // Historical data - solid line
        dataPoint[type] = values.historical[idx] ?? null;
        dataPoint[`${type}_forecast`] = null;
      } else if (idx === historyCount) {
        // Transition point - connect last historical to first forecast
        const lastHistorical = values.historical[values.historical.length - 1] ?? 0;
        dataPoint[type] = lastHistorical;
        dataPoint[`${type}_forecast`] = values.forecast[0] ?? lastHistorical;
      } else {
        // Forecast data - dashed line
        const forecastIdx = idx - historyCount;
        dataPoint[type] = null;
        dataPoint[`${type}_forecast`] = values.forecast[forecastIdx] ?? null;
      }
    });

    return dataPoint;
  });

  const threatTypes = Object.keys(datasets);

  return (
    <div className={styles.container}>
      <div className={styles.header}>
        <h3 className={styles.title}>
          <span className={styles.icon}>📈</span>
          Threat Trend Analysis
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
              dataKey="date" 
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
              x={labels[historyCount]?.slice(5)}
              stroke="#fbbf24"
              strokeDasharray="5 5"
              label={{ value: 'พยากรณ์ →', fill: '#fbbf24', fontSize: 10 }}
            />
            
            {threatTypes.map((type, idx) => (
              <Line
                key={type}
                type="monotone"
                dataKey={type}
                name={type}
                stroke={COLORS[idx % COLORS.length]}
                strokeWidth={2}
                dot={{ r: 3 }}
                connectNulls={false}
              />
            ))}
            
            {/* Forecast lines - dashed */}
            {threatTypes.map((type, idx) => (
              <Line
                key={`${type}_forecast`}
                type="monotone"
                dataKey={`${type}_forecast`}
                name={`${type} (พยากรณ์)`}
                stroke={COLORS[idx % COLORS.length]}
                strokeWidth={2}
                strokeDasharray="5 5"
                dot={{ r: 3, strokeDasharray: '0' }}
                connectNulls={true}
                legendType="none"
              />
            ))}
          </LineChart>
        </ResponsiveContainer>
      </div>

      <div className={styles.footer}>
        <span>ข้อมูล: {predictions.meta.date_range.start} - {predictions.meta.date_range.end}</span>
        <span>พยากรณ์: 7 วันข้างหน้า</span>
      </div>
    </div>
  );
}
