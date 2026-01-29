'use client';

import { useState, useEffect } from 'react';
import styles from './TrendPrediction.module.css';

interface TrendItem {
  threat_type: string;
  direction: 'increasing' | 'decreasing' | 'stable';
  change_percent: number;
  confidence: number;
  prediction_text: string;
  prediction_text_en: string;
  alert_level: 'warning' | 'info' | 'success' | 'neutral';
  total_count: number;
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
  predictions: TrendItem[];
  top_increasing: TrendItem[];
  summary: {
    total_threat_types: number;
    increasing_count: number;
    decreasing_count: number;
    stable_count: number;
  };
}

export default function TrendPrediction() {
  const [predictions, setPredictions] = useState<PredictionsData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    fetch('/data/predictions.json')
      .then(res => {
        if (!res.ok) throw new Error('Failed to load predictions');
        return res.json();
      })
      .then(data => {
        setPredictions(data);
        setLoading(false);
      })
      .catch(err => {
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

  if (error || !predictions) {
    return (
      <div className={styles.container}>
        <div className={styles.error}>ไม่สามารถโหลดข้อมูลพยากรณ์ได้</div>
      </div>
    );
  }

  const { top_increasing, summary, meta } = predictions;

  return (
    <div className={styles.container}>
      <div className={styles.header}>
        <h3 className={styles.title}>
          <span className={styles.icon}>🔮</span>
          Trend Prediction
        </h3>
        <span className={styles.subtitle}>พยากรณ์ 7 วันข้างหน้า</span>
      </div>

      {top_increasing.length > 0 && (
        <div className={styles.alertSection}>
          <div className={styles.alertHeader}>
            <span className={styles.alertIcon}>⚠️</span>
            <span>ภัยคุกคามที่มีแนวโน้มเพิ่มขึ้น</span>
          </div>
          <div className={styles.trendList}>
            {top_increasing.slice(0, 4).map((item, idx) => (
              <div 
                key={idx} 
                className={`${styles.trendItem} ${styles[item.alert_level]}`}
              >
                <div className={styles.trendType}>
                  <span className={styles.arrow}>↑</span>
                  <span>{item.threat_type}</span>
                </div>
                <div className={styles.trendStats}>
                  <span className={styles.changePercent}>
                    +{item.change_percent.toFixed(0)}%
                  </span>
                  <span className={styles.confidence}>
                    conf: {(item.confidence * 100).toFixed(0)}%
                  </span>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      <div className={styles.summary}>
        <div className={styles.summaryItem}>
          <span className={styles.summaryValue}>{summary.increasing_count}</span>
          <span className={styles.summaryLabel}>เพิ่มขึ้น ↑</span>
        </div>
        <div className={styles.summaryItem}>
          <span className={styles.summaryValue}>{summary.stable_count}</span>
          <span className={styles.summaryLabel}>คงที่ →</span>
        </div>
        <div className={styles.summaryItem}>
          <span className={styles.summaryValue}>{summary.decreasing_count}</span>
          <span className={styles.summaryLabel}>ลดลง ↓</span>
        </div>
      </div>

      <div className={styles.footer}>
        <span>ข้อมูลจาก {meta.date_range.total_days} วัน</span>
        <span className={styles.dateRange}>
          {meta.date_range.start} - {meta.date_range.end}
        </span>
      </div>
    </div>
  );
}
