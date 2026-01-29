'use client';

import styles from './SeverityChart.module.css';

interface SeverityData {
  critical: number;
  high: number;
  medium: number;
  low: number;
  clean?: number;
}

interface SeverityChartProps {
  data: SeverityData;
  title?: string;
}

export default function SeverityChart({ 
  data, 
  title = 'Threats by Severity' 
}: SeverityChartProps) {
  const total = data.critical + data.high + data.medium + data.low + (data.clean || 0);
  
  const items = [
    { key: 'critical', label: 'Critical', value: data.critical, color: 'var(--color-severity-critical)' },
    { key: 'high', label: 'High', value: data.high, color: 'var(--color-severity-high)' },
    { key: 'medium', label: 'Medium', value: data.medium, color: 'var(--color-severity-medium)' },
    { key: 'low', label: 'Low', value: data.low, color: 'var(--color-severity-low)' },
  ];

  // Calculate percentages for the donut chart
  let cumulativePercent = 0;
  const segments = items.map(item => {
    const percent = total > 0 ? (item.value / total) * 100 : 0;
    const start = cumulativePercent;
    cumulativePercent += percent;
    return {
      ...item,
      percent,
      start,
      end: cumulativePercent,
    };
  });

  // Create conic-gradient
  const gradientStops = segments
    .filter(s => s.percent > 0)
    .map(s => `${s.color} ${s.start}% ${s.end}%`)
    .join(', ');
  
  const gradient = gradientStops || 'var(--color-bg-tertiary) 0% 100%';

  return (
    <div className={styles.container}>
      <h3 className={styles.title}>{title}</h3>
      
      <div className={styles.chartWrapper}>
        <div 
          className={styles.donut}
          style={{ background: `conic-gradient(${gradient})` }}
        >
          <div className={styles.donutCenter}>
            <span className={styles.totalValue}>{total.toLocaleString()}</span>
            <span className={styles.totalLabel}>Total</span>
          </div>
        </div>

        <div className={styles.legend}>
          {items.map(item => (
            <div key={item.key} className={styles.legendItem}>
              <span 
                className={styles.legendColor} 
                style={{ backgroundColor: item.color }}
              />
              <span className={styles.legendLabel}>{item.label}</span>
              <span className={styles.legendValue}>{item.value.toLocaleString()}</span>
              <span className={styles.legendPercent}>
                {total > 0 ? ((item.value / total) * 100).toFixed(1) : 0}%
              </span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
