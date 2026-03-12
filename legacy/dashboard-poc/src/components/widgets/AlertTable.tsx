'use client';

import Link from 'next/link';
import styles from './AlertTable.module.css';
import type { ThreatEvent } from '@/lib/types';
import { getSeverityBadgeClass, getIOCTypeBadgeClass } from '@/lib/scoring';

interface AlertTableProps {
  alerts: ThreatEvent[];
  title?: string;
  showViewAll?: boolean;
  maxRows?: number;
}

export default function AlertTable({ 
  alerts, 
  title = 'Recent Alerts',
  showViewAll = true,
  maxRows = 10
}: AlertTableProps) {
  const displayAlerts = alerts.slice(0, maxRows);

  const formatDate = (dateStr: string) => {
    const date = new Date(dateStr);
    return date.toLocaleDateString('th-TH', {
      day: '2-digit',
      month: 'short',
      year: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
    });
  };

  const truncate = (str: string, len: number = 50) => {
    return str.length > len ? str.substring(0, len) + '...' : str;
  };

  return (
    <div className={styles.container}>
      <div className={styles.header}>
        <h3 className={styles.title}>{title}</h3>
        {showViewAll && (
          <Link href="/alerts" className={styles.viewAll}>
            View All →
          </Link>
        )}
      </div>

      <div className={styles.tableContainer}>
        <table className={styles.table}>
          <thead>
            <tr>
              <th>Severity</th>
              <th>IOC Type</th>
              <th>Value</th>
              <th>Source</th>
              <th>Description</th>
              <th>Time</th>
            </tr>
          </thead>
          <tbody>
            {displayAlerts.length === 0 ? (
              <tr>
                <td colSpan={6} className={styles.empty}>
                  No alerts found
                </td>
              </tr>
            ) : (
              displayAlerts.map((alert, index) => (
                <tr key={`${alert.ioc.value}-${index}`}>
                  <td>
                    <span className={getSeverityBadgeClass(alert.aiSeverity || alert.severity || 'low')}>
                      {alert.aiSeverity || alert.severity || 'low'}
                    </span>
                  </td>
                  <td>
                    <span className={getIOCTypeBadgeClass(alert.ioc.type)}>
                      {alert.ioc.type}
                    </span>
                  </td>
                  <td>
                    <Link 
                      href={`/ioc/${alert.ioc.type}/${encodeURIComponent(alert.ioc.value)}`}
                      className={styles.iocLink}
                    >
                      {truncate(alert.ioc.value, 40)}
                    </Link>
                  </td>
                  <td className={styles.source}>{alert.source_name}</td>
                  <td className={styles.description}>
                    {truncate(alert.description || '-', 60)}
                  </td>
                  <td className={styles.time}>
                    {formatDate(alert.event_time)}
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
