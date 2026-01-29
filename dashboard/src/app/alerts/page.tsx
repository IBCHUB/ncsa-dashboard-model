'use client';

import { useState, useEffect } from 'react';
import Header from '@/components/layout/Header';
import type { ThreatEvent } from '@/lib/types';
import { getSeverityBadgeClass, getIOCTypeBadgeClass } from '@/lib/scoring';
import styles from './page.module.css';
import Link from 'next/link';

type AlertStatus = 'open' | 'acknowledged' | 'resolved';

interface Alert extends ThreatEvent {
  id: string;
  status: AlertStatus;
  acknowledgedAt?: string;
}

export default function AlertsCenterPage() {
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [loading, setLoading] = useState(true);
  const [statusFilter, setStatusFilter] = useState<AlertStatus | ''>('');
  const [severityFilter, setSeverityFilter] = useState('');
  const [typeFilter, setTypeFilter] = useState('');

  useEffect(() => {
    fetchAlerts();
  }, []);

  const fetchAlerts = async () => {
    setLoading(true);
    try {
      // Fetch high severity threats as alerts
      const response = await fetch('/api/iocs?limit=500');
      const data = await response.json();
      
      // Convert to alerts (high/critical AI severity threats)
      const alertEvents = (data.data || [])
        .filter((e: ThreatEvent) => (e.aiSeverity || e.severity) === 'high' || (e.aiSeverity || e.severity) === 'critical' || (e.aiSeverity || e.severity) === 'medium')
        .map((e: ThreatEvent, idx: number) => ({
          ...e,
          id: `ALERT-${String(idx + 1).padStart(5, '0')}`,
          status: 'open' as AlertStatus,
        }));
      
      setAlerts(alertEvents);
    } catch (error) {
      console.error('Error fetching alerts:', error);
    } finally {
      setLoading(false);
    }
  };

  const handleStatusChange = (alertId: string, newStatus: AlertStatus) => {
    setAlerts(alerts.map(a => 
      a.id === alertId 
        ? { ...a, status: newStatus, acknowledgedAt: newStatus === 'acknowledged' ? new Date().toISOString() : undefined }
        : a
    ));
  };

  const filteredAlerts = alerts.filter(alert => {
    const matchesStatus = !statusFilter || alert.status === statusFilter;
    const matchesSeverity = !severityFilter || (alert.aiSeverity || alert.severity) === severityFilter;
    const matchesType = !typeFilter || alert.ioc.type === typeFilter;
    return matchesStatus && matchesSeverity && matchesType;
  });

  const stats = {
    total: alerts.length,
    open: alerts.filter(a => a.status === 'open').length,
    acknowledged: alerts.filter(a => a.status === 'acknowledged').length,
    resolved: alerts.filter(a => a.status === 'resolved').length,
    critical: alerts.filter(a => (a.aiSeverity || a.severity) === 'critical').length,
    high: alerts.filter(a => (a.aiSeverity || a.severity) === 'high').length,
  };

  const formatDate = (dateStr: string) => {
    return new Date(dateStr).toLocaleDateString('th-TH', {
      day: '2-digit',
      month: 'short',
      year: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
    });
  };

  const getStatusClass = (status: AlertStatus) => {
    switch (status) {
      case 'open': return styles.statusOpen;
      case 'acknowledged': return styles.statusAcknowledged;
      case 'resolved': return styles.statusResolved;
    }
  };

  return (
    <>
      <Header title="Alerts Center" />
      <div className="page-content">
        {/* Stats Overview */}
        <div className={styles.statsGrid}>
          <div className={styles.statCard}>
            <span className={styles.statValue}>{stats.total}</span>
            <span className={styles.statLabel}>Total Alerts</span>
          </div>
          <div className={`${styles.statCard} ${styles.open}`}>
            <span className={styles.statValue}>{stats.open}</span>
            <span className={styles.statLabel}>Open</span>
          </div>
          <div className={`${styles.statCard} ${styles.acknowledged}`}>
            <span className={styles.statValue}>{stats.acknowledged}</span>
            <span className={styles.statLabel}>Acknowledged</span>
          </div>
          <div className={`${styles.statCard} ${styles.resolved}`}>
            <span className={styles.statValue}>{stats.resolved}</span>
            <span className={styles.statLabel}>Resolved</span>
          </div>
        </div>

        {/* Filters */}
        <div className={styles.filterSection}>
          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value as AlertStatus | '')}
            className={styles.filterSelect}
          >
            <option value="">All Statuses</option>
            <option value="open">Open</option>
            <option value="acknowledged">Acknowledged</option>
            <option value="resolved">Resolved</option>
          </select>
          <select
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value)}
            className={styles.filterSelect}
          >
            <option value="">All Severities</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
          </select>
          <select
            value={typeFilter}
            onChange={(e) => setTypeFilter(e.target.value)}
            className={styles.filterSelect}
          >
            <option value="">All IOC Types</option>
            <option value="ip">IP</option>
            <option value="domain">Domain</option>
            <option value="url">URL</option>
            <option value="cve">CVE</option>
          </select>
          <button 
            onClick={() => {
              setStatusFilter('');
              setSeverityFilter('');
              setTypeFilter('');
            }}
            className="btn btn-secondary"
          >
            Clear Filters
          </button>
        </div>

        {/* Results Info */}
        <div className={styles.resultsInfo}>
          Showing {filteredAlerts.length} of {alerts.length} alerts
        </div>

        {/* Alerts Table */}
        <div className={styles.tableContainer}>
          {loading ? (
            <div className={styles.loading}>
              <div className="loading-spinner" />
              <p>Loading alerts...</p>
            </div>
          ) : filteredAlerts.length === 0 ? (
            <div className={styles.empty}>
              <p>No alerts found</p>
            </div>
          ) : (
            <table className={styles.table}>
              <thead>
                <tr>
                  <th>Alert ID</th>
                  <th>Status</th>
                  <th>Severity</th>
                  <th>IOC Type</th>
                  <th>IOC Value</th>
                  <th>Source</th>
                  <th>Time</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {filteredAlerts.map((alert) => (
                  <tr key={alert.id}>
                    <td className={styles.alertId}>{alert.id}</td>
                    <td>
                      <span className={`${styles.status} ${getStatusClass(alert.status)}`}>
                        {alert.status}
                      </span>
                    </td>
                    <td>
                      <span className={getSeverityBadgeClass(alert.aiSeverity || alert.severity || 'low')}>
                        {alert.aiSeverity || alert.severity}
                      </span>
                    </td>
                    <td>
                      <span className={getIOCTypeBadgeClass(alert.ioc.type)}>
                        {alert.ioc.type}
                      </span>
                    </td>
                    <td className={styles.iocValue}>
                      <Link href={`/ioc/${alert.ioc.type}/${encodeURIComponent(alert.ioc.value)}`}>
                        {alert.ioc.value.length > 35 
                          ? alert.ioc.value.substring(0, 35) + '...' 
                          : alert.ioc.value}
                      </Link>
                    </td>
                    <td className={styles.source}>{alert.source_name}</td>
                    <td className={styles.time}>{formatDate(alert.event_time)}</td>
                    <td className={styles.actions}>
                      {alert.status === 'open' && (
                        <button
                          onClick={() => handleStatusChange(alert.id, 'acknowledged')}
                          className={styles.ackBtn}
                        >
                          Acknowledge
                        </button>
                      )}
                      {alert.status === 'acknowledged' && (
                        <button
                          onClick={() => handleStatusChange(alert.id, 'resolved')}
                          className={styles.resolveBtn}
                        >
                          Resolve
                        </button>
                      )}
                      {alert.status === 'resolved' && (
                        <span className={styles.resolvedLabel}>✓ Resolved</span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </div>
    </>
  );
}
