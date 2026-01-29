'use client';

import { useState, useEffect } from 'react';
import Header from '@/components/layout/Header';
import type { ThreatEvent } from '@/lib/types';
import { getSeverityBadgeClass } from '@/lib/scoring';
import styles from './page.module.css';
import Link from 'next/link';

export default function CVEIntelligencePage() {
  const [cves, setCves] = useState<ThreatEvent[]>([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');
  const [severityFilter, setSeverityFilter] = useState('');

  useEffect(() => {
    fetchCVEs();
  }, []);

  const fetchCVEs = async () => {
    setLoading(true);
    try {
      const response = await fetch('/api/iocs?type=cve&limit=500');
      const data = await response.json();
      setCves(data.data || []);
    } catch (error) {
      console.error('Error fetching CVEs:', error);
    } finally {
      setLoading(false);
    }
  };

  const filteredCVEs = cves.filter(cve => {
    const matchesSearch = !search || 
      cve.ioc.value.toLowerCase().includes(search.toLowerCase()) ||
      cve.description?.toLowerCase().includes(search.toLowerCase());
    const matchesSeverity = !severityFilter || cve.severity === severityFilter;
    return matchesSearch && matchesSeverity;
  });

  // Group CVEs by severity for stats
  const stats = {
    total: cves.length,
    critical: cves.filter(c => c.severity === 'critical').length,
    high: cves.filter(c => c.severity === 'high').length,
    medium: cves.filter(c => c.severity === 'medium').length,
    low: cves.filter(c => c.severity === 'low').length,
  };

  const formatDate = (dateStr: string) => {
    return new Date(dateStr).toLocaleDateString('th-TH', {
      day: '2-digit',
      month: 'short',
      year: 'numeric',
    });
  };

  return (
    <>
      <Header title="CVE Intelligence" />
      <div className="page-content">
        {/* Stats Overview */}
        <div className={styles.statsGrid}>
          <div className={styles.statCard}>
            <span className={styles.statValue}>{stats.total}</span>
            <span className={styles.statLabel}>Total CVEs</span>
          </div>
          <div className={`${styles.statCard} ${styles.critical}`}>
            <span className={styles.statValue}>{stats.critical}</span>
            <span className={styles.statLabel}>Critical</span>
          </div>
          <div className={`${styles.statCard} ${styles.high}`}>
            <span className={styles.statValue}>{stats.high}</span>
            <span className={styles.statLabel}>High</span>
          </div>
          <div className={`${styles.statCard} ${styles.medium}`}>
            <span className={styles.statValue}>{stats.medium}</span>
            <span className={styles.statLabel}>Medium</span>
          </div>
        </div>

        {/* Search and Filter */}
        <div className={styles.filterSection}>
          <input
            type="text"
            placeholder="Search CVE ID or description..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className={styles.searchInput}
          />
          <select
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value)}
            className={styles.filterSelect}
          >
            <option value="">All Severities</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>
        </div>

        {/* Results Info */}
        <div className={styles.resultsInfo}>
          Showing {filteredCVEs.length} of {cves.length} CVEs
        </div>

        {/* CVE Table */}
        <div className={styles.tableContainer}>
          {loading ? (
            <div className={styles.loading}>
              <div className="loading-spinner" />
              <p>Loading CVEs...</p>
            </div>
          ) : filteredCVEs.length === 0 ? (
            <div className={styles.empty}>
              <p>No CVEs found</p>
            </div>
          ) : (
            <table className={styles.table}>
              <thead>
                <tr>
                  <th>CVE ID</th>
                  <th>Severity</th>
                  <th>Source</th>
                  <th>Description</th>
                  <th>Published Date</th>
                  <th>Action</th>
                </tr>
              </thead>
              <tbody>
                {filteredCVEs.map((cve, idx) => (
                  <tr key={`${cve.ioc.value}-${idx}`}>
                    <td>
                      <span className={styles.cveId}>{cve.ioc.value}</span>
                    </td>
                    <td>
                      <span className={getSeverityBadgeClass(cve.severity || 'low')}>
                        {cve.severity || 'low'}
                      </span>
                    </td>
                    <td className={styles.source}>{cve.source_name}</td>
                    <td className={styles.description}>
                      {cve.description 
                        ? (cve.description.length > 100 
                           ? cve.description.substring(0, 100) + '...' 
                           : cve.description)
                        : '-'}
                    </td>
                    <td className={styles.date}>{formatDate(cve.event_time)}</td>
                    <td>
                      <Link
                        href={`/ioc/cve/${encodeURIComponent(cve.ioc.value)}`}
                        className={styles.viewBtn}
                      >
                        View
                      </Link>
                      <a
                        href={`https://nvd.nist.gov/vuln/detail/${cve.ioc.value}`}
                        target="_blank"
                        rel="noopener noreferrer"
                        className={styles.nvdLink}
                      >
                        NVD
                      </a>
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
