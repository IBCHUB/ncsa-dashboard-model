'use client';

import { useState, useEffect, useCallback, Suspense } from 'react';
import { useSearchParams } from 'next/navigation';
import Header from '@/components/layout/Header';
import type { ThreatEvent, IOCType, SeverityLevel } from '@/lib/types';
import { getSeverityBadgeClass, getIOCTypeBadgeClass, buildEnhancedBreakdown } from '@/lib/scoring';
import { ScoreInfoTooltip } from '@/components/widgets/ScoreInfoTooltip';
import styles from './page.module.css';
import Link from 'next/link';

function IOCExplorerContent() {
  const searchParams = useSearchParams();
  const initialQuery = searchParams.get('q') || '';

  const [events, setEvents] = useState<ThreatEvent[]>([]);
  const [loading, setLoading] = useState(true);
  const [searchQuery, setSearchQuery] = useState(initialQuery);
  const [filters, setFilters] = useState({
    type: '' as IOCType | '',
    severity: '' as SeverityLevel | '',
    source: '',
    threatType: '',
    threatActor: '',
  });
  const [sources, setSources] = useState<string[]>([]);
  const [threatTypes, setThreatTypes] = useState<string[]>([]);
  const [threatActors, setThreatActors] = useState<string[]>([]);

  const fetchEvents = useCallback(async () => {
    setLoading(true);
    try {
      const params = new URLSearchParams();
      if (searchQuery) params.set('q', searchQuery);
      if (filters.type) params.set('type', filters.type);
      if (filters.severity) params.set('severity', filters.severity);
      if (filters.source) params.set('source', filters.source);
      if (filters.threatType) params.set('threatType', filters.threatType);
      if (filters.threatActor) params.set('threatActor', filters.threatActor);

      const response = await fetch(`/api/iocs?${params.toString()}`);
      if (!response.ok) throw new Error('Failed to fetch');
      const data = await response.json();
      setEvents(data.data || []);
      if (data.sources) setSources(data.sources);
      if (data.threatTypes) setThreatTypes(data.threatTypes);
      if (data.threatActors) setThreatActors(data.threatActors);
    } catch (error) {
      console.error('Error fetching IOCs:', error);
    } finally {
      setLoading(false);
    }
  }, [searchQuery, filters]);

  useEffect(() => {
    fetchEvents();
  }, [fetchEvents]);

  // Note: AI scores are pre-computed in normalized data
  // Use event.aiRiskScore, event.aiSeverity, event.aiScoreBreakdown

  const handleSearch = (e: React.FormEvent) => {
    e.preventDefault();
    fetchEvents();
  };

  const formatDate = (dateStr: string) => {
    return new Date(dateStr).toLocaleDateString('th-TH', {
      day: '2-digit',
      month: 'short',
      year: 'numeric',
    });
  };

  const truncate = (str: string, len: number = 50) => {
    return str && str.length > len ? str.substring(0, len) + '...' : str || '-';
  };

  return (
    <>
      <Header title="IOC Explorer" />
      <div className="page-content">
        {/* Search and Filters */}
        <div className={styles.searchSection}>
          <form onSubmit={handleSearch} className={styles.searchForm}>
            <input
              type="text"
              placeholder="Search IOC (IP, Domain, Hash, CVE, URL)..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className={styles.searchInput}
            />
            <button type="submit" className="btn btn-primary">
              Search
            </button>
          </form>

          <div className={styles.filters}>
            <select
              value={filters.type}
              onChange={(e) => setFilters({ ...filters, type: e.target.value as IOCType })}
              className={styles.filterSelect}
            >
              <option value="">All Types</option>
              <option value="ip">IP Address</option>
              <option value="domain">Domain</option>
              <option value="url">URL</option>
              <option value="cve">CVE</option>
              <option value="sha256">SHA256</option>
              <option value="sha1">SHA1</option>
              <option value="md5">MD5</option>
            </select>

            <select
              value={filters.severity}
              onChange={(e) => setFilters({ ...filters, severity: e.target.value as SeverityLevel })}
              className={styles.filterSelect}
            >
              <option value="">All Severities</option>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
              <option value="clean">Clean</option>
            </select>

            <select
              value={filters.source}
              onChange={(e) => setFilters({ ...filters, source: e.target.value })}
              className={styles.filterSelect}
            >
              <option value="">All Sources</option>
              {sources.map((s) => (
                <option key={s} value={s}>{s}</option>
              ))}
            </select>

            <select
              value={filters.threatType}
              onChange={(e) => setFilters({ ...filters, threatType: e.target.value })}
              className={styles.filterSelect}
            >
              <option value="">All Threats</option>
              {threatTypes.map((t) => (
                <option key={t} value={t}>{t}</option>
              ))}
            </select>

            {/* Threat Actor Filter */}
            <select
              value={filters.threatActor}
              onChange={(e) => setFilters({ ...filters, threatActor: e.target.value })}
              className={styles.filterSelect}
            >
              <option value="">All Actors</option>
              {threatActors.map((a) => (
                <option key={a} value={a}>☠️ {a}</option>
              ))}
            </select>

            <button
              type="button"
              onClick={() => setFilters({ type: '', severity: '', source: '', threatType: '', threatActor: '' })}
              className="btn btn-secondary"
            >
              Clear
            </button>
          </div>
        </div>

        {/* Results Count */}
        <div className={styles.resultsInfo}>
          <span>Found {events.length} IOCs</span>
        </div>

        {/* Results Table */}
        <div className={styles.tableContainer}>
          {loading ? (
            <div className={styles.loading}>
              <div className="loading-spinner" />
              <p>Loading IOCs...</p>
            </div>
          ) : events.length === 0 ? (
            <div className={styles.empty}>
              <p>No IOCs found matching your criteria</p>
            </div>
          ) : (
            <table className={styles.table}>
              <thead>
                <tr>
                  <th>Type</th>
                  <th>Value</th>
                  <th>AI Risk Score</th>
                  <th>Severity</th>
                  <th>Threat Types</th>
                  <th>Threat Actors</th>
                  <th>Source</th>
                  <th>Date</th>
                </tr>
              </thead>
              <tbody>
                {events.map((event, idx) => (
                  <tr key={`${event.ioc.value}-${idx}`}>
                    <td>
                      <span className={getIOCTypeBadgeClass(event.ioc.type)}>
                        {event.ioc.type}
                      </span>
                    </td>
                    <td>
                      <Link
                        href={`/ioc/${event.ioc.type}/${encodeURIComponent(event.ioc.value)}`}
                        className={styles.iocValue}
                      >
                        {truncate(event.ioc.value, 45)}
                      </Link>
                    </td>
                    <td>
                      <ScoreInfoTooltip 
                        scoreBreakdown={buildEnhancedBreakdown(event as any)} 
                        showThai={true} 
                      />
                    </td>
                    <td>
                      <span className={getSeverityBadgeClass(event.aiSeverity || event.severity || 'clean')}>
                        {event.aiSeverity || event.severity || 'clean'}
                      </span>
                    </td>
                    <td className={styles.threatTypes}>
                      {(event as any).aiThreatTypes && (event as any).aiThreatTypes.length > 0 ? (
                        (event as any).aiThreatTypes.slice(0, 3).map((tt: string, i: number) => (
                          <span key={i} className={styles.threatBadge}>{tt}</span>
                        ))
                      ) : (
                        <span className={styles.noData}>-</span>
                      )}
                    </td>
                    <td className={styles.threatActors}>
                      {(event as any).aiThreatActors && (event as any).aiThreatActors.length > 0 ? (
                        (event as any).aiThreatActors.map((actor: string, i: number) => (
                          <span key={i} className={styles.actorBadge}>{actor}</span>
                        ))
                      ) : (
                        <span className={styles.noData}>-</span>
                      )}
                    </td>
                    <td className={styles.source}>{event.source_name}</td>
                    <td className={styles.date}>{formatDate(event.event_time)}</td>
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

export default function IOCExplorerPage() {
  return (
    <Suspense fallback={
      <>
        <Header title="IOC Explorer" />
        <div className="page-content">
          <div className={styles.loading}>
            <div className="loading-spinner" />
            <p>Loading IOC Explorer...</p>
          </div>
        </div>
      </>
    }>
      <IOCExplorerContent />
    </Suspense>
  );
}
