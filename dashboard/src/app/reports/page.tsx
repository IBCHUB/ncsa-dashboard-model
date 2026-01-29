'use client';

import { useState, useEffect } from 'react';
import Header from '@/components/layout/Header';
import type { DashboardStats, ThreatEvent } from '@/lib/types';
import styles from './page.module.css';

type ReportType = 'daily' | 'weekly' | 'monthly' | 'custom';
type ExportFormat = 'csv' | 'json' | 'suricata' | 'snort' | 'text' | 'blocklist';

export default function ReportsPage() {
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [events, setEvents] = useState<ThreatEvent[]>([]);
  const [loading, setLoading] = useState(false);
  const [reportType, setReportType] = useState<ReportType>('daily');
  const [exportFormat, setExportFormat] = useState<ExportFormat>('csv');
  const [dateFrom, setDateFrom] = useState(() => {
    const d = new Date();
    d.setDate(d.getDate() - 1);
    return d.toISOString().split('T')[0];
  });
  const [dateTo, setDateTo] = useState(() => new Date().toISOString().split('T')[0]);
  const [selectedTypes, setSelectedTypes] = useState<string[]>([]);
  const [selectedSeverities, setSelectedSeverities] = useState<string[]>([]);

  useEffect(() => {
    fetchStats();
  }, []);

  const fetchStats = async () => {
    try {
      const response = await fetch('/api/stats');
      const data = await response.json();
      setStats(data.data);
    } catch (error) {
      console.error('Error fetching stats:', error);
    }
  };

  const fetchReportData = async () => {
    setLoading(true);
    try {
      const params = new URLSearchParams({ limit: '1000' });
      if (selectedTypes.length > 0) {
        params.set('type', selectedTypes.join(','));
      }
      if (selectedSeverities.length > 0) {
        params.set('severity', selectedSeverities.join(','));
      }
      
      const response = await fetch(`/api/iocs?${params.toString()}`);
      const data = await response.json();
      setEvents(data.data || []);
    } catch (error) {
      console.error('Error fetching report data:', error);
    } finally {
      setLoading(false);
    }
  };

  const generateSuricataRules = (events: ThreatEvent[]): string => {
    let rules = '# TCTI Suricata Rules Export\n';
    rules += `# Generated: ${new Date().toISOString()}\n`;
    rules += `# Total Rules: ${events.length}\n\n`;

    let sid = 9000000;
    for (const event of events) {
      const msg = `TCTI ${event.ioc.type.toUpperCase()}: ${event.source_name}`;
      
      if (event.ioc.type === 'ip') {
        rules += `alert ip ${event.ioc.value} any -> any any (msg:"${msg}"; sid:${sid++}; rev:1;)\n`;
      } else if (event.ioc.type === 'domain') {
        rules += `alert dns any any -> any any (msg:"${msg}"; dns.query; content:"${event.ioc.value}"; nocase; sid:${sid++}; rev:1;)\n`;
      } else if (event.ioc.type === 'url') {
        const urlHost = event.ioc.value.replace(/^https?:\/\//, '').split('/')[0];
        rules += `alert http any any -> any any (msg:"${msg}"; http.host; content:"${urlHost}"; nocase; sid:${sid++}; rev:1;)\n`;
      }
    }
    return rules;
  };

  const generateSnortRules = (events: ThreatEvent[]): string => {
    let rules = '# TCTI Snort Rules Export\n';
    rules += `# Generated: ${new Date().toISOString()}\n`;
    rules += `# Total Rules: ${events.length}\n\n`;

    let sid = 9000000;
    for (const event of events) {
      const msg = `TCTI ${event.ioc.type.toUpperCase()}: ${event.source_name}`;
      
      if (event.ioc.type === 'ip') {
        rules += `alert ip ${event.ioc.value} any <> any any (msg:"${msg}"; sid:${sid++}; rev:1;)\n`;
      } else if (event.ioc.type === 'domain') {
        rules += `alert udp any any -> any 53 (msg:"${msg}"; content:"|${event.ioc.value.length.toString(16).padStart(2, '0')}|${event.ioc.value}"; nocase; sid:${sid++}; rev:1;)\n`;
      }
    }
    return rules;
  };

  const generateCSV = (events: ThreatEvent[]): string => {
    const headers = ['IOC Type', 'IOC Value', 'Severity', 'Confidence', 'Source', 'Threat Type', 'Event Time', 'Description'];
    const rows = events.map(e => [
      e.ioc.type,
      `"${e.ioc.value}"`,
      e.aiSeverity || e.severity || 'low',
      e.confidence || 0,
      e.source_name,
      (e.threat_type || []).join(';'),
      e.event_time,
      `"${(e.description || '').replace(/"/g, '""')}"`
    ].join(','));
    
    return [headers.join(','), ...rows].join('\n');
  };

  const generateJSON = (events: ThreatEvent[]): string => {
    const exportData = {
      meta: {
        generated: new Date().toISOString(),
        source: 'Thailand Cyber Threat Intelligence',
        total: events.length,
        reportType,
        dateRange: { from: dateFrom, to: dateTo },
      },
      iocs: events.map(e => ({
        type: e.ioc.type,
        value: e.ioc.value,
        severity: e.aiSeverity || e.severity,
        confidence: e.confidence,
        source: e.source_name,
        threat_type: e.threat_type,
        event_time: e.event_time,
        description: e.description,
        enrichment: e.enrichment,
      })),
    };
    return JSON.stringify(exportData, null, 2);
  };

  const generatePlainText = (events: ThreatEvent[]): string => {
    let text = `# Thailand Cyber Threat Intelligence - IOC Export\n`;
    text += `# Generated: ${new Date().toISOString()}\n`;
    text += `# Total IOCs: ${events.length}\n\n`;
    
    // Group by type
    const byType: Record<string, string[]> = {};
    for (const e of events) {
      if (!byType[e.ioc.type]) byType[e.ioc.type] = [];
      byType[e.ioc.type].push(e.ioc.value);
    }
    
    for (const [type, values] of Object.entries(byType)) {
      text += `\n## ${type.toUpperCase()} (${values.length})\n`;
      text += values.join('\n') + '\n';
    }
    
    return text;
  };

  // Generate blocklist for firewall use (IP and Domain only)
  const generateBlocklist = (events: ThreatEvent[]): string => {
    let text = `# Thailand Cyber Threat Intelligence - Blocklist\n`;
    text += `# Generated: ${new Date().toISOString()}\n`;
    text += `# For use with firewall, DNS blockers, or pfSense\n`;
    text += `# Only includes High/Critical severity IP and Domain\n\n`;
    
    const ips = events
      .filter(e => e.ioc.type === 'ip' && ['high', 'critical'].includes((e.aiSeverity || e.severity) || ''))
      .map(e => e.ioc.value);
    const domains = events
      .filter(e => e.ioc.type === 'domain' && ['high', 'critical'].includes((e.aiSeverity || e.severity) || ''))
      .map(e => e.ioc.value);
    
    if (ips.length > 0) {
      text += `# IP Addresses (${ips.length})\n`;
      text += [...new Set(ips)].join('\n') + '\n\n';
    }
    
    if (domains.length > 0) {
      text += `# Domains (${domains.length})\n`;
      text += [...new Set(domains)].join('\n') + '\n';
    }
    
    return text;
  };

  const handleGenerateReport = async () => {
    await fetchReportData();
  };

  const handleExport = () => {
    if (events.length === 0) {
      alert('No data to export. Generate a report first.');
      return;
    }

    let content: string;
    let filename: string;
    let mimeType: string;
    const timestamp = new Date().toISOString().split('T')[0];

    switch (exportFormat) {
      case 'csv':
        content = generateCSV(events);
        filename = `tcti_ioc_export_${timestamp}.csv`;
        mimeType = 'text/csv';
        break;
      case 'json':
        content = generateJSON(events);
        filename = `tcti_ioc_export_${timestamp}.json`;
        mimeType = 'application/json';
        break;
      case 'suricata':
        content = generateSuricataRules(events.filter(e => ['ip', 'domain', 'url'].includes(e.ioc.type)));
        filename = `tcti_suricata_rules_${timestamp}.rules`;
        mimeType = 'text/plain';
        break;
      case 'snort':
        content = generateSnortRules(events.filter(e => ['ip', 'domain'].includes(e.ioc.type)));
        filename = `tcti_snort_rules_${timestamp}.rules`;
        mimeType = 'text/plain';
        break;
      case 'text':
        content = generatePlainText(events);
        filename = `tcti_ioc_list_${timestamp}.txt`;
        mimeType = 'text/plain';
        break;
      case 'blocklist':
        content = generateBlocklist(events);
        filename = `tcti_blocklist_${timestamp}.txt`;
        mimeType = 'text/plain';
        break;
      default:
        return;
    }

    // Download file
    const blob = new Blob([content], { type: mimeType });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  const iocTypes = ['ip', 'domain', 'url', 'cve', 'sha256', 'md5'];
  const severities = ['critical', 'high', 'medium', 'low', 'clean'];

  return (
    <>
      <Header title="Reports & Export" />
      <div className="page-content">
        {/* Report Configuration */}
        <div className={styles.configSection}>
          <h2>Generate Report</h2>
          
          <div className={styles.configGrid}>
            {/* Report Type */}
            <div className={styles.configItem}>
              <label>Report Type</label>
              <select 
                value={reportType} 
                onChange={(e) => setReportType(e.target.value as ReportType)}
                className={styles.select}
              >
                <option value="daily">Daily Summary</option>
                <option value="weekly">Weekly Digest</option>
                <option value="monthly">Monthly Report</option>
                <option value="custom">Custom Range</option>
              </select>
            </div>

            {/* Date Range */}
            <div className={styles.configItem}>
              <label>Date From</label>
              <input
                type="date"
                value={dateFrom}
                onChange={(e) => setDateFrom(e.target.value)}
                className={styles.input}
              />
            </div>
            <div className={styles.configItem}>
              <label>Date To</label>
              <input
                type="date"
                value={dateTo}
                onChange={(e) => setDateTo(e.target.value)}
                className={styles.input}
              />
            </div>

            {/* Export Format */}
            <div className={styles.configItem}>
              <label>Export Format</label>
              <select 
                value={exportFormat} 
                onChange={(e) => setExportFormat(e.target.value as ExportFormat)}
                className={styles.select}
              >
                <option value="csv">CSV (Spreadsheet)</option>
                <option value="json">JSON (API/MISP)</option>
                <option value="suricata">Suricata Rules</option>
                <option value="snort">Snort Rules</option>
                <option value="blocklist">🛡️ Blocklist (Firewall)</option>
                <option value="text">Plain Text</option>
              </select>
            </div>
          </div>

          {/* IOC Type Filter */}
          <div className={styles.filterSection}>
            <label>Filter by IOC Type</label>
            <div className={styles.checkboxGrid}>
              {iocTypes.map(type => (
                <label key={type} className={styles.checkbox}>
                  <input
                    type="checkbox"
                    checked={selectedTypes.includes(type)}
                    onChange={(e) => {
                      if (e.target.checked) {
                        setSelectedTypes([...selectedTypes, type]);
                      } else {
                        setSelectedTypes(selectedTypes.filter(t => t !== type));
                      }
                    }}
                  />
                  <span className={`ioc-type ioc-type-${type === 'sha256' || type === 'md5' ? 'hash' : type}`}>
                    {type}
                  </span>
                </label>
              ))}
            </div>
          </div>

          {/* Severity Filter */}
          <div className={styles.filterSection}>
            <label>Filter by Severity</label>
            <div className={styles.checkboxGrid}>
              {severities.map(sev => (
                <label key={sev} className={styles.checkbox}>
                  <input
                    type="checkbox"
                    checked={selectedSeverities.includes(sev)}
                    onChange={(e) => {
                      if (e.target.checked) {
                        setSelectedSeverities([...selectedSeverities, sev]);
                      } else {
                        setSelectedSeverities(selectedSeverities.filter(s => s !== sev));
                      }
                    }}
                  />
                  <span className={`badge badge-${sev}`}>{sev}</span>
                </label>
              ))}
            </div>
          </div>

          {/* Action Buttons */}
          <div className={styles.actions}>
            <button 
              onClick={handleGenerateReport}
              className="btn btn-primary"
              disabled={loading}
            >
              {loading ? 'Generating...' : 'Generate Report'}
            </button>
            <button 
              onClick={handleExport}
              className="btn btn-secondary"
              disabled={events.length === 0}
            >
              Export ({exportFormat.toUpperCase()})
            </button>
          </div>
        </div>

        {/* Report Preview */}
        {events.length > 0 && (
          <div className={styles.previewSection}>
            <h2>Report Preview</h2>
            
            {/* Summary Stats */}
            <div className={styles.summaryGrid}>
              <div className={styles.summaryCard}>
                <span className={styles.summaryValue}>{events.length}</span>
                <span className={styles.summaryLabel}>Total IOCs</span>
              </div>
              <div className={styles.summaryCard}>
                <span className={styles.summaryValue}>
                  {events.filter(e => (e.aiSeverity || e.severity) === 'critical' || (e.aiSeverity || e.severity) === 'high').length}
                </span>
                <span className={styles.summaryLabel}>Critical/High</span>
              </div>
              <div className={styles.summaryCard}>
                <span className={styles.summaryValue}>
                  {[...new Set(events.map(e => e.source_name))].length}
                </span>
                <span className={styles.summaryLabel}>Sources</span>
              </div>
              <div className={styles.summaryCard}>
                <span className={styles.summaryValue}>
                  {[...new Set(events.map(e => e.ioc.type))].length}
                </span>
                <span className={styles.summaryLabel}>IOC Types</span>
              </div>
            </div>

            {/* By Severity */}
            <div className={styles.breakdownSection}>
              <h3>By Severity</h3>
              <div className={styles.breakdownList}>
                {severities.map(sev => {
                  const count = events.filter(e => (e.aiSeverity || e.severity) === sev).length;
                  if (count === 0) return null;
                  return (
                    <div key={sev} className={styles.breakdownItem}>
                      <span className={`badge badge-${sev}`}>{sev}</span>
                      <span className={styles.breakdownCount}>{count}</span>
                    </div>
                  );
                })}
              </div>
            </div>

            {/* By Type */}
            <div className={styles.breakdownSection}>
              <h3>By IOC Type</h3>
              <div className={styles.breakdownList}>
                {iocTypes.map(type => {
                  const count = events.filter(e => e.ioc.type === type).length;
                  if (count === 0) return null;
                  return (
                    <div key={type} className={styles.breakdownItem}>
                      <span className={`ioc-type ioc-type-${type === 'sha256' || type === 'md5' ? 'hash' : type}`}>
                        {type}
                      </span>
                      <span className={styles.breakdownCount}>{count}</span>
                    </div>
                  );
                })}
              </div>
            </div>

            {/* Sample Data */}
            <div className={styles.sampleSection}>
              <h3>Sample Data (First 10)</h3>
              <table className={styles.table}>
                <thead>
                  <tr>
                    <th>Type</th>
                    <th>Value</th>
                    <th>Severity</th>
                    <th>Source</th>
                  </tr>
                </thead>
                <tbody>
                  {events.slice(0, 10).map((e, idx) => (
                    <tr key={idx}>
                      <td>
                        <span className={`ioc-type ioc-type-${e.ioc.type === 'sha256' || e.ioc.type === 'md5' ? 'hash' : e.ioc.type}`}>
                          {e.ioc.type}
                        </span>
                      </td>
                      <td className={styles.iocValue}>
                        {e.ioc.value.length > 40 ? e.ioc.value.substring(0, 40) + '...' : e.ioc.value}
                      </td>
                      <td>
                        <span className={`badge badge-${e.aiSeverity || e.severity || 'low'}`}>
                          {e.aiSeverity || e.severity || 'low'}
                        </span>
                      </td>
                      <td>{e.source_name}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* Quick Stats */}
        {stats && (
          <div className={styles.quickStats}>
            <h3>Available Data Overview</h3>
            <p>Total IOCs in database: <strong>{stats.totalIOCs}</strong></p>
            <p>Sources: <strong>{Object.keys(stats.bySource).length}</strong></p>
            <p>IOC Types: <strong>{Object.keys(stats.byType).length}</strong></p>
          </div>
        )}
      </div>
    </>
  );
}
