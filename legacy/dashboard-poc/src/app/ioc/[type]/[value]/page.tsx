'use client';

import { useState, useEffect, useMemo } from 'react';
import { useParams } from 'next/navigation';
import Header from '@/components/layout/Header';
import type { ThreatEvent } from '@/lib/types';
import { getSeverityBadgeClass, getIOCTypeBadgeClass, buildEnhancedBreakdown, type AnyScoreBreakdown } from '@/lib/scoring';
import { ScoreInfoTooltip } from '@/components/widgets/ScoreInfoTooltip';
import { ThreatGraph } from '@/components/widgets/ThreatGraph';
import { buildGraphFromEvents } from '@/lib/graph';
import styles from './page.module.css';
import Link from 'next/link';

interface AIAnalysis {
  severity: string;
  confidence: number;
  threatActors: string[];
  mitreTechniques: string[];
  threatCategory: string;
  summary: string;
  recommendedActions: string[];
  aiScore: number;
}

export default function IOCDetailPage() {
  const params = useParams();
  const type = params.type as string;
  const value = decodeURIComponent(params.value as string);

  const [events, setEvents] = useState<ThreatEvent[]>([]);
  const [loading, setLoading] = useState(true);
  const [aiAnalysis, setAiAnalysis] = useState<AIAnalysis | null>(null);
  const [aiLoading, setAiLoading] = useState(false);
  const [ticketStatus, setTicketStatus] = useState<{
    loading: boolean;
    success: boolean | null;
    message: string;
    ticketId: string | null;
  }>({ loading: false, success: null, message: '', ticketId: null });

  // Create HelpDesk Ticket function
  const createHelpDeskTicket = async () => {
    if (!primaryEvent) return;
    setTicketStatus({ loading: true, success: null, message: '', ticketId: null });
    
    try {
      const response = await fetch('/api/helpdesk/ticket', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          iocValue: value,
          iocType: type,
          description: primaryEvent.description || `IOC detected: ${value}`,
          riskScore: primaryEvent.aiRiskScore || 50,
          severity: primaryEvent.aiSeverity || primaryEvent.severity || 'medium',
          threatTypes: (primaryEvent as any).aiThreatTypes || primaryEvent.threat_type || [],
          threatActors: (primaryEvent as any).aiThreatActors || []
        })
      });
      
      if (!response.ok) throw new Error('Failed to create ticket');
      const result = await response.json();
      
      setTicketStatus({
        loading: false,
        success: result.success,
        message: result.message,
        ticketId: result.ticketId
      });
    } catch (error) {
      console.error('HelpDesk ticket error:', error);
      setTicketStatus({
        loading: false,
        success: false,
        message: 'Failed to create ticket',
        ticketId: null
      });
    }
  };

  useEffect(() => {
    async function fetchData() {
      try {
        const response = await fetch(`/api/iocs?q=${encodeURIComponent(value)}&type=${type}`);
        if (!response.ok) throw new Error('Failed to fetch');
        const data = await response.json();
        setEvents(data.data || []);
      } catch (error) {
        console.error('Error fetching IOC details:', error);
      } finally {
        setLoading(false);
      }
    }
    fetchData();
  }, [type, value]);

  const primaryEvent = events[0];
  const enrichment = primaryEvent?.enrichment;

  // Use ONLY pre-computed AI Risk Score from normalized data
  // If not available, return null to indicate "Pending Analysis"
  const scoreBreakdown = useMemo((): AnyScoreBreakdown | null => {
    if (events.length === 0) return null;
    
    // Check for pre-computed AI scores from Python service
    if (primaryEvent?.aiRiskScore !== undefined && primaryEvent?.aiScoreBreakdown) {
      return buildEnhancedBreakdown(primaryEvent as any);
    }
    
    // No fallback - return null to show "Pending Analysis" state
    return null;
  }, [events, primaryEvent]);

  // Get unique sources
  const sources = useMemo(() => 
    [...new Set(events.map(e => e.source_name))], 
    [events]
  );

  // Build graph data from events
  const graphData = useMemo(() => 
    buildGraphFromEvents(events), 
    [events]
  );

  // Run AI Deep Analysis
  const runAIAnalysis = async () => {
    if (!primaryEvent) return;
    setAiLoading(true);
    try {
      const response = await fetch('/api/analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          iocValue: value,
          iocType: type,
          description: primaryEvent.description || '',
          sources: sources,
          tags: primaryEvent.tags,
          threatTypes: primaryEvent.threat_type
        })
      });
      if (!response.ok) throw new Error('Analysis failed');
      const result = await response.json();
      setAiAnalysis(result.data);
    } catch (error) {
      console.error('AI Analysis error:', error);
    } finally {
      setAiLoading(false);
    }
  };

  const formatDate = (dateStr?: string) => {
    if (!dateStr) return '-';
    return new Date(dateStr).toLocaleDateString('th-TH', {
      day: '2-digit',
      month: 'short',
      year: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
    });
  };

  if (loading) {
    return (
      <>
        <Header title="IOC Details" />
        <div className="page-content">
          <div className={styles.loading}>
            <div className="loading-spinner" />
            <p>Loading IOC details...</p>
          </div>
        </div>
      </>
    );
  }

  if (!primaryEvent) {
    return (
      <>
        <Header title="IOC Details" />
        <div className="page-content">
          <div className={styles.notFound}>
            <h2>IOC Not Found</h2>
            <p>No data found for: {value}</p>
            <Link href="/ioc" className="btn btn-primary">
              Back to IOC Explorer
            </Link>
          </div>
        </div>
      </>
    );
  }

  return (
    <>
      <Header title="IOC Details" />
      <div className="page-content">
        {/* Breadcrumb */}
        <div className={styles.breadcrumb}>
          <Link href="/ioc">IOC Explorer</Link>
          <span>/</span>
          <span>{type}</span>
          <span>/</span>
          <span className={styles.currentPage}>{value}</span>
        </div>

        {/* Threat Actor Alert Banner */}
        {(primaryEvent as any).aiThreatActors && (primaryEvent as any).aiThreatActors.length > 0 && (
          <div className={styles.actorAlert}>
            <span className={styles.actorAlertIcon}>⚠️</span>
            <span className={styles.actorAlertText}>
              Linked to threat actor{(primaryEvent as any).aiThreatActors.length > 1 ? 's' : ''}: 
              <strong> {(primaryEvent as any).aiThreatActors.join(', ')}</strong>
            </span>
          </div>
        )}

        {/* Main Info Card */}
        <div className={styles.mainCard}>
          <div className={styles.iocHeader}>
            <span className={getIOCTypeBadgeClass(type)}>{type}</span>
            <h1 className={styles.iocValue}>{value}</h1>
          </div>

          <div className={styles.metaGrid}>
            <div className={styles.metaItem}>
              <span className={styles.metaLabel}>Severity</span>
              <span className={getSeverityBadgeClass(primaryEvent.aiSeverity || primaryEvent.severity || 'low')}>
                {primaryEvent.aiSeverity || primaryEvent.severity || 'low'}
              </span>
            </div>
            <div className={styles.metaItem}>
              <span className={styles.metaLabel}>AI Risk Score</span>
              {scoreBreakdown ? (
                <ScoreInfoTooltip scoreBreakdown={scoreBreakdown} showThai={true} />
              ) : (
                <span className={styles.pendingBadge} title="IOC ยังไม่ได้รับการวิเคราะห์จาก AI Service">
                  ⏳ Pending Analysis
                </span>
              )}
            </div>
            <div className={styles.metaItem}>
              <span className={styles.metaLabel}>Sources</span>
              <span className={styles.metaValue}>{sources.join(', ')}</span>
            </div>
            <div className={styles.metaItem}>
              <span className={styles.metaLabel}>First Seen</span>
              <span className={styles.metaValue}>{formatDate(primaryEvent.event_time)}</span>
            </div>
          </div>

          {primaryEvent.description && (
            <div className={styles.description}>
              <h3>Description</h3>
              <p>{primaryEvent.description}</p>
            </div>
          )}

          {primaryEvent.tags && primaryEvent.tags.length > 0 && (
            <div className={styles.tags}>
              <h3>Tags</h3>
              <div className={styles.tagList}>
                {primaryEvent.tags.map((tag, idx) => (
                  <span key={idx} className={styles.tag}>{tag}</span>
                ))}
              </div>
            </div>
          )}

          {/* HelpDesk Ticket Creation */}
          <div className={styles.helpdeskSection}>
            <h3>🎫 Escalate to HelpDesk</h3>
            {ticketStatus.success === true ? (
              <div className={styles.ticketSuccess}>
                <span>✅ Ticket created: <strong>{ticketStatus.ticketId}</strong></span>
                <p>{ticketStatus.message}</p>
              </div>
            ) : ticketStatus.success === false ? (
              <div className={styles.ticketError}>
                <span>❌ {ticketStatus.message}</span>
                <button 
                  className="btn btn-secondary"
                  onClick={createHelpDeskTicket}
                  disabled={ticketStatus.loading}
                >
                  Retry
                </button>
              </div>
            ) : (
              <div className={styles.ticketForm}>
                <p className={styles.ticketHint}>
                  Create a ticket in THCert HelpDesk to escalate this threat for investigation.
                </p>
                <button 
                  className={`btn btn-primary ${styles.createTicketBtn}`}
                  onClick={createHelpDeskTicket}
                  disabled={ticketStatus.loading}
                >
                  {ticketStatus.loading ? 'Creating...' : '📝 Create HelpDesk Ticket'}
                </button>
              </div>
            )}
          </div>
        </div>

        {/* AI Classification (from pre-computed data) */}
        {((primaryEvent as any).aiThreatTypes?.length > 0 || 
          (primaryEvent as any).aiThreatActors?.length > 0 ||
          (primaryEvent as any).aiMitreTechniques?.length > 0) && (
          <div className={styles.classificationCard}>
            <h2>🔍 AI Classification (NLP)</h2>
            <div className={styles.classificationGrid}>
              {(primaryEvent as any).aiThreatTypes?.length > 0 && (
                <div className={styles.classificationItem}>
                  <span className={styles.classificationLabel}>Threat Types</span>
                  <div className={styles.badgeList}>
                    {(primaryEvent as any).aiThreatTypes.map((tt: string, i: number) => (
                      <span key={i} className={styles.threatTypeBadge}>{tt}</span>
                    ))}
                  </div>
                </div>
              )}
              
              {(primaryEvent as any).aiThreatActors?.length > 0 && (
                <div className={styles.classificationItem}>
                  <span className={styles.classificationLabel}>Threat Actors</span>
                  <div className={styles.badgeList}>
                    {(primaryEvent as any).aiThreatActors.map((actor: string, i: number) => (
                      <span key={i} className={styles.actorBadge}>{actor}</span>
                    ))}
                  </div>
                </div>
              )}
              
              {(primaryEvent as any).aiMitreTechniques?.length > 0 && (
                <div className={styles.classificationItem}>
                  <span className={styles.classificationLabel}>MITRE ATT&CK</span>
                  <div className={styles.badgeList}>
                    {(primaryEvent as any).aiMitreTechniques.map((tech: string, i: number) => (
                      <span key={i} className={styles.mitreBadge}>{tech}</span>
                    ))}
                  </div>
                </div>
              )}
              
              {(primaryEvent as any).aiClassificationConfidence > 0 && (
                <div className={styles.classificationItem}>
                  <span className={styles.classificationLabel}>AI Confidence</span>
                  <span className={styles.confidenceValue}>
                    {((primaryEvent as any).aiClassificationConfidence * 100).toFixed(1)}%
                  </span>
                </div>
              )}
            </div>
          </div>
        )}

        {/* Relationship Graph */}
        {graphData.nodes.length > 1 && (
          <div className={styles.graphSection}>
            <h2>🔗 Relationship Graph</h2>
            <p className={styles.graphDescription}>
              Interactive visualization of IOC relationships, threat actors, and related entities.
              Click nodes to zoom, drag to pan.
            </p>
            <ThreatGraph data={graphData} height={400} />
          </div>
        )}



        {/* Enrichment Data */}
        {enrichment && (
          <div className={styles.enrichmentSection}>
            <h2>Enrichment Data</h2>

            <div className={styles.enrichmentGrid}>
              {enrichment.whois && (
                <div className={styles.enrichmentCard}>
                  <h3>WHOIS Information</h3>
                  <dl className={styles.dataList}>
                    {enrichment.whois.registrar && (
                      <>
                        <dt>Registrar</dt>
                        <dd>{enrichment.whois.registrar}</dd>
                      </>
                    )}
                    {enrichment.whois.creation_date && (
                      <>
                        <dt>Created</dt>
                        <dd>{formatDate(enrichment.whois.creation_date)}</dd>
                      </>
                    )}
                    {enrichment.whois.expiration_date && (
                      <>
                        <dt>Expires</dt>
                        <dd>{formatDate(enrichment.whois.expiration_date)}</dd>
                      </>
                    )}
                    {enrichment.whois.org && (
                      <>
                        <dt>Organization</dt>
                        <dd>{enrichment.whois.org}</dd>
                      </>
                    )}
                    {(enrichment.whois as any).country && (
                      <>
                        <dt>Country</dt>
                        <dd>{(enrichment.whois as any).country}</dd>
                      </>
                    )}
                  </dl>
                </div>
              )}

              {enrichment.ip_info && (
                <div className={styles.enrichmentCard}>
                  <h3>IP Information</h3>
                  <dl className={styles.dataList}>
                    <dt>Status</dt>
                    <dd>
                      <span className={`badge badge-${enrichment.ip_info.status === 'active' ? 'high' : 'low'}`}>
                        {enrichment.ip_info.status || 'Unknown'}
                      </span>
                    </dd>
                    {enrichment.ip_info.asn_data && (
                      <>
                        {enrichment.ip_info.asn_data.org && (
                          <>
                            <dt>Organization</dt>
                            <dd>{enrichment.ip_info.asn_data.org}</dd>
                          </>
                        )}
                        {enrichment.ip_info.asn_data.country_code && (
                          <>
                            <dt>Country</dt>
                            <dd>{enrichment.ip_info.asn_data.country_code}</dd>
                          </>
                        )}
                        {enrichment.ip_info.asn_data.city && (
                          <>
                            <dt>City</dt>
                            <dd>{enrichment.ip_info.asn_data.city}</dd>
                          </>
                        )}
                      </>
                    )}
                  </dl>
                </div>
              )}

              {enrichment.categories && Object.keys(enrichment.categories).length > 0 && (
                <div className={styles.enrichmentCard}>
                  <h3>Categories</h3>
                  <dl className={styles.dataList}>
                    {Object.entries(enrichment.categories).map(([key, val]) => (
                      <div key={key}>
                        <dt>{key}</dt>
                        <dd>{val}</dd>
                      </div>
                    ))}
                  </dl>
                </div>
              )}

              {enrichment.file && (
                <div className={styles.enrichmentCard}>
                  <h3>File Information</h3>
                  <dl className={styles.dataList}>
                    {enrichment.file.filename && (
                      <>
                        <dt>Filename</dt>
                        <dd>{enrichment.file.filename}</dd>
                      </>
                    )}
                    {enrichment.file.size && (
                      <>
                        <dt>Size</dt>
                        <dd>{enrichment.file.size.toLocaleString()} bytes</dd>
                      </>
                    )}
                    {enrichment.file.md5 && (
                      <>
                        <dt>MD5</dt>
                        <dd className={styles.hash}>{enrichment.file.md5}</dd>
                      </>
                    )}
                    {enrichment.file.sha1 && (
                      <>
                        <dt>SHA1</dt>
                        <dd className={styles.hash}>{enrichment.file.sha1}</dd>
                      </>
                    )}
                    {enrichment.file.sha256 && (
                      <>
                        <dt>SHA256</dt>
                        <dd className={styles.hash}>{enrichment.file.sha256}</dd>
                      </>
                    )}
                  </dl>
                </div>
              )}
            </div>
          </div>
        )}

        {/* Related Events */}
        {events.length > 1 && (
          <div className={styles.relatedSection}>
            <h2>Related Events ({events.length})</h2>
            <table className={styles.table}>
              <thead>
                <tr>
                  <th>Source</th>
                  <th>Severity</th>
                  <th>Description</th>
                  <th>Date</th>
                </tr>
              </thead>
              <tbody>
                {events.map((event, idx) => (
                  <tr key={idx}>
                    <td>{event.source_name}</td>
                    <td>
                      <span className={getSeverityBadgeClass(event.severity || 'low')}>
                        {event.severity || 'low'}
                      </span>
                    </td>
                    <td className={styles.descCell}>
                      {event.description || '-'}
                    </td>
                    <td className={styles.dateCell}>{formatDate(event.event_time)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </>
  );
}
