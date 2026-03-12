'use client';

import { useEffect, useState } from 'react';
import Header from '@/components/layout/Header';
import { ThreatGraph } from '@/components/widgets/ThreatGraph';
import type { AttackGraphResponse } from '@/lib/analytics/types';
import styles from './page.module.css';

type GraphFilter = 'all' | 'with_actors' | 'with_entities';

export default function GraphPage() {
    const [response, setResponse] = useState<AttackGraphResponse | null>(null);
    const [loading, setLoading] = useState(true);
    const [filter, setFilter] = useState<GraphFilter>('with_actors');

    useEffect(() => {
        async function fetchData() {
            setLoading(true);
            try {
                const graphResponse = await fetch(`/api/attack-graph?mode=${filter}&limit=250`);
                if (!graphResponse.ok) {
                    throw new Error('Failed to fetch graph');
                }
                const payload = await graphResponse.json() as AttackGraphResponse;
                setResponse(payload);
            } catch (error) {
                console.error('Error fetching graph data:', error);
                setResponse(null);
            } finally {
                setLoading(false);
            }
        }

        fetchData();
    }, [filter]);

    if (loading) {
        return (
            <>
                <Header title="Threat Graph" />
                <div className="page-content">
                    <div className={styles.loading}>
                        <div className="loading-spinner" />
                        <p>Loading threat data...</p>
                    </div>
                </div>
            </>
        );
    }

    const stats = response?.stats;
    const graphData = response?.data || { nodes: [], links: [] };

    return (
        <>
            <Header title="Threat Graph" />
            <div className="page-content">
                <div className={styles.pageHeader}>
                    <h1>🔗 Interactive Threat Relationship Graph</h1>
                    <p>Warehouse-first graph with datalake enrichment fallback</p>
                </div>

                <div className={styles.statsRow}>
                    <div className={styles.statCard}>
                        <span className={styles.statValue}>{stats?.iocs || 0}</span>
                        <span className={styles.statLabel}>IOCs</span>
                    </div>
                    <div className={styles.statCard}>
                        <span className={styles.statValue} style={{ color: '#dc2626' }}>{stats?.actors || 0}</span>
                        <span className={styles.statLabel}>Threat Actors</span>
                    </div>
                    <div className={styles.statCard}>
                        <span className={styles.statValue} style={{ color: '#f97316' }}>{stats?.threat_types || 0}</span>
                        <span className={styles.statLabel}>Threat Types</span>
                    </div>
                    <div className={styles.statCard}>
                        <span className={styles.statValue}>{stats?.links || 0}</span>
                        <span className={styles.statLabel}>Connections</span>
                    </div>
                </div>

                <div className={styles.filterRow}>
                    <label htmlFor="graph-filter">Show:</label>
                    <select
                        id="graph-filter"
                        value={filter}
                        onChange={(e) => setFilter(e.target.value as GraphFilter)}
                        className={styles.filterSelect}
                    >
                        <option value="with_actors">IOCs with Threat Actors</option>
                        <option value="with_entities">IOCs with Enrichment Context</option>
                        <option value="all">All IOCs</option>
                    </select>
                    <span className={styles.filterInfo}>
                        campaigns: {response?.capabilities.campaigns ? 'on' : 'off'} | infrastructure: {response?.capabilities.infrastructure ? 'on' : 'off'}
                    </span>
                </div>

                <div className={styles.graphWrapper}>
                    {graphData.nodes.length > 0 ? (
                        <ThreatGraph data={graphData} height={600} />
                    ) : (
                        <div className={styles.emptyState}>
                            <p>No relationship data found for the selected filter.</p>
                            <p>Try selecting “All IOCs” or backfill more datalake enrichment.</p>
                        </div>
                    )}
                </div>

                <div className={styles.instructions}>
                    <h3>How to use</h3>
                    <ul>
                        <li><strong>Zoom:</strong> Use mouse wheel to zoom in/out</li>
                        <li><strong>Pan:</strong> Click and drag to move the view</li>
                        <li><strong>Focus:</strong> Click on a node to center and zoom to it</li>
                        <li><strong>Capabilities:</strong> Campaign and infrastructure nodes appear only when datalake fields are populated</li>
                    </ul>
                </div>
            </div>
        </>
    );
}
