'use client';

import { useState, useEffect, useMemo } from 'react';
import Header from '@/components/layout/Header';
import { ThreatGraph } from '@/components/widgets/ThreatGraph';
import { buildGraphFromEvents } from '@/lib/graph';
import type { ThreatEvent } from '@/lib/types';
import type { GraphData } from '@/lib/types/graph-types';
import styles from './page.module.css';

export default function GraphPage() {
    const [events, setEvents] = useState<ThreatEvent[]>([]);
    const [loading, setLoading] = useState(true);
    const [filter, setFilter] = useState<'all' | 'with_actors' | 'with_entities'>('with_actors');

    useEffect(() => {
        async function fetchData() {
            try {
                const response = await fetch('/api/iocs?limit=1000');
                if (!response.ok) throw new Error('Failed to fetch');
                const data = await response.json();
                setEvents(data.data || []);
            } catch (error) {
                console.error('Error fetching data:', error);
            } finally {
                setLoading(false);
            }
        }
        fetchData();
    }, []);

    // Filter events based on selection
    const filteredEvents = useMemo(() => {
        switch (filter) {
            case 'with_actors':
                return events.filter(e => 
                    ((e as any).aiThreatActors?.length > 0) ||
                    ((e.enrichment?.related_entities?.threat_actor?.length ?? 0) > 0)
                );
            case 'with_entities':
                return events.filter(e => 
                    ((e as any).aiThreatActors?.length > 0) ||
                    ((e.enrichment?.related_entities?.threat_actor?.length ?? 0) > 0) ||
                    ((e.enrichment?.related_entities?.malware_family?.length ?? 0) > 0) ||
                    ((e.enrichment?.related_entities?.campaign?.length ?? 0) > 0)
                );
            default:
                return events;
        }
    }, [events, filter]);

    // Build graph from filtered events
    const graphData: GraphData = useMemo(() => {
        if (filteredEvents.length === 0) {
            return { nodes: [], links: [] };
        }
        return buildGraphFromEvents(filteredEvents);
    }, [filteredEvents]);

    // Count stats
    const stats = useMemo(() => {
        const actorNodes = graphData.nodes.filter(n => n.type === 'threat_actor');
        const iocNodes = graphData.nodes.filter(n => n.type === 'ioc');
        const entityNodes = graphData.nodes.filter(n => n.type === 'entity');
        return {
            actors: actorNodes.length,
            iocs: iocNodes.length,
            entities: entityNodes.length,
            links: graphData.links.length
        };
    }, [graphData]);

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

    return (
        <>
            <Header title="Threat Graph" />
            <div className="page-content">
                <div className={styles.pageHeader}>
                    <h1>🔗 Interactive Threat Relationship Graph</h1>
                    <p>Visualize connections between IOCs, Threat Actors, and related entities</p>
                </div>

                {/* Stats */}
                <div className={styles.statsRow}>
                    <div className={styles.statCard}>
                        <span className={styles.statValue}>{stats.iocs}</span>
                        <span className={styles.statLabel}>IOCs</span>
                    </div>
                    <div className={styles.statCard}>
                        <span className={styles.statValue} style={{ color: '#dc2626' }}>{stats.actors}</span>
                        <span className={styles.statLabel}>Threat Actors</span>
                    </div>
                    <div className={styles.statCard}>
                        <span className={styles.statValue} style={{ color: '#7c3aed' }}>{stats.entities}</span>
                        <span className={styles.statLabel}>Entities</span>
                    </div>
                    <div className={styles.statCard}>
                        <span className={styles.statValue}>{stats.links}</span>
                        <span className={styles.statLabel}>Connections</span>
                    </div>
                </div>

                {/* Filter */}
                <div className={styles.filterRow}>
                    <label>Show:</label>
                    <select 
                        value={filter} 
                        onChange={(e) => setFilter(e.target.value as any)}
                        className={styles.filterSelect}
                    >
                        <option value="with_actors">IOCs with Threat Actors</option>
                        <option value="with_entities">IOCs with Any Entities</option>
                        <option value="all">All IOCs</option>
                    </select>
                    <span className={styles.filterInfo}>
                        Showing {filteredEvents.length} of {events.length} events
                    </span>
                </div>

                {/* Graph */}
                <div className={styles.graphWrapper}>
                    {graphData.nodes.length > 0 ? (
                        <ThreatGraph 
                            data={graphData} 
                            height={600}
                        />
                    ) : (
                        <div className={styles.emptyState}>
                            <p>No relationship data found for the selected filter.</p>
                            <p>Try selecting "All IOCs" or run the AI enrichment script.</p>
                        </div>
                    )}
                </div>

                {/* Instructions */}
                <div className={styles.instructions}>
                    <h3>How to use</h3>
                    <ul>
                        <li><strong>Zoom:</strong> Use mouse wheel to zoom in/out</li>
                        <li><strong>Pan:</strong> Click and drag to move the view</li>
                        <li><strong>Focus:</strong> Click on a node to center and zoom to it</li>
                        <li><strong>Legend:</strong> Blue = IOC, Red = Threat Actor, Purple = Entity</li>
                    </ul>
                </div>
            </div>
        </>
    );
}
