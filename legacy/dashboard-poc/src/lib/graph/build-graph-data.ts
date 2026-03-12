import type { ThreatEvent, SeverityLevel } from '@/lib/types';
import type { GraphData, GraphNode, GraphLink, GraphNodeType } from '@/lib/types/graph-types';
import { DEFAULT_NODE_COLORS } from '@/lib/types/graph-types';

/**
 * Build a graph from threat events
 * Extracts relationships between IOCs, threat actors, and related entities
 */
export function buildGraphFromEvents(events: ThreatEvent[]): GraphData {
    const nodes: Map<string, GraphNode> = new Map();
    const links: GraphLink[] = [];
    const addedLinks: Set<string> = new Set();

    // Helper to add a link without duplicates
    const addLink = (source: string, target: string, type: GraphLink['type'], label?: string) => {
        const linkKey = `${source}|${target}|${type}`;
        const reverseLinkKey = `${target}|${source}|${type}`;

        if (!addedLinks.has(linkKey) && !addedLinks.has(reverseLinkKey)) {
            links.push({ source, target, type, label });
            addedLinks.add(linkKey);
        }
    };

    // Helper to get severity safely
    const getSeverity = (event: ThreatEvent): SeverityLevel | undefined => {
        const severity = event.aiSeverity || event.severity;
        if (!severity || (typeof severity === 'string' && severity.trim() === '')) return undefined;
        return severity as SeverityLevel;
    };

    for (const event of events) {
        // 1. Add IOC node (center of the graph)
        const iocId = `ioc:${event.ioc.type}:${event.ioc.value}`;
        if (!nodes.has(iocId)) {
            nodes.set(iocId, {
                id: iocId,
                label: truncateLabel(event.ioc.value, 30),
                type: 'ioc',
                subType: event.ioc.type,
                severity: getSeverity(event),
                size: 12,
                color: DEFAULT_NODE_COLORS.ioc,
                metadata: {
                    fullValue: event.ioc.value,
                    iocType: event.ioc.type,
                }
            });
        }

        // 2. Add Threat Actors from AI classification
        const aiThreatActors = (event as any).aiThreatActors || [];
        for (const actor of aiThreatActors) {
            const actorId = `actor:${actor.toLowerCase().replace(/\s+/g, '_')}`;
            if (!nodes.has(actorId)) {
                nodes.set(actorId, {
                    id: actorId,
                    label: actor,
                    type: 'threat_actor',
                    size: 15,
                    color: DEFAULT_NODE_COLORS.threat_actor,
                    metadata: { source: 'ai_classification' }
                });
            }
            addLink(iocId, actorId, 'attributed_to', 'attributed to');
        }

        // 3. Add Related Entities from enrichment (RelatedEntities is an object with arrays)
        const relatedEntities = event.enrichment?.related_entities;
        if (relatedEntities) {
            // Handle threat_actor array
            if (relatedEntities.threat_actor && Array.isArray(relatedEntities.threat_actor)) {
                for (const actor of relatedEntities.threat_actor) {
                    const actorId = `actor:${actor.toLowerCase().replace(/\s+/g, '_')}`;
                    if (!nodes.has(actorId)) {
                        nodes.set(actorId, {
                            id: actorId,
                            label: actor,
                            type: 'threat_actor',
                            size: 15,
                            color: DEFAULT_NODE_COLORS.threat_actor,
                            metadata: { source: 'enrichment' }
                        });
                    }
                    addLink(iocId, actorId, 'attributed_to', 'attributed to');
                }
            }

            // Handle malware_family array
            if (relatedEntities.malware_family && Array.isArray(relatedEntities.malware_family)) {
                for (const malware of relatedEntities.malware_family) {
                    const malwareId = `entity:malware:${malware.toLowerCase().replace(/\s+/g, '_')}`;
                    if (!nodes.has(malwareId)) {
                        nodes.set(malwareId, {
                            id: malwareId,
                            label: malware,
                            type: 'entity',
                            subType: 'malware_family',
                            size: 10,
                            color: DEFAULT_NODE_COLORS.entity,
                        });
                    }
                    addLink(iocId, malwareId, 'related_to', 'uses malware');
                }
            }

            // Handle campaign array
            if (relatedEntities.campaign && Array.isArray(relatedEntities.campaign)) {
                for (const campaign of relatedEntities.campaign) {
                    const campaignId = `entity:campaign:${campaign.toLowerCase().replace(/\s+/g, '_')}`;
                    if (!nodes.has(campaignId)) {
                        nodes.set(campaignId, {
                            id: campaignId,
                            label: campaign,
                            type: 'entity',
                            subType: 'campaign',
                            size: 10,
                            color: DEFAULT_NODE_COLORS.entity,
                        });
                    }
                    addLink(iocId, campaignId, 'related_to', 'part of campaign');
                }
            }
        }

        // 4. Add Related Domains if exists (is array)
        const relatedDomains = event.ioc.related_domain;
        if (relatedDomains && Array.isArray(relatedDomains)) {
            for (const domain of relatedDomains) {
                if (domain && domain !== event.ioc.value) {
                    const domainId = `ioc:domain:${domain}`;
                    if (!nodes.has(domainId)) {
                        nodes.set(domainId, {
                            id: domainId,
                            label: truncateLabel(domain, 25),
                            type: 'domain',
                            subType: 'domain',
                            size: 8,
                            color: DEFAULT_NODE_COLORS.domain,
                        });
                    }
                    addLink(iocId, domainId, 'related_to', 'related domain');
                }
            }
        }

        // 5. Add Related Hashes if exists (is array)
        const relatedHashes = event.ioc.related_hash;
        if (relatedHashes && Array.isArray(relatedHashes)) {
            for (const hash of relatedHashes) {
                if (hash) {
                    const hashId = `ioc:hash:${hash.substring(0, 16)}`;
                    if (!nodes.has(hashId)) {
                        nodes.set(hashId, {
                            id: hashId,
                            label: hash.substring(0, 12) + '...',
                            type: 'ioc',
                            subType: 'hash',
                            size: 8,
                            color: DEFAULT_NODE_COLORS.ioc,
                            metadata: { fullHash: hash }
                        });
                    }
                    addLink(iocId, hashId, 'contains', 'contains hash');
                }
            }
        }
    }

    return {
        nodes: Array.from(nodes.values()),
        links
    };
}

/**
 * Truncate a label for display
 */
function truncateLabel(text: string, maxLength: number): string {
    if (text.length <= maxLength) return text;
    return text.substring(0, maxLength - 3) + '...';
}

/**
 * Build a focused graph around a single IOC
 */
export function buildFocusedGraph(
    centerValue: string,
    centerType: string,
    events: ThreatEvent[]
): GraphData {
    // Filter events related to this IOC
    const relatedEvents = events.filter(e =>
        e.ioc.value === centerValue && e.ioc.type === centerType
    );

    return buildGraphFromEvents(relatedEvents);
}
