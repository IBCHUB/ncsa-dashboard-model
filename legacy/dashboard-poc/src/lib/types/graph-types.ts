import type { SeverityLevel } from './index';

/**
 * Graph Node Types
 */
export type GraphNodeType =
    | 'ioc'
    | 'threat_actor'
    | 'threat_type'
    | 'sector'
    | 'country'
    | 'infrastructure'
    | 'campaign'
    | 'malware'
    | 'entity'
    | 'ip'
    | 'domain';

export interface GraphNode {
    id: string;
    label: string;
    type: GraphNodeType;
    subType?: string; // e.g., ioc.type or entity_type
    severity?: SeverityLevel;
    size?: number;
    color?: string;
    metadata?: Record<string, unknown>;
}

/**
 * Graph Link Types
 */
export type GraphLinkType =
    | 'related_to'
    | 'attributed_to'
    | 'classified_as'
    | 'targets'
    | 'located_in'
    | 'uses_malware'
    | 'shares_infrastructure'
    | 'same_campaign'
    | 'resolves_to'
    | 'contains'
    | 'same_actor';

export interface GraphLink {
    source: string;
    target: string;
    type: GraphLinkType;
    label?: string;
    weight?: number;
    color?: string;
}

/**
 * Complete Graph Data Structure
 */
export interface GraphData {
    nodes: GraphNode[];
    links: GraphLink[];
}

/**
 * Graph Configuration
 */
export interface GraphConfig {
    width?: number;
    height?: number;
    backgroundColor?: string;
    nodeColors?: Record<GraphNodeType, string>;
    linkColors?: Record<GraphLinkType, string>;
    enableZoom?: boolean;
    enableDrag?: boolean;
}

/**
 * Default node colors by type
 */
export const DEFAULT_NODE_COLORS: Record<GraphNodeType, string> = {
    ioc: '#3b82f6',        // Blue
    threat_actor: '#dc2626', // Red
    threat_type: '#f97316',
    sector: '#22c55e',
    country: '#06b6d4',
    infrastructure: '#eab308',
    campaign: '#ec4899',
    malware: '#8b5cf6',
    entity: '#7c3aed',     // Purple
    ip: '#06b6d4',         // Cyan
    domain: '#10b981',     // Green
};

/**
 * Default link colors by type
 */
export const DEFAULT_LINK_COLORS: Record<GraphLinkType, string> = {
    related_to: 'rgba(255,255,255,0.3)',
    attributed_to: 'rgba(220,38,38,0.5)',
    classified_as: 'rgba(249,115,22,0.5)',
    targets: 'rgba(34,197,94,0.5)',
    located_in: 'rgba(6,182,212,0.5)',
    uses_malware: 'rgba(139,92,246,0.5)',
    shares_infrastructure: 'rgba(234,179,8,0.5)',
    same_campaign: 'rgba(236,72,153,0.5)',
    resolves_to: 'rgba(6,182,212,0.5)',
    contains: 'rgba(16,185,129,0.5)',
    same_actor: 'rgba(124,58,237,0.5)',
};
