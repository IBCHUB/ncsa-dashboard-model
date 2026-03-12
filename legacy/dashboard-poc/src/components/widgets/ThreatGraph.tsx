'use client';

import { useCallback, useEffect, useRef, useState } from 'react';
import dynamic from 'next/dynamic';
import type { GraphConfig, GraphData, GraphNode } from '@/lib/types/graph-types';
import { DEFAULT_LINK_COLORS, DEFAULT_NODE_COLORS } from '@/lib/types/graph-types';
import styles from './ThreatGraph.module.css';

// eslint-disable-next-line @typescript-eslint/no-explicit-any
const ForceGraph2D = dynamic<any>(
    () => import('react-force-graph-2d'),
    { ssr: false, loading: () => <div className={styles.loading}>Loading graph...</div> }
);

interface ThreatGraphProps {
    data: GraphData;
    width?: number;
    height?: number;
    config?: Partial<GraphConfig>;
    onNodeClick?: (node: GraphNode) => void;
}

const LEGEND_ITEMS = [
    { label: 'IOC', color: DEFAULT_NODE_COLORS.ioc },
    { label: 'Threat Actor', color: DEFAULT_NODE_COLORS.threat_actor },
    { label: 'Threat Type', color: DEFAULT_NODE_COLORS.threat_type },
    { label: 'Sector', color: DEFAULT_NODE_COLORS.sector },
    { label: 'Infrastructure', color: DEFAULT_NODE_COLORS.infrastructure },
];

export function ThreatGraph({
    data,
    width,
    height = 400,
    config = {},
    onNodeClick
}: ThreatGraphProps) {
    const containerRef = useRef<HTMLDivElement>(null);
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const graphRef = useRef<any>(null);
    const [dimensions, setDimensions] = useState({ width: width || 800, height });

    useEffect(() => {
        if (!containerRef.current || width) {
            return undefined;
        }

        const updateDimensions = () => {
            if (containerRef.current) {
                setDimensions({
                    width: containerRef.current.offsetWidth,
                    height
                });
            }
        };

        updateDimensions();
        window.addEventListener('resize', updateDimensions);
        return () => window.removeEventListener('resize', updateDimensions);
    }, [width, height]);

    useEffect(() => {
        if (graphRef.current && data.nodes.length > 0) {
            setTimeout(() => {
                graphRef.current?.zoomToFit(400, 50);
            }, 500);
        }
    }, [data]);

    const getNodeColor = useCallback((node: GraphNode) => {
        const nodeColors = config.nodeColors || DEFAULT_NODE_COLORS;
        return node.color || nodeColors[node.type] || '#6b7280';
    }, [config.nodeColors]);

    const getLinkColor = useCallback((link: { type: keyof typeof DEFAULT_LINK_COLORS; color?: string }) => {
        const linkColors = config.linkColors || DEFAULT_LINK_COLORS;
        return link.color || linkColors[link.type] || 'rgba(255,255,255,0.2)';
    }, [config.linkColors]);

    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const drawNode = useCallback((node: any, ctx: CanvasRenderingContext2D, globalScale: number) => {
        const size = node.size || 8;
        const fontSize = Math.max(10 / globalScale, 3);
        const label = node.label || node.id;

        ctx.beginPath();
        ctx.arc(node.x, node.y, size, 0, 2 * Math.PI);
        ctx.fillStyle = getNodeColor(node as GraphNode);
        ctx.fill();

        if (node.type === 'threat_actor') {
            ctx.strokeStyle = '#fff';
            ctx.lineWidth = 2 / globalScale;
            ctx.stroke();
        }

        ctx.font = `${fontSize}px Inter, sans-serif`;
        ctx.textAlign = 'center';
        ctx.textBaseline = 'top';
        ctx.fillStyle = 'rgba(255, 255, 255, 0.9)';
        ctx.fillText(label, node.x, node.y + size + 2);
    }, [getNodeColor]);

    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const handleNodeClick = useCallback((node: any) => {
        if (onNodeClick) {
            onNodeClick(node as GraphNode);
        }

        if (graphRef.current) {
            graphRef.current.centerAt(node.x, node.y, 500);
            graphRef.current.zoom(2, 500);
        }
    }, [onNodeClick]);

    if (data.nodes.length === 0) {
        return (
            <div className={styles.empty}>
                <p>No relationship data available</p>
            </div>
        );
    }

    return (
        <div ref={containerRef} className={styles.graphContainer}>
            <ForceGraph2D
                ref={graphRef}
                graphData={data}
                width={dimensions.width}
                height={dimensions.height}
                backgroundColor="transparent"
                nodeCanvasObject={drawNode}
                nodePointerAreaPaint={(node: { x: number; y: number; size?: number }, color: string, ctx: CanvasRenderingContext2D) => {
                    const size = node.size || 8;
                    ctx.beginPath();
                    ctx.arc(node.x, node.y, size + 5, 0, 2 * Math.PI);
                    ctx.fillStyle = color;
                    ctx.fill();
                }}
                linkColor={getLinkColor}
                linkWidth={1.5}
                linkDirectionalArrowLength={4}
                linkDirectionalArrowRelPos={0.9}
                linkCurvature={0.1}
                onNodeClick={handleNodeClick}
                cooldownTicks={100}
                d3AlphaDecay={0.02}
                d3VelocityDecay={0.3}
                enableZoomInteraction={config.enableZoom !== false}
                enablePanInteraction={config.enableDrag !== false}
            />

            <div className={styles.legend}>
                {LEGEND_ITEMS.map((item) => (
                    <div key={item.label} className={styles.legendItem}>
                        <span className={styles.legendDot} style={{ background: item.color }} />
                        <span>{item.label}</span>
                    </div>
                ))}
            </div>
        </div>
    );
}
