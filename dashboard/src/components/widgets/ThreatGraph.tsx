'use client';

import { useRef, useCallback, useEffect, useState } from 'react';
import dynamic from 'next/dynamic';
import type { GraphData, GraphNode, GraphConfig } from '@/lib/types/graph-types';
import { DEFAULT_NODE_COLORS } from '@/lib/types/graph-types';
import styles from './ThreatGraph.module.css';

// Dynamic import to avoid SSR issues with canvas
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

    // Update dimensions on resize
    useEffect(() => {
        if (!containerRef.current || width) return;
        
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

    // Center graph on mount
    useEffect(() => {
        if (graphRef.current && data.nodes.length > 0) {
            setTimeout(() => {
                graphRef.current?.zoomToFit(400, 50);
            }, 500);
        }
    }, [data]);

    // Get node color based on type
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const getNodeColor = useCallback((node: any) => {
        const nodeColors = config.nodeColors || DEFAULT_NODE_COLORS;
        return node.color || nodeColors[node.type as keyof typeof nodeColors] || '#6b7280';
    }, [config.nodeColors]);

    // Get link color based on type
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const getLinkColor = useCallback((link: any) => {
        const linkColors = config.linkColors || DEFAULT_LINK_COLORS;
        return link.color || linkColors[link.type as keyof typeof linkColors] || 'rgba(255,255,255,0.2)';
    }, [config.linkColors]);

    // Import link colors
    const DEFAULT_LINK_COLORS = {
        related_to: 'rgba(255,255,255,0.3)',
        attributed_to: 'rgba(220,38,38,0.5)',
        resolves_to: 'rgba(6,182,212,0.5)',
        contains: 'rgba(16,185,129,0.5)',
        same_actor: 'rgba(124,58,237,0.5)',
    };

    // Draw custom node
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const drawNode = useCallback((node: any, ctx: CanvasRenderingContext2D, globalScale: number) => {
        const size = node.size || 8;
        const fontSize = Math.max(10 / globalScale, 3);
        const label = node.label || node.id;
        
        // Draw node circle
        ctx.beginPath();
        ctx.arc(node.x, node.y, size, 0, 2 * Math.PI);
        ctx.fillStyle = getNodeColor(node);
        ctx.fill();
        
        // Draw border for threat actors
        if (node.type === 'threat_actor') {
            ctx.strokeStyle = '#fff';
            ctx.lineWidth = 2 / globalScale;
            ctx.stroke();
        }
        
        // Draw label
        ctx.font = `${fontSize}px Inter, sans-serif`;
        ctx.textAlign = 'center';
        ctx.textBaseline = 'top';
        ctx.fillStyle = 'rgba(255, 255, 255, 0.9)';
        ctx.fillText(label, node.x, node.y + size + 2);
    }, [getNodeColor]);

    // Handle node click
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const handleNodeClick = useCallback((node: any) => {
        if (onNodeClick) {
            onNodeClick(node as GraphNode);
        }
        
        // Zoom to node
        if (graphRef.current) {
            graphRef.current.centerAt(node.x, node.y, 500);
            graphRef.current.zoom(2, 500);
        }
    }, [onNodeClick]);

    // No data state
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
            
            {/* Legend */}
            <div className={styles.legend}>
                <div className={styles.legendItem}>
                    <span className={styles.legendDot} style={{ background: DEFAULT_NODE_COLORS.ioc }} />
                    <span>IOC</span>
                </div>
                <div className={styles.legendItem}>
                    <span className={styles.legendDot} style={{ background: DEFAULT_NODE_COLORS.threat_actor }} />
                    <span>Threat Actor</span>
                </div>
                <div className={styles.legendItem}>
                    <span className={styles.legendDot} style={{ background: DEFAULT_NODE_COLORS.entity }} />
                    <span>Entity</span>
                </div>
                <div className={styles.legendItem}>
                    <span className={styles.legendDot} style={{ background: DEFAULT_NODE_COLORS.ip }} />
                    <span>IP</span>
                </div>
            </div>
        </div>
    );
}
