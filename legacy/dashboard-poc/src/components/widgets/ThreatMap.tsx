'use client';

import { useEffect, useRef, useState } from 'react';
import * as d3 from 'd3';
import * as topojson from 'topojson-client';
import styles from './ThreatMap.module.css';

interface CountryThreat {
  code: string;
  name: string;
  count: number;
  lat: number;
  lng: number;
  primarySeverity: string;
}

interface ThreatMapProps {
  countries: CountryThreat[];
  target: {
    code: string;
    name: string;
    lat: number;
    lng: number;
  };
}

const SEVERITY_COLORS: Record<string, string> = {
  critical: '#e53935',
  high: '#ff9800',
  medium: '#ffc107',
  low: '#4caf50',
  clean: '#2196f3',
  unknown: '#666',
};

export default function ThreatMap({ countries, target }: ThreatMapProps) {
  const svgRef = useRef<SVGSVGElement>(null);
  const [hoveredCountry, setHoveredCountry] = useState<CountryThreat | null>(null);
  const [worldData, setWorldData] = useState<any>(null);

  // Load world map data
  useEffect(() => {
    fetch('/data/world-110m.json')
      .then(res => res.json())
      .then(data => setWorldData(data))
      .catch(err => console.error('Error loading world map:', err));
  }, []);

  useEffect(() => {
    if (!svgRef.current || countries.length === 0 || !worldData) return;

    const svg = d3.select(svgRef.current);
    svg.selectAll('*').remove();

    const width = svgRef.current.clientWidth;
    const height = svgRef.current.clientHeight;

    // Create projection with wider global view (showing US to Asia)
    const projection = d3.geoNaturalEarth1()
      .center([0, 20]) // Center on global view
      .scale(width / 5.5)
      .translate([width / 2, height / 2]);

    const pathGenerator = d3.geoPath().projection(projection);

    // Draw ocean background
    svg.append('rect')
      .attr('width', width)
      .attr('height', height)
      .attr('fill', '#0a1628'); // Dark ocean

    // Draw country boundaries
    const countriesGeo = topojson.feature(worldData, worldData.objects.countries) as any;
    
    // Create a set of source country codes for highlighting
    const sourceCountryCodes = new Set(countries.map(c => c.code));

    svg.append('g')
      .attr('class', 'countries')
      .selectAll('path')
      .data(countriesGeo.features)
      .enter()
      .append('path')
      .attr('d', pathGenerator as any)
      .attr('fill', (d: any) => {
        // Highlight Thailand
        if (d.id === '764') return '#00e676'; // Thailand ISO numeric code
        return '#1a2a4a'; // Default country color
      })
      .attr('stroke', '#2a3a5a')
      .attr('stroke-width', 0.5);

    // Create arc line generator
    const createArc = (source: [number, number], targetCoord: [number, number]) => {
      const sourceProj = projection(source);
      const targetProj = projection(targetCoord);
      
      if (!sourceProj || !targetProj) return '';

      const dx = targetProj[0] - sourceProj[0];
      const dy = targetProj[1] - sourceProj[1];
      const dr = Math.sqrt(dx * dx + dy * dy) * 0.8; // Curve radius

      return `M${sourceProj[0]},${sourceProj[1]}A${dr},${dr} 0 0,1 ${targetProj[0]},${targetProj[1]}`;
    };

    // Draw arcs from source countries to Thailand
    const arcGroup = svg.append('g').attr('class', 'arcs');
    
    // Limit to top countries for performance
    const topCountries = countries.slice(0, 15);
    const maxCount = Math.max(...topCountries.map(c => c.count));

    topCountries.forEach((country, index) => {
      const source: [number, number] = [country.lng, country.lat];
      const targetCoord: [number, number] = [target.lng, target.lat];
      const arcPath = createArc(source, targetCoord);
      
      if (!arcPath) return;

      const strokeWidth = 1.5 + (country.count / maxCount) * 4;
      const color = SEVERITY_COLORS[country.primarySeverity] || SEVERITY_COLORS.unknown;

      // Draw glow effect first (behind the arc)
      arcGroup.append('path')
        .attr('d', arcPath)
        .attr('fill', 'none')
        .attr('stroke', color)
        .attr('stroke-width', strokeWidth + 6)
        .attr('stroke-opacity', 0.15)
        .attr('filter', 'blur(4px)');

      // Draw arc path
      const arc = arcGroup.append('path')
        .attr('d', arcPath)
        .attr('fill', 'none')
        .attr('stroke', color)
        .attr('stroke-width', strokeWidth)
        .attr('stroke-opacity', 0.8)
        .attr('stroke-linecap', 'round')
        .attr('class', styles.arcPath);

      // Get total length for animation
      const totalLength = arc.node()?.getTotalLength() || 0;

      // Animate arc drawing
      arc
        .attr('stroke-dasharray', `${totalLength} ${totalLength}`)
        .attr('stroke-dashoffset', totalLength)
        .transition()
        .delay(index * 150)
        .duration(1500)
        .ease(d3.easeQuadOut)
        .attr('stroke-dashoffset', 0);
    });

    // Draw source country markers with labels
    const markerGroup = svg.append('g').attr('class', 'markers');

    topCountries.forEach((country) => {
      const coords = projection([country.lng, country.lat]);
      if (!coords) return;

      const color = SEVERITY_COLORS[country.primarySeverity] || SEVERITY_COLORS.unknown;
      const radius = 3 + Math.log2(country.count + 1) * 1.2; // Smaller markers

      // Outer glow
      markerGroup.append('circle')
        .attr('cx', coords[0])
        .attr('cy', coords[1])
        .attr('r', radius + 3)
        .attr('fill', color)
        .attr('opacity', 0.25);

      // Main marker
      markerGroup.append('circle')
        .attr('cx', coords[0])
        .attr('cy', coords[1])
        .attr('r', radius)
        .attr('fill', color)
        .attr('stroke', 'white')
        .attr('stroke-width', 1.5)
        .attr('cursor', 'pointer')
        .on('mouseenter', () => setHoveredCountry(country))
        .on('mouseleave', () => setHoveredCountry(null));

      // Country label
      markerGroup.append('text')
        .attr('x', coords[0])
        .attr('y', coords[1] - radius - 8)
        .attr('text-anchor', 'middle')
        .attr('fill', 'white')
        .attr('font-size', '10px')
        .attr('font-weight', '500')
        .attr('paint-order', 'stroke')
        .attr('stroke', '#0a1628')
        .attr('stroke-width', '3px')
        .text(country.code);
    });

    // Draw Thailand (target) marker
    const thCoords = projection([target.lng, target.lat]);
    if (thCoords) {
      const pulseGroup = svg.append('g').attr('class', 'target');

      // Pulse rings
      for (let i = 0; i < 3; i++) {
        pulseGroup.append('circle')
          .attr('cx', thCoords[0])
          .attr('cy', thCoords[1])
          .attr('r', 12)
          .attr('fill', 'none')
          .attr('stroke', '#00e676')
          .attr('stroke-width', 2)
          .attr('opacity', 0.8)
          .attr('class', styles.pulse)
          .style('animation-delay', `${i * 0.6}s`);
      }

      // Center point with flag emoji
      pulseGroup.append('circle')
        .attr('cx', thCoords[0])
        .attr('cy', thCoords[1])
        .attr('r', 12)
        .attr('fill', '#00e676')
        .attr('stroke', 'white')
        .attr('stroke-width', 2);

      // Label
      pulseGroup.append('text')
        .attr('x', thCoords[0])
        .attr('y', thCoords[1] + 30)
        .attr('text-anchor', 'middle')
        .attr('fill', '#00e676')
        .attr('font-size', '12px')
        .attr('font-weight', 'bold')
        .attr('paint-order', 'stroke')
        .attr('stroke', '#0a1628')
        .attr('stroke-width', '3px')
        .text('🇹🇭 THAILAND');
    }

  }, [countries, target, worldData]);

  return (
    <div className={styles.mapContainer}>
      {!worldData && (
        <div className={styles.mapLoading}>
          <div className="loading-spinner" />
          <p>Loading world map...</p>
        </div>
      )}
      <svg ref={svgRef} className={styles.mapSvg} />
      
      {hoveredCountry && (
        <div className={styles.tooltip}>
          <div className={styles.tooltipHeader}>
            <span className={styles.countryName}>{hoveredCountry.name}</span>
            <span 
              className={styles.severityBadge}
              style={{ backgroundColor: SEVERITY_COLORS[hoveredCountry.primarySeverity] }}
            >
              {hoveredCountry.primarySeverity}
            </span>
          </div>
          <div className={styles.tooltipContent}>
            <strong>{hoveredCountry.count}</strong> threats detected
          </div>
        </div>
      )}
    </div>
  );
}
