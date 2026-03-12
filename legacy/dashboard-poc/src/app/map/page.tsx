'use client';

import { useState, useEffect } from 'react';
import dynamic from 'next/dynamic';
import Header from '@/components/layout/Header';
import styles from './page.module.css';

// Dynamic import to avoid SSR issues with D3
const ThreatMap = dynamic(
  () => import('@/components/widgets/ThreatMap'),
  { ssr: false, loading: () => <div className={styles.mapLoading}>Loading map...</div> }
);

interface CountryThreat {
  code: string;
  name: string;
  count: number;
  lat: number;
  lng: number;
  primarySeverity: string;
  severities: Record<string, number>;
}

interface GeoData {
  countries: CountryThreat[];
  topCountries: CountryThreat[];
  totalThreats: number;
  uniqueCountries: number;
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
};

export default function ConnectionMapPage() {
  const [data, setData] = useState<GeoData | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchGeoData();
  }, []);

  const fetchGeoData = async () => {
    try {
      const response = await fetch('/api/geo-threats');
      const result = await response.json();
      if (result.success) {
        setData(result.data);
      }
    } catch (error) {
      console.error('Error fetching geo data:', error);
    } finally {
      setLoading(false);
    }
  };

  return (
    <>
      <Header title="Connection Map" />
      <div className="page-content">
        {/* Stats Cards */}
        <div className={styles.statsGrid}>
          <div className={styles.statCard}>
            <span className={styles.statValue}>{data?.totalThreats || 0}</span>
            <span className={styles.statLabel}>Total Threats</span>
          </div>
          <div className={styles.statCard}>
            <span className={styles.statValue}>{data?.uniqueCountries || 0}</span>
            <span className={styles.statLabel}>Source Countries</span>
          </div>
          <div className={styles.statCard} style={{ borderLeftColor: '#00e676' }}>
            <span className={styles.statValue}>🇹🇭</span>
            <span className={styles.statLabel}>Target: Thailand</span>
          </div>
        </div>

        {/* Map Section */}
        <div className={styles.mapSection}>
          <div className={styles.mapHeader}>
            <h2>🌍 Threat Origin Map</h2>
            <p>Attacks targeting Thailand from around the world</p>
          </div>
          
          {loading ? (
            <div className={styles.mapLoading}>
              <div className="loading-spinner" />
              <p>Loading threat data...</p>
            </div>
          ) : data ? (
            <ThreatMap 
              countries={data.countries} 
              target={data.target} 
            />
          ) : (
            <div className={styles.mapLoading}>
              <p>No data available</p>
            </div>
          )}
        </div>

        {/* Top Countries Section */}
        <div className={styles.topCountriesSection}>
          <h2>📊 Top Source Countries</h2>
          
          <div className={styles.countriesList}>
            {data?.topCountries.map((country, idx) => {
              const maxCount = data.topCountries[0]?.count || 1;
              const percentage = (country.count / maxCount) * 100;
              
              return (
                <div key={country.code} className={styles.countryRow}>
                  <div className={styles.countryRank}>#{idx + 1}</div>
                  <div className={styles.countryInfo}>
                    <span className={styles.countryName}>{country.name}</span>
                    <span className={styles.countryCode}>{country.code}</span>
                  </div>
                  <div className={styles.countryBar}>
                    <div 
                      className={styles.countryBarFill}
                      style={{ 
                        width: `${percentage}%`,
                        backgroundColor: SEVERITY_COLORS[country.primarySeverity] || '#666'
                      }}
                    />
                  </div>
                  <div className={styles.countryCount}>
                    {country.count}
                    <span className={styles.countLabel}>threats</span>
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* Legend */}
        <div className={styles.legend}>
          <h3>Severity Legend</h3>
          <div className={styles.legendItems}>
            {Object.entries(SEVERITY_COLORS).map(([severity, color]) => (
              <div key={severity} className={styles.legendItem}>
                <span 
                  className={styles.legendColor}
                  style={{ backgroundColor: color }}
                />
                <span className={styles.legendLabel}>{severity}</span>
              </div>
            ))}
          </div>
        </div>
      </div>
    </>
  );
}
