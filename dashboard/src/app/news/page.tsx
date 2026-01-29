'use client';

import { useState, useEffect } from 'react';
import Header from '@/components/layout/Header';
import styles from './page.module.css';

interface NewsArticle {
  id: string;
  title: string;
  url: string;
  source: string;
  date: string;
  relatedIOCs: Array<{ type: string; value: string }>;
  iocCount: number;
}

const sourceColors: Record<string, string> = {
  'TheHackerNews': '#e53935',
  'DarkReading': '#1e88e5',
  'BleepingComputer': '#43a047',
};

const sourceIcons: Record<string, string> = {
  'TheHackerNews': '🔐',
  'DarkReading': '🌑',
  'BleepingComputer': '💻',
};

export default function CyberNewsPage() {
  const [articles, setArticles] = useState<NewsArticle[]>([]);
  const [sources, setSources] = useState<string[]>([]);
  const [loading, setLoading] = useState(true);
  const [sourceFilter, setSourceFilter] = useState('');
  const [search, setSearch] = useState('');

  useEffect(() => {
    fetchNews();
  }, []);

  const fetchNews = async () => {
    try {
      const response = await fetch('/api/news');
      const data = await response.json();
      if (data.success) {
        setArticles(data.data);
        setSources(data.sources);
      }
    } catch (error) {
      console.error('Error fetching news:', error);
    } finally {
      setLoading(false);
    }
  };

  const filteredArticles = articles.filter(article => {
    const matchesSource = !sourceFilter || article.source === sourceFilter;
    const matchesSearch = !search || 
      article.title.toLowerCase().includes(search.toLowerCase());
    return matchesSource && matchesSearch;
  });

  const formatDate = (dateStr: string) => {
    return new Date(dateStr).toLocaleDateString('th-TH', {
      day: '2-digit',
      month: 'short',
      year: 'numeric',
    });
  };

  const getIOCTypeClass = (type: string) => {
    const typeMap: Record<string, string> = {
      'ip': 'ioc-type-ip',
      'domain': 'ioc-type-domain',
      'url': 'ioc-type-url',
      'cve': 'ioc-type-cve',
      'sha256': 'ioc-type-hash',
      'sha1': 'ioc-type-hash',
      'md5': 'ioc-type-hash',
    };
    return typeMap[type] || 'ioc-type-domain';
  };

  // Stats
  const stats = {
    total: articles.length,
    bySource: sources.reduce((acc, source) => {
      acc[source] = articles.filter(a => a.source === source).length;
      return acc;
    }, {} as Record<string, number>),
  };

  return (
    <>
      <Header title="Cyber News" />
      <div className="page-content">
        {/* Stats */}
        <div className={styles.statsGrid}>
          <div className={styles.statCard}>
            <span className={styles.statValue}>{stats.total}</span>
            <span className={styles.statLabel}>Total Articles</span>
          </div>
          {sources.map(source => (
            <div 
              key={source} 
              className={styles.statCard}
              style={{ borderLeftColor: sourceColors[source] || '#666' }}
            >
              <span className={styles.statValue}>{stats.bySource[source]}</span>
              <span className={styles.statLabel}>
                {sourceIcons[source]} {source}
              </span>
            </div>
          ))}
        </div>

        {/* Filters */}
        <div className={styles.filterSection}>
          <input
            type="text"
            placeholder="Search articles..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className={styles.searchInput}
          />
          <select
            value={sourceFilter}
            onChange={(e) => setSourceFilter(e.target.value)}
            className={styles.filterSelect}
          >
            <option value="">All Sources</option>
            {sources.map(source => (
              <option key={source} value={source}>
                {source} ({stats.bySource[source]})
              </option>
            ))}
          </select>
        </div>

        {/* Results Info */}
        <div className={styles.resultsInfo}>
          Showing {filteredArticles.length} of {articles.length} articles
        </div>

        {/* News Grid */}
        {loading ? (
          <div className={styles.loading}>
            <div className="loading-spinner" />
            <p>Loading news...</p>
          </div>
        ) : filteredArticles.length === 0 ? (
          <div className={styles.empty}>
            <p>No articles found</p>
          </div>
        ) : (
          <div className={styles.newsGrid}>
            {filteredArticles.map(article => (
              <article key={article.id} className={styles.newsCard}>
                <div className={styles.cardHeader}>
                  <span 
                    className={styles.sourceBadge}
                    style={{ backgroundColor: sourceColors[article.source] || '#666' }}
                  >
                    {sourceIcons[article.source]} {article.source}
                  </span>
                  <span className={styles.date}>{formatDate(article.date)}</span>
                </div>
                
                <h3 className={styles.title}>{article.title}</h3>
                
                {article.relatedIOCs.length > 0 && (
                  <div className={styles.iocsSection}>
                    <span className={styles.iocsLabel}>Related IOCs:</span>
                    <div className={styles.iocsList}>
                      {article.relatedIOCs.map((ioc, idx) => (
                        <span 
                          key={idx} 
                          className={`ioc-type ${getIOCTypeClass(ioc.type)}`}
                          title={ioc.value}
                        >
                          {ioc.type}: {ioc.value.length > 20 
                            ? ioc.value.substring(0, 20) + '...' 
                            : ioc.value}
                        </span>
                      ))}
                      {article.iocCount > 5 && (
                        <span className={styles.moreIOCs}>
                          +{article.iocCount - 5} more
                        </span>
                      )}
                    </div>
                  </div>
                )}
                
                <div className={styles.cardFooter}>
                  <span className={styles.iocCount}>
                    {article.iocCount} IOC{article.iocCount !== 1 ? 's' : ''}
                  </span>
                  <a 
                    href={article.url}
                    target="_blank"
                    rel="noopener noreferrer"
                    className={styles.readMore}
                  >
                    Read Article →
                  </a>
                </div>
              </article>
            ))}
          </div>
        )}
      </div>
    </>
  );
}
