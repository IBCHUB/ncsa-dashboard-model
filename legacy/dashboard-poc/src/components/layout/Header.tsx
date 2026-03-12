'use client';

import { useState } from 'react';
import styles from './Header.module.css';

interface HeaderProps {
  title?: string;
}

export default function Header({ title = 'Dashboard' }: HeaderProps) {
  const [searchQuery, setSearchQuery] = useState('');

  const handleSearch = (e: React.FormEvent) => {
    e.preventDefault();
    if (searchQuery.trim()) {
      // Navigate to IOC search with query
      window.location.href = `/ioc?q=${encodeURIComponent(searchQuery)}`;
    }
  };

  return (
    <header className={styles.header}>
      <div className={styles.left}>
        <h1 className={styles.title}>{title}</h1>
      </div>

      <div className={styles.center}>
        <form onSubmit={handleSearch} className={styles.searchForm}>
          <input
            type="text"
            placeholder="Search IOC (IP, Domain, Hash, CVE)..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className={styles.searchInput}
          />
          <kbd className={styles.shortcut}>⌘K</kbd>
        </form>
      </div>

      <div className={styles.right}>
        <button className={styles.iconButton} title="Notifications">
          <span>🔔</span>
          <span className={styles.notificationBadge}>3</span>
        </button>
        <button className={styles.iconButton} title="Settings">
          <span>⚙️</span>
        </button>
        <div className={styles.timeInfo}>
          <span className={styles.timezone}>Bangkok (UTC+7)</span>
          <span className={styles.time}>
            {new Date().toLocaleTimeString('th-TH', { 
              hour: '2-digit', 
              minute: '2-digit',
              hour12: false 
            })}
          </span>
        </div>
      </div>
    </header>
  );
}
