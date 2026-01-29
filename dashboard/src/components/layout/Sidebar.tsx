'use client';

import Link from 'next/link';
import { usePathname } from 'next/navigation';
import styles from './Sidebar.module.css';

interface NavItem {
  id: string;
  label: string;
  href: string;
  icon: string;
  badge?: number;
  comingSoon?: boolean;
  children?: NavItem[];
}

const navigation: NavItem[] = [
  {
    id: 'dashboard',
    label: 'Dashboards',
    href: '/',
    icon: '📊',
    children: [
      { id: 'operational', label: 'Operational', href: '/', icon: '📈' },
    ],
  },
  {
    id: 'alerts',
    label: 'Alerts Center',
    href: '/alerts',
    icon: '🔔',
    badge: 12,
  },
  {
    id: 'ioc',
    label: 'IOC Explorer',
    href: '/ioc',
    icon: '🔍',
  },
  {
    id: 'threats',
    label: 'Threat Intelligence',
    href: '/threats',
    icon: '🛡️',
    children: [
      { id: 'landscape', label: 'Threat Landscape', href: '/threats', icon: '🌍' },
      { id: 'cve', label: 'CVE Intelligence', href: '/threats/cve', icon: '🔓' },
      { id: 'actors', label: 'Threat Actors', href: '/threats/actors', icon: '👤', comingSoon: true },
      { id: 'malware', label: 'Malware Intel', href: '/threats/malware', icon: '🦠', comingSoon: true },
    ],
  },
  {
    id: 'reports',
    label: 'Reports & Export',
    href: '/reports',
    icon: '📄',
  },
  {
    id: 'news',
    label: 'Cyber News',
    href: '/news',
    icon: '📰',
  },
  {
    id: 'map',
    label: 'Connection Map',
    href: '/map',
    icon: '🌐',
  },
];

export default function Sidebar() {
  const pathname = usePathname();

  const isActive = (href: string) => {
    if (href === '/') return pathname === '/';
    return pathname.startsWith(href);
  };

  return (
    <aside className={styles.sidebar}>
      <div className={styles.logo}>
        <span className={styles.logoIcon}>🛡️</span>
        <div className={styles.logoText}>
          <span className={styles.logoTitle}>IBC</span>
          <span className={styles.logoSubtitle}>Cyber Intelligence</span>
        </div>
      </div>

      <nav className={styles.nav}>
        {navigation.map((item) => (
          <div key={item.id} className={styles.navGroup}>
            {item.children ? (
              <>
                <div className={styles.navGroupLabel}>
                  <span className={styles.navIcon}>{item.icon}</span>
                  <span>{item.label}</span>
                </div>
                <div className={styles.navChildren}>
                  {item.children.map((child) => (
                    child.comingSoon ? (
                      <span
                        key={child.id}
                        className={`${styles.navItem} ${styles.disabled}`}
                      >
                        <span className={styles.navIcon}>{child.icon}</span>
                        <span>{child.label}</span>
                        <span className={styles.comingSoon}>Soon</span>
                      </span>
                    ) : (
                      <Link
                        key={child.id}
                        href={child.href}
                        className={`${styles.navItem} ${isActive(child.href) ? styles.active : ''}`}
                      >
                        <span className={styles.navIcon}>{child.icon}</span>
                        <span>{child.label}</span>
                      </Link>
                    )
                  ))}
                </div>
              </>
            ) : item.comingSoon ? (
              <span
                className={`${styles.navItem} ${styles.disabled}`}
              >
                <span className={styles.navIcon}>{item.icon}</span>
                <span>{item.label}</span>
                <span className={styles.comingSoon}>Soon</span>
              </span>
            ) : (
              <Link
                href={item.href}
                className={`${styles.navItem} ${isActive(item.href) ? styles.active : ''}`}
              >
                <span className={styles.navIcon}>{item.icon}</span>
                <span>{item.label}</span>
                {item.badge && <span className={styles.badge}>{item.badge}</span>}
              </Link>
            )}
          </div>
        ))}
      </nav>

      <div className={styles.footer}>
        <div className={styles.userSection}>
          <div className={styles.avatar}>👤</div>
          <div className={styles.userInfo}>
            <span className={styles.userName}>Demo User</span>
            <span className={styles.userRole}>Internal</span>
          </div>
        </div>
      </div>
    </aside>
  );
}
