import styles from './StatCard.module.css';

interface StatCardProps {
  title: string;
  value: string | number;
  change?: {
    value: number;
    type: 'positive' | 'negative' | 'neutral';
  };
  icon?: string;
  color?: 'default' | 'critical' | 'high' | 'medium' | 'low' | 'accent';
}

export default function StatCard({ 
  title, 
  value, 
  change, 
  icon,
  color = 'default' 
}: StatCardProps) {
  return (
    <div className={`${styles.card} ${styles[color]}`}>
      <div className={styles.header}>
        <span className={styles.title}>{title}</span>
        {icon && <span className={styles.icon}>{icon}</span>}
      </div>
      <div className={styles.value}>{value.toLocaleString()}</div>
      {change && (
        <div className={`${styles.change} ${styles[change.type]}`}>
          {change.type === 'positive' && '↑'}
          {change.type === 'negative' && '↓'}
          {Math.abs(change.value)}% vs last period
        </div>
      )}
    </div>
  );
}
