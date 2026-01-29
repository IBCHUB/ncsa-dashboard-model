'use client';

import React, { useState } from 'react';
import styles from './SimpleScoreTooltip.module.css';

interface SimpleScoreBreakdown {
    crossSource: number;
    typeSpecific: number;
    entropy: number;
    keywords: number;
}

interface SimpleScoreTooltipProps {
    score: number;
    breakdown?: SimpleScoreBreakdown;
    severity: string;
}

const CATEGORY_INFO = {
    crossSource: {
        name: 'การยืนยันข้าม Source',
        nameEn: 'Cross-Source Validation',
        description: 'คะแนนจากการถูกรายงานจากหลายแหล่ง (Threat Intel, Sandbox, Security Tools)',
        max: 40
    },
    typeSpecific: {
        name: 'ลักษณะ IOC',
        nameEn: 'IOC Characteristics',
        description: 'คะแนนจากความผิดปกติของ IOC + ประเภทภัยคุกคาม',
        max: 25
    },
    entropy: {
        name: 'ความซับซ้อน',
        nameEn: 'Entropy/Randomness',
        description: 'คะแนนจากความซับซ้อนของชื่อ (DGA detection)',
        max: 20
    },
    keywords: {
        name: 'คำที่พบ',
        nameEn: 'Keywords Detected',
        description: 'คะแนนจากคำสำคัญที่พบ เช่น malware, ransomware',
        max: 15
    }
};

export function SimpleScoreTooltip({ score, breakdown, severity }: SimpleScoreTooltipProps) {
    const [isOpen, setIsOpen] = useState(false);

    const getScoreColor = (value: number) => {
        if (value >= 45) return '#ff4757';
        if (value >= 30) return '#ff6b35';
        if (value >= 15) return '#ffa502';
        if (value >= 6) return '#2ed573';
        return '#747d8c';
    };

    return (
        <div className={styles.container}>
            <div className={styles.scoreDisplay}>
                <span 
                    className={styles.scoreValue}
                    style={{ color: getScoreColor(score) }}
                >
                    {score}
                </span>
                <span className={styles.scoreMax}>/100</span>
                
                {breakdown && (
                    <button
                        className={styles.infoButton}
                        onClick={() => setIsOpen(!isOpen)}
                        aria-label="Show score breakdown"
                        title="ดูรายละเอียดคะแนน"
                    >
                        <svg width="14" height="14" viewBox="0 0 24 24" fill="currentColor">
                            <path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm1 15h-2v-6h2v6zm0-8h-2V7h2v2z"/>
                        </svg>
                    </button>
                )}
            </div>

            {isOpen && breakdown && (
                <div className={styles.tooltip}>
                    <div className={styles.tooltipHeader}>
                        <h4>รายละเอียดคะแนน AI</h4>
                        <button 
                            className={styles.closeButton}
                            onClick={() => setIsOpen(false)}
                        >
                            ×
                        </button>
                    </div>

                    <div className={styles.breakdownList}>
                        {Object.entries(CATEGORY_INFO).map(([key, info]) => {
                            const value = breakdown[key as keyof SimpleScoreBreakdown] || 0;
                            return (
                                <div key={key} className={styles.breakdownItem}>
                                    <div className={styles.categoryRow}>
                                        <span className={styles.category}>{info.name}</span>
                                        <span className={styles.itemScore}>
                                            <strong>{value}</strong>/{info.max}
                                        </span>
                                    </div>
                                    <div className={styles.progressBar}>
                                        <div 
                                            className={styles.progressFill}
                                            style={{ 
                                                width: `${(value / info.max) * 100}%`,
                                                backgroundColor: getScoreColor((value / info.max) * 100)
                                            }}
                                        />
                                    </div>
                                    <p className={styles.description}>{info.description}</p>
                                </div>
                            );
                        })}
                    </div>

                    <div className={styles.tooltipFooter}>
                        <div className={styles.totalRow}>
                            <span>คะแนนรวม</span>
                            <span 
                                className={styles.totalScore}
                                style={{ color: getScoreColor(score) }}
                            >
                                {score}/100
                            </span>
                        </div>
                        <div className={styles.severityRow}>
                            <span>ระดับความเสี่ยง</span>
                            <span className={`${styles.severityBadge} ${styles[severity]}`}>
                                {severity.toUpperCase()}
                            </span>
                        </div>
                    </div>
                </div>
            )}
        </div>
    );
}

export default SimpleScoreTooltip;
