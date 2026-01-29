'use client';

import React, { useState } from 'react';
import type { ScoreBreakdown, AnyScoreBreakdown, EnhancedScoreBreakdown } from '@/lib/scoring';
import { getScoreColor, isEnhancedBreakdown } from '@/lib/scoring';
import styles from './ScoreInfoTooltip.module.css';

interface ScoreInfoTooltipProps {
    scoreBreakdown: AnyScoreBreakdown;
    showThai?: boolean;
}

/**
 * Component to display AI Risk Score with an info button
 * that shows detailed breakdown of how the score was calculated
 * Supports both legacy ScoreBreakdown and new EnhancedScoreBreakdown formats
 */
export function ScoreInfoTooltip({ scoreBreakdown, showThai = true }: ScoreInfoTooltipProps) {
    const [isOpen, setIsOpen] = useState(false);
    const [expandedMethodology, setExpandedMethodology] = useState<number | null>(null);
    
    const { totalScore, severity } = scoreBreakdown;
    const isEnhanced = isEnhancedBreakdown(scoreBreakdown);
    const maxScore = isEnhanced ? 100 : (scoreBreakdown as ScoreBreakdown).maxScore;

    const toggleMethodology = (index: number) => {
        setExpandedMethodology(expandedMethodology === index ? null : index);
    };

    // Render enhanced breakdown (new AI service format)
    const renderEnhancedBreakdown = (enhanced: EnhancedScoreBreakdown) => {
        const { breakdown, topFactors, summary } = enhanced;
        
        // Render top factors first
        const factorsToDisplay = topFactors && topFactors.length > 0 ? topFactors : [
            // Fallback: extract from breakdown if topFactors not available
            ...(breakdown.cross_source?.score > 0 ? [{ factor: 'cross_source', score: breakdown.cross_source.score, label: 'การยืนยันข้ามแหล่ง' }] : []),
            ...(breakdown.source_quality?.score > 0 ? [{ factor: 'source_quality', score: breakdown.source_quality.score, label: 'คุณภาพแหล่งข้อมูล' }] : []),
            ...(breakdown.threat_type_severity?.score > 0 ? [{ factor: 'threat_type_severity', score: breakdown.threat_type_severity.score, label: 'ประเภทภัยคุกคาม (AI)' }] : []),
            ...(breakdown.threat_actor?.score > 0 ? [{ factor: 'threat_actor', score: breakdown.threat_actor.score, label: 'กลุ่มผู้โจมตี (AI)' }] : []),
            ...(breakdown.mitre_techniques?.score > 0 ? [{ factor: 'mitre_techniques', score: breakdown.mitre_techniques.score, label: 'MITRE ATT&CK (AI)' }] : []),
            ...(breakdown.ai_confidence?.score > 0 ? [{ factor: 'ai_confidence', score: breakdown.ai_confidence.score, label: 'ความมั่นใจ AI' }] : []),
            ...(breakdown.keywords?.score > 0 ? [{ factor: 'keywords', score: breakdown.keywords.score, label: 'คำสำคัญอันตราย' }] : []),
            ...(breakdown.entropy?.score > 0 ? [{ factor: 'entropy', score: breakdown.entropy.score, label: 'Entropy (DGA)' }] : []),
            ...(breakdown.geo_risk?.score > 0 ? [{ factor: 'geo_risk', score: breakdown.geo_risk.score, label: 'ความเสี่ยงภูมิศาสตร์' }] : []),
            ...(breakdown.domain_age?.score > 0 ? [{ factor: 'domain_age', score: breakdown.domain_age.score, label: 'อายุโดเมน' }] : []),
        ].sort((a, b) => b.score - a.score).slice(0, 6);
        
        // Helper to get factor details from breakdown
        const getFactorDetails = (factorName: string) => {
            const factorData = breakdown[factorName];
            if (!factorData) return null;
            return factorData;
        };
        
        return (
            <>
                {/* Score Summary */}
                {summary && (
                    <div className={styles.scoreSummary}>
                        <div className={styles.summaryRow}>
                            <span>คะแนนดั้งเดิม</span>
                            <span className={styles.traditionalScore}>{summary.traditional_score}</span>
                        </div>
                        <div className={styles.summaryRow}>
                            <span>คะแนน AI 🤖</span>
                            <span className={styles.aiScore}>{summary.ai_score}</span>
                        </div>
                        {summary.has_threat_actor && (
                            <div className={styles.summaryBadge}>
                                <span className={styles.actorBadge}>🎯 ระบุกลุ่มผู้โจมตีได้</span>
                            </div>
                        )}
                        {summary.primary_threat && (
                            <div className={styles.primaryThreat}>
                                <span>ประเภทหลัก: <strong>{summary.primary_threat}</strong></span>
                            </div>
                        )}
                    </div>
                )}
                
                {/* Top Factors */}
                <div className={styles.breakdownList}>
                    <h5 className={styles.sectionTitle}>
                        {showThai ? 'ปัจจัยหลักในการให้คะแนน' : 'Top Scoring Factors'}
                    </h5>
                    {factorsToDisplay.map((factor, index) => {
                        const maxForFactor = getMaxScoreForFactor(factor.factor);
                        const factorDetails = getFactorDetails(factor.factor);
                        const isExpanded = expandedMethodology === index;
                        
                        return (
                            <div key={index} className={styles.breakdownItem}>
                                <div className={styles.categoryRow}>
                                    <span className={styles.category}>
                                        {showThai ? factor.label : factor.factor}
                                    </span>
                                    <div className={styles.categoryActions}>
                                        {factorDetails?.methodology && (
                                            <button
                                                className={styles.methodologyButton}
                                                onClick={() => toggleMethodology(index)}
                                                title={showThai ? 'ดูหลักการให้คะแนน' : 'View methodology'}
                                            >
                                                ?
                                            </button>
                                        )}
                                        <span className={styles.itemScore}>
                                            <strong>{factor.score}</strong>/{factorDetails?.maxScore || maxForFactor}
                                        </span>
                                    </div>
                                </div>
                                <div className={styles.progressBar}>
                                    <div 
                                        className={styles.progressFill}
                                        style={{ 
                                            width: `${Math.min((factor.score / (factorDetails?.maxScore || maxForFactor)) * 100, 100)}%`,
                                            backgroundColor: getScoreColor((factor.score / (factorDetails?.maxScore || maxForFactor)) * 100)
                                        }}
                                    />
                                </div>
                                
                                {/* Reason - What data was found */}
                                {factorDetails?.reason && (
                                    <p className={styles.reason}>
                                        {showThai ? factorDetails.reason : (factorDetails.reasonEn || factorDetails.reason)}
                                    </p>
                                )}
                                
                                {/* Methodology (expandable) */}
                                {isExpanded && factorDetails && (
                                    <div className={styles.methodologyContent}>
                                        <span className={styles.methodologyLabel}>
                                            {showThai ? '📖 หลักการให้คะแนน:' : '📖 Methodology:'}
                                        </span>
                                        <p className={styles.methodologyText}>
                                            {showThai ? factorDetails.methodology : (factorDetails.methodologyEn || factorDetails.methodology)}
                                        </p>
                                        {factorDetails.scoringRules && (
                                            <p className={styles.scoringRules}>
                                                📐 {factorDetails.scoringRules}
                                            </p>
                                        )}
                                    </div>
                                )}
                            </div>
                        );
                    })}
                </div>
            </>
        );
    };

    // Render legacy breakdown format
    const renderLegacyBreakdown = (legacy: ScoreBreakdown) => {
        return (
            <div className={styles.breakdownList}>
                {legacy.breakdown.map((item, index) => (
                    <div key={index} className={styles.breakdownItem}>
                        <div className={styles.categoryRow}>
                            <span className={styles.category}>
                                {showThai ? item.categoryTh : item.category}
                            </span>
                            <div className={styles.categoryActions}>
                                <button
                                    className={styles.methodologyButton}
                                    onClick={() => toggleMethodology(index)}
                                    title={showThai ? 'ดูหลักการให้คะแนน' : 'View methodology'}
                                >
                                    ?
                                </button>
                                <span className={styles.itemScore}>
                                    <strong>{item.score}</strong>/{item.maxScore}
                                </span>
                            </div>
                        </div>
                        <div className={styles.progressBar}>
                            <div 
                                className={styles.progressFill}
                                style={{ 
                                    width: `${(item.score / item.maxScore) * 100}%`,
                                    backgroundColor: getScoreColor((item.score / item.maxScore) * 100)
                                }}
                            />
                        </div>
                        <p className={styles.reason}>
                            {showThai ? item.reasonTh : item.reason}
                        </p>
                        {expandedMethodology === index && (
                            <div className={styles.methodologyContent}>
                                <span className={styles.methodologyLabel}>
                                    {showThai ? '📖 หลักการให้คะแนน:' : '📖 Methodology:'}
                                </span>
                                <p className={styles.methodologyText}>
                                    {showThai ? item.methodologyTh : item.methodology}
                                </p>
                            </div>
                        )}
                    </div>
                ))}
            </div>
        );
    };

    return (
        <div className={styles.container}>
            {/* Score Display */}
            <div className={styles.scoreDisplay}>
                <span 
                    className={styles.scoreValue}
                    style={{ color: getScoreColor(totalScore) }}
                >
                    {totalScore}
                </span>
                <span className={styles.scoreMax}>/{maxScore}</span>
                
                {/* Info Button */}
                <button
                    className={styles.infoButton}
                    onClick={() => setIsOpen(!isOpen)}
                    aria-label="Show score breakdown"
                    title="ดูรายละเอียดการคำนวณคะแนน"
                >
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor">
                        <path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm1 15h-2v-6h2v6zm0-8h-2V7h2v2z"/>
                    </svg>
                </button>
            </div>

            {/* Tooltip Popup */}
            {isOpen && (
                <div className={styles.tooltip}>
                    <div className={styles.tooltipHeader}>
                        <h4>{showThai ? 'รายละเอียดการคำนวณคะแนน AI' : 'AI Score Breakdown'}</h4>
                        <button 
                            className={styles.closeButton}
                            onClick={() => setIsOpen(false)}
                            aria-label="Close"
                        >
                            ×
                        </button>
                    </div>

                    {isEnhanced 
                        ? renderEnhancedBreakdown(scoreBreakdown as EnhancedScoreBreakdown)
                        : renderLegacyBreakdown(scoreBreakdown as ScoreBreakdown)
                    }

                    <div className={styles.tooltipFooter}>
                        <div className={styles.totalRow}>
                            <span>{showThai ? 'คะแนนรวม' : 'Total Score'}</span>
                            <span 
                                className={styles.totalScore}
                                style={{ color: getScoreColor(totalScore) }}
                            >
                                {totalScore}/{maxScore}
                            </span>
                        </div>
                        <div className={styles.severityRow}>
                            <span>{showThai ? 'ระดับความเสี่ยง' : 'Risk Level'}</span>
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

/**
 * Get max score for a specific factor
 */
function getMaxScoreForFactor(factor: string): number {
    const maxScores: Record<string, number> = {
        cross_source: 40,
        source_quality: 40,
        threat_type_severity: 35,
        threat_actor: 30,
        mitre_techniques: 20,
        ai_confidence: 10,
        keywords: 25,
        entropy: 15,
        geo_risk: 15,
        domain_age: 20,
    };
    return maxScores[factor] || 25;
}

export default ScoreInfoTooltip;
