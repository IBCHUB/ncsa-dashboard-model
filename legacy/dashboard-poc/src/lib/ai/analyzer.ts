/**
 * AI Threat Analyzer using OpenAI
 * 
 * Analyzes IOC descriptions and provides:
 * - Severity assessment
 * - Threat actor attribution
 * - MITRE ATT&CK technique mapping
 * - Recommended actions
 */

import { getOpenAIClient, isOpenAIConfigured } from './openai';
import type { SeverityLevel } from '@/lib/types';

export interface ThreatAnalysis {
    severity: SeverityLevel;
    confidence: number;
    threatActors: string[];
    mitreTechniques: string[];
    threatCategory: string;
    summary: string;
    recommendedActions: string[];
    aiScore: number;
}

interface AnalysisInput {
    iocValue: string;
    iocType: string;
    description: string;
    sources: string[];
    tags?: string[];
    threatTypes?: string[];
}

const SYSTEM_PROMPT = `You are a cyber threat intelligence analyst. Analyze IOCs (Indicators of Compromise) and provide structured assessments.

For each IOC, evaluate:
1. **Severity**: critical, high, medium, low, or clean
2. **Confidence**: 0-100 how confident you are
3. **Threat Actors**: Known groups (e.g., Lazarus, APT29, LockBit)
4. **MITRE ATT&CK**: Relevant techniques (e.g., T1566, T1059)
5. **Category**: ransomware, phishing, c2, botnet, defacement, etc.
6. **AI Score**: 0-100 risk score based on all factors

Consider:
- IOC type (domain, IP, hash, CVE)
- Source credibility (VirusTotal > news sites)
- Context from description and tags
- Known threat patterns

Respond in JSON format only.`;

export async function analyzeThreat(input: AnalysisInput): Promise<ThreatAnalysis | null> {
    if (!isOpenAIConfigured()) {
        console.warn('OpenAI not configured, skipping AI analysis');
        return null;
    }

    try {
        const openai = getOpenAIClient();

        const userMessage = `Analyze this IOC:

**IOC Value**: ${input.iocValue}
**IOC Type**: ${input.iocType}
**Description**: ${input.description}
**Sources**: ${input.sources.join(', ')}
${input.tags?.length ? `**Tags**: ${input.tags.join(', ')}` : ''}
${input.threatTypes?.length ? `**Threat Types**: ${input.threatTypes.join(', ')}` : ''}

Provide your analysis in this exact JSON format:
{
  "severity": "critical|high|medium|low|clean",
  "confidence": 0-100,
  "threatActors": ["actor1", "actor2"],
  "mitreTechniques": ["T1566", "T1059"],
  "threatCategory": "ransomware|phishing|c2|botnet|defacement|malware|other",
  "summary": "Brief 1-2 sentence summary",
  "recommendedActions": ["action1", "action2"],
  "aiScore": 0-100
}`;

        const response = await openai.chat.completions.create({
            model: 'gpt-4o-mini',
            response_format: { type: 'json_object' },
            messages: [
                { role: 'system', content: SYSTEM_PROMPT },
                { role: 'user', content: userMessage }
            ],
            temperature: 0.3,
            max_tokens: 500
        });

        const content = response.choices[0]?.message?.content;
        if (!content) {
            throw new Error('Empty response from OpenAI');
        }

        const analysis = JSON.parse(content) as ThreatAnalysis;

        // Validate and normalize
        return {
            severity: normalizeSeverity(analysis.severity),
            confidence: Math.min(100, Math.max(0, analysis.confidence || 50)),
            threatActors: analysis.threatActors || [],
            mitreTechniques: analysis.mitreTechniques || [],
            threatCategory: analysis.threatCategory || 'other',
            summary: analysis.summary || '',
            recommendedActions: analysis.recommendedActions || [],
            aiScore: Math.min(100, Math.max(0, analysis.aiScore || 0))
        };
    } catch (error) {
        console.error('Error analyzing threat with OpenAI:', error);
        return null;
    }
}

function normalizeSeverity(severity: string): SeverityLevel {
    const normalized = severity?.toLowerCase()?.trim();
    switch (normalized) {
        case 'critical': return 'critical';
        case 'high': return 'high';
        case 'medium': return 'medium';
        case 'low': return 'low';
        default: return 'clean';
    }
}

/**
 * Batch analyze multiple IOCs (with rate limiting)
 */
export async function batchAnalyzeThreats(
    inputs: AnalysisInput[],
    options?: { maxConcurrent?: number; delayMs?: number }
): Promise<Map<string, ThreatAnalysis | null>> {
    const results = new Map<string, ThreatAnalysis | null>();
    const { maxConcurrent = 3, delayMs = 200 } = options || {};

    // Process in batches
    for (let i = 0; i < inputs.length; i += maxConcurrent) {
        const batch = inputs.slice(i, i + maxConcurrent);
        const batchResults = await Promise.all(
            batch.map(input => analyzeThreat(input))
        );

        batch.forEach((input, idx) => {
            results.set(input.iocValue, batchResults[idx]);
        });

        // Rate limiting delay
        if (i + maxConcurrent < inputs.length) {
            await new Promise(resolve => setTimeout(resolve, delayMs));
        }
    }

    return results;
}
