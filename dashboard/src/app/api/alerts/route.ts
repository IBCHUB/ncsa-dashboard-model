import { NextRequest, NextResponse } from 'next/server';
import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import type { ThreatEvent } from '@/lib/types';
import { checkElasticsearchHealth, searchWarehouse } from '@/lib/elastic';

type AlertStatus = 'open' | 'acknowledged' | 'resolved';

interface AlertState {
    status: AlertStatus;
    assignee?: string;
    acknowledgedAt?: string;
    resolvedAt?: string;
    updatedAt: string;
    updatedBy: string;
    audit: Array<{
        at: string;
        by: string;
        action: string;
        from?: AlertStatus;
        to?: AlertStatus;
        assignee?: string;
    }>;
}

interface AlertStore {
    alerts: Record<string, AlertState>;
}

const ALERT_STORE_PATH = path.join(process.cwd(), '.data', 'alerts-state.json');
const ACTIVE_SEVERITIES = new Set(['medium', 'high', 'critical']);

function ensureStore(): void {
    const dir = path.dirname(ALERT_STORE_PATH);
    if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true });
    }
    if (!fs.existsSync(ALERT_STORE_PATH)) {
        fs.writeFileSync(ALERT_STORE_PATH, JSON.stringify({ alerts: {} }, null, 2), 'utf-8');
    }
}

function readStore(): AlertStore {
    ensureStore();
    try {
        const raw = fs.readFileSync(ALERT_STORE_PATH, 'utf-8');
        return JSON.parse(raw) as AlertStore;
    } catch {
        return { alerts: {} };
    }
}

function writeStore(store: AlertStore): void {
    ensureStore();
    fs.writeFileSync(ALERT_STORE_PATH, JSON.stringify(store, null, 2), 'utf-8');
}

function alertIdFromIOC(iocType: string, iocValue: string): string {
    const digest = crypto
        .createHash('sha1')
        .update(`${iocType.toLowerCase()}:${iocValue.toLowerCase()}`)
        .digest('hex')
        .slice(0, 10)
        .toUpperCase();
    return `ALERT-${digest}`;
}

function normalizeSeverity(severity: string | undefined): string {
    const value = (severity || 'low').toLowerCase();
    if (value === 'very high') return 'critical';
    return value;
}

function toAlertEvent(event: ThreatEvent): any {
    const severity = normalizeSeverity((event as any).aiSeverity || event.severity || 'low');
    if (!ACTIVE_SEVERITIES.has(severity)) return null;
    const id = alertIdFromIOC(event.ioc.type, event.ioc.value);
    return {
        ...event,
        severity,
        aiSeverity: (event as any).aiSeverity || severity,
        id
    };
}

async function loadAlertCandidates(): Promise<any[]> {
    let usedElasticsearch = false;
    try {
        const health = await checkElasticsearchHealth();
        if (health.available) {
            usedElasticsearch = true;
            const result = await searchWarehouse({
                severityLevels: ['medium', 'high', 'critical'],
                limit: 2000,
                sortBy: 'time'
            });
            return result.data.map((doc: any) => ({
                source_type: doc.source_type || 'unknown',
                source_name: doc.source_name || 'unknown',
                collect_time: doc.last_seen || doc.processed_at || new Date().toISOString(),
                event_time: doc.first_seen || doc.event_time || doc.collect_time || new Date().toISOString(),
                threat_type: doc.threat_type || doc.ai_threat_types || [],
                severity: doc.severity || 'low',
                confidence: doc.ai_classification_confidence || 0,
                ioc: { type: doc.ioc_type, value: doc.ioc_value },
                description: doc.description || '',
                tags: doc.tags || [],
                status: 'open',
                aiRiskScore: doc.ai_risk_score,
                aiSeverity: doc.ai_severity,
                aiThreatTypes: doc.ai_threat_types || [],
                aiThreatActors: doc.ai_threat_actors || []
            } as ThreatEvent))
                .map(toAlertEvent)
                .filter(Boolean);
        }
    } catch (error) {
        console.error('[Alerts API] Elasticsearch unavailable, fallback to file', error);
    }

    if (usedElasticsearch) {
        return [];
    }

    try {
        const filePath = path.join(process.cwd(), 'public', 'data', 'normalized_iocs.json');
        if (!fs.existsSync(filePath)) return [];
        const raw = fs.readFileSync(filePath, 'utf-8');
        const json = JSON.parse(raw);
        const events = (json.events || []) as ThreatEvent[];
        return events.map(toAlertEvent).filter(Boolean);
    } catch (error) {
        console.error('[Alerts API] Failed to read fallback file', error);
        return [];
    }
}

export async function GET() {
    try {
        const store = readStore();
        const candidates = await loadAlertCandidates();
        const now = new Date().toISOString();

        const alerts = candidates.map((alert: any) => {
            const existing = store.alerts[alert.id];
            if (!existing) {
                return {
                    ...alert,
                    status: 'open' as AlertStatus
                };
            }
            return {
                ...alert,
                status: existing.status,
                assignee: existing.assignee,
                acknowledgedAt: existing.acknowledgedAt,
                resolvedAt: existing.resolvedAt,
                updatedAt: existing.updatedAt
            };
        });

        // Keep store entries for non-active alerts as audit history, but update timestamp for active
        for (const alert of alerts) {
            const existing = store.alerts[alert.id];
            if (!existing) {
                store.alerts[alert.id] = {
                    status: 'open',
                    updatedAt: now,
                    updatedBy: 'system',
                    audit: [
                        { at: now, by: 'system', action: 'created', to: 'open' }
                    ]
                };
            }
        }
        writeStore(store);

        return NextResponse.json({
            success: true,
            data: alerts
        });
    } catch (error) {
        console.error('Error in /api/alerts GET:', error);
        return NextResponse.json(
            { success: false, error: 'Failed to load alerts' },
            { status: 500 }
        );
    }
}

export async function PATCH(request: NextRequest) {
    try {
        const body = await request.json();
        const alertId = String(body.alertId || '');
        const status = String(body.status || '') as AlertStatus;
        const actor = String(body.actor || 'analyst');
        const assignee = body.assignee ? String(body.assignee) : undefined;

        if (!alertId || !['open', 'acknowledged', 'resolved'].includes(status)) {
            return NextResponse.json(
                { success: false, error: 'Invalid alertId or status' },
                { status: 400 }
            );
        }

        const store = readStore();
        const now = new Date().toISOString();
        const current = store.alerts[alertId] || {
            status: 'open' as AlertStatus,
            updatedAt: now,
            updatedBy: 'system',
            audit: [{ at: now, by: 'system', action: 'created', to: 'open' as AlertStatus }]
        };

        // Enforce lifecycle transitions.
        const validTransition =
            current.status === status ||
            (current.status === 'open' && status === 'acknowledged') ||
            (current.status === 'acknowledged' && status === 'resolved') ||
            (current.status === 'resolved' && status === 'open');
        if (!validTransition) {
            return NextResponse.json(
                { success: false, error: `Invalid transition ${current.status} -> ${status}` },
                { status: 409 }
            );
        }

        const updated: AlertState = {
            ...current,
            status,
            assignee: assignee ?? current.assignee,
            updatedAt: now,
            updatedBy: actor,
            acknowledgedAt: status === 'acknowledged' ? now : current.acknowledgedAt,
            resolvedAt: status === 'resolved' ? now : (status === 'open' ? undefined : current.resolvedAt),
            audit: [
                ...(current.audit || []),
                {
                    at: now,
                    by: actor,
                    action: 'status_change',
                    from: current.status,
                    to: status,
                    assignee: assignee ?? current.assignee
                }
            ]
        };

        store.alerts[alertId] = updated;
        writeStore(store);

        return NextResponse.json({
            success: true,
            data: {
                alertId,
                status: updated.status,
                assignee: updated.assignee,
                acknowledgedAt: updated.acknowledgedAt,
                resolvedAt: updated.resolvedAt,
                updatedAt: updated.updatedAt
            }
        });
    } catch (error) {
        console.error('Error in /api/alerts PATCH:', error);
        return NextResponse.json(
            { success: false, error: 'Failed to update alert' },
            { status: 500 }
        );
    }
}
