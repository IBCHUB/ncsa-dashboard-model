import crypto from 'crypto';

export type SessionRole = 'internal';

interface SessionPayload {
    role: SessionRole;
    exp: number;
    user: string;
}

const SESSION_TTL_SECONDS = parseInt(process.env.DASHBOARD_SESSION_TTL_SECONDS || '28800', 10);

function getSessionSecret(): string {
    const secret = process.env.DASHBOARD_SESSION_SECRET || '';
    if (!secret) {
        throw new Error('DASHBOARD_SESSION_SECRET is not configured');
    }
    return secret;
}

function signPayload(payloadB64: string): string {
    const secret = getSessionSecret();
    return crypto.createHmac('sha256', secret).update(payloadB64).digest('hex');
}

export function buildSessionToken(user: string, role: SessionRole = 'internal'): string {
    const now = Math.floor(Date.now() / 1000);
    const payload: SessionPayload = {
        role,
        user,
        exp: now + SESSION_TTL_SECONDS
    };
    const payloadB64 = Buffer.from(JSON.stringify(payload), 'utf-8').toString('base64url');
    const sig = signPayload(payloadB64);
    return `${payloadB64}.${sig}`;
}

export function verifySessionToken(token: string): SessionPayload | null {
    if (!token || !token.includes('.')) return null;
    const [payloadB64, sig] = token.split('.', 2);
    if (!payloadB64 || !sig) return null;

    const expected = signPayload(payloadB64);
    if (sig !== expected) return null;

    try {
        const payload = JSON.parse(Buffer.from(payloadB64, 'base64url').toString('utf-8')) as SessionPayload;
        const now = Math.floor(Date.now() / 1000);
        if (!payload.exp || payload.exp <= now) return null;
        if (payload.role !== 'internal') return null;
        return payload;
    } catch {
        return null;
    }
}
