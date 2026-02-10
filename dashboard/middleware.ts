import { NextRequest, NextResponse } from 'next/server';

const COOKIE_NAME = 'tcti_session';
const PROTECTED_PREFIXES = [
    '/alerts',
    '/reports',
    '/ioc',
    '/graph',
    '/threats/cve',
    '/api/helpdesk',
    '/api/alerts',
    '/api/iocs'
];

type SessionPayload = {
    role?: string;
    exp?: number;
    user?: string;
};

function isProtected(pathname: string): boolean {
    return PROTECTED_PREFIXES.some(prefix => pathname.startsWith(prefix));
}

function decodePayload(payloadB64: string): SessionPayload | null {
    try {
        const base64 = payloadB64.replace(/-/g, '+').replace(/_/g, '/');
        const padded = base64 + '==='.slice((base64.length + 3) % 4);
        const json = atob(padded);
        return JSON.parse(json) as SessionPayload;
    } catch {
        return null;
    }
}

async function signHex(payloadB64: string, secret: string): Promise<string> {
    const enc = new TextEncoder();
    const key = await crypto.subtle.importKey(
        'raw',
        enc.encode(secret),
        { name: 'HMAC', hash: 'SHA-256' },
        false,
        ['sign']
    );
    const sig = await crypto.subtle.sign('HMAC', key, enc.encode(payloadB64));
    return Array.from(new Uint8Array(sig))
        .map(b => b.toString(16).padStart(2, '0'))
        .join('');
}

async function isInternalSessionValid(token: string): Promise<boolean> {
    if (!token || !token.includes('.')) return false;
    const secret = process.env.DASHBOARD_SESSION_SECRET || '';
    if (!secret) return false;

    const [payloadB64, providedSig] = token.split('.', 2);
    if (!payloadB64 || !providedSig) return false;

    const expectedSig = await signHex(payloadB64, secret);
    if (expectedSig !== providedSig) return false;

    const payload = decodePayload(payloadB64);
    if (!payload) return false;
    const now = Math.floor(Date.now() / 1000);
    return payload.role === 'internal' && typeof payload.exp === 'number' && payload.exp > now;
}

export async function middleware(request: NextRequest) {
    const { pathname } = request.nextUrl;

    // Explicit escape hatch (dev / incident response).
    if ((process.env.DASHBOARD_DISABLE_INTERNAL_AUTH || '').toLowerCase() === 'true') {
        return NextResponse.next();
    }

    // If session signing isn't configured, don't block access (avoids breaking local dev).
    if (!process.env.DASHBOARD_SESSION_SECRET) {
        return NextResponse.next();
    }

    if (!isProtected(pathname)) {
        return NextResponse.next();
    }

    const token = request.cookies.get(COOKIE_NAME)?.value || '';
    const valid = await isInternalSessionValid(token);
    if (valid) {
        return NextResponse.next();
    }

    if (pathname.startsWith('/api/')) {
        return NextResponse.json(
            { success: false, error: 'Authentication required (internal access)' },
            { status: 401 }
        );
    }

    const loginUrl = request.nextUrl.clone();
    loginUrl.pathname = '/login';
    loginUrl.searchParams.set('next', pathname);
    return NextResponse.redirect(loginUrl);
}

export const config = {
    matcher: [
        '/alerts/:path*',
        '/reports/:path*',
        '/ioc/:path*',
        '/graph/:path*',
        '/threats/cve/:path*',
        '/api/helpdesk/:path*',
        '/api/alerts/:path*',
        '/api/iocs/:path*'
    ]
};
