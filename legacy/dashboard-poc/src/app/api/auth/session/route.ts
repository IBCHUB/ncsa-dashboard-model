import { NextRequest, NextResponse } from 'next/server';
import { verifySessionToken } from '@/lib/session';

const COOKIE_NAME = 'tcti_session';

export async function GET(request: NextRequest) {
    const token = request.cookies.get(COOKIE_NAME)?.value || '';
    let payload = null;
    try {
        payload = verifySessionToken(token);
    } catch {
        payload = null;
    }

    if (!payload) {
        return NextResponse.json({
            authenticated: false,
            role: 'public'
        });
    }

    return NextResponse.json({
        authenticated: true,
        role: payload.role,
        user: payload.user,
        expiresAt: payload.exp
    });
}
