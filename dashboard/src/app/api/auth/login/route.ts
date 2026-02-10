import { NextRequest, NextResponse } from 'next/server';
import crypto from 'crypto';
import { buildSessionToken } from '@/lib/session';

const COOKIE_NAME = 'tcti_session';

function base32ToBuffer(input: string): Buffer {
    const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    const clean = input.toUpperCase().replace(/=+$/g, '').replace(/[^A-Z2-7]/g, '');
    let bits = '';
    for (const char of clean) {
        const value = alphabet.indexOf(char);
        if (value === -1) continue;
        bits += value.toString(2).padStart(5, '0');
    }
    const bytes: number[] = [];
    for (let i = 0; i + 8 <= bits.length; i += 8) {
        bytes.push(parseInt(bits.slice(i, i + 8), 2));
    }
    return Buffer.from(bytes);
}

function generateTotp(secretBase32: string, timestampMs: number, stepSeconds = 30): string {
    const key = base32ToBuffer(secretBase32);
    const counter = Math.floor(timestampMs / 1000 / stepSeconds);
    const counterBuffer = Buffer.alloc(8);
    counterBuffer.writeUInt32BE(Math.floor(counter / 0x100000000), 0);
    counterBuffer.writeUInt32BE(counter % 0x100000000, 4);

    const hmac = crypto.createHmac('sha1', key).update(counterBuffer).digest();
    const offset = hmac[hmac.length - 1] & 0x0f;
    const binary =
        ((hmac[offset] & 0x7f) << 24) |
        ((hmac[offset + 1] & 0xff) << 16) |
        ((hmac[offset + 2] & 0xff) << 8) |
        (hmac[offset + 3] & 0xff);
    const otp = (binary % 1_000_000).toString().padStart(6, '0');
    return otp;
}

function verifyTotp(secretBase32: string, code: string): boolean {
    const now = Date.now();
    const windows = [-1, 0, 1];
    for (const w of windows) {
        const candidate = generateTotp(secretBase32, now + w * 30_000);
        if (candidate === code) return true;
    }
    return false;
}

export async function POST(request: NextRequest) {
    try {
        const body = await request.json();
        const username = String(body.username || '').trim();
        const password = String(body.password || '');
        const otp = String(body.otp || '').trim();

        const authUser = process.env.DASHBOARD_AUTH_USER || '';
        const authPassword = process.env.DASHBOARD_AUTH_PASSWORD || '';
        const require2FA = (process.env.DASHBOARD_REQUIRE_2FA || 'true').toLowerCase() !== 'false';
        const otpSecret = process.env.DASHBOARD_2FA_SECRET || '';
        const sessionSecret = process.env.DASHBOARD_SESSION_SECRET || '';

        if (!authUser || !authPassword) {
            return NextResponse.json(
                { success: false, error: 'Auth is not configured on server' },
                { status: 500 }
            );
        }
        if (!sessionSecret) {
            return NextResponse.json(
                { success: false, error: 'Session secret is not configured on server' },
                { status: 500 }
            );
        }
        if (require2FA && !otpSecret) {
            return NextResponse.json(
                { success: false, error: '2FA secret is not configured on server' },
                { status: 500 }
            );
        }

        if (username !== authUser || password !== authPassword) {
            return NextResponse.json(
                { success: false, error: 'Invalid credentials' },
                { status: 401 }
            );
        }

        if (require2FA && !verifyTotp(otpSecret, otp)) {
            return NextResponse.json(
                { success: false, error: 'Invalid OTP code' },
                { status: 401 }
            );
        }

        const token = buildSessionToken(username, 'internal');
        const response = NextResponse.json({
            success: true,
            data: { role: 'internal', user: username }
        });

        response.cookies.set({
            name: COOKIE_NAME,
            value: token,
            httpOnly: true,
            sameSite: 'lax',
            secure: process.env.COOKIE_SECURE === 'true' || (process.env.NODE_ENV === 'production' && process.env.COOKIE_SECURE !== 'false'),
            path: '/',
            maxAge: parseInt(process.env.DASHBOARD_SESSION_TTL_SECONDS || '28800', 10)
        });

        return response;
    } catch (error) {
        console.error('Error in auth/login:', error);
        return NextResponse.json(
            { success: false, error: 'Login failed' },
            { status: 500 }
        );
    }
}
