import { NextResponse } from 'next/server';

const COOKIE_NAME = 'tcti_session';

export async function POST() {
    const response = NextResponse.json({ success: true });
    response.cookies.set({
        name: COOKIE_NAME,
        value: '',
        httpOnly: true,
        sameSite: 'lax',
        secure: process.env.NODE_ENV === 'production',
        path: '/',
        maxAge: 0
    });
    return response;
}
