/**
 * AI Analysis API Endpoint
 * 
 * POST /api/analyze
 * Body: { iocValue, iocType, description, sources, tags?, threatTypes? }
 * 
 * Returns: ThreatAnalysis object
 */

import { NextRequest, NextResponse } from 'next/server';
import { analyzeThreat, isOpenAIConfigured } from '@/lib/ai';

export async function POST(request: NextRequest) {
    try {
        // Check if OpenAI is configured
        if (!isOpenAIConfigured()) {
            return NextResponse.json(
                { error: 'OpenAI API not configured' },
                { status: 503 }
            );
        }

        const body = await request.json();

        // Validate required fields
        const { iocValue, iocType, description, sources } = body;
        if (!iocValue || !iocType) {
            return NextResponse.json(
                { error: 'Missing required fields: iocValue, iocType' },
                { status: 400 }
            );
        }

        // Analyze the threat
        const analysis = await analyzeThreat({
            iocValue,
            iocType,
            description: description || '',
            sources: sources || [],
            tags: body.tags,
            threatTypes: body.threatTypes
        });

        if (!analysis) {
            return NextResponse.json(
                { error: 'Failed to analyze threat' },
                { status: 500 }
            );
        }

        return NextResponse.json({
            success: true,
            data: analysis
        });
    } catch (error) {
        console.error('Error in /api/analyze:', error);
        return NextResponse.json(
            { error: 'Internal server error' },
            { status: 500 }
        );
    }
}

/**
 * GET /api/analyze - Check status
 */
export async function GET() {
    return NextResponse.json({
        status: 'ok',
        openaiConfigured: isOpenAIConfigured(),
        model: 'gpt-4o-mini'
    });
}
