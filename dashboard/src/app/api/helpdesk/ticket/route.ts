import { NextRequest, NextResponse } from 'next/server';

const AI_SERVICE_URL = process.env.AI_SERVICE_URL || 'http://localhost:8000';
const AI_SERVICE_API_KEY = process.env.AI_SERVICE_API_KEY || 'tcti-dashboard-key';

export async function POST(request: NextRequest) {
    try {
        const body = await request.json();

        // Transform request body to match AI Service API
        const aiServiceBody = {
            ioc_value: body.iocValue,
            ioc_type: body.iocType,
            description: body.description,
            risk_score: body.riskScore,
            severity: body.severity,
            threat_types: body.threatTypes || [],
            threat_actors: body.threatActors || []
        };

        const response = await fetch(`${AI_SERVICE_URL}/helpdesk/ticket`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-API-Key': AI_SERVICE_API_KEY
            },
            body: JSON.stringify(aiServiceBody)
        });

        if (!response.ok) {
            const errorText = await response.text();
            return NextResponse.json(
                { success: false, message: `AI Service error: ${response.status}`, error: errorText },
                { status: response.status }
            );
        }

        const result = await response.json();

        return NextResponse.json({
            success: result.success,
            ticketId: result.ticket_id,
            message: result.message,
            mock: result.mock
        });

    } catch (error) {
        console.error('HelpDesk API error:', error);
        return NextResponse.json(
            { success: false, message: 'Failed to connect to AI Service' },
            { status: 500 }
        );
    }
}
