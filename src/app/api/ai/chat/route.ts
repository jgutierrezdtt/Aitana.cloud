import { NextRequest, NextResponse } from 'next/server';
import { queryNormativaAssistant } from '@/lib/ai/aiClient';

export const runtime = 'edge';

export async function POST(request: NextRequest) {
  try {
    const { question, context } = await request.json();

    if (!question) {
      return NextResponse.json(
        { success: false, error: 'Falta el parámetro: question' },
        { status: 400 }
      );
    }

    const result = await queryNormativaAssistant(question, context);

    return NextResponse.json({
      success: true,
      response: result.content,
      metadata: {
        provider: result.provider,
        model: result.model,
        timestamp: new Date().toISOString()
      }
    });

  } catch (error) {
    console.error('AI chat error:', error);
    
    return NextResponse.json(
      { 
        success: false, 
        error: error instanceof Error ? error.message : 'Error en el chat de IA'
      },
      { status: 500 }
    );
  }
}
