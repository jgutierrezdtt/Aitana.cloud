import { NextRequest, NextResponse } from 'next/server';
import { analyzeSSLDCResponses } from '@/lib/ai/aiClient';

// Edge runtime para mejor rendimiento en Vercel
export const runtime = 'edge';

export async function POST(request: NextRequest) {
  try {
    const { domain, responses, sector } = await request.json();

    // Validación
    if (!domain || !responses || !sector) {
      return NextResponse.json(
        { 
          success: false, 
          error: 'Faltan parámetros requeridos: domain, responses, sector' 
        },
        { status: 400 }
      );
    }

    // Análisis con IA
    const result = await analyzeSSLDCResponses(domain, responses, sector);

    return NextResponse.json({
      success: true,
      analysis: result.content,
      metadata: {
        provider: result.provider,
        model: result.model,
        timestamp: new Date().toISOString()
      }
    });

  } catch (error) {
    console.error('AI analysis error:', error);
    
    return NextResponse.json(
      { 
        success: false, 
        error: error instanceof Error ? error.message : 'Error desconocido en el análisis de IA',
        details: process.env.NODE_ENV === 'development' ? String(error) : undefined
      },
      { status: 500 }
    );
  }
}
