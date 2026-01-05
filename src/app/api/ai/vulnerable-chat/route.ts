import { NextRequest, NextResponse } from 'next/server';
import { getChallengeById } from '@/data/prompt-injection-challenges';

// Edge runtime for Vercel optimization
export const runtime = 'edge';

/**
 * INTENTIONALLY VULNERABLE AI ENDPOINT
 * For educational purposes - Prompt Injection Lab
 * 
 * WARNING: This endpoint has NO safety filters on purpose
 */
export async function POST(request: NextRequest) {
  try {
    const { challengeId, userPrompt } = await request.json();

    if (!challengeId || !userPrompt) {
      return NextResponse.json(
        { error: 'Missing challengeId or userPrompt' },
        { status: 400 }
      );
    }

    // Get challenge configuration
    const challenge = getChallengeById(challengeId);
    if (!challenge) {
      return NextResponse.json(
        { error: 'Challenge not found' },
        { status: 404 }
      );
    }

    const startTime = Date.now();

    // Query AI with vulnerable configuration
    const aiResponse = await queryVulnerableAI(
      challenge.systemPrompt,
      userPrompt
    );

    const executionTime = Date.now() - startTime;

    // Check if attack was successful
    const success = checkAttackSuccess(
      aiResponse.content,
      challenge.successPatterns,
      challenge.forbiddenPatterns
    );

    // Check if secret data was extracted
    const secretExtracted = challenge.secretData 
      ? aiResponse.content.includes(challenge.secretData)
      : false;

    return NextResponse.json({
      success: true,
      response: aiResponse.content,
      metadata: {
        ...aiResponse.metadata,
        executionTime,
        challengeId,
      },
      attackSuccess: success || secretExtracted,
      secretExtracted,
      pointsEarned: (success || secretExtracted) ? challenge.points : 0,
    });

  } catch (error) {
    console.error('Vulnerable chat error:', error);
    return NextResponse.json(
      { 
        error: 'Internal server error',
        details: process.env.NODE_ENV === 'development' ? String(error) : undefined
      },
      { status: 500 }
    );
  }
}

/**
 * Query AI with VULNERABLE configuration (no safety filters)
 */
async function queryVulnerableAI(
  systemPrompt: string,
  userPrompt: string
): Promise<{
  content: string;
  metadata: {
    provider: string;
    model: string;
    tokensUsed: number;
  };
}> {
  // Detect which AI provider is available
  const apiKey = process.env.TOGETHER_API_KEY || 
                 process.env.GROQ_API_KEY || 
                 process.env.OPENAI_API_KEY;

  if (!apiKey) {
    throw new Error('No AI provider configured. Set TOGETHER_API_KEY, GROQ_API_KEY, or OPENAI_API_KEY');
  }

  const provider = process.env.TOGETHER_API_KEY ? 'together-ai' :
                   process.env.GROQ_API_KEY ? 'groq' : 'openai';

  const baseURL = provider === 'together-ai' 
    ? (process.env.TOGETHER_BASE_URL || 'https://api.together.xyz/v1')
    : provider === 'groq'
    ? (process.env.GROQ_BASE_URL || 'https://api.groq.com/openai/v1')
    : 'https://api.openai.com/v1';

  const model = provider === 'together-ai'
    ? (process.env.TOGETHER_MODEL || 'meta-llama/Meta-Llama-3.1-8B-Instruct-Turbo')
    : provider === 'groq'
    ? (process.env.GROQ_MODEL || 'llama-3.2-3b-preview')
    : 'gpt-3.5-turbo';

  const response = await fetch(`${baseURL}/chat/completions`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${apiKey}`,
    },
    body: JSON.stringify({
      model,
      messages: [
        { role: 'system', content: systemPrompt },
        { role: 'user', content: userPrompt },
      ],
      temperature: 0.7,
      max_tokens: 1000,
      // VULNERABLE: No safety settings, no content filtering
    }),
  });

  if (!response.ok) {
    const error = await response.text();
    throw new Error(`AI provider error: ${error}`);
  }

  const data = await response.json();

  return {
    content: data.choices[0]?.message?.content || 'No response',
    metadata: {
      provider,
      model,
      tokensUsed: data.usage?.total_tokens || 0,
    },
  };
}

/**
 * Check if the attack was successful based on patterns
 */
function checkAttackSuccess(
  response: string,
  successPatterns: string[],
  forbiddenPatterns: string[]
): boolean {
  const lowerResponse = response.toLowerCase();

  // Check if forbidden patterns are present (means attack failed)
  for (const pattern of forbiddenPatterns) {
    const regex = new RegExp(pattern, 'i');
    if (regex.test(response)) {
      return false; // Attack blocked
    }
  }

  // Check if success patterns are present (means attack succeeded)
  for (const pattern of successPatterns) {
    const regex = new RegExp(pattern, 'i');
    if (regex.test(response)) {
      return true; // Attack successful!
    }
  }

  return false; // Inconclusive
}

/**
 * GET endpoint to check available challenges
 */
export async function GET() {
  return NextResponse.json({
    endpoint: '/api/ai/vulnerable-chat',
    description: 'INTENTIONALLY VULNERABLE endpoint for educational prompt injection training',
    warning: 'This endpoint has NO safety filters. Use only for authorized security training.',
    usage: {
      method: 'POST',
      body: {
        challengeId: 'string (e.g., "jb-001")',
        userPrompt: 'string (your attack prompt)',
      },
    },
    availableChallenges: [
      'jb-001', 'pl-001', 'de-001', 'rp-001',
      'ii-001', 'ms-001', 'adv-001', 'master-001'
    ],
  });
}
