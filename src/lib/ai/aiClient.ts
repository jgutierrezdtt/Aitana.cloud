/**
 * Cliente de IA universal que funciona con:
 * - Ollama (local development)
 * - Together AI (producción recomendada)
 * - Groq (alternativa rápida)
 * - OpenAI (fallback)
 */

interface AIMessage {
  role: 'system' | 'user' | 'assistant';
  content: string;
}

interface AIResponse {
  content: string;
  provider: 'ollama' | 'together-ai' | 'groq' | 'openai' | 'fallback';
  model: string;
}

/**
 * Query Ollama local (desarrollo)
 */
async function queryOllama(
  messages: AIMessage[],
  model: string = 'qwen2.5:7b'
): Promise<AIResponse> {
  const baseUrl = process.env.OLLAMA_BASE_URL || 'http://localhost:11434';
  
  try {
    const response = await fetch(`${baseUrl}/api/chat`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        model,
        messages,
        stream: false,
        options: {
          temperature: 0.7,
          top_p: 0.9,
          num_predict: 800
        }
      })
    });

    if (!response.ok) {
      throw new Error(`Ollama error: ${response.statusText}`);
    }

    const data = await response.json();
    return {
      content: data.message.content,
      provider: 'ollama',
      model
    };
  } catch (error) {
    console.warn('Ollama no disponible:', error);
    throw error;
  }
}

/**
 * Query proveedores cloud con API compatible OpenAI
 */
async function queryCloudAI(messages: AIMessage[]): Promise<AIResponse> {
  // Detectar proveedor configurado
  const apiKey = process.env.TOGETHER_API_KEY || 
                 process.env.GROQ_API_KEY || 
                 process.env.OPENAI_API_KEY;
  
  const baseURL = process.env.TOGETHER_BASE_URL || 
                  process.env.GROQ_BASE_URL || 
                  'https://api.openai.com/v1';
  
  const model = process.env.TOGETHER_MODEL || 
                process.env.GROQ_MODEL || 
                'gpt-3.5-turbo';

  const provider = process.env.TOGETHER_API_KEY ? 'together-ai' :
                   process.env.GROQ_API_KEY ? 'groq' :
                   'openai';

  if (!apiKey) {
    throw new Error('No AI API key configured');
  }

  const response = await fetch(`${baseURL}/chat/completions`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${apiKey}`
    },
    body: JSON.stringify({
      model,
      messages,
      temperature: 0.7,
      max_tokens: 800
    })
  });

  if (!response.ok) {
    const error = await response.text();
    throw new Error(`AI API error: ${error}`);
  }

  const data = await response.json();
  return {
    content: data.choices[0]?.message?.content || '',
    provider: provider as AIResponse['provider'],
    model
  };
}

/**
 * Cliente inteligente que prueba Ollama primero (dev) y fallback a cloud
 */
export async function queryAI(
  prompt: string,
  systemPrompt?: string
): Promise<AIResponse> {
  const messages: AIMessage[] = [
    ...(systemPrompt ? [{ role: 'system' as const, content: systemPrompt }] : []),
    { role: 'user' as const, content: prompt }
  ];

  // Intentar Ollama en desarrollo
  if (process.env.NODE_ENV === 'development' && process.env.OLLAMA_BASE_URL) {
    try {
      return await queryOllama(messages);
    } catch (error) {
      console.warn('Fallback a cloud AI provider');
    }
  }

  // Usar cloud provider (Together AI, Groq, OpenAI)
  return await queryCloudAI(messages);
}

/**
 * Análisis especializado de evaluación SSDLC
 */
export async function analyzeSSLDCResponses(
  domain: string,
  responses: Record<string, boolean>,
  sector: string
): Promise<AIResponse> {
  const systemPrompt = `Eres un experto en seguridad de aplicaciones, cumplimiento normativo y SSDLC.
Analiza las respuestas de evaluación y genera recomendaciones específicas y accionables.
Sector objetivo: ${sector}
Responde en español de forma concisa y profesional.`;

  const answeredYes = Object.entries(responses).filter(([_, v]) => v).length;
  const total = Object.keys(responses).length;
  const percentage = Math.round((answeredYes / total) * 100);

  const prompt = `
## Evaluación del Dominio: ${domain}

**Progreso**: ${answeredYes}/${total} implementados (${percentage}%)

**Respuestas detalladas**:
${Object.entries(responses).map(([question, answer]) => 
  `- ${question}: ${answer ? '✓ Implementado' : '✗ No implementado'}`
).join('\n')}

**Sector**: ${sector}

## Tareas:

1. **Análisis de madurez**: Evalúa el nivel actual (1-5) basado en las respuestas
2. **Top 3 gaps críticos**: Identifica las carencias más importantes
3. **Recomendaciones priorizadas**: Genera 3 acciones concretas para mejorar

Formato de respuesta:
### Nivel de Madurez: [1-5] - [Nombre del nivel]
[Breve justificación]

### Gaps Críticos
1. **[Título]**: [Descripción concisa]
2. **[Título]**: [Descripción concisa]
3. **[Título]**: [Descripción concisa]

### Recomendaciones Prioritarias
1. **[Título]** (Plazo: [corto/medio/largo])
   [Acción específica y pasos concretos]

2. **[Título]** (Plazo: [corto/medio/largo])
   [Acción específica y pasos concretos]

3. **[Título]** (Plazo: [corto/medio/largo])
   [Acción específica y pasos concretos]
`;

  return await queryAI(prompt, systemPrompt);
}

/**
 * Chatbot de consultoría en normativas
 */
export async function queryNormativaAssistant(
  question: string,
  context?: string
): Promise<AIResponse> {
  const systemPrompt = `Eres un consultor experto en normativas de seguridad y cumplimiento regulatorio.
Especializaciones: GDPR, NIS2, DORA, PCI-DSS, ISO 27001, OWASP, NIST, MITRE ATT&CK.
Responde de forma clara, práctica y con ejemplos concretos en español.`;

  const prompt = context 
    ? `Contexto:\n${context}\n\nPregunta: ${question}`
    : question;

  return await queryAI(prompt, systemPrompt);
}

/**
 * Generador de plan de acción
 */
export async function generateActionPlan(
  sector: string,
  currentLevel: number,
  targetLevel: number,
  gaps: string[]
): Promise<AIResponse> {
  const systemPrompt = `Eres un arquitecto de seguridad especializado en roadmaps de transformación.
Genera planes de acción realistas, medibles y específicos por sector.`;

  const prompt = `
Sector: ${sector}
Nivel actual de madurez SSDLC: ${currentLevel}
Nivel objetivo: ${targetLevel}

Gaps identificados:
${gaps.map((gap, i) => `${i + 1}. ${gap}`).join('\n')}

Genera un plan de acción de 90 días con:
- Fases semanales
- Entregables específicos
- Recursos necesarios
- Métricas de éxito
- Quick wins identificados

Formato: Markdown con tablas y listas claras.
`;

  return await queryAI(prompt, systemPrompt);
}
