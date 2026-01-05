# Integración de IA Open-Source en Aitana.cloud

## 🎯 Objetivos

Integrar modelos de IA open-source para:
- Análisis automático de respuestas de evaluación
- Generación de recomendaciones personalizadas
- Chatbot de consultoría en seguridad
- Análisis de documentación de normativas

---

## 🏠 Opción 1: Ollama Local (Desarrollo)

### Instalación

```bash
# macOS
brew install ollama

# Iniciar servicio
ollama serve

# Descargar modelos recomendados
ollama pull llama3.2:3b        # Ligero, rápido (2GB)
ollama pull mistral:7b         # Balanceado (4GB)
ollama pull codellama:7b       # Para código (4GB)
ollama pull qwen2.5:7b         # Multilingüe excelente (4GB)
```

### Configuración en Next.js

**1. Variables de entorno (.env.local)**

```env
# Ollama local
OLLAMA_BASE_URL=http://localhost:11434
OLLAMA_MODEL=qwen2.5:7b

# Fallback para producción (ver Opción 2)
OPENAI_API_KEY=your_key_here  # OpenAI compatible
OPENAI_BASE_URL=https://api.together.xyz/v1  # Together AI, Groq, etc.
```

**2. Cliente API (/src/lib/ai/ollamaClient.ts)**

```typescript
interface OllamaResponse {
  model: string;
  response: string;
  done: boolean;
}

export async function queryOllama(
  prompt: string,
  systemPrompt?: string,
  model: string = process.env.OLLAMA_MODEL || 'qwen2.5:7b'
): Promise<string> {
  const baseUrl = process.env.OLLAMA_BASE_URL || 'http://localhost:11434';
  
  try {
    const response = await fetch(`${baseUrl}/api/generate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        model,
        prompt: systemPrompt ? `${systemPrompt}\n\n${prompt}` : prompt,
        stream: false,
        options: {
          temperature: 0.7,
          top_p: 0.9,
          num_predict: 500
        }
      })
    });

    if (!response.ok) {
      throw new Error(`Ollama error: ${response.statusText}`);
    }

    const data: OllamaResponse = await response.json();
    return data.response;
  } catch (error) {
    console.error('Ollama query failed:', error);
    throw error;
  }
}

// Chat mode (conversación)
export async function chatOllama(
  messages: Array<{ role: 'system' | 'user' | 'assistant'; content: string }>,
  model: string = process.env.OLLAMA_MODEL || 'qwen2.5:7b'
): Promise<string> {
  const baseUrl = process.env.OLLAMA_BASE_URL || 'http://localhost:11434';
  
  const response = await fetch(`${baseUrl}/api/chat`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      model,
      messages,
      stream: false
    })
  });

  const data = await response.json();
  return data.message.content;
}
```

**3. API Route (/src/app/api/ai/analyze/route.ts)**

```typescript
import { NextRequest, NextResponse } from 'next/server';
import { queryOllama } from '@/lib/ai/ollamaClient';

export async function POST(request: NextRequest) {
  try {
    const { domain, responses, sector } = await request.json();

    const systemPrompt = `Eres un experto en seguridad de aplicaciones y cumplimiento normativo.
Analiza las respuestas de la evaluación SSDLC y genera recomendaciones específicas.
Considera el sector: ${sector}
Responde en español de forma concisa y accionable.`;

    const prompt = `
Dominio evaluado: ${domain}
Respuestas:
${Object.entries(responses).map(([q, a]) => `- ${q}: ${a ? 'Sí' : 'No'}`).join('\n')}

Genera 3 recomendaciones priorizadas para mejorar la madurez.
`;

    const analysis = await queryOllama(prompt, systemPrompt);

    return NextResponse.json({ 
      success: true, 
      analysis,
      model: 'ollama-local' 
    });
  } catch (error) {
    console.error('AI analysis error:', error);
    return NextResponse.json(
      { success: false, error: 'Error en el análisis de IA' },
      { status: 500 }
    );
  }
}
```

**4. Hook React (/src/hooks/useAIAnalysis.ts)**

```typescript
import { useState } from 'react';

interface AIAnalysisResult {
  analysis: string;
  model: string;
}

export function useAIAnalysis() {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const analyzeResponses = async (
    domain: string,
    responses: Record<string, boolean>,
    sector: string
  ): Promise<string | null> => {
    setLoading(true);
    setError(null);

    try {
      const response = await fetch('/api/ai/analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ domain, responses, sector })
      });

      const data: AIAnalysisResult = await response.json();

      if (!response.ok) {
        throw new Error(data.error || 'Error en el análisis');
      }

      return data.analysis;
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Error desconocido');
      return null;
    } finally {
      setLoading(false);
    }
  };

  return { analyzeResponses, loading, error };
}
```

### Uso en Componentes

```typescript
// En ResultsDashboard.tsx
import { useAIAnalysis } from '@/hooks/useAIAnalysis';

export default function ResultsDashboard({ domain, responses, sector }) {
  const { analyzeResponses, loading, error } = useAIAnalysis();
  const [aiInsights, setAiInsights] = useState<string | null>(null);

  const handleAIAnalysis = async () => {
    const insights = await analyzeResponses(domain.id, responses, sector);
    setAiInsights(insights);
  };

  return (
    <div>
      {/* ... existing code ... */}
      
      <button
        onClick={handleAIAnalysis}
        disabled={loading}
        className="btn-primary"
      >
        {loading ? 'Analizando con IA...' : '🤖 Análisis con IA'}
      </button>

      {aiInsights && (
        <div className="mt-4 p-4 bg-purple-500/10 border border-purple-500 rounded">
          <h3>💡 Insights de IA</h3>
          <p className="whitespace-pre-wrap">{aiInsights}</p>
        </div>
      )}
    </div>
  );
}
```

---

## ☁️ Opción 2: Producción en Vercel

**Problema**: Vercel no permite ejecutar Ollama (serverless, sin estado persistente)

**Soluciones**:

### 2A. Together AI (Recomendado) 💰 Gratis para empezar

```bash
# Registro en https://together.ai (8B tokens gratis)
# API compatible con OpenAI
```

**Variables de entorno en Vercel:**

```env
# Together AI
TOGETHER_API_KEY=your_together_api_key
TOGETHER_BASE_URL=https://api.together.xyz/v1

# Modelos disponibles
TOGETHER_MODEL=meta-llama/Meta-Llama-3.1-8B-Instruct-Turbo
# Alternativas:
# - mistralai/Mistral-7B-Instruct-v0.3
# - Qwen/Qwen2.5-7B-Instruct-Turbo
```

**Cliente universal (/src/lib/ai/aiClient.ts)**

```typescript
import OpenAI from 'openai';

// Cliente que funciona con Together AI, Groq, OpenAI, etc.
const client = new OpenAI({
  apiKey: process.env.TOGETHER_API_KEY || process.env.OPENAI_API_KEY,
  baseURL: process.env.TOGETHER_BASE_URL || 'https://api.openai.com/v1'
});

export async function queryAI(
  prompt: string,
  systemPrompt?: string,
  model?: string
): Promise<string> {
  const response = await client.chat.completions.create({
    model: model || process.env.TOGETHER_MODEL || 'gpt-3.5-turbo',
    messages: [
      ...(systemPrompt ? [{ role: 'system' as const, content: systemPrompt }] : []),
      { role: 'user' as const, content: prompt }
    ],
    temperature: 0.7,
    max_tokens: 500
  });

  return response.choices[0]?.message?.content || '';
}
```

**API Route universal (/src/app/api/ai/analyze/route.ts)**

```typescript
import { NextRequest, NextResponse } from 'next/server';
import { queryAI } from '@/lib/ai/aiClient';

export const runtime = 'edge'; // Vercel Edge (más rápido)

export async function POST(request: NextRequest) {
  try {
    const { domain, responses, sector } = await request.json();

    const systemPrompt = `Eres un experto en seguridad de aplicaciones y cumplimiento normativo.
Analiza las respuestas de la evaluación SSDLC y genera recomendaciones específicas.
Sector: ${sector}
Responde en español de forma concisa y accionable (máximo 3 recomendaciones).`;

    const prompt = `
Dominio: ${domain}
Respuestas: ${JSON.stringify(responses, null, 2)}

Genera 3 recomendaciones priorizadas para mejorar la madurez en este dominio.
Formato:
1. [TÍTULO]: descripción breve
2. [TÍTULO]: descripción breve
3. [TÍTULO]: descripción breve
`;

    const analysis = await queryAI(prompt, systemPrompt);

    return NextResponse.json({ 
      success: true, 
      analysis,
      provider: process.env.TOGETHER_API_KEY ? 'together-ai' : 'openai'
    });
  } catch (error) {
    console.error('AI analysis error:', error);
    return NextResponse.json(
      { success: false, error: 'Error en el análisis de IA' },
      { status: 500 }
    );
  }
}
```

### 2B. Groq (Ultra rápido, gratis) ⚡

```env
# Groq (más rápido que Together AI)
GROQ_API_KEY=your_groq_api_key
GROQ_BASE_URL=https://api.groq.com/openai/v1
GROQ_MODEL=llama-3.2-3b-preview  # o mixtral-8x7b-32768
```

### 2C. Replicate (Modelos específicos)

```env
REPLICATE_API_TOKEN=your_replicate_token
```

```typescript
import Replicate from 'replicate';

const replicate = new Replicate({
  auth: process.env.REPLICATE_API_TOKEN,
});

const output = await replicate.run(
  "meta/llama-2-7b-chat",
  { input: { prompt: "Your prompt here" } }
);
```

### 2D. Self-Hosted Ollama en VPS (Avanzado)

```bash
# En un VPS (DigitalOcean, Hetzner, etc.)
# Instalar Ollama
curl -fsSL https://ollama.com/install.sh | sh

# Exponer API públicamente
OLLAMA_HOST=0.0.0.0:11434 ollama serve

# Configurar HTTPS con Nginx/Caddy
# Agregar autenticación básica
```

**En Vercel:**

```env
OLLAMA_BASE_URL=https://your-vps-domain.com
OLLAMA_API_KEY=your_basic_auth_token
```

---

## 🚀 Opción 3: Híbrida (Recomendada)

**Local**: Ollama para desarrollo  
**Producción**: Together AI / Groq para Vercel

**Cliente inteligente (/src/lib/ai/smartClient.ts)**

```typescript
import { queryOllama } from './ollamaClient';
import { queryAI } from './aiClient';

export async function querySmartAI(
  prompt: string,
  systemPrompt?: string
): Promise<{ response: string; provider: string }> {
  const isLocal = process.env.NODE_ENV === 'development' && 
                  process.env.OLLAMA_BASE_URL;

  if (isLocal) {
    try {
      const response = await queryOllama(prompt, systemPrompt);
      return { response, provider: 'ollama-local' };
    } catch (error) {
      console.warn('Ollama no disponible, usando fallback cloud');
    }
  }

  // Fallback a Together AI / Groq
  const response = await queryAI(prompt, systemPrompt);
  return { 
    response, 
    provider: process.env.TOGETHER_API_KEY ? 'together-ai' : 'groq' 
  };
}
```

---

## 📦 Instalación Rápida

```bash
# Dependencias
npm install openai replicate

# Variables de entorno (.env.local)
cat >> .env.local << 'EOF'

# === AI Configuration ===
# Local (Ollama)
OLLAMA_BASE_URL=http://localhost:11434
OLLAMA_MODEL=qwen2.5:7b

# Production (Together AI - Gratis para empezar)
TOGETHER_API_KEY=your_key_here
TOGETHER_BASE_URL=https://api.together.xyz/v1
TOGETHER_MODEL=meta-llama/Meta-Llama-3.1-8B-Instruct-Turbo

# Alternative: Groq (ultra rápido)
# GROQ_API_KEY=your_groq_key
# GROQ_BASE_URL=https://api.groq.com/openai/v1
# GROQ_MODEL=llama-3.2-3b-preview
EOF

# Instalar Ollama (macOS)
brew install ollama

# Descargar modelo recomendado
ollama pull qwen2.5:7b  # Excelente multilingüe, 4GB
```

---

## 🎯 Casos de Uso en tu App

### 1. Análisis Inteligente de Respuestas
```typescript
// Botón en ResultsDashboard
const insights = await querySmartAI(`
Analiza estas respuestas del dominio ${domain.name}:
${JSON.stringify(responses)}

Genera 3 recomendaciones específicas.
`);
```

### 2. Chatbot de Consultoría
```typescript
// Componente ChatBot
const response = await chatOllama([
  { role: 'system', content: 'Eres un consultor experto en SSDLC y normativas' },
  { role: 'user', content: '¿Cómo implemento DORA en mi banco?' }
]);
```

### 3. Generador de Planes de Acción
```typescript
const actionPlan = await querySmartAI(`
Sector: ${sector}
Nivel actual: ${maturityLevel}
Gaps: ${gaps.join(', ')}

Genera un plan de acción de 90 días.
`);
```

### 4. Asistente de Normativas
```typescript
const explanation = await querySmartAI(`
Explica el artículo 10 de NIS2 de forma simple y con ejemplos prácticos.
`);
```

---

## 💰 Comparativa de Costos

| Proveedor | Gratis | Costo | Velocidad | Calidad |
|-----------|--------|-------|-----------|---------|
| **Ollama Local** | ✅ Ilimitado | $0 | Media | Alta |
| **Together AI** | 8B tokens | $0.20/M tokens | Media | Alta |
| **Groq** | 30 req/min | $0 (beta) | ⚡ Ultra | Alta |
| **OpenAI** | ❌ | $0.50-2/M tokens | Alta | Muy Alta |
| **Replicate** | ❌ | $0.10-1/M tokens | Media | Variable |

**Recomendación**: 
- **Desarrollo**: Ollama (gratis, privado)
- **Producción**: Together AI o Groq (gratis tier generoso)

---

## 🔒 Seguridad

```typescript
// Rate limiting (Vercel Edge Middleware)
import { Ratelimit } from '@upstash/ratelimit';
import { Redis } from '@upstash/redis';

const ratelimit = new Ratelimit({
  redis: Redis.fromEnv(),
  limiter: Ratelimit.slidingWindow(10, '1 m'), // 10 requests/min
});

export async function middleware(request: NextRequest) {
  if (request.nextUrl.pathname.startsWith('/api/ai')) {
    const ip = request.ip ?? 'anonymous';
    const { success } = await ratelimit.limit(ip);
    
    if (!success) {
      return NextResponse.json(
        { error: 'Rate limit exceeded' },
        { status: 429 }
      );
    }
  }
  
  return NextResponse.next();
}
```

---

## ✅ Próximos Pasos

1. **Instalar Ollama localmente** → `brew install ollama`
2. **Descargar modelo** → `ollama pull qwen2.5:7b`
3. **Crear cliente AI** → Usar código de arriba
4. **Registrarse en Together AI** → https://together.ai
5. **Configurar variables de entorno** → `.env.local` + Vercel
6. **Probar localmente** → Desarrollo con Ollama
7. **Deploy a Vercel** → Automático con Together AI

---

## 📚 Recursos

- **Ollama**: https://ollama.com
- **Together AI**: https://together.ai (8B tokens gratis)
- **Groq**: https://groq.com (ultra rápido)
- **Replicate**: https://replicate.com
- **OpenAI SDK**: Compatible con todos los proveedores
