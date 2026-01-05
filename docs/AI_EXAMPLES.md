# 💡 Ejemplos de Uso - Integración de IA

## 📋 Casos de Uso Implementados

### 1️⃣ Análisis Inteligente en Evaluador de Madurez

**Ubicación**: `/evaluacion-madurez` → Tarjeta de cada dominio

**Flujo del Usuario**:
1. Usuario selecciona sector (ej: Financiero)
2. Responde preguntas del dominio Governance
3. Click en "🤖 Análisis Inteligente"
4. IA genera:
   - Nivel de madurez (1-5)
   - 3 gaps críticos
   - 3 recomendaciones priorizadas

**Ejemplo de Output**:
```markdown
### Nivel de Madurez: 2 - Gestionado

Has implementado prácticas básicas de governance, pero falta 
estandarización y automatización. Tu organización tiene políticas 
definidas pero no están completamente integradas en los procesos.

### Gaps Críticos

1. **Falta de automatización en revisiones de políticas**
   Las políticas se revisan manualmente, aumentando el riesgo de 
   inconsistencias y retrasos.

2. **Capacitación no periódica**
   La formación en seguridad no está institucionalizada, limitando 
   la concienciación del personal.

3. **Métricas de cumplimiento inexistentes**
   No se mide el nivel de adopción de las políticas de seguridad.

### Recomendaciones Prioritarias

1. **Implementar herramienta de gestión de políticas** (Plazo: corto)
   - Adoptar plataforma como PolicyTech o similar
   - Configurar workflows de aprobación automática
   - Establecer recordatorios de revisión trimestral
   - Quick win: Usar SharePoint con flujos de Power Automate

2. **Establecer programa de capacitación continua** (Plazo: medio)
   - Calendario anual de formaciones (GDPR, DORA, ISO 27001)
   - Plataforma LMS con tracking de completitud
   - Certificaciones obligatorias por rol
   - Presupuesto: 500€/persona/año

3. **Dashboard de métricas de cumplimiento** (Plazo: medio)
   - KPIs: % políticas leídas, tiempo respuesta incidentes, % formados
   - Integración con SIEM/GRC existente
   - Reportes mensuales para dirección
   - Herramienta sugerida: Power BI + Azure Sentinel
```

---

## 🔌 Ejemplos de API

### POST /api/ai/analyze

**Request**:
```bash
curl -X POST http://localhost:3000/api/ai/analyze \
  -H "Content-Type: application/json" \
  -d '{
    "domain": "Governance",
    "responses": {
      "gov-policy-1": true,
      "gov-policy-2": false,
      "gov-roles-1": true,
      "gov-roles-2": false,
      "gov-training-1": false
    },
    "sector": "financiero"
  }'
```

**Response**:
```json
{
  "success": true,
  "analysis": "### Nivel de Madurez: 2 - Gestionado\n\n...",
  "metadata": {
    "provider": "ollama",
    "model": "qwen2.5:7b",
    "timestamp": "2025-12-06T14:30:00.000Z"
  }
}
```

### POST /api/ai/chat

**Request**:
```bash
curl -X POST http://localhost:3000/api/ai/chat \
  -H "Content-Type: application/json" \
  -d '{
    "question": "¿Cuáles son los 5 controles más importantes de DORA para un banco mediano?",
    "context": "Banco con 500 empleados, 3 sucursales, operando en España"
  }'
```

**Response**:
```json
{
  "success": true,
  "response": "Para un banco mediano bajo DORA, los 5 controles prioritarios son:\n\n1. **Gestión de Riesgos TIC** (Art. 6-15)\n   - Identificación de activos críticos\n   - Evaluación continua de riesgos\n   - Plan de gestión de riesgos aprobado por Consejo\n\n2. **Continuidad de Negocio y Recuperación ante Desastres** (Art. 11-12)\n   - RTO/RPO documentados por servicio crítico\n   - Backup geográficamente distribuido\n   - Pruebas de recuperación trimestrales\n\n3. **Gestión de Incidentes TIC** (Art. 17-20)\n   - Clasificación de incidentes (Alto/Medio/Bajo)\n   - Notificación a autoridades en 24h (incidentes graves)\n   - Registro centralizado de incidentes\n\n4. **Pruebas de Resiliencia Digital** (Art. 24-27)\n   - TLPT (Threat-Led Penetration Testing) cada 3 años\n   - Análisis de vulnerabilidades trimestral\n   - Remedación de hallazgos críticos en 30 días\n\n5. **Gestión de Terceros TIC** (Art. 28-30)\n   - Registro de proveedores críticos\n   - Due diligence pre-contratación\n   - Auditorías de proveedores cloud (mínimo anual)\n\nPrioriza implementar primero los controles 1 y 2, ya que son fundacionales.",
  "metadata": {
    "provider": "ollama",
    "model": "qwen2.5:7b",
    "timestamp": "2025-12-06T14:32:00.000Z"
  }
}
```

---

## 💻 Ejemplos de Código

### Uso del Hook `useAIAnalysis`

```typescript
'use client';

import { useAIAnalysis } from '@/hooks/useAIAnalysis';

export default function MyComponent() {
  const { analyzeResponses, loading, error } = useAIAnalysis();
  const [insights, setInsights] = useState<string | null>(null);

  const handleAnalyze = async () => {
    const result = await analyzeResponses(
      'Governance',
      {
        'gov-policy-1': true,
        'gov-roles-1': false
      },
      'financiero'
    );

    if (result) {
      setInsights(result);
    }
  };

  return (
    <div>
      <button 
        onClick={handleAnalyze} 
        disabled={loading}
      >
        {loading ? 'Analizando...' : '🤖 Analizar'}
      </button>

      {error && <div className="error">{error}</div>}
      {insights && <div className="insights">{insights}</div>}
    </div>
  );
}
```

### Uso Directo del Cliente de IA

```typescript
import { queryAI, analyzeSSLDCResponses } from '@/lib/ai/aiClient';

// Análisis especializado
const result = await analyzeSSLDCResponses(
  'Governance',
  { 'gov-1': true, 'gov-2': false },
  'financiero'
);

console.log(result.content);    // Análisis en Markdown
console.log(result.provider);   // 'ollama' | 'together-ai' | 'groq'
console.log(result.model);      // 'qwen2.5:7b' | 'llama-3.1-8b' etc.

// Query genérica
const answer = await queryAI(
  'Explica qué es SQL Injection',
  'Eres un experto en seguridad de aplicaciones'
);

console.log(answer.content);
```

### API Route Personalizada

```typescript
// /src/app/api/my-custom-ai/route.ts

import { NextRequest, NextResponse } from 'next/server';
import { queryAI } from '@/lib/ai/aiClient';

export const runtime = 'edge';

export async function POST(request: NextRequest) {
  const { codeSnippet, language } = await request.json();

  const systemPrompt = `Eres un experto en seguridad de código.
Analiza el siguiente código y detecta vulnerabilidades.
Responde en español con formato Markdown.`;

  const prompt = `
Lenguaje: ${language}

Código:
\`\`\`${language}
${codeSnippet}
\`\`\`

Analiza y reporta:
1. Vulnerabilidades encontradas (CWE)
2. Severidad (Crítica/Alta/Media/Baja)
3. Solución recomendada (código seguro)
`;

  const result = await queryAI(prompt, systemPrompt);

  return NextResponse.json({
    vulnerabilities: result.content,
    provider: result.provider,
    model: result.model
  });
}
```

**Uso**:
```bash
curl -X POST http://localhost:3000/api/my-custom-ai \
  -H "Content-Type: application/json" \
  -d '{
    "codeSnippet": "SELECT * FROM users WHERE id = \"${userId}\"",
    "language": "sql"
  }'
```

---

## 🎨 Ejemplos de UI

### Botón Simple

```typescript
import { useAIAnalysis } from '@/hooks/useAIAnalysis';
import { Sparkles } from 'lucide-react';

export default function SimpleAIButton({ domain, responses, sector }) {
  const { analyzeResponses, loading } = useAIAnalysis();
  const [result, setResult] = useState(null);

  return (
    <>
      <button
        onClick={async () => {
          const analysis = await analyzeResponses(domain, responses, sector);
          setResult(analysis);
        }}
        disabled={loading}
        className="btn-primary"
      >
        <Sparkles className="w-4 h-4" />
        {loading ? 'Analizando...' : 'Analizar con IA'}
      </button>

      {result && (
        <div className="mt-4 p-4 bg-purple-500/10 rounded">
          <pre className="whitespace-pre-wrap">{result}</pre>
        </div>
      )}
    </>
  );
}
```

### Chat Conversacional

```typescript
import { useAIChat } from '@/hooks/useAIAnalysis';
import { useState } from 'react';

export default function ChatBot() {
  const { ask, loading } = useAIChat();
  const [messages, setMessages] = useState<Array<{role: string, content: string}>>([]);
  const [input, setInput] = useState('');

  const handleSend = async () => {
    if (!input.trim()) return;

    // Agregar pregunta del usuario
    const userMessage = { role: 'user', content: input };
    setMessages(prev => [...prev, userMessage]);

    // Obtener respuesta de IA
    const response = await ask(input);
    
    if (response) {
      setMessages(prev => [...prev, { role: 'assistant', content: response }]);
    }

    setInput('');
  };

  return (
    <div className="chat-container">
      <div className="messages">
        {messages.map((msg, i) => (
          <div key={i} className={`message ${msg.role}`}>
            <div className="avatar">
              {msg.role === 'user' ? '👤' : '🤖'}
            </div>
            <div className="content">{msg.content}</div>
          </div>
        ))}
      </div>

      <div className="input-area">
        <input
          value={input}
          onChange={(e) => setInput(e.target.value)}
          onKeyPress={(e) => e.key === 'Enter' && handleSend()}
          placeholder="Pregunta sobre normativas..."
        />
        <button onClick={handleSend} disabled={loading}>
          {loading ? 'Pensando...' : 'Enviar'}
        </button>
      </div>
    </div>
  );
}
```

### Loading con Skeleton

```typescript
export default function AIAnalysisWithSkeleton() {
  const { analyzeResponses, loading } = useAIAnalysis();
  const [analysis, setAnalysis] = useState(null);

  return (
    <div>
      <button onClick={async () => {
        const result = await analyzeResponses(...);
        setAnalysis(result);
      }}>
        Analizar
      </button>

      {loading && (
        <div className="animate-pulse space-y-3">
          <div className="h-4 bg-slate-700 rounded w-3/4"></div>
          <div className="h-4 bg-slate-700 rounded"></div>
          <div className="h-4 bg-slate-700 rounded w-5/6"></div>
        </div>
      )}

      {analysis && (
        <div className="prose prose-invert">
          {analysis}
        </div>
      )}
    </div>
  );
}
```

---

## 🧪 Ejemplos de Testing

### Test con Jest

```typescript
import { queryAI } from '@/lib/ai/aiClient';

describe('AI Client', () => {
  it('should return analysis in Spanish', async () => {
    const result = await queryAI(
      'Resume en 3 palabras qué es SSDLC',
      'Responde en español'
    );

    expect(result.content).toBeTruthy();
    expect(result.provider).toMatch(/ollama|together-ai|groq|openai/);
  });

  it('should handle errors gracefully', async () => {
    // Mock de error
    global.fetch = jest.fn(() => Promise.reject('Network error'));

    await expect(queryAI('test')).rejects.toThrow();
  });
});
```

### Test de Integración

```bash
#!/bin/bash

echo "Testing AI Integration..."

# Test 1: Análisis de evaluación
echo -e "\n1. Testing /api/ai/analyze..."
RESPONSE=$(curl -s -X POST http://localhost:3000/api/ai/analyze \
  -H "Content-Type: application/json" \
  -d '{"domain":"Governance","responses":{"gov-1":true},"sector":"financiero"}')

if echo "$RESPONSE" | grep -q "success.*true"; then
  echo "✅ /api/ai/analyze OK"
else
  echo "❌ /api/ai/analyze FAILED"
  echo "$RESPONSE"
  exit 1
fi

# Test 2: Chat
echo -e "\n2. Testing /api/ai/chat..."
RESPONSE=$(curl -s -X POST http://localhost:3000/api/ai/chat \
  -H "Content-Type: application/json" \
  -d '{"question":"¿Qué es GDPR?"}')

if echo "$RESPONSE" | grep -q "success.*true"; then
  echo "✅ /api/ai/chat OK"
else
  echo "❌ /api/ai/chat FAILED"
  exit 1
fi

echo -e "\n✅ All tests passed!"
```

---

## 🔄 Ejemplos de Streaming (Futuro)

```typescript
// Preparado para streaming de respuestas

async function streamingQuery(prompt: string) {
  const response = await fetch('/api/ai/stream', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ prompt })
  });

  const reader = response.body?.getReader();
  const decoder = new TextDecoder();

  while (true) {
    const { done, value } = await reader.read();
    if (done) break;

    const chunk = decoder.decode(value);
    console.log(chunk); // Mostrar palabra por palabra
  }
}
```

---

## 📊 Ejemplo de Dashboard Completo

```typescript
export default function AIInsightsDashboard() {
  const [domainAnalyses, setDomainAnalyses] = useState<Record<string, string>>({});
  const { analyzeResponses, loading } = useAIAnalysis();

  const analyzeAllDomains = async () => {
    const domains = ['Governance', 'Design', 'Implementation', 'Verification'];
    
    for (const domain of domains) {
      const analysis = await analyzeResponses(
        domain,
        responses[domain],
        sector
      );
      
      setDomainAnalyses(prev => ({ ...prev, [domain]: analysis }));
    }
  };

  return (
    <div className="grid grid-cols-2 gap-6">
      {Object.entries(domainAnalyses).map(([domain, analysis]) => (
        <div key={domain} className="card">
          <h3>{domain}</h3>
          <div className="prose prose-sm">{analysis}</div>
        </div>
      ))}

      <button onClick={analyzeAllDomains} disabled={loading}>
        {loading ? 'Analizando todos los dominios...' : '🤖 Análisis Completo'}
      </button>
    </div>
  );
}
```

---

## 🎯 Tips de Uso

### Optimizar Prompts

```typescript
// ❌ Prompt genérico
const bad = await queryAI('Analiza esto');

// ✅ Prompt específico con contexto
const good = await queryAI(`
Analiza las siguientes respuestas del dominio Governance:
- Política de seguridad: Implementada ✓
- Roles definidos: No implementado ✗
- Capacitación: No implementado ✗

Sector: Financiero (Banco mediano)
Framework: OWASP SAMM + ISO 27001

Genera:
1. Nivel de madurez (1-5)
2. Top 3 gaps
3. 3 recomendaciones específicas con plazos y costos estimados
`);
```

### Caché de Respuestas

```typescript
const cache = new Map<string, string>();

async function cachedAnalysis(domain: string, responses: any, sector: string) {
  const key = JSON.stringify({ domain, responses, sector });
  
  if (cache.has(key)) {
    return cache.get(key);
  }

  const result = await analyzeResponses(domain, responses, sector);
  cache.set(key, result);
  
  return result;
}
```

### Rate Limiting Local

```typescript
let lastCall = 0;
const MIN_INTERVAL = 2000; // 2 segundos entre llamadas

async function rateLimitedQuery(prompt: string) {
  const now = Date.now();
  const timeSinceLastCall = now - lastCall;
  
  if (timeSinceLastCall < MIN_INTERVAL) {
    await new Promise(resolve => 
      setTimeout(resolve, MIN_INTERVAL - timeSinceLastCall)
    );
  }

  lastCall = Date.now();
  return await queryAI(prompt);
}
```

---

## 📚 Referencias

- **Documentación completa**: `/docs/AI_INTEGRATION.md`
- **Inicio rápido**: `/docs/AI_QUICKSTART.md`
- **Arquitectura**: `/docs/AI_README.md`
- **Código fuente**: `/src/lib/ai/aiClient.ts`

---

**¿Más ejemplos?** Consulta los componentes en `/src/components/evaluacion/` o crea un issue.
