# 🚀 Despliegue en Vercel con IA

## 📋 Opciones de Producción

Vercel es **serverless** y no permite ejecutar Ollama directamente. Necesitas un proveedor cloud de IA.

---

## ⭐ OPCIÓN 1: Together AI (Recomendada)

### ✅ Ventajas
- **8 mil millones de tokens gratis** al registrarse
- API compatible con OpenAI (fácil integración)
- Modelos open-source (Llama, Mistral, Qwen)
- Sin tarjeta de crédito requerida inicialmente
- Latencia baja (<2s respuesta)

### 💰 Costos
- **Gratis**: Primeros 8B tokens (~8,000 análisis completos)
- **Después**: $0.20 por millón de tokens
- **Estimación 1000 usuarios/mes**: $1-2/mes

### 📝 Paso a Paso

#### 1. Crear cuenta en Together AI

```bash
# Abrir navegador
open https://together.ai

# Registro:
# 1. Sign Up (Google/GitHub o email)
# 2. Verificar email
# 3. Acceder al Dashboard
```

#### 2. Obtener API Key

```
Dashboard → Settings → API Keys → Create new key

Copiar la key (empieza con: together_...)
```

#### 3. Configurar en Vercel

**Opción A: Desde la Web**

```
1. Ir a tu proyecto en Vercel
2. Settings → Environment Variables
3. Agregar 3 variables:

   Name: TOGETHER_API_KEY
   Value: together_xxxxxxxxxxxxxxxxx
   Environment: Production, Preview, Development
   
   Name: TOGETHER_BASE_URL
   Value: https://api.together.xyz/v1
   Environment: Production, Preview, Development
   
   Name: TOGETHER_MODEL
   Value: meta-llama/Meta-Llama-3.1-8B-Instruct-Turbo
   Environment: Production, Preview, Development

4. Save
```

**Opción B: Desde CLI**

```bash
# Instalar Vercel CLI si no lo tienes
npm i -g vercel

# Login
vercel login

# Agregar variables
vercel env add TOGETHER_API_KEY production
# Pegar tu key cuando te lo pida

vercel env add TOGETHER_BASE_URL production
# Pegar: https://api.together.xyz/v1

vercel env add TOGETHER_MODEL production
# Pegar: meta-llama/Meta-Llama-3.1-8B-Instruct-Turbo

# Repetir para preview y development si quieres
vercel env add TOGETHER_API_KEY preview
vercel env add TOGETHER_API_KEY development
```

#### 4. Deploy

```bash
# Commit y push (si usas GitHub integration)
git add .
git commit -m "Add AI integration with Together AI"
git push origin main

# O deploy manual
vercel --prod
```

#### 5. Verificar

```bash
# Probar endpoint
curl https://tu-app.vercel.app/api/ai/analyze \
  -X POST \
  -H "Content-Type: application/json" \
  -d '{
    "domain": "Governance",
    "responses": {"gov-1": true},
    "sector": "financiero"
  }'

# Debería retornar análisis de IA
```

### 🔧 Modelos Recomendados en Together AI

| Modelo | Parámetros | Velocidad | Calidad | Costo/1M tokens |
|--------|-----------|-----------|---------|-----------------|
| **Meta-Llama-3.1-8B-Instruct-Turbo** ⭐ | 8B | ⚡⚡⚡ | ⭐⭐⭐⭐⭐ | $0.20 |
| Meta-Llama-3.1-70B-Instruct-Turbo | 70B | ⚡⚡ | ⭐⭐⭐⭐⭐ | $0.88 |
| Qwen/Qwen2.5-7B-Instruct-Turbo | 7B | ⚡⚡⚡ | ⭐⭐⭐⭐⭐ | $0.20 |
| mistralai/Mistral-7B-Instruct-v0.3 | 7B | ⚡⚡⚡ | ⭐⭐⭐⭐ | $0.20 |

**Recomendación**: Meta-Llama-3.1-8B-Instruct-Turbo (balance perfecto)

---

## ⚡ OPCIÓN 2: Groq (Ultra rápido)

### ✅ Ventajas
- **Velocidad extrema**: <500ms respuesta (el más rápido)
- Gratis durante beta (30 requests/min)
- Excelente para producción
- API compatible con OpenAI

### 💰 Costos
- **Gratis**: Beta pública (límite 30 req/min)
- **Después beta**: Por anunciar (esperado ~$0.10/M tokens)

### 📝 Configuración

```bash
# 1. Registrarse
open https://console.groq.com

# 2. Crear API Key
# Console → API Keys → Create API Key

# 3. Variables en Vercel
vercel env add GROQ_API_KEY production
# Pegar: gsk_...

vercel env add GROQ_BASE_URL production
# Pegar: https://api.groq.com/openai/v1

vercel env add GROQ_MODEL production
# Pegar: llama-3.2-3b-preview
# O: mixtral-8x7b-32768 (más potente)

# 4. Deploy
vercel --prod
```

### 🔧 Modelos Disponibles en Groq

| Modelo | Parámetros | Tokens/seg | Contexto |
|--------|-----------|------------|----------|
| llama-3.2-3b-preview | 3B | ~800 | 8K |
| mixtral-8x7b-32768 | 47B | ~500 | 32K |
| llama-3.1-70b-versatile | 70B | ~300 | 128K |

---

## 🏢 OPCIÓN 3: OpenAI (Más cara pero estable)

### ✅ Ventajas
- Máxima calidad (GPT-4)
- Infraestructura probada
- Muy buenos en español

### 💰 Costos
- **GPT-3.5-turbo**: $0.50 / 1M tokens input, $1.50 / 1M output
- **GPT-4o-mini**: $0.15 / 1M tokens input, $0.60 / 1M output
- **GPT-4o**: $2.50 / 1M tokens input, $10 / 1M output

### 📝 Configuración

```bash
# 1. Crear cuenta
open https://platform.openai.com

# 2. Agregar método de pago
# Billing → Payment methods

# 3. Crear API Key
# API keys → Create new secret key

# 4. Variables en Vercel
vercel env add OPENAI_API_KEY production
# Pegar: sk-...

# No necesitas BASE_URL (usa default)

# 5. Deploy
vercel --prod
```

---

## 🔀 OPCIÓN 4: Multi-Provider con Fallback (Recomendada para Producción)

Usa **Together AI como principal** y **Groq como fallback** para máxima disponibilidad.

### Configuración en Vercel

```bash
# Together AI (principal)
vercel env add TOGETHER_API_KEY production
vercel env add TOGETHER_BASE_URL production
vercel env add TOGETHER_MODEL production

# Groq (fallback)
vercel env add GROQ_API_KEY production
vercel env add GROQ_BASE_URL production
vercel env add GROQ_MODEL production
```

El código ya implementado en `aiClient.ts` automáticamente:
1. Intentará Together AI primero
2. Si falla, usará Groq
3. Si ambos fallan, error controlado

### Ventajas
- ✅ 99.9% uptime (redundancia)
- ✅ Aprovechas tiers gratuitos de ambos
- ✅ Groq como backup ultra rápido
- ✅ Sin código adicional (ya implementado)

---

## 🧪 Testing en Producción

### 1. Verificar Variables de Entorno

```bash
# Ver variables configuradas
vercel env ls

# Debería mostrar:
# TOGETHER_API_KEY (Production, Preview, Development)
# TOGETHER_BASE_URL (Production, Preview, Development)
# TOGETHER_MODEL (Production, Preview, Development)
```

### 2. Test de API

```bash
# Reemplaza con tu dominio de Vercel
VERCEL_URL="https://tu-app.vercel.app"

curl -X POST "$VERCEL_URL/api/ai/analyze" \
  -H "Content-Type: application/json" \
  -d '{
    "domain": "Governance",
    "responses": {
      "gov-policy-1": true,
      "gov-roles-1": false,
      "gov-training-1": true
    },
    "sector": "financiero"
  }'

# Respuesta esperada (200 OK):
{
  "success": true,
  "analysis": "### Nivel de Madurez: 2 - Gestionado\n...",
  "metadata": {
    "provider": "together-ai",
    "model": "meta-llama/Meta-Llama-3.1-8B-Instruct-Turbo",
    "timestamp": "2025-12-06T..."
  }
}
```

### 3. Test desde UI

```
1. Abrir: https://tu-app.vercel.app/evaluacion-madurez
2. Seleccionar sector
3. Responder preguntas
4. Click "🤖 Análisis Inteligente"
5. Verificar que aparece respuesta
6. Revisar console del navegador (F12) para errores
```

### 4. Monitoreo de Logs

```bash
# Ver logs en tiempo real
vercel logs tu-app.vercel.app --follow

# O desde web
# Vercel Dashboard → tu proyecto → Logs
```

---

## 📊 Monitoreo y Optimización

### Configurar Límites de Uso (Together AI)

```
Together AI Dashboard → Usage → Set alerts

Configurar alerta cuando uses:
- 50% de tu tier gratuito (4B tokens)
- 80% de tu tier gratuito (6.4B tokens)
```

### Rate Limiting (Opcional pero Recomendado)

Si quieres limitar requests por usuario/IP:

#### Opción A: Upstash Redis (Gratis hasta 10K requests/día)

```bash
# 1. Registrarse
open https://upstash.com

# 2. Crear Redis database
# Console → Create Database → Global (multi-region)

# 3. Copiar credenciales
# Database → REST API → Copy .env

# 4. Instalar SDK
npm install @upstash/ratelimit @upstash/redis

# 5. Agregar variables en Vercel
vercel env add UPSTASH_REDIS_REST_URL production
vercel env add UPSTASH_REDIS_REST_TOKEN production
```

**Middleware de Rate Limiting** (`src/middleware.ts`):

```typescript
import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';
import { Ratelimit } from '@upstash/ratelimit';
import { Redis } from '@upstash/redis';

const redis = Redis.fromEnv();
const ratelimit = new Ratelimit({
  redis,
  limiter: Ratelimit.slidingWindow(10, '1 m'), // 10 req/min
});

export async function middleware(request: NextRequest) {
  if (request.nextUrl.pathname.startsWith('/api/ai')) {
    const ip = request.ip ?? 'anonymous';
    const { success, limit, reset, remaining } = await ratelimit.limit(ip);

    if (!success) {
      return NextResponse.json(
        { 
          error: 'Rate limit exceeded. Try again later.',
          reset: new Date(reset).toISOString()
        },
        { 
          status: 429,
          headers: {
            'X-RateLimit-Limit': limit.toString(),
            'X-RateLimit-Remaining': remaining.toString(),
            'X-RateLimit-Reset': reset.toString(),
          }
        }
      );
    }

    const response = NextResponse.next();
    response.headers.set('X-RateLimit-Limit', limit.toString());
    response.headers.set('X-RateLimit-Remaining', remaining.toString());
    return response;
  }

  return NextResponse.next();
}

export const config = {
  matcher: '/api/ai/:path*',
};
```

#### Opción B: Vercel Edge Config (Simple, incluido en plan)

```typescript
// src/app/api/ai/analyze/route.ts
import { NextRequest } from 'next/server';

const rateLimitMap = new Map<string, { count: number; resetTime: number }>();

function checkRateLimit(ip: string, limit: number = 10, window: number = 60000): boolean {
  const now = Date.now();
  const userLimit = rateLimitMap.get(ip);

  if (!userLimit || now > userLimit.resetTime) {
    rateLimitMap.set(ip, { count: 1, resetTime: now + window });
    return true;
  }

  if (userLimit.count >= limit) {
    return false;
  }

  userLimit.count++;
  return true;
}

export async function POST(request: NextRequest) {
  const ip = request.ip ?? 'anonymous';
  
  if (!checkRateLimit(ip, 10, 60000)) { // 10 req/min
    return NextResponse.json(
      { error: 'Too many requests. Please wait.' },
      { status: 429 }
    );
  }

  // ... resto del código
}
```

---

## 🔐 Seguridad en Producción

### 1. Proteger API Keys

```bash
# ✅ CORRECTO: Variables de entorno en Vercel
vercel env add TOGETHER_API_KEY production

# ❌ INCORRECTO: Nunca en código o .env.local commiteado
# const API_KEY = "together_abc123"; // ¡NO!
```

### 2. Validación de Inputs

El código ya incluye validación, pero verifica:

```typescript
// src/app/api/ai/analyze/route.ts
if (!domain || !responses || !sector) {
  return NextResponse.json(
    { error: 'Missing required parameters' },
    { status: 400 }
  );
}
```

### 3. CORS (si necesitas llamadas desde otros dominios)

```typescript
// src/app/api/ai/analyze/route.ts
export async function POST(request: NextRequest) {
  const response = NextResponse.json({ ... });
  
  // Solo si necesitas CORS
  response.headers.set('Access-Control-Allow-Origin', 'https://tu-dominio.com');
  response.headers.set('Access-Control-Allow-Methods', 'POST');
  
  return response;
}
```

---

## 📈 Escalado

### Estimación de Uso

```
1000 usuarios/mes × 5 análisis/usuario = 5000 requests/mes
5000 requests × ~1000 tokens/request = 5M tokens/mes

Costos:
- Together AI: Gratis (dentro de 8B tokens)
- Cuando se agote: 5M tokens × $0.20/1M = $1.00/mes
```

### Si creces mucho (>100K usuarios/mes)

1. **Caché de respuestas comunes**
   ```typescript
   // Guardar análisis repetidos en Redis/Vercel KV
   const cacheKey = `analysis:${domain}:${hash(responses)}`;
   const cached = await redis.get(cacheKey);
   if (cached) return cached;
   ```

2. **Modelo más pequeño para casos simples**
   ```typescript
   // Usar modelo 3B para evaluaciones básicas
   // Usar modelo 70B solo para análisis complejos
   const model = complexity === 'high' 
     ? 'llama-3.1-70b' 
     : 'llama-3.2-3b';
   ```

3. **Batch processing**
   ```typescript
   // Analizar múltiples dominios en una sola llamada
   const allDomains = await analyzeBatch([...domains]);
   ```

---

## ✅ Checklist de Despliegue

- [ ] **Cuenta creada** en Together AI o Groq
- [ ] **API Key obtenida**
- [ ] **Variables configuradas en Vercel**:
  - [ ] `TOGETHER_API_KEY` (o `GROQ_API_KEY`)
  - [ ] `TOGETHER_BASE_URL` (o `GROQ_BASE_URL`)
  - [ ] `TOGETHER_MODEL` (o `GROQ_MODEL`)
- [ ] **Código commiteado** a GitHub/GitLab
- [ ] **Deploy realizado**: `vercel --prod`
- [ ] **Test de API**: `curl https://tu-app.vercel.app/api/ai/analyze`
- [ ] **Test de UI**: Botón funciona en producción
- [ ] **Logs revisados**: Sin errores en Vercel Dashboard
- [ ] **Alertas configuradas**: Together AI usage alerts
- [ ] **(Opcional) Rate limiting** configurado
- [ ] **(Opcional) Monitoring** con Sentry/LogRocket

---

## 🆘 Troubleshooting Producción

### Error: "API key not configured"

```bash
# Verificar variables en Vercel
vercel env ls

# Si no están, agregarlas
vercel env add TOGETHER_API_KEY production
```

### Error: "Network timeout"

```typescript
// Aumentar timeout en fetch (aiClient.ts)
const response = await fetch(url, {
  method: 'POST',
  headers: { ... },
  body: JSON.stringify({ ... }),
  signal: AbortSignal.timeout(30000) // 30 segundos
});
```

### Error: "Rate limit exceeded" (429)

- Verifica límites en Together AI Dashboard
- Considera upgrade de plan
- Implementa rate limiting en tu lado

### Error 500 en producción pero funciona local

```bash
# Ver logs detallados
vercel logs tu-app.vercel.app --follow

# Verificar que variables existan en producción (no solo preview)
vercel env ls

# Redeploy forzado
vercel --prod --force
```

---

## 💡 Tips de Optimización

### 1. Edge Runtime (ya configurado)

```typescript
// src/app/api/ai/analyze/route.ts
export const runtime = 'edge'; // ✅ Más rápido que Node.js
```

### 2. Streaming (futuro)

```typescript
// Para respuestas palabra por palabra
export const runtime = 'edge';

export async function POST(request: NextRequest) {
  const stream = new ReadableStream({
    async start(controller) {
      // Enviar chunks conforme llegan
    }
  });
  
  return new Response(stream);
}
```

### 3. Caché de Respuestas

```typescript
// Usar Vercel KV para cachear análisis comunes
import { kv } from '@vercel/kv';

const cacheKey = `ai:${domain}:${hash(responses)}`;
const cached = await kv.get(cacheKey);

if (cached) return cached;

const result = await analyzeSSLDCResponses(...);
await kv.set(cacheKey, result, { ex: 3600 }); // 1 hora
```

---

## 📚 Recursos

- **Together AI Docs**: https://docs.together.ai
- **Groq Docs**: https://console.groq.com/docs
- **Vercel Env Vars**: https://vercel.com/docs/projects/environment-variables
- **Vercel Edge Runtime**: https://vercel.com/docs/functions/edge-functions
- **Upstash Redis**: https://docs.upstash.com/redis

---

## 🎯 Resumen: Configuración Recomendada

```bash
# 1. Registrarse en Together AI (https://together.ai)
# 2. Obtener API Key
# 3. Configurar en Vercel:

vercel env add TOGETHER_API_KEY production
# Valor: together_xxxxx

vercel env add TOGETHER_BASE_URL production
# Valor: https://api.together.xyz/v1

vercel env add TOGETHER_MODEL production
# Valor: meta-llama/Meta-Llama-3.1-8B-Instruct-Turbo

# 4. Deploy
git push origin main
# O: vercel --prod

# 5. Probar
curl https://tu-app.vercel.app/api/ai/analyze -X POST \
  -H "Content-Type: application/json" \
  -d '{"domain":"Governance","responses":{},"sector":"general"}'
```

**Costo estimado**: $0/mes (dentro de tier gratuito de 8B tokens)

**¡Listo para producción!** 🚀
