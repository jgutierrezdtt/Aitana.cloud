# 🤖 Integración de IA en Aitana.cloud

## 📋 Resumen

Se ha integrado **IA open-source** en el evaluador de madurez SSDLC con soporte para:

- ✅ **Ollama local** (desarrollo, gratis, privado)
- ✅ **Together AI** (producción, 8B tokens gratis)
- ✅ **Groq** (alternativa ultra rápida, gratis en beta)
- ✅ **OpenAI** (fallback compatible)

---

## 🎯 Funcionalidades Implementadas

### 1. Análisis Inteligente de Respuestas
**Ubicación**: Tarjeta de cada dominio en `/evaluacion-madurez`

**Qué hace**:
- Analiza las respuestas del usuario en cada dominio
- Evalúa el nivel de madurez (1-5)
- Identifica los 3 gaps críticos
- Genera 3 recomendaciones priorizadas con plazos

**Cómo funciona**:
1. Usuario responde preguntas de un dominio
2. Click en botón "🤖 Análisis Inteligente"
3. La IA analiza respuestas considerando el sector
4. Muestra insights personalizados

### 2. API Endpoints

```bash
# Análisis de evaluación SSDLC
POST /api/ai/analyze
Content-Type: application/json

{
  "domain": "Governance",
  "responses": {
    "gov-1": true,
    "gov-2": false,
    "gov-3": true
  },
  "sector": "financiero"
}

# Respuesta
{
  "success": true,
  "analysis": "### Nivel de Madurez: 2 - Gestionado\n...",
  "metadata": {
    "provider": "ollama",
    "model": "qwen2.5:7b",
    "timestamp": "2025-12-06T10:30:00.000Z"
  }
}
```

```bash
# Chat de consultoría normativa
POST /api/ai/chat
Content-Type: application/json

{
  "question": "¿Cómo implementar controles DORA en un banco?",
  "context": "Banco mediano, 500 empleados, España"
}
```

---

## 🚀 Instalación

### Opción A: Desarrollo Local (Ollama)

```bash
# 1. Instalar Ollama
brew install ollama

# 2. Iniciar servidor
ollama serve

# 3. En otra terminal, descargar modelo
ollama pull qwen2.5:7b  # 4GB, recomendado

# 4. Iniciar Next.js
npm run dev

# 5. Probar en http://localhost:3000/evaluacion-madurez
```

### Opción B: Producción (Together AI)

```bash
# 1. Registrarse en https://together.ai (gratis)
# 2. Obtener API Key en Dashboard → API Keys
# 3. Configurar variables de entorno

# Local (.env.local)
echo 'TOGETHER_API_KEY=tu_key_aqui' >> .env.local
echo 'TOGETHER_BASE_URL=https://api.together.xyz/v1' >> .env.local
echo 'TOGETHER_MODEL=meta-llama/Meta-Llama-3.1-8B-Instruct-Turbo' >> .env.local

# Vercel (producción)
vercel env add TOGETHER_API_KEY production
vercel env add TOGETHER_BASE_URL production
vercel env add TOGETHER_MODEL production
vercel --prod
```

---

## 📁 Archivos Creados

### Core

1. **`/src/lib/ai/aiClient.ts`** (280 líneas)
   - Cliente universal de IA
   - `queryAI()`: Función principal
   - `analyzeSSLDCResponses()`: Análisis especializado
   - `queryNormativaAssistant()`: Chatbot de consultoría
   - `generateActionPlan()`: Generador de roadmaps
   - Auto-fallback: Ollama → Together AI → Groq → OpenAI

2. **`/src/app/api/ai/analyze/route.ts`** (40 líneas)
   - API endpoint para análisis de evaluaciones
   - Edge runtime (rápido en Vercel)
   - Validación de inputs
   - Error handling completo

3. **`/src/app/api/ai/chat/route.ts`** (35 líneas)
   - API endpoint para chat de consultoría
   - Compatible con streaming futuro
   - Rate limiting ready

### UI Components

4. **`/src/components/evaluacion/AIInsightsButton.tsx`** (100 líneas)
   - Botón con estados (loading, error, success)
   - Expansión/colapso de insights
   - Accessibilidad completa (ARIA, keyboard)
   - Iconos animados (Sparkles, Loader2)

5. **`/src/hooks/useAIAnalysis.ts`** (60 líneas)
   - `useAIAnalysis()`: Hook para análisis
   - `useAIChat()`: Hook para chatbot
   - Manejo de estados (loading, error)
   - TypeScript estricto

### Documentación

6. **`/docs/AI_INTEGRATION.md`** (400+ líneas)
   - Guía completa de integración
   - Ejemplos de código
   - Comparativa de proveedores
   - Troubleshooting detallado
   - Seguridad y rate limiting

7. **`/docs/AI_QUICKSTART.md`** (300+ líneas)
   - Inicio rápido (5 minutos)
   - Comandos copy-paste
   - Verificación paso a paso
   - Checklist de implementación

8. **`/scripts/setup-ai.sh`** (80 líneas)
   - Script de instalación automática
   - Configura variables de entorno
   - Instrucciones interactivas
   - Compatible con macOS/Linux

### Actualizaciones

9. **`/src/components/evaluacion/ResultsDashboard.tsx`** (modificado)
   - Importa `AIInsightsButton`
   - Integrado en cada tarjeta de dominio
   - Pasa contexto completo al análisis

---

## 🔧 Configuración

### Variables de Entorno

**Desarrollo Local (`.env.local`)**

```env
# Ollama Local (Recomendado para desarrollo)
OLLAMA_BASE_URL=http://localhost:11434
OLLAMA_MODEL=qwen2.5:7b

# Producción - Together AI (8B tokens gratis)
TOGETHER_API_KEY=your_together_key
TOGETHER_BASE_URL=https://api.together.xyz/v1
TOGETHER_MODEL=meta-llama/Meta-Llama-3.1-8B-Instruct-Turbo

# Alternativa - Groq (ultra rápido)
GROQ_API_KEY=your_groq_key
GROQ_BASE_URL=https://api.groq.com/openai/v1
GROQ_MODEL=llama-3.2-3b-preview

# Fallback - OpenAI (requiere pago)
OPENAI_API_KEY=your_openai_key
```

**Vercel (Producción)**

En Dashboard → Settings → Environment Variables:
- `TOGETHER_API_KEY`
- `TOGETHER_BASE_URL`
- `TOGETHER_MODEL`

---

## 🧪 Testing

### Test Manual

```bash
# 1. Abrir evaluador
open http://localhost:3000/evaluacion-madurez

# 2. Seleccionar sector (ej: Financiero)
# 3. Responder 5-10 preguntas del dominio Governance
# 4. Click en "🤖 Análisis Inteligente"
# 5. Verificar respuesta de IA en español
```

### Test con cURL

```bash
# Probar endpoint directamente
curl -X POST http://localhost:3000/api/ai/analyze \
  -H "Content-Type: application/json" \
  -d '{
    "domain": "Governance",
    "responses": {
      "gov-policy-1": true,
      "gov-roles-1": false,
      "gov-training-1": true
    },
    "sector": "financiero"
  }' | jq

# Respuesta esperada (200 OK)
{
  "success": true,
  "analysis": "### Nivel de Madurez: 2 - Gestionado\n\n[Justificación del nivel]\n\n### Gaps Críticos...",
  "metadata": {
    "provider": "ollama",
    "model": "qwen2.5:7b",
    "timestamp": "2025-12-06T12:34:56.789Z"
  }
}
```

### Test de Fallback

```bash
# Detener Ollama
pkill ollama

# Reiniciar Next.js (debería usar Together AI)
npm run dev

# Probar endpoint - debería funcionar con cloud provider
curl -X POST http://localhost:3000/api/ai/analyze ...
```

---

## 📊 Arquitectura

```
┌─────────────────────────────────────────────────────────┐
│                  Next.js Frontend                        │
│                                                           │
│  ┌────────────────────────────────────────────────┐     │
│  │ ResultsDashboard.tsx                           │     │
│  │   └─> AIInsightsButton.tsx                     │     │
│  │        └─> useAIAnalysis() hook                │     │
│  └────────────────────────────────────────────────┘     │
│                          │                               │
│                          ▼                               │
│  ┌────────────────────────────────────────────────┐     │
│  │ POST /api/ai/analyze                           │     │
│  │  - Validación                                  │     │
│  │  - Edge runtime                                │     │
│  │  - Error handling                              │     │
│  └────────────────────────────────────────────────┘     │
│                          │                               │
└──────────────────────────┼───────────────────────────────┘
                           ▼
              ┌─────────────────────────┐
              │ /src/lib/ai/aiClient.ts │
              │  - queryAI()            │
              │  - Smart fallback       │
              └─────────────────────────┘
                           │
           ┌───────────────┼───────────────┐
           ▼               ▼               ▼
    ┌──────────┐   ┌─────────────┐  ┌──────────┐
    │ Ollama   │   │ Together AI │  │   Groq   │
    │  Local   │   │   Cloud     │  │  Cloud   │
    │  :11434  │   │  REST API   │  │ REST API │
    └──────────┘   └─────────────┘  └──────────┘
       Dev            Prod             Fallback
```

---

## 💰 Costos

### Gratis (Tier Gratuito)

| Proveedor | Límite Gratis | Renovable |
|-----------|---------------|-----------|
| **Ollama Local** | Ilimitado | ✅ Siempre |
| **Together AI** | 8B tokens | ❌ Una vez |
| **Groq** | 30 req/min | ✅ En beta |

### De Pago (Cuando se agote gratis)

| Proveedor | Costo/1M tokens | Velocidad |
|-----------|-----------------|-----------|
| Together AI | $0.20 | ⚡⚡⚡ |
| Groq | TBD (en beta) | ⚡⚡⚡⚡⚡ |
| OpenAI GPT-3.5 | $0.50 | ⚡⚡⚡ |
| OpenAI GPT-4 | $15.00 | ⚡⚡ |

**Estimación para 1000 usuarios/mes**:
- 5 análisis por usuario = 5000 requests
- ~1000 tokens por análisis = 5M tokens
- Costo con Together AI = $1.00/mes
- Costo con Ollama local = $0

---

## 🔒 Seguridad

### Implementado

- ✅ Validación de inputs en API
- ✅ Error handling sin exponer detalles
- ✅ Edge runtime (aislamiento)
- ✅ Variables de entorno seguras
- ✅ CORS configurado en Vercel

### Recomendado Agregar

```bash
# Rate limiting con Upstash
npm install @upstash/ratelimit @upstash/redis

# Registrarse: https://upstash.com (gratis)
# Agregar a middleware.ts
```

---

## 🐛 Troubleshooting

### "Cannot connect to Ollama"

```bash
# Verificar que está corriendo
ps aux | grep ollama

# Si no, iniciarlo
ollama serve

# Verificar puerto
lsof -i :11434
# Debería mostrar: ollama
```

### "Model not found"

```bash
# Listar modelos instalados
ollama list

# Descargar si falta
ollama pull qwen2.5:7b
```

### "API key not configured"

```bash
# Verificar .env.local
cat .env.local | grep -E "TOGETHER|GROQ|OPENAI"

# Reiniciar Next.js para cargar cambios
pkill -f "next dev"
npm run dev
```

### Respuestas en inglés (esperabas español)

El prompt ya incluye "Responde en español". Si sigue en inglés:
1. Modelo incorrecto (usar qwen2.5:7b o mistral:7b)
2. Temperatura muy alta (verificar en aiClient.ts)
3. Contexto en inglés (revisar inputs)

---

## 📚 Referencias

- **Ollama**: https://ollama.com
- **Together AI**: https://together.ai
- **Groq**: https://console.groq.com
- **OpenAI SDK**: https://github.com/openai/openai-node
- **Vercel Edge Runtime**: https://vercel.com/docs/functions/edge-functions

---

## ✅ Checklist de Implementación

- [x] Código creado
  - [x] Cliente de IA (`aiClient.ts`)
  - [x] API endpoints (`/api/ai/*`)
  - [x] Hooks React (`useAIAnalysis`)
  - [x] UI Component (`AIInsightsButton`)
  - [x] Integración en dashboard

- [ ] Configuración local
  - [ ] Ollama instalado
  - [ ] Modelo descargado
  - [ ] Variables en `.env.local`
  - [ ] Next.js corriendo

- [ ] Testing
  - [ ] Botón visible en UI
  - [ ] Click funciona sin errores
  - [ ] Respuesta en español
  - [ ] Consola sin errores

- [ ] Producción (opcional)
  - [ ] Cuenta Together AI
  - [ ] API Key configurada
  - [ ] Variables en Vercel
  - [ ] Deploy exitoso

---

## 🎯 Próximos Pasos

### Mejoras Futuras

1. **Streaming de respuestas**
   ```typescript
   // En lugar de esperar respuesta completa
   // mostrar palabra por palabra
   const stream = await queryAI(prompt, { stream: true });
   ```

2. **Chatbot conversacional**
   ```typescript
   // Chat con historial de mensajes
   const messages = [
     { role: 'system', content: 'Eres un consultor...' },
     { role: 'user', content: 'Pregunta 1' },
     { role: 'assistant', content: 'Respuesta 1' },
     { role: 'user', content: 'Pregunta 2' }
   ];
   ```

3. **Análisis de documentos**
   ```typescript
   // Upload PDF de política de seguridad
   // IA analiza cumplimiento contra normativas
   ```

4. **Generación de informes**
   ```typescript
   // Export PDF con insights de IA
   // Formato ejecutivo + técnico
   ```

5. **Benchmarking con IA**
   ```typescript
   // Comparar tu evaluación con industria
   // Usando datos agregados anónimos
   ```

---

**¿Problemas?** Revisa `/docs/AI_INTEGRATION.md` o `/docs/AI_QUICKSTART.md`
