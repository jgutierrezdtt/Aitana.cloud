# 🚀 Guía Rápida: Integración de IA

## ⚡ Inicio Rápido (5 minutos)

### 1. Desarrollo Local con Ollama (Recomendado)

```bash
# 1. Instalar Ollama
brew install ollama

# 2. Iniciar servidor en segundo plano
ollama serve &

# 3. Descargar modelo (una sola vez)
ollama pull qwen2.5:7b  # 4GB - Excelente multilingüe

# 4. Verificar instalación
ollama list
# Deberías ver: qwen2.5:7b

# 5. Iniciar Next.js
npm run dev
```

**✅ Listo!** Abre http://localhost:3000/evaluacion-madurez

---

### 2. Producción en Vercel con Together AI

```bash
# 1. Registrarse en Together AI (Gratis)
# https://together.ai

# 2. Obtener API Key
# Dashboard → API Keys → Create new key

# 3. Configurar localmente
echo 'TOGETHER_API_KEY=tu_key_aqui' >> .env.local
echo 'TOGETHER_BASE_URL=https://api.together.xyz/v1' >> .env.local
echo 'TOGETHER_MODEL=meta-llama/Meta-Llama-3.1-8B-Instruct-Turbo' >> .env.local

# 4. Probar localmente
npm run dev

# 5. Deploy a Vercel
vercel env add TOGETHER_API_KEY
vercel env add TOGETHER_BASE_URL
vercel env add TOGETHER_MODEL
vercel --prod
```

---

## 🧪 Probar la Integración

1. **Abrir evaluador**: http://localhost:3000/evaluacion-madurez
2. **Seleccionar sector**: Financiero, Salud, Industrial, etc.
3. **Responder preguntas**: Al menos 5-10 preguntas de un dominio
4. **Clic en "🤖 Análisis Inteligente"**
5. **Ver insights**: La IA analizará tus respuestas y generará recomendaciones

---

## 🔍 Verificar que Funciona

### Check Ollama Local

```bash
# Terminal 1: Servidor corriendo
ollama serve
# Debería decir: "Listening on 127.0.0.1:11434"

# Terminal 2: Probar manualmente
ollama run qwen2.5:7b "Resume en 3 puntos qué es SSDLC"

# Terminal 3: Next.js
npm run dev
```

### Check API Endpoint

```bash
# Probar endpoint directamente
curl -X POST http://localhost:3000/api/ai/analyze \
  -H "Content-Type: application/json" \
  -d '{
    "domain": "Governance",
    "responses": {"gov-1": true, "gov-2": false},
    "sector": "financiero"
  }'
```

**Respuesta esperada:**
```json
{
  "success": true,
  "analysis": "### Nivel de Madurez: 2 - Gestionado\n...",
  "metadata": {
    "provider": "ollama",
    "model": "qwen2.5:7b",
    "timestamp": "2025-12-06T..."
  }
}
```

---

## 🐛 Troubleshooting

### Error: "Cannot connect to Ollama"

```bash
# Verificar que Ollama está corriendo
ps aux | grep ollama

# Si no está, iniciarlo
ollama serve

# Verificar puerto
lsof -i :11434
```

### Error: "Model not found"

```bash
# Listar modelos instalados
ollama list

# Si está vacío, descargar
ollama pull qwen2.5:7b
```

### Error: "API key not configured"

```bash
# Verificar variables de entorno
cat .env.local | grep -E "OLLAMA|TOGETHER|GROQ"

# Asegurarse que Next.js las carga
npm run dev
# Deberías ver: "✓ Ready in 2.5s"
```

### Error: CORS en producción

En Vercel, las variables de entorno deben configurarse en:
1. Dashboard de Vercel
2. Project Settings → Environment Variables
3. Add: TOGETHER_API_KEY, TOGETHER_BASE_URL, TOGETHER_MODEL
4. Redeploy

---

## 📊 Modelos Recomendados

### Para Desarrollo Local (Ollama)

| Modelo | Tamaño | Velocidad | Calidad | Uso |
|--------|--------|-----------|---------|-----|
| **qwen2.5:7b** ⭐ | 4GB | ⚡⚡⚡ | ⭐⭐⭐⭐⭐ | Multilingüe excelente |
| llama3.2:3b | 2GB | ⚡⚡⚡⚡ | ⭐⭐⭐⭐ | Ligero, rápido |
| mistral:7b | 4GB | ⚡⚡⚡ | ⭐⭐⭐⭐ | Bueno en español |
| codellama:7b | 4GB | ⚡⚡⚡ | ⭐⭐⭐⭐ | Análisis de código |

```bash
# Descargar varios para comparar
ollama pull qwen2.5:7b
ollama pull llama3.2:3b
ollama pull mistral:7b

# Cambiar modelo activo en .env.local
OLLAMA_MODEL=mistral:7b
```

### Para Producción (Cloud)

| Proveedor | Modelo | Gratis | Velocidad | Calidad |
|-----------|--------|--------|-----------|---------|
| **Together AI** ⭐ | Llama-3.1-8B | 8B tokens | ⚡⚡⚡ | ⭐⭐⭐⭐⭐ |
| Groq | llama-3.2-3b | 30 req/min | ⚡⚡⚡⚡⚡ | ⭐⭐⭐⭐ |
| Groq | mixtral-8x7b | 30 req/min | ⚡⚡⚡⚡ | ⭐⭐⭐⭐⭐ |

---

## 🎯 Casos de Uso Implementados

### 1. Análisis de Respuestas
- **Ubicación**: Tarjeta de cada dominio en ResultsDashboard
- **Botón**: "🤖 Análisis Inteligente"
- **Output**: 
  - Nivel de madurez actual
  - Top 3 gaps críticos
  - 3 recomendaciones priorizadas con plazos

### 2. API Disponibles

```typescript
// Análisis de evaluación
POST /api/ai/analyze
{
  "domain": "Governance",
  "responses": { "gov-1": true, ... },
  "sector": "financiero"
}

// Chat de consultoría
POST /api/ai/chat
{
  "question": "¿Cómo implementar DORA?",
  "context": "Banco mediano en España"
}
```

### 3. Hooks React

```typescript
import { useAIAnalysis, useAIChat } from '@/hooks/useAIAnalysis';

// En tu componente
const { analyzeResponses, loading, error } = useAIAnalysis();
const insights = await analyzeResponses(domain, responses, sector);
```

---

## 💰 Costos Estimados

### Desarrollo
- **Ollama Local**: $0 (gratis ilimitado)
- **Electricidad**: ~$0.01/hora en Mac M1/M2

### Producción (1000 usuarios/mes)

Asumiendo 5 análisis por usuario = 5000 requests/mes

| Proveedor | Tokens/req | Costo/mes | Gratis hasta |
|-----------|------------|-----------|--------------|
| **Together AI** | ~1000 | **$0** | 8B tokens (~8000 users) |
| **Groq** | ~1000 | **$0** | En beta (30 req/min) |
| OpenAI GPT-3.5 | ~1000 | $7.50 | Sin tier gratis |
| OpenAI GPT-4 | ~1000 | $75 | Sin tier gratis |

**Recomendación**: Together AI (gratis generoso) + Groq (fallback ultra rápido)

---

## 🔐 Seguridad

### Rate Limiting (Opcional pero recomendado)

```bash
# Instalar Upstash Redis
npm install @upstash/ratelimit @upstash/redis

# Registrarse en Upstash (gratis)
# https://upstash.com

# Agregar variables
echo 'UPSTASH_REDIS_REST_URL=https://...' >> .env.local
echo 'UPSTASH_REDIS_REST_TOKEN=...' >> .env.local
```

**Límites sugeridos:**
- Desarrollo: Sin límite
- Producción: 10 requests/min por IP
- Usuarios registrados: 30 requests/min

---

## 📚 Recursos

- **Ollama Docs**: https://ollama.com/docs
- **Together AI**: https://together.ai/docs
- **Groq**: https://console.groq.com/docs
- **OpenAI SDK**: https://github.com/openai/openai-node
- **Documentación completa**: `docs/AI_INTEGRATION.md`

---

## ✅ Checklist de Implementación

- [x] Archivos creados
  - [x] `/src/lib/ai/aiClient.ts`
  - [x] `/src/app/api/ai/analyze/route.ts`
  - [x] `/src/app/api/ai/chat/route.ts`
  - [x] `/src/hooks/useAIAnalysis.ts`
  - [x] `/src/components/evaluacion/AIInsightsButton.tsx`
  - [x] `/docs/AI_INTEGRATION.md`
  - [x] `/docs/AI_QUICKSTART.md`

- [ ] Configuración local
  - [ ] Ollama instalado (`brew install ollama`)
  - [ ] Modelo descargado (`ollama pull qwen2.5:7b`)
  - [ ] Variables en `.env.local`
  - [ ] Next.js corriendo (`npm run dev`)

- [ ] Pruebas
  - [ ] Botón "🤖 Análisis Inteligente" visible
  - [ ] Click genera respuesta de IA
  - [ ] Respuesta en español
  - [ ] Sin errores en consola

- [ ] Producción (opcional)
  - [ ] Cuenta en Together AI
  - [ ] API Key obtenida
  - [ ] Variables en Vercel
  - [ ] Deploy exitoso

---

**¿Problemas?** Revisa `docs/AI_INTEGRATION.md` para troubleshooting detallado.
