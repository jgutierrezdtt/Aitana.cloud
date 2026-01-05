#!/bin/bash

echo "🤖 Configuración de Integración de IA en Aitana.cloud"
echo "=========================================================="
echo ""

# Colores
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# 1. Instalar dependencias necesarias
echo -e "${BLUE}📦 Instalando dependencias de IA...${NC}"
npm install lucide-react

echo ""
echo -e "${GREEN}✅ Dependencias instaladas${NC}"
echo ""

# 2. Configurar variables de entorno
echo -e "${BLUE}⚙️  Configurando variables de entorno...${NC}"
echo ""

if [ ! -f .env.local ]; then
    echo "Creando .env.local..."
    touch .env.local
fi

# Verificar si ya existen las variables
if grep -q "OLLAMA_BASE_URL" .env.local; then
    echo -e "${YELLOW}⚠️  Variables de IA ya configuradas en .env.local${NC}"
else
    echo "" >> .env.local
    echo "# === AI Configuration ===" >> .env.local
    echo "# Local development (Ollama)" >> .env.local
    echo "OLLAMA_BASE_URL=http://localhost:11434" >> .env.local
    echo "OLLAMA_MODEL=qwen2.5:7b" >> .env.local
    echo "" >> .env.local
    echo "# Production (Together AI - Gratis para empezar)" >> .env.local
    echo "# Registro: https://together.ai" >> .env.local
    echo "# TOGETHER_API_KEY=your_key_here" >> .env.local
    echo "# TOGETHER_BASE_URL=https://api.together.xyz/v1" >> .env.local
    echo "# TOGETHER_MODEL=meta-llama/Meta-Llama-3.1-8B-Instruct-Turbo" >> .env.local
    echo "" >> .env.local
    echo "# Alternative: Groq (ultra rápido, gratis)" >> .env.local
    echo "# Registro: https://console.groq.com" >> .env.local
    echo "# GROQ_API_KEY=your_groq_key" >> .env.local
    echo "# GROQ_BASE_URL=https://api.groq.com/openai/v1" >> .env.local
    echo "# GROQ_MODEL=llama-3.2-3b-preview" >> .env.local
    
    echo -e "${GREEN}✅ Variables agregadas a .env.local${NC}"
fi

echo ""
echo -e "${BLUE}🎯 Próximos pasos:${NC}"
echo ""
echo "=== OPCIÓN 1: Desarrollo Local con Ollama (Gratis) ==="
echo ""
echo "1. Instalar Ollama:"
echo "   ${GREEN}brew install ollama${NC}"
echo ""
echo "2. Iniciar servidor Ollama:"
echo "   ${GREEN}ollama serve${NC}"
echo ""
echo "3. En otra terminal, descargar modelo recomendado:"
echo "   ${GREEN}ollama pull qwen2.5:7b${NC}  # 4GB, excelente multilingüe"
echo "   Alternativas:"
echo "   - ollama pull llama3.2:3b    # 2GB, más ligero"
echo "   - ollama pull mistral:7b     # 4GB, muy bueno"
echo ""
echo "4. Verificar que funciona:"
echo "   ${GREEN}ollama list${NC}"
echo "   ${GREEN}ollama run qwen2.5:7b \"Hola, ¿cómo estás?\"${NC}"
echo ""
echo "5. Reiniciar Next.js:"
echo "   ${GREEN}npm run dev${NC}"
echo ""
echo "=== OPCIÓN 2: Producción con Together AI (Gratis para empezar) ==="
echo ""
echo "1. Crear cuenta en Together AI:"
echo "   ${BLUE}https://together.ai${NC}"
echo "   (8B tokens gratis al registrarse)"
echo ""
echo "2. Obtener API Key:"
echo "   - Dashboard → API Keys → Create new key"
echo ""
echo "3. Configurar en .env.local:"
echo "   ${GREEN}TOGETHER_API_KEY=tu_api_key_aqui${NC}"
echo "   ${GREEN}TOGETHER_BASE_URL=https://api.together.xyz/v1${NC}"
echo "   ${GREEN}TOGETHER_MODEL=meta-llama/Meta-Llama-3.1-8B-Instruct-Turbo${NC}"
echo ""
echo "4. En Vercel, agregar variables de entorno:"
echo "   - Settings → Environment Variables → Add"
echo "   - TOGETHER_API_KEY"
echo "   - TOGETHER_BASE_URL"
echo "   - TOGETHER_MODEL"
echo ""
echo "=== OPCIÓN 3: Groq (Alternativa ultra rápida, gratis) ==="
echo ""
echo "1. Registro: ${BLUE}https://console.groq.com${NC}"
echo "2. Obtener API Key"
echo "3. Configurar:"
echo "   ${GREEN}GROQ_API_KEY=tu_groq_key${NC}"
echo "   ${GREEN}GROQ_BASE_URL=https://api.groq.com/openai/v1${NC}"
echo "   ${GREEN}GROQ_MODEL=llama-3.2-3b-preview${NC}"
echo ""
echo "=========================================================="
echo -e "${GREEN}🚀 Configuración completa!${NC}"
echo ""
echo "📖 Documentación completa: docs/AI_INTEGRATION.md"
echo ""
echo "🧪 Prueba la integración:"
echo "   1. Abre: http://localhost:3000/evaluacion-madurez"
echo "   2. Responde algunas preguntas"
echo "   3. Haz clic en '🤖 Análisis Inteligente'"
echo ""
