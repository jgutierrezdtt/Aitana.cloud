#!/bin/bash

# Script de Deploy a Vercel con Together AI
# Uso: ./scripts/deploy-vercel.sh

set -e  # Exit on error

echo "🚀 Deploy de Aitana.cloud a Vercel con IA"
echo "=========================================="
echo ""

# Colores
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Verificar que estamos en el directorio correcto
if [ ! -f "package.json" ]; then
    echo -e "${RED}❌ Error: Ejecuta este script desde la raíz del proyecto${NC}"
    exit 1
fi

# Verificar que Vercel CLI está instalado
if ! command -v vercel &> /dev/null; then
    echo -e "${YELLOW}⚠️  Vercel CLI no encontrado. Instalando...${NC}"
    npm install -g vercel
fi

echo -e "${BLUE}📦 Verificando configuración...${NC}"
echo ""

# Preguntar si ya tiene cuenta en Together AI
echo -e "${YELLOW}¿Ya tienes cuenta en Together AI?${NC}"
echo "1) Sí, tengo mi API key"
echo "2) No, necesito crear una cuenta"
read -p "Opción [1/2]: " HAS_ACCOUNT

if [ "$HAS_ACCOUNT" == "2" ]; then
    echo ""
    echo -e "${BLUE}📝 Pasos para crear cuenta en Together AI:${NC}"
    echo ""
    echo "1. Abre: https://together.ai"
    echo "2. Click en 'Sign Up'"
    echo "3. Regístrate con Google/GitHub o email"
    echo "4. Verifica tu email"
    echo "5. Dashboard → Settings → API Keys"
    echo "6. Click 'Create new key'"
    echo "7. Copia la key (empieza con 'together_')"
    echo ""
    echo "Recibes 8 mil millones de tokens GRATIS 🎉"
    echo ""
    read -p "Presiona Enter cuando tengas tu API key..."
fi

echo ""
read -p "Ingresa tu Together AI API Key: " TOGETHER_API_KEY

if [ -z "$TOGETHER_API_KEY" ]; then
    echo -e "${RED}❌ API Key no puede estar vacía${NC}"
    exit 1
fi

# Validar formato de API key
if [[ ! "$TOGETHER_API_KEY" =~ ^together_ ]]; then
    echo -e "${YELLOW}⚠️  La API key no tiene el formato esperado (debería empezar con 'together_')${NC}"
    read -p "¿Continuar de todas formas? [y/N]: " CONTINUE
    if [ "$CONTINUE" != "y" ] && [ "$CONTINUE" != "Y" ]; then
        exit 1
    fi
fi

echo ""
echo -e "${BLUE}🔧 Configurando variables de entorno en Vercel...${NC}"

# Login a Vercel
echo ""
echo "Autenticándote en Vercel..."
vercel login

echo ""
echo "Seleccionando proyecto..."
vercel link

echo ""
echo "Agregando variables de entorno..."

# Together AI - Principal
vercel env add TOGETHER_API_KEY production << EOF
$TOGETHER_API_KEY
EOF

vercel env add TOGETHER_BASE_URL production << EOF
https://api.together.xyz/v1
EOF

vercel env add TOGETHER_MODEL production << EOF
meta-llama/Meta-Llama-3.1-8B-Instruct-Turbo
EOF

echo ""
echo -e "${GREEN}✅ Variables configuradas en producción${NC}"

# Preguntar si quiere configurar para preview/development
echo ""
read -p "¿Configurar también para Preview y Development? [Y/n]: " CONFIGURE_ALL

if [ "$CONFIGURE_ALL" != "n" ] && [ "$CONFIGURE_ALL" != "N" ]; then
    echo "Configurando preview..."
    vercel env add TOGETHER_API_KEY preview << EOF
$TOGETHER_API_KEY
EOF

    vercel env add TOGETHER_BASE_URL preview << EOF
https://api.together.xyz/v1
EOF

    vercel env add TOGETHER_MODEL preview << EOF
meta-llama/Meta-Llama-3.1-8B-Instruct-Turbo
EOF

    echo "Configurando development..."
    vercel env add TOGETHER_API_KEY development << EOF
$TOGETHER_API_KEY
EOF

    vercel env add TOGETHER_BASE_URL development << EOF
https://api.together.xyz/v1
EOF

    vercel env add TOGETHER_MODEL development << EOF
meta-llama/Meta-Llama-3.1-8B-Instruct-Turbo
EOF

    echo -e "${GREEN}✅ Variables configuradas en todos los entornos${NC}"
fi

echo ""
echo -e "${BLUE}📋 Resumen de configuración:${NC}"
vercel env ls

echo ""
echo -e "${BLUE}🚀 Desplegando a producción...${NC}"
echo ""

# Deploy a producción
vercel --prod

echo ""
echo -e "${GREEN}✅ Deploy completado!${NC}"
echo ""

# Obtener URL de producción
PROD_URL=$(vercel ls --prod | grep -o 'https://[^ ]*' | head -1)

if [ -n "$PROD_URL" ]; then
    echo -e "${GREEN}🌍 Tu aplicación está en: ${PROD_URL}${NC}"
    echo ""
    
    echo -e "${BLUE}🧪 Probando la integración de IA...${NC}"
    echo ""
    
    # Test del API endpoint
    TEST_RESPONSE=$(curl -s -X POST "$PROD_URL/api/ai/analyze" \
        -H "Content-Type: application/json" \
        -d '{
            "domain": "Governance",
            "responses": {"test": true},
            "sector": "general"
        }')
    
    if echo "$TEST_RESPONSE" | grep -q '"success":true'; then
        echo -e "${GREEN}✅ API de IA funcionando correctamente!${NC}"
        echo ""
        echo "Respuesta de prueba:"
        echo "$TEST_RESPONSE" | python3 -m json.tool 2>/dev/null || echo "$TEST_RESPONSE"
    else
        echo -e "${YELLOW}⚠️  El endpoint responde pero hubo un problema:${NC}"
        echo "$TEST_RESPONSE"
        echo ""
        echo "Verifica los logs con: vercel logs"
    fi
else
    echo -e "${YELLOW}⚠️  No se pudo obtener la URL de producción${NC}"
    echo "Ejecuta 'vercel ls --prod' para verla"
fi

echo ""
echo -e "${BLUE}📚 Próximos pasos:${NC}"
echo ""
echo "1. Abre tu app: ${PROD_URL:-$(vercel ls --prod | grep -o 'https://[^ ]*' | head -1)}"
echo "2. Navega a /evaluacion-madurez"
echo "3. Responde algunas preguntas"
echo "4. Click en '🤖 Análisis Inteligente'"
echo ""
echo "📊 Monitoreo:"
echo "  • Ver logs: vercel logs --follow"
echo "  • Dashboard: https://vercel.com/dashboard"
echo "  • Together AI usage: https://together.ai/dashboard"
echo ""
echo "📖 Documentación completa: docs/VERCEL_DEPLOYMENT.md"
echo ""
echo -e "${GREEN}🎉 ¡Deploy exitoso!${NC}"
