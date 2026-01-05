#!/bin/bash

# 🎨 GUÍA DE TROUBLESHOOTING - Dark Mode Wiki
# ============================================

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "🔍 DIAGNÓSTICO DARK MODE - Guía de Pasos"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

echo "📋 PASO 1: Verifica que el dev server esté corriendo"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
if pgrep -f "next dev" > /dev/null; then
    echo "✅ Next.js dev server está corriendo"
else
    echo "❌ Next.js dev server NO está corriendo"
    echo "   Ejecuta: npm run dev"
    exit 1
fi
echo ""

echo "📋 PASO 2: Verifica archivos del design system"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
if [ -f "src/app/design-system.css" ]; then
    echo "✅ design-system.css existe"
    lines=$(wc -l < src/app/design-system.css)
    echo "   $lines líneas de código"
else
    echo "❌ design-system.css NO existe"
fi

if grep -q "design-system.css" src/app/\[locale\]/layout.tsx; then
    echo "✅ design-system.css importado en layout.tsx"
else
    echo "❌ design-system.css NO importado en layout.tsx"
    echo "   Agrega: import '../design-system.css'"
fi
echo ""

echo "📋 PASO 3: Verifica WikiSidebar"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
if grep -q "dark:bg-slate-800" src/components/WikiSidebar.tsx; then
    echo "✅ WikiSidebar tiene clases dark: correctas"
    count=$(grep -o "dark:bg-slate-800" src/components/WikiSidebar.tsx | wc -l)
    echo "   $count ocurrencias de 'dark:bg-slate-800'"
else
    echo "❌ WikiSidebar NO tiene clases dark:"
fi

if grep -q "dark:bg-white/5" src/components/WikiSidebar.tsx; then
    echo "⚠️  WikiSidebar tiene dark:bg-white/5 (TRANSPARENTE - PROBLEMA)"
else
    echo "✅ WikiSidebar NO tiene fondos transparentes inválidos"
fi
echo ""

echo "📋 PASO 4: Ejecuta el script de diagnóstico en el navegador"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "1. Abre http://localhost:3000/wiki en el navegador"
echo "2. Abre DevTools (F12 o Cmd+Opt+I)"
echo "3. Ve a la pestaña Console"
echo "4. Ejecuta el script de diagnóstico:"
echo ""
echo "   // Opción 1: Cargar desde public"
echo "   fetch('/diagnose-dark-mode.js').then(r => r.text()).then(eval)"
echo ""
echo "   // Opción 2: Copiar y pegar contenido de:"
echo "   cat public/diagnose-dark-mode.js"
echo ""
echo ""

echo "📋 PASO 5: Acciones rápidas"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "🔄 Hard reload navegador:"
echo "   macOS: Cmd + Shift + R"
echo "   Windows/Linux: Ctrl + Shift + R"
echo ""
echo "🧹 Limpiar cache de Next.js:"
echo "   rm -rf .next && npm run dev"
echo ""
echo "🕵️ Modo incógnito:"
echo "   Cmd + Shift + N (Chrome)"
echo "   Cmd + Shift + P (Firefox)"
echo ""
echo "🔧 Forzar rebuild Tailwind:"
echo "   pkill -f 'next dev' && npm run dev"
echo ""

echo "📋 PASO 6: Validar con tests automatizados"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
if [ -f "scripts/validate-wiki-colors.js" ]; then
    echo "✅ Test de validación existe"
    echo "   Ejecuta: node scripts/validate-wiki-colors.js"
else
    echo "❌ Test de validación NO existe"
fi
echo ""

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "💡 PROBLEMAS COMUNES Y SOLUCIONES"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "❓ Los filtros siguen blancos"
echo "   → Cache del navegador (Cmd+Shift+R)"
echo "   → Clase 'dark' no aplicada al <html> (verifica con DevTools)"
echo "   → Tailwind no compiló (reinicia dev server)"
echo ""
echo "❓ CSS Variables no funcionan"
echo "   → design-system.css no importado (verifica layout.tsx)"
echo "   → Orden de importación (debe ir ANTES de globals.css)"
echo ""
echo "❓ Algunos componentes funcionan, otros no"
echo "   → Estilos inline con !important sobreescribiendo"
echo "   → Clases hardcoded sin dark: variant"
echo ""
echo "❓ Funciona en código pero no visual"
echo "   → Dev server no recargó (restart)"
echo "   → Cache navegador agresivo (incógnito)"
echo "   → Extensiones del navegador interfiriendo"
echo ""

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "📊 CHECKLIST FINAL"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "[ ] Dev server corriendo (npm run dev)"
echo "[ ] design-system.css creado e importado"
echo "[ ] WikiSidebar con dark:bg-slate-800"
echo "[ ] Hard reload en navegador (Cmd+Shift+R)"
echo "[ ] Script diagnose-dark-mode.js ejecutado"
echo "[ ] Clase 'dark' presente en <html> (DevTools)"
echo "[ ] CSS variables cargadas (--color-bg-primary definido)"
echo "[ ] Tests automatizados pasando (54/54)"
echo ""

echo "✅ Si todos los checks pasan y sigue sin funcionar:"
echo "   → Ejecuta el script de diagnóstico en el navegador"
echo "   → Comparte el output completo para debugging"
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
