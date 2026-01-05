#!/bin/bash

echo "🎨 VERIFICACIÓN VISUAL DE COLORES - WikiSidebar"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "📋 Checklist de colores que deberías ver:"
echo ""
echo "MODO CLARO (☀️):"
echo "  ✓ Fondo del sidebar: Blanco"
echo "  ✓ Input de búsqueda: Gris muy claro (slate-50)"
echo "  ✓ Botones de filtro no seleccionados: Gris claro (slate-100)"
echo "  ✓ Texto: Negro/Gris oscuro"
echo ""
echo "MODO OSCURO (🌙):"
echo "  ✓ Fondo del sidebar: Gris muy oscuro (casi negro)"
echo "  ✓ Input de búsqueda: Gris oscuro (slate-800)"
echo "  ✓ Botones de filtro no seleccionados: Gris oscuro (slate-800)"
echo "  ✓ Texto: Blanco/Gris claro"
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "🔍 Clases aplicadas actualmente:"
echo ""

# Sidebar background
echo "1️⃣ Fondo del Sidebar:"
grep -n "className=\"w-80 bg-white" src/components/WikiSidebar.tsx | head -1
echo ""

# Search input background  
echo "2️⃣ Input de búsqueda:"
grep -n "bg-slate-50 dark:bg-slate-800" src/components/WikiSidebar.tsx | head -1
echo ""

# Filter buttons
echo "3️⃣ Botones de filtro:"
grep -n "bg-slate-100 dark:bg-slate-800" src/components/WikiSidebar.tsx | head -1
echo ""

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "🧪 Cómo probar:"
echo "  1. Abre http://localhost:3000/es/wiki en tu navegador"
echo "  2. Cambia entre modo claro/oscuro usando el toggle del sistema"
echo "  3. Verifica que TODOS los elementos cambien de color"
echo ""
echo "❌ Si el fondo sigue blanco en dark mode:"
echo "  → Revisa que Tailwind esté detectando la clase 'dark'"
echo "  → Verifica que tu sistema esté en modo oscuro"
echo "  → Recarga la página con Cmd+Shift+R (hard reload)"
echo ""
