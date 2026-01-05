#!/bin/bash

# Script para actualizar todos los archivos de la Wiki con soporte dark mode
# Uso: ./scripts/update-wiki-dark-mode.sh

echo "🎨 Actualizando Wiki para soportar modo claro/oscuro..."

# Encontrar todos los archivos page.tsx en la wiki
WIKI_FILES=$(find src/app/\[locale\]/wiki -name "page.tsx" -type f)

for file in $WIKI_FILES; do
  echo "📝 Procesando: $file"
  
  # Backup
  cp "$file" "$file.bak"
  
  # Aplicar reemplazos con sed
  sed -i '' \
    -e 's/bg-slate-900\/50 border-b border-white\/10/bg-white dark:bg-slate-900\/50 border-b border-slate-200 dark:border-white\/10/g' \
    -e 's/bg-slate-900 /bg-white dark:bg-slate-900 /g' \
    -e 's/bg-slate-800\/50 /bg-slate-100 dark:bg-slate-800\/50 /g' \
    -e 's/text-white /text-slate-900 dark:text-white /g' \
    -e 's/text-slate-300/text-slate-700 dark:text-slate-300/g' \
    -e 's/text-slate-400/text-slate-600 dark:text-slate-400/g' \
    -e 's/text-green-300/text-green-700 dark:text-green-300/g' \
    -e 's/text-green-400/text-green-600 dark:text-green-400/g' \
    -e 's/text-cyan-400/text-cyan-600 dark:text-cyan-400/g' \
    -e 's/text-blue-300/text-blue-700 dark:text-blue-300/g' \
    -e 's/text-blue-400/text-blue-600 dark:text-blue-400/g' \
    -e 's/text-yellow-300/text-yellow-700 dark:text-yellow-300/g' \
    -e 's/text-red-300/text-red-700 dark:text-red-300/g' \
    -e 's/text-red-400/text-red-600 dark:text-red-400/g' \
    -e 's/text-purple-300/text-purple-700 dark:text-purple-300/g' \
    -e 's/text-orange-300/text-orange-700 dark:text-orange-300/g' \
    -e 's/border-slate-700/border-slate-300 dark:border-slate-700/g' \
    -e 's/border-blue-400/border-blue-500 dark:border-blue-400/g' \
    "$file"
  
  echo "✅ Actualizado: $file"
done

echo ""
echo "🎉 Completado! Se actualizaron todos los archivos de la Wiki."
echo "📦 Se crearon backups con extensión .bak"
echo ""
echo "Para eliminar los backups si todo está correcto:"
echo "  find src/app/[locale]/wiki -name '*.bak' -delete"
