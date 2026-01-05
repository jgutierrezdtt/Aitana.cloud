#!/bin/bash

# Script para mejorar el dark mode en artículos de Wiki
# Reemplaza fondos transparentes por fondos sólidos

echo "🔧 Mejorando dark mode en artículos de Wiki..."

# Contador
count=0

# Buscar todos los archivos page.tsx en wiki (excluyendo el index)
find src/app/\[locale\]/wiki -type f -name "page.tsx" ! -path "*/wiki/page.tsx" | while read file; do
  if [ -f "$file" ]; then
    echo "📝 Procesando: $file"
    
    # Backup
    cp "$file" "$file.bak2"
    
    # Reemplazar fondos transparentes por sólidos
    sed -i '' 's/bg-white\/80 dark:bg-white\/5/bg-white dark:bg-slate-900/g' "$file"
    sed -i '' 's/bg-white\/90 dark:bg-white\/5/bg-white dark:bg-slate-900/g' "$file"
    sed -i '' 's/bg-slate-100\/80 dark:bg-white\/5/bg-slate-100 dark:bg-slate-800/g' "$file"
    
    # Mejorar bordes
    sed -i '' 's/border-slate-200 dark:border-white\/10/border-slate-200 dark:border-slate-700/g' "$file"
    
    # Mejorar hovers
    sed -i '' 's/hover:bg-white\/10/hover:bg-slate-50 dark:hover:bg-slate-800/g' "$file"
    sed -i '' 's/hover:bg-slate-100 dark:hover:bg-white\/5/hover:bg-slate-200 dark:hover:bg-slate-800/g' "$file"
    
    echo "✅ Actualizado: $file"
    ((count++))
  fi
done

echo ""
echo "🎉 Completado! $count archivos actualizados"
echo "📦 Backups guardados con extensión .bak2"
