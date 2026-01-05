# 🎨 Guía de Design Tokens y Temas

## ❌ Problema: Hardcodeo de Colores

### Antes (MAL):
```tsx
// ❌ Color hardcodeado - siempre oscuro
<div className="bg-[#1B1663] text-white">
  
// ❌ Color al revés - dark primero
<div className="dark:text-white">

// ❌ Sin variante light
<div className="text-blue-400">
```

### Después (BIEN):
```tsx
// ✅ Light primero, dark después
<div className="bg-gray-50 dark:bg-[#1B1663] text-gray-900 dark:text-white">

// ✅ Usando design tokens
import { themeClasses } from '@/config/design-tokens';
<div className={themeClasses.card.background}>
  <h3 className={themeClasses.text.primary}>Título</h3>
</div>
```

---

## 📋 Reglas de Oro

### 1. **SIEMPRE Light Mode Primero**
```tsx
✅ className="bg-gray-50 dark:bg-[#1B1663]"
❌ className="dark:bg-gray-50 bg-[#1B1663]"
```

### 2. **NO Hardcodear Colores Oscuros**
```tsx
✅ className="bg-gray-100 dark:bg-blue-500/20"
❌ className="bg-blue-500/20"  // Siempre azul!
```

### 3. **Texto SIEMPRE con Variante**
```tsx
✅ className="text-gray-900 dark:text-white"
❌ className="text-white"  // Siempre blanco!
```

### 4. **Borders con Gray + Dark**
```tsx
✅ className="border-gray-300 dark:border-blue-500/30"
❌ className="border-blue-500/30"  // Siempre azul!
```

### 5. **Icons con Color Adaptativo**
```tsx
✅ className="text-gray-700 dark:text-blue-400"
❌ className="text-blue-400"  // Siempre azul!
```

---

## 🏗️ Arquitectura Mejorada: Design Tokens

### Opción A: Inline (Actual - OK pero verbose)
```tsx
<div className="bg-gray-50 dark:bg-gradient-to-br dark:from-[#0A0525] dark:via-[#1B1663] dark:to-[#0A0525] border border-gray-300 dark:border-blue-500/20">
  <p className="text-gray-700 dark:text-white/80">Texto</p>
</div>
```

**Pros:** Explícito, fácil de entender
**Contras:** Repetitivo, propenso a errores, difícil de mantener

### Opción B: Design Tokens (RECOMENDADO)
```tsx
import { themeClasses, cn } from '@/config/design-tokens';

<div className={cn(
  themeClasses.card.background,
  themeClasses.card.border,
  'p-6 rounded-lg'
)}>
  <p className={themeClasses.text.secondary}>Texto</p>
</div>
```

**Pros:** 
- ✅ Centralizado
- ✅ Consistente
- ✅ Fácil de mantener
- ✅ Menos errores
- ✅ Autocomplete

**Contras:**
- Requiere importar
- Abstracción extra

### Opción C: CSS Variables (Para proyectos grandes)
```tsx
// tailwind.config.ts
theme: {
  extend: {
    colors: {
      'card-bg': 'var(--card-bg)',
      'card-text': 'var(--card-text)',
    }
  }
}

// globals.css
:root {
  --card-bg: theme('colors.gray.50');
  --card-text: theme('colors.gray.900');
}

.dark {
  --card-bg: #1B1663;
  --card-text: white;
}

// Componente
<div className="bg-card-bg text-card-text">
```

---

## 🧪 Tests Automatizados

### Ejecutar Tests
```bash
# Test básico de temas
npm run test:theme

# Test de elementos oscuros en light mode
npm run test:dark

# Todos los tests
npm run test:all
```

### Lo que Detectan:
- ✅ `bg-white` sin `dark:bg-*`
- ✅ Colores hardcodeados (#hex sin variante)
- ✅ `text-white` sin `dark:text-white`
- ✅ `text-blue-400` sin prefijo
- ✅ Borders oscuros sin alternativa
- ✅ Gradientes sin variante
- ✅ Cobertura del patrón adaptativo

---

## 📊 Patrón Recomendado

### Cards
```tsx
<div className={cn(
  // Background
  'bg-gray-50',
  'dark:bg-gradient-to-br',
  'dark:from-[#0A0525]',
  'dark:via-[#1B1663]',
  'dark:to-[#0A0525]',
  
  // Border
  'border border-gray-300',
  'dark:border-blue-500/20',
  'hover:border-gray-400',
  'dark:hover:border-blue-400/50',
  
  // Shadow
  'shadow-md',
  'dark:shadow-[0_0_30px_rgba(59,130,246,0.15)]',
  
  // Otros
  'rounded-xl p-8 transition-all'
)}>
  {children}
</div>
```

### Texto
```tsx
// Títulos
<h2 className="text-gray-900 dark:text-white">

// Párrafos
<p className="text-gray-700 dark:text-white/80">

// Secundario
<span className="text-gray-600 dark:text-white/70">

// Muted
<small className="text-gray-500 dark:text-white/60">
```

### Icons
```tsx
// Container
<div className="bg-gray-100 dark:bg-blue-500/20 border border-gray-300 dark:border-blue-400/30">
  {/* Icon */}
  <Icon className="text-gray-700 dark:text-blue-400" />
</div>
```

---

## 🔄 Migración Gradual

### Paso 1: Identificar Problemas
```bash
npm run test:dark
```

### Paso 2: Priorizar
1. Elementos visibles en homepage
2. Cards y botones principales
3. Navegación y footer
4. Páginas internas

### Paso 3: Refactorizar
```tsx
// Antes
<div className="bg-blue-500/20 text-white">

// Después
<div className="bg-gray-100 dark:bg-blue-500/20 text-gray-900 dark:text-white">
```

### Paso 4: Validar
```bash
npm run test:all
```

---

## 💡 Tips

### 1. Usar Prefijos Consistentes
```tsx
// ✅ BIEN: Light primero
bg-gray-50 dark:bg-[#1B1663]
text-gray-900 dark:text-white
border-gray-300 dark:border-blue-500/30

// ❌ MAL: Inconsistente
dark:bg-blue-500 bg-gray-50  // Orden invertido
```

### 2. Agrupar por Categoría
```tsx
className={cn(
  // Layout
  'flex items-center gap-4',
  // Colors
  'bg-gray-50 dark:bg-[#1B1663]',
  'text-gray-900 dark:text-white',
  // Borders
  'border border-gray-300 dark:border-blue-500/20',
  // Interactive
  'hover:scale-105 transition-all'
)}
```

### 3. Crear Componentes Reutilizables
```tsx
// components/ui/Card.tsx
export function Card({ children, className }: CardProps) {
  return (
    <div className={cn(
      themeClasses.card.background,
      themeClasses.card.border,
      themeClasses.card.shadow,
      className
    )}>
      {children}
    </div>
  );
}

// Uso
<Card>
  <h3 className={themeClasses.text.primary}>Título</h3>
</Card>
```

---

## ✅ Checklist de Revisión

Antes de commit, verificar:

- [ ] `npm run test:dark` pasa
- [ ] No hay `bg-white` sin `dark:bg-*`
- [ ] No hay `text-white` sin contexto oscuro
- [ ] No hay colores hex hardcodeados
- [ ] Borders tienen variante dark
- [ ] Icons tienen colores adaptativos
- [ ] Shadows tienen prefijo `dark:`
- [ ] Gradientes tienen alternativa light

---

## 📚 Recursos

- `/src/config/design-tokens.ts` - Tokens centralizados
- `/scripts/test-dark-elements.js` - Test de consistencia
- `/scripts/verify-theme.js` - Test básico
- `THEME_MIGRATION_GUIDE.md` - Esta guía

---

## 🎯 Objetivo Final

**100% de cobertura del patrón adaptativo:**
- Modo claro: Todo gris/neutral
- Modo oscuro: Colores vibrantes CyberGuard
- Sin hardcodeo de colores
- Tests automatizados pasando
- Design tokens implementados
