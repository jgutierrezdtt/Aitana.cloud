# Sistema de Design Tokens - Aitana.cloud

## Problema Actual

❌ **Hardcoded styles en todos los componentes:**
- `bg-white dark:bg-slate-900` repetido 50+ veces
- Difícil de mantener y propenso a errores
- Inconsistencias entre componentes
- Imposible cambiar el tema global

## Solución: Design System Centralizado

### 📐 Arquitectura

```
src/
├── app/
│   ├── design-system.css          ← Design tokens centralizados
│   └── globals.css                ← Styles globales (deprecar)
├── styles/
│   ├── tokens/
│   │   ├── colors.css             ← Variables de color
│   │   ├── spacing.css            ← Sistema de espaciado
│   │   └── typography.css         ← Tipografía
│   └── components/
│       ├── wiki.css               ← Estilos Wiki
│       ├── cards.css              ← Cards reutilizables
│       └── buttons.css            ← Botones
└── components/
    └── *.tsx                      ← Usan clases semánticas
```

### 🎨 Design Tokens

#### Colores Semánticos (no hardcoded)

**Antes:**
```tsx
className="bg-white dark:bg-slate-900"
className="text-slate-900 dark:text-white"
className="border-slate-200 dark:border-slate-700"
```

**Después:**
```tsx
className="bg-primary"          // Se adapta automáticamente
className="text-primary"
className="border-primary"
```

#### Variables CSS

```css
:root {
  --color-bg-primary: 255 255 255;      /* Light mode */
  --color-text-primary: 15 23 42;
}

.dark {
  --color-bg-primary: 15 23 42;          /* Dark mode */
  --color-text-primary: 248 250 252;
}
```

### 🧩 Componentes Reutilizables

#### Wiki Sidebar

**Antes (151 líneas, muchas repetidas):**
```tsx
<div className="w-80 bg-white dark:bg-slate-900 backdrop-blur-sm border-r border-slate-200 dark:border-slate-700 sticky top-16 h-[calc(100vh-4rem)] overflow-y-auto">
  <input className="w-full pl-10 pr-10 py-3 bg-slate-50 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-xl text-slate-900 dark:text-white..." />
  <button className="px-3 py-1 rounded-lg text-xs font-medium border bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-300 border-slate-200 dark:border-slate-700 hover:bg-slate-200 dark:hover:bg-slate-700">
</div>
```

**Después (más limpio):**
```tsx
<div className="wiki-sidebar">
  <input className="wiki-search-input" />
  <button className="wiki-filter-btn">
</div>
```

### 📊 Beneficios

1. **Mantenibilidad**: Cambiar el tema = 1 archivo (design-system.css)
2. **Consistencia**: Todos usan las mismas variables
3. **Performance**: Menos CSS generado
4. **Escalabilidad**: Fácil agregar nuevos temas
5. **DX**: Nombres semánticos vs clase

s técnicas

### 🔄 Plan de Migración

#### Fase 1: Setup (AHORA)
- [x] Crear `design-system.css` con tokens
- [ ] Importar en layout principal
- [ ] Documentar sistema

#### Fase 2: Refactor Componentes (Prioritario)
- [ ] WikiSidebar (componente crítico)
- [ ] WikiArticleCard
- [ ] Navigation
- [ ] Hero sections

#### Fase 3: Cleanup
- [ ] Remover clases hardcoded
- [ ] Crear linter rule (no más `dark:bg-slate-`)
- [ ] Tests de regresión

### 🎯 Implementación

#### 1. Importar el sistema

```tsx
// src/app/[locale]/layout.tsx
import "../design-system.css";  // ← Antes de globals.css
```

#### 2. Refactorizar componentes

```tsx
// Antes
<div className="bg-white dark:bg-slate-900 border-slate-200 dark:border-slate-700">

// Después
<div className="surface-primary">
```

#### 3. Usar clases de utilidad

```css
/* design-system.css */
.wiki-filter-btn {
  background-color: rgb(var(--color-surface-secondary));
  /* Más propiedades... */
}
```

### 📝 Convenciones

#### Naming

- `bg-primary/secondary/tertiary` - Fondos de página
- `surface-primary/secondary/elevated` - Componentes (cards, modals)
- `text-primary/secondary/tertiary` - Jerarquía de texto
- `border-primary/secondary` - Bordes

#### Uso

- **Pages**: `bg-primary` (fondo de página)
- **Cards**: `surface-primary` (componente elevado)
- **Buttons**: `wiki-filter-btn` (componente específico)
- **Text**: `text-primary` (siempre legible)

### 🚀 Ejemplo Completo: WikiSidebar Refactorizado

Ver: `src/components/WikiSidebar.refactored.tsx`

### 📚 Referencias

- Design tokens: `src/app/design-system.css`
- Component styles: `src/styles/components/`
- Documentation: Este archivo

---

**Próximo paso:** Importar design-system.css y refactorizar WikiSidebar
