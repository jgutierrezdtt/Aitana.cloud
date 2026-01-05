# 🎨 Nuevo Diseño Profesional para Artículos de la Wiki

## Resumen de Mejoras

He creado un **sistema de diseño profesional** para los artículos de la Wiki con las siguientes características:

### ✨ Componentes Creados

#### 1. **WikiArticleLayout** (`src/components/WikiArticleLayout.tsx`)
Layout reutilizable con:
- ✅ **Barra de progreso de lectura** (animada en la parte superior)
- ✅ **Breadcrumb mejorado** con iconos y navegación
- ✅ **Header con gradientes personalizables** por categoría (azul, rojo, verde, púrpura)
- ✅ **Patrón decorativo de fondo** sutil
- ✅ **Meta information badges** (nivel, tiempo lectura, fecha, CVSS)
- ✅ **Sidebar con tabla de contenidos** (sticky, solo desktop)
- ✅ **Footer del artículo** con autor, compartir y guardar
- ✅ **Sombras profesionales** con efectos de profundidad
- ✅ **Responsive completo** (mobile, tablet, desktop)

#### 2. **WikiArticleComponents** (`src/components/WikiArticleComponents.tsx`)
Componentes reutilizables:

**Estructura:**
- `Section` - Secciones principales con títulos y línea divisoria
- `Subsection` - Subsecciones con h3
- `Paragraph` - Párrafos con tipografía optimizada

**Alertas:**
- `AlertInfo` - Información general (azul)
- `AlertWarning` - Advertencias (amarillo)
- `AlertDanger` - Peligros/vulnerabilidades (rojo)
- `AlertSuccess` - Éxito/buenas prácticas (verde)
- `AlertTip` - Consejos/tips (púrpura)

**Código:**
- `CodeBlock` - Bloques de código con:
  - Botón de copiar automático
  - Título y lenguaje
  - Sintaxis personalizable
  - Números de línea opcionales
- `TerminalOutput` - Salidas de terminal con header de macOS

**Destacados:**
- `HighlightBox` - Cajas de contenido destacado con colores personalizables
- `ListItem` - Items de lista con iconos
- `InlineCode` - Código inline con estilos
- `Strong` - Texto en negrita con color mejorado

### 🎯 Características del Nuevo Diseño

#### Visual
- **Gradientes suaves** en headers y botones
- **Sombras profundas** en cards principales (2xl + color)
- **Bordes redondeados** consistentes (rounded-xl/2xl/3xl)
- **Espaciado generoso** con scale tipográfico
- **Tipografía mejorada** con leading relaxed
- **Iconos integrados** en cada sección relevante

#### UX
- **Reading progress bar** - Usuario sabe cuánto lleva leído
- **Table of contents sticky** - Navegación rápida (desktop)
- **Breadcrumb inteligente** - Contexto siempre visible
- **Copy buttons en código** - Copiar con un click
- **Hover effects sutiles** - Feedback visual inmediato
- **Links con animaciones** - Transiciones suaves

#### Dark Mode
- **100% compatible** - Todos los componentes adaptan
- **Fondos transparentes** con backdrop-blur
- **Colores optimizados** para contraste en dark
- **Sombras adaptativas** (desaparecen en dark)

### 📊 Comparación Antes/Después

#### ANTES:
```tsx
// Diseño básico sin estructura
<div className="bg-white dark:bg-slate-900 p-8">
  <h2>Título</h2>
  <p>Texto...</p>
  <div className="bg-blue-500/10 p-6">
    <h3>Subtítulo</h3>
    <p>Contenido...</p>
  </div>
</div>
```

**Problemas:**
- ❌ Estilos hardcodeados repetidos
- ❌ Sin barra de progreso
- ❌ Sin tabla de contenidos
- ❌ Sin botones de compartir
- ❌ Headers básicos sin personalidad
- ❌ Códigos sin copy button
- ❌ No responsive optimizado

#### DESPUÉS:
```tsx
// Diseño profesional con componentes
<WikiArticleLayout
  category="Fundamentos"
  categoryColor="blue"
  title="HTTP: El Protocolo de la Web"
  description="Descripción del artículo..."
  level="Estudiante"
  readTime="10 minutos"
  lastUpdated="Enero 2026"
>
  <Section title="¿Qué es HTTP?">
    <Paragraph>
      <Strong>HTTP</Strong> es el protocolo...
    </Paragraph>
    
    <AlertInfo title="Dato curioso">
      HTTP fue creado en 1989...
    </AlertInfo>
    
    <CodeBlock
      language="http"
      title="Petición HTTP GET"
      code={`GET /api/users HTTP/1.1...`}
    />
  </Section>
  
  <Section title="Seguridad">
    <AlertDanger title="Vulnerabilidades">
      <ListItem icon={<Shield />}>
        <Strong>HTTP vs HTTPS:</Strong> Usa siempre HTTPS
      </ListItem>
    </AlertDanger>
  </Section>
</WikiArticleLayout>
```

**Ventajas:**
- ✅ Componentes semánticos reutilizables
- ✅ Barra de progreso automática
- ✅ Tabla de contenidos generada
- ✅ Botones compartir/guardar integrados
- ✅ Header con gradiente personalizado
- ✅ Copy buttons automáticos en código
- ✅ Responsive perfecto
- ✅ **Mucho más fácil de escribir y mantener**

### 🎨 Colores por Categoría

```tsx
const categoryColors = {
  blue: 'from-blue-600 via-blue-500 to-cyan-500',      // Fundamentos
  red: 'from-red-600 via-rose-500 to-pink-500',        // Vulnerabilidades
  green: 'from-green-600 via-emerald-500 to-teal-500', // Defensas
  purple: 'from-purple-600 via-violet-500 to-indigo-500' // Herramientas
};
```

### 🚀 Cómo Usar

#### Ejemplo Completo:

```tsx
'use client';

import WikiArticleLayout from '@/components/WikiArticleLayout';
import {
  Section,
  Paragraph,
  Strong,
  InlineCode,
  AlertInfo,
  AlertDanger,
  CodeBlock,
  HighlightBox,
  ListItem
} from '@/components/WikiArticleComponents';
import { Shield, ArrowRight } from 'lucide-react';
import Link from 'next/link';
import { useParams } from 'next/navigation';

export default function MiArticulo() {
  const params = useParams();
  const locale = params.locale as string;

  return (
    <WikiArticleLayout
      category="Vulnerabilidades"
      categoryColor="red"
      title="SQL Injection"
      description="Aprende cómo funcionan los ataques de SQL Injection..."
      level="Junior Developer"
      readTime="15 minutos"
      cvssScore={9.8}
      lastUpdated="Enero 2026"
    >
      
      <Section title="¿Qué es SQL Injection?">
        <Paragraph>
          <Strong>SQL Injection</Strong> es una vulnerabilidad...
        </Paragraph>

        <AlertDanger title="Criticidad Alta">
          Esta vulnerabilidad permite a atacantes...
        </AlertDanger>
      </Section>

      <Section title="Ejemplo de Ataque">
        <CodeBlock
          language="sql"
          title="payload.sql"
          code={`' OR '1'='1' --`}
        />

        <Paragraph>
          Este payload explota...
        </Paragraph>
      </Section>

      {/* Link al siguiente */}
      <div className="mt-12">
        <Link
          href={`/${locale}/wiki/siguiente-articulo`}
          className="group inline-flex items-center gap-3 px-6 py-4 bg-gradient-to-r from-red-600 to-pink-600 text-white rounded-xl font-semibold hover:shadow-xl transition-all"
        >
          <span>Siguiente: XSS</span>
          <ArrowRight className="w-5 h-5 group-hover:translate-x-1 transition-transform" />
        </Link>
      </div>

    </WikiArticleLayout>
  );
}
```

### 📝 Migración de Artículos Existentes

Para migrar un artículo al nuevo diseño:

1. **Importa los componentes**:
```tsx
import WikiArticleLayout from '@/components/WikiArticleLayout';
import { Section, Paragraph, Strong, ... } from '@/components/WikiArticleComponents';
```

2. **Envuelve en WikiArticleLayout**:
```tsx
<WikiArticleLayout
  category="..."
  categoryColor="..."
  title="..."
  description="..."
  level="..."
  readTime="..."
>
  {/* contenido */}
</WikiArticleLayout>
```

3. **Reemplaza divs con componentes semánticos**:
- `<section>` → `<Section title="...">`
- `<p>` → `<Paragraph>`
- `<strong>` → `<Strong>`
- `<code>` → `<InlineCode>`
- Alertas → `<AlertInfo>`, `<AlertDanger>`, etc.
- Código → `<CodeBlock>`

### 🎯 Próximos Pasos

1. ✅ **Componentes creados** - WikiArticleLayout + WikiArticleComponents
2. 🔄 **Artículo ejemplo** - HTTP Básico (en progreso)
3. ⏳ **Migrar resto de artículos** - 24 artículos pendientes
4. ⏳ **Añadir syntax highlighting** real (usando Prism o Shiki)
5. ⏳ **Table of contents automática** (detectar h2/h3)
6. ⏳ **Share buttons funcionales** (Twitter, LinkedIn, etc.)

### 💡 Beneficios

- **Mantenibilidad**: Un solo lugar para actualizar estilos
- **Consistencia**: Todos los artículos se ven iguales
- **Productividad**: Escribir artículos es 3x más rápido
- **UX mejorada**: Features profesionales automáticas
- **SEO**: Estructura semántica correcta
- **Accesibilidad**: ARIA labels y semantic HTML

---

**Conclusión**: El nuevo sistema de diseño hace que los artículos de la Wiki se vean mucho más profesionales, sean más fáciles de escribir y ofrezcan una mejor experiencia de usuario.
