# 🌐 Guía de Traducción de Artículos Wiki

## Estructura Multi-Idioma

Los artículos de la Wiki soportan múltiples idiomas con la siguiente estructura:

```
src/content/wiki/{category}/
├── article-name.tsx       # Español (obligatorio - idioma base)
├── article-name.en.tsx    # Inglés (opcional)
├── article-name.fr.tsx    # Francés (opcional)
└── article-name.de.tsx    # Alemán (opcional)
```

## Idiomas Soportados

- **es** (Español) - Idioma base (obligatorio)
- **en** (Inglés) - Opcional
- **fr** (Francés) - Opcional
- **de** (Alemán) - Opcional

## Cómo Traducir un Artículo

### Paso 1: Copiar el archivo español

```bash
# Ejemplo: traducir SQL Injection a inglés
cp src/content/wiki/bug-bounty/sql-injection-avanzada.tsx \
   src/content/wiki/bug-bounty/sql-injection-avanzada.en.tsx
```

### Paso 2: Traducir el contenido

Editar el nuevo archivo `.en.tsx` y traducir:
- Títulos de secciones
- Párrafos descriptivos
- Mensajes de alerta
- Comentarios en código (opcional)
- **NO traducir:** código de ejemplos, comandos, URLs

```tsx
// ❌ NO TRADUCIR
<CodeBlock
  language="bash"
  title="SQL Injection básico"  // ✅ Traducir título
  code={`SELECT * FROM users WHERE id = 1 OR 1=1`}  // ❌ NO traducir código
/>

// ✅ TRADUCIR
<Section title="Introduction">  {/* Antes: "Introducción" */}
  <Paragraph>
    SQL Injection is a vulnerability...  {/* Antes: "SQL Injection es una vulnerabilidad..." */}
  </Paragraph>
</Section>
```

### Paso 3: Registrar la traducción

Editar `src/data/wiki-article-contents.tsx`:

```tsx
// 1. Agregar import
import SqlInjectionAvanzadaContentEN from '@/content/wiki/bug-bounty/sql-injection-avanzada.en';

// 2. Agregar al mapa
export const articleContentMapByLocale = {
  'sql-injection-avanzada': {
    es: SqlInjectionAvanzadaContent,
    en: SqlInjectionAvanzadaContentEN,  // ← Nueva línea
  },
  // ...
};
```

### Paso 4: Verificar

```bash
# Iniciar servidor de desarrollo
npm run dev

# Visitar en diferentes idiomas
# http://localhost:3000/es/wiki/bug-bounty/sql-injection-avanzada  (español)
# http://localhost:3000/en/wiki/bug-bounty/sql-injection-avanzada  (inglés)
# http://localhost:3000/fr/wiki/bug-bounty/sql-injection-avanzada  (francés - fallback a español con banner)
```

## Comportamiento del Sistema

### Si existe traducción
✅ Muestra el artículo en el idioma solicitado

### Si NO existe traducción
✅ Muestra el artículo en español (fallback)
✅ Banner azul informando que solo está disponible en español
✅ Lista de idiomas disponibles
✅ Link a versión española

## Ejemplo Completo

### Archivo español: `sql-injection-avanzada.tsx`

```tsx
export default function SqlInjectionAvanzadaContent({ locale }: { locale: string }) {
  return (
    <>
      <Section title="Introducción">
        <Paragraph>
          SQL Injection es una vulnerabilidad crítica...
        </Paragraph>
      </Section>
      
      <Section title="Tipos de SQL Injection">
        <Subsection title="Error-Based">
          <Paragraph>Extrae datos mediante mensajes de error...</Paragraph>
        </Subsection>
      </Section>
    </>
  );
}
```

### Archivo inglés: `sql-injection-avanzada.en.tsx`

```tsx
export default function SqlInjectionAvanzadaContentEN({ locale }: { locale: string }) {
  return (
    <>
      <Section title="Introduction">
        <Paragraph>
          SQL Injection is a critical vulnerability...
        </Paragraph>
      </Section>
      
      <Section title="Types of SQL Injection">
        <Subsection title="Error-Based">
          <Paragraph>Extracts data through error messages...</Paragraph>
        </Subsection>
      </Section>
    </>
  );
}
```

## Prioridades de Traducción

### Alta prioridad (artículos más visitados)
1. SQL Injection
2. XSS (todos los tipos)
3. CSRF
4. SSRF
5. Authentication vulnerabilities

### Media prioridad
- Database injections
- API security
- CORS issues

### Baja prioridad
- Artículos avanzados/específicos
- Técnicas muy especializadas

## Herramientas Recomendadas

### Para mantener consistencia terminológica:
- **DeepL** (mejor que Google Translate para contexto técnico)
- **Glosario de términos** (mantener en `/docs/glossary.md`)

### Términos que NO se traducen:
- Nombres de herramientas: Burp Suite, sqlmap, etc.
- Comandos: `curl`, `wget`, `SELECT`, etc.
- Nombres de funciones: `eval()`, `system()`, etc.
- Acrónimos técnicos: OWASP, CVE, CVSS, etc.

## Checklist de Traducción

- [ ] Copiar archivo `.tsx` a `.{locale}.tsx`
- [ ] Traducir todos los textos descriptivos
- [ ] Mantener código de ejemplos sin cambios
- [ ] Traducir títulos de secciones
- [ ] Traducir mensajes de alertas
- [ ] Revisar enlaces (actualizar si apuntan a recursos en otros idiomas)
- [ ] Agregar import en `wiki-article-contents.tsx`
- [ ] Agregar entrada en `articleContentMapByLocale`
- [ ] Probar en navegador
- [ ] Verificar que no hay errores TypeScript

## Estado Actual

### Artículos con traducciones: 0/25
- [ ] sql-injection-avanzada
- [ ] mongodb-injection
- [ ] redis-rce
- [ ] cassandra-injection
- [ ] sqlite-local-injection
- [ ] firebase-misconfiguration
- [ ] ssrf-basico
- [ ] idor
- [ ] race-conditions
- [ ] xss-stored
- [ ] (15 artículos más pendientes...)

## Contribuir

Para contribuir traducciones:

1. Fork del repositorio
2. Crear branch: `git checkout -b translate-article-name-{locale}`
3. Traducir el artículo siguiendo esta guía
4. Commit: `git commit -m "Translate: article-name to {locale}"`
5. Push y crear Pull Request

## Contacto

Para preguntas sobre traducciones: [crear issue en GitHub]
