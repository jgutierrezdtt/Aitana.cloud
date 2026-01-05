# 📚 Template para Artículos de Bug Bounty

## Estructura Profesional y Reutilizable

Todos los artículos de Bug Bounty siguen esta estructura consistente para facilitar la escritura y mantenimiento.

## 🎯 Template Base

```tsx
'use client';

import WikiArticleLayout from '@/components/WikiArticleLayout';
import {
  Section,
  Subsection,
  Paragraph,
  Strong,
  InlineCode,
  AlertInfo,
  AlertWarning,
  AlertDanger,
  AlertTip,
  AlertSuccess,
  CodeBlock,
  TerminalOutput,
  HighlightBox,
  ListItem
} from '@/components/WikiArticleComponents';
import { [ICONOS_NECESARIOS] } from 'lucide-react';
import Link from 'next/link';
import { useParams } from 'next/navigation';

export default function [NombreArticulo]Page() {
  const params = useParams();
  const locale = params.locale as string;

  return (
    <WikiArticleLayout
      category="Bug Bounty"
      categoryColor="red"  // red para vulnerabilidades
      title="[Título del Artículo]"
      description="[Descripción corta de 1-2 líneas]"
      level="Junior Developer"  // Para Bug Bounty hunters
      readTime="[X] minutos"
      cvssScore={[X.X]}  // Score CVSS si aplica
      lastUpdated="Enero 2026"
    >
      
      {/* SECCIÓN 1: Introducción */}
      <Section id="introduccion" title="¿Qué es [Vulnerabilidad]?">
        <Paragraph>
          Explicación clara del concepto...
        </Paragraph>

        <AlertInfo title="Contexto">
          Información relevante de contexto...
        </AlertInfo>
      </Section>

      {/* SECCIÓN 2: Técnica Principal */}
      <Section id="tecnica-1" title="1. [Nombre de Técnica]">
        
        <Subsection title="Escenario Vulnerable">
          <CodeBlock
            language="[lenguaje]"
            title="❌ Código vulnerable"
            code={`// Código de ejemplo vulnerable`}
          />
        </Subsection>

        <Subsection title="Payload de Ataque">
          <CodeBlock
            language="[lenguaje]"
            title="Payload - [descripción]"
            code={`// Payload de ejemplo`}
          />

          <HighlightBox color="red" title="🔓 ¿Cómo funciona?">
            <Paragraph>
              Explicación detallada del exploit...
            </Paragraph>
          </HighlightBox>
        </Subsection>

        <Subsection title="Ejemplo Práctico">
          <TerminalOutput title="Resultado del ataque">
            {`Output esperado del exploit`}
          </TerminalOutput>
        </Subsection>
      </Section>

      {/* SECCIÓN 3: Técnicas Avanzadas */}
      <Section id="tecnicas-avanzadas" title="2. Técnicas Avanzadas">
        <Subsection title="[Variante 1]">
          <CodeBlock
            language="[lenguaje]"
            code={`// Código de variante`}
          />
        </Subsection>
      </Section>

      {/* SECCIÓN 4: Bypass de Protecciones */}
      <Section id="bypass" title="3. Bypass de Protecciones">
        <AlertTip title="Técnicas de evasión">
          Lista de técnicas para bypassear WAF/filters...
        </AlertTip>
      </Section>

      {/* SECCIÓN 5: Mitigación */}
      <Section id="mitigacion" title="Mitigación para Developers">
        <AlertDanger title="Cómo prevenir [Vulnerabilidad]">
          <ul className="space-y-3 mt-3">
            <ListItem icon={<Shield className="w-5 h-5 text-green-600 dark:text-green-400" />}>
              <Strong>Medida 1:</Strong> Descripción
            </ListItem>
            <ListItem icon={<Shield className="w-5 h-5 text-green-600 dark:text-green-400" />}>
              <Strong>Medida 2:</Strong> Descripción
            </ListItem>
          </ul>
        </AlertDanger>

        <CodeBlock
          language="[lenguaje]"
          title="✅ Código seguro"
          code={`// Implementación segura`}
        />
      </Section>

      {/* Siguiente Artículo */}
      <div className="mt-12 pt-8 border-t border-slate-200 dark:border-slate-800">
        <h3 className="text-2xl font-bold text-slate-900 dark:text-white mb-4">Siguiente: [Título]</h3>
        <Link
          href={`/${locale}/wiki/bug-bounty/[slug-siguiente]`}
          className="group inline-flex items-center gap-3 px-6 py-4 bg-gradient-to-r from-red-600 to-pink-600 text-white rounded-xl font-semibold hover:shadow-xl hover:shadow-red-500/50 transition-all"
        >
          <span>[Título del siguiente artículo]</span>
          <ArrowRight className="w-5 h-5 group-hover:translate-x-1 transition-transform" />
        </Link>
      </div>

    </WikiArticleLayout>
  );
}
```

## 📝 Guía de Iconos Comunes

```tsx
// Importar según necesidad
import {
  Database,      // Bases de datos
  Shield,        // Seguridad/protección
  Lock,          // Autenticación/cifrado
  Code2,         // Código/scripting
  Terminal,      // Comandos/CLI
  AlertTriangle, // Advertencias
  Zap,           // Ataques/exploits
  Key,           // Llaves/tokens
  Server,        // Servidores
  Cloud,         // Cloud/metadata
  FileCode,      // Archivos de código
  Bug,           // Vulnerabilidades
  Eye,           // Monitoreo/observación
  Wifi,          // Red/comunicaciones
  ArrowRight     // Navegación
} from 'lucide-react';
```

## 🎨 Paleta de Colores por Tipo

```tsx
// Alertas
<AlertInfo>     // Azul - Información neutral
<AlertTip>      // Púrpura - Consejos/optimizaciones
<AlertWarning>  // Amarillo - Advertencias
<AlertDanger>   // Rojo - Peligros/vulnerabilidades
<AlertSuccess>  // Verde - Buenas prácticas

// HighlightBox
color="blue"    // Información técnica
color="purple"  // Tips avanzados
color="green"   // Defensas/mitigación
color="red"     // Exploits/ataques
```

## 📂 Estructura de Carpetas

```
src/app/[locale]/wiki/bug-bounty/
├── sql-injection-avanzada/
│   └── page.tsx
├── mongodb-operator-injection/
│   └── page.tsx
├── redis-lua-rce/
│   └── page.tsx
├── homograph-attacks/
│   └── page.tsx
├── ssrf-cloud-metadata/
│   └── page.tsx
├── jwt-attacks/
│   └── page.tsx
└── [más artículos...]
```

## ✅ Checklist por Artículo

Cada artículo debe incluir:

- [ ] **Introducción clara** - ¿Qué es y por qué importa?
- [ ] **Ejemplo vulnerable** - Código que muestre el problema
- [ ] **Payloads de ataque** - Mínimo 2-3 variantes
- [ ] **Explicación técnica** - Cómo funciona el exploit
- [ ] **Output esperado** - Qué verás si funciona
- [ ] **Script de automatización** - Python/Bash cuando aplique
- [ ] **Técnicas de bypass** - Cómo evadir protecciones
- [ ] **Sección de mitigación** - Cómo defenderse
- [ ] **Código seguro** - Implementación correcta
- [ ] **Link al siguiente** - Mantener navegación fluida

## 🎯 Artículos Creados

1. ✅ **SQL Injection Manual Avanzada** (`sql-injection-avanzada/`)
   - UNION-based, Error-based, Time-blind
   - Scripts Python de automatización
   - Bypass de WAF

2. ✅ **MongoDB Operator Injection** (`mongodb-operator-injection/`)
   - $ne, $gt, $regex operators
   - Login bypass
   - Password exfiltration
   - $where JavaScript injection

## 📋 Artículos Pendientes (con slugs sugeridos)

### Bases de Datos
- `redis-lua-rce` - Redis RCE via Lua Sandboxing
- `cassandra-cql-injection` - Cassandra (CQL) Injection
- `sqlite-local-injection` - SQLite Local Injections
- `firebase-misconfiguration` - Firebase Realtime DB Misconfiguration
- `realm-coredata-forensics` - Realm & CoreData Forensics

### Unicode y Alfabetos
- `homograph-attacks` - Homograph Attacks (IDN)
- `unicode-normalization-bypass` - Unicode Normalization Bypass
- `utf8-smuggling` - Smuggling via Overlong UTF-8
- `sqli-small-windows` - SQLi en "Small Windows"
- `multi-stage-payload` - Multi-stage Payload (Fragmentación)

### SSRF
- `ssrf-cloud-metadata` - SSRF en Cloud Metadata (AWS/GCP/Azure)
- `dns-rebinding` - DNS Rebinding
- `gopher-protocol-smuggling` - Gopher Protocol Smuggling
- `ssrf-pdf-renderers` - SSRF via PDF/Image Renderers

### IA Móvil
- `prompt-injection-mobile` - Prompt Injection en Interfaces Móviles
- `coreml-hijacking` - CoreML/ML Kit Model Hijacking
- `app-intents-abuse` - Abuso de App Intents (Apple Intelligence)
- `intent-injection-gemini` - Intent Injection en Gemini Nano
- `npu-side-channel` - Side-channel Attacks en NPU

### Comunicaciones
- `ssl-pinning-bypass` - SSL/TLS Pinning Bypass
- `broken-certificate-validation` - Broken Certificate Validation
- `mitm-non-http` - Man-in-the-Middle en protocolos no-HTTP
- `certificate-transparency` - Certificate Transparency Log Monitoring

### Criptografía
- `broken-integrity-checks` - Broken Integrity Checks (APK/IPA)
- `insecure-key-storage` - Insecure Key Storage
- `weak-cryptography` - Weak Cryptography
- `crypto-side-channel` - Side-Channel en Criptografía
- `whitebox-crypto-reverse` - White-box Cryptography Reverse Engineering

### Lógica de Negocio
- `idor` - IDOR (Insecure Direct Object Reference)
- `race-conditions` - Race Conditions
- `jwt-attacks` - JWT Attacks
- `oauth-misconfigurations` - OAuth Misconfigurations

## 💡 Tips para Escribir Artículos

1. **Ejemplo real primero**: Empieza con un escenario vulnerable real
2. **Progresión gradual**: De básico a avanzado
3. **Código completo**: No uses placeholders, código ejecutable
4. **Output visible**: Siempre muestra qué esperar ver
5. **Automatización**: Include scripts cuando aplique
6. **Contexto Bug Bounty**: Menciona WAF bypass, sigilo, eficiencia
7. **Balance**: 60% ataque, 40% defensa
8. **Links cruzados**: Conecta con artículos relacionados

## 🚀 Comando Rápido para Crear Artículo

```bash
# Crear estructura
mkdir -p "src/app/[locale]/wiki/bug-bounty/[nombre-slug]"

# Copiar template y editar
# (Usar el template de arriba)
```

---

**Total de artículos por crear**: ~35  
**Estimado de tiempo**: 15-20 minutos por artículo  
**Total**: ~10-12 horas de trabajo

**Ventajas del sistema**:
- ✅ Diseño consistente y profesional
- ✅ Reutilizable 100%
- ✅ Fácil de actualizar centralmente (cambios en WikiArticleLayout se propagan)
- ✅ Dark mode completo automático
- ✅ Responsive sin esfuerzo adicional
- ✅ SEO optimizado con estructura semántica
