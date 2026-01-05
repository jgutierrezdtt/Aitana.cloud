# Configuración de Entornos - Aitana.cloud

Este proyecto implementa un sistema de **separación de entornos** que permite diferentes configuraciones entre **desarrollo** y **producción**.

## 📋 Entornos Disponibles

### 🛠️ Development (Desarrollo)
- **Objetivo:** Entorno completo para desarrollo y testing
- **Features habilitadas:** Todas
- **Rutas disponibles:**
  - ✅ Blue Team Labs
  - ✅ AI Red Team Lab (Prompt Injection)
  - ✅ Traditional Red Team Labs (14 vulnerabilidades)
  - ✅ SSDLC Assessment Tool
  - ✅ Compliance Matrix
  - ✅ SSDLC Guides
  - ✅ API Documentation

### 🚀 Production (Producción)
- **Objetivo:** Entorno público solo con Blue Team + AI Lab
- **Features habilitadas:** Limitadas
- **Rutas disponibles:**
  - ✅ Blue Team Labs
  - ✅ AI Red Team Lab (Prompt Injection)
  - ❌ Traditional Red Team Labs (ocultos)
  - ❌ SSDLC Assessment (oculto)
  - ❌ Compliance Matrix (oculto)
  - ❌ SSDLC Guides (oculto)
  - ❌ API Documentation (oculto)

## 🔧 Configuración

### Variables de Entorno

#### `.env.development`
```env
NEXT_PUBLIC_ENV=development
NEXT_PUBLIC_APP_URL=http://localhost:3000
NEXT_PUBLIC_ENABLE_ALL_LABS=true
NEXT_PUBLIC_ENABLE_SSDLC=true
NEXT_PUBLIC_ENABLE_DOCS=true
NEXT_PUBLIC_ENABLE_MATRIX=true
NEXT_PUBLIC_ENABLE_GUIDES=true
NEXT_PUBLIC_ANALYTICS=false
```

#### `.env.production`
```env
NEXT_PUBLIC_ENV=production
NEXT_PUBLIC_APP_URL=https://aitana.cloud
NEXT_PUBLIC_ENABLE_ALL_LABS=false
NEXT_PUBLIC_ENABLE_SSDLC=false
NEXT_PUBLIC_ENABLE_DOCS=false
NEXT_PUBLIC_ENABLE_MATRIX=false
NEXT_PUBLIC_ENABLE_GUIDES=false
NEXT_PUBLIC_ANALYTICS=true
```

### Configuración Local

1. **Copia el archivo de ejemplo:**
   ```bash
   cp .env.local.example .env.local
   ```

2. **Edita `.env.local` según tus necesidades:**
   ```env
   NEXT_PUBLIC_ENV=development  # o 'production' para testing
   ```

## 🚀 Scripts NPM

### Desarrollo
```bash
# Modo desarrollo (todas las features)
npm run dev

# Forzar entorno development
npm run dev:development

# Testing producción en local
npm run dev:production
```

### Build
```bash
# Build con configuración actual
npm run build

# Build para desarrollo (todas las features)
npm run build:development

# Build para producción (features limitadas)
npm run build:production
```

### Deployment
```bash
# Deploy preview (desarrollo)
npm run deploy:preview

# Deploy producción
npm run deploy:production
```

## 🛡️ Sistema de Feature Flags

### Uso en Código

```typescript
import { isFeatureEnabled } from '@/config/features';

// Verificar si una feature está habilitada
if (isFeatureEnabled('SQLI')) {
  // Mostrar lab de SQL Injection
}

// En componentes
{isFeatureEnabled('API_DOCS') && (
  <Link href="/docs">API Docs</Link>
)}
```

### Features Disponibles

| Feature | Development | Production |
|---------|-------------|------------|
| `BLUE_TEAM` | ✅ | ✅ |
| `RED_TEAM_AI` | ✅ | ✅ |
| `PROMPT_INJECTION` | ✅ | ✅ |
| `SQLI` | ✅ | ❌ |
| `XSS` | ✅ | ❌ |
| `AUTH` | ✅ | ❌ |
| `SENSITIVE_DATA` | ✅ | ❌ |
| `ACCESS_CONTROL` | ✅ | ❌ |
| `MISCONFIG` | ✅ | ❌ |
| `COMMAND_INJECTION` | ✅ | ❌ |
| `XXE` | ✅ | ❌ |
| `LDAP` | ✅ | ❌ |
| `SSTI` | ✅ | ❌ |
| `SESSION_FIXATION` | ✅ | ❌ |
| `CSP` | ✅ | ❌ |
| `FILE_UPLOAD` | ✅ | ❌ |
| `SSDLC_ASSESSMENT` | ✅ | ❌ |
| `API_DOCS` | ✅ | ❌ |
| `COMPLIANCE_MATRIX` | ✅ | ❌ |
| `SSDLC_GUIDES` | ✅ | ❌ |
| `ANALYTICS` | ❌ | ✅ |

## 🔒 Middleware de Protección

El middleware (`src/middleware.ts`) protege automáticamente las rutas en producción:

```typescript
// Rutas protegidas (redirigen a home en producción)
const PROTECTED_ROUTES = [
  '/lab/sqli',
  '/lab/xss',
  // ... otras rutas tradicionales
  '/evaluacion-madurez',
  '/matriz-normativas',
  '/guias',
  '/docs',
];

// Rutas siempre permitidas
const ALLOWED_ROUTES = [
  '/',
  '/lab/prompt-injection',
  '/blue-team',
];
```

## 🧪 Testing de Entornos

### Probar Modo Desarrollo
```bash
# 1. Configurar .env.local
echo "NEXT_PUBLIC_ENV=development" > .env.local

# 2. Iniciar servidor
npm run dev

# 3. Verificar en navegador
# - Todas las rutas deben estar visibles
# - Navigation debe mostrar todos los dropdowns
```

### Probar Modo Producción
```bash
# 1. Configurar .env.local
echo "NEXT_PUBLIC_ENV=production" > .env.local

# 2. Iniciar servidor
npm run dev:production

# 3. Verificar en navegador
# - Solo AI Lab y Blue Team visibles
# - Intentar acceder a /lab/sqli → redirige a home
# - Navigation solo muestra "Labs" con AI Lab
```

## 📊 Arquitectura de Archivos

```
Aitana.cloud/
├── .env.development          # Config desarrollo
├── .env.production           # Config producción
├── .env.local.example        # Template
├── src/
│   ├── config/
│   │   ├── features.ts       # Feature flags
│   │   └── routes.ts         # Rutas dinámicas
│   ├── middleware.ts         # Protección de rutas
│   └── components/
│       └── Navigation.tsx    # Nav dinámico
```

## 🔄 Flujo de Deployment

### Vercel (Recomendado)

1. **Environment Variables en Vercel Dashboard:**
   - Preview: `NEXT_PUBLIC_ENV=development`
   - Production: `NEXT_PUBLIC_ENV=production`

2. **Deploy:**
   ```bash
   # Preview deployment
   vercel

   # Production deployment
   vercel --prod
   ```

### Otros Servicios (Netlify, AWS, etc.)

1. Configurar variables de entorno en el dashboard
2. Especificar comando de build:
   ```bash
   npm run build:production
   ```

## 📝 Notas Importantes

⚠️ **Seguridad:**
- Las rutas están protegidas a nivel de middleware
- Usuarios no pueden acceder a rutas deshabilitadas
- No se envía código de labs deshabilitados al cliente

✅ **Performance:**
- Next.js tree-shaking elimina código no usado
- Build de producción es más ligero
- Menos JavaScript enviado al navegador

🎯 **Mantenimiento:**
- Agregar nuevas features en `src/config/features.ts`
- Agregar nuevas rutas en `src/config/routes.ts`
- El middleware y Navigation se actualizan automáticamente

## 🆘 Troubleshooting

### Problema: "Todas las rutas visibles en producción"
**Solución:**
```bash
# Verificar variable de entorno
echo $NEXT_PUBLIC_ENV

# Debe mostrar: production
# Si no, configurar en .env.local o Vercel dashboard
```

### Problema: "Navigation vacío"
**Solución:**
```bash
# Verificar que los imports estén correctos
# src/components/Navigation.tsx debe importar:
import { getEnabledRoutes, getRoutesByCategory } from "@/config/routes";
import { isFeatureEnabled } from "@/config/features";
```

### Problema: "Middleware no redirige"
**Solución:**
1. Verificar que `src/middleware.ts` existe
2. Verificar configuración en `export const config`
3. Reiniciar servidor de desarrollo

## 📚 Referencias

- [Next.js Environment Variables](https://nextjs.org/docs/app/building-your-application/configuring/environment-variables)
- [Next.js Middleware](https://nextjs.org/docs/app/building-your-application/routing/middleware)
- [Feature Flags Best Practices](https://martinfowler.com/articles/feature-toggles.html)
