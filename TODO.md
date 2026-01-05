# 📋 TODO - Aitana.cloud Improvements

**Fecha de creación:** 4 de enero de 2026  
**Versión:** 1.0.1  
**Proyecto:** Aitana Security Lab - CyberGuard Implementation

---

## ✅ COMPLETADO

### ✨ Sistema de Logos Dinámicos (Header + Footer)
**Fecha:** 4 de enero de 2026  
**Estado:** ✅ COMPLETADO

#### Implementación:
- ✅ Componente `Logo.tsx` creado con detección automática de tema
- ✅ Variante **Header** (Shield icon + gradiente blue)
- ✅ Variante **Footer** (Lock icon + gradiente purple/pink)
- ✅ Tamaños: sm (32px), md (48px), lg (64px)
- ✅ Adaptación automática dark/light mode
- ✅ MutationObserver para cambios de tema en tiempo real
- ✅ Integrado en Navigation component
- ✅ Integrado en Homepage footer
- ✅ Documentación completa en `LOGO_SYSTEM.md`
- ✅ 10 ejemplos de uso en `LOGO_EXAMPLES.md`

#### Archivos creados:
- `/src/components/Logo.tsx` (168 líneas)
- `/LOGO_SYSTEM.md` (documentación técnica)
- `/LOGO_EXAMPLES.md` (ejemplos prácticos)

#### Archivos modificados:
- `/src/components/Navigation.tsx` (integración header)
- `/src/app/page.tsx` (integración footer)

---

## 🎯 Tabla de Contenidos
1. [Tarea 1: Sistema de Temas Dinámicos (Dark/Light Mode)](#tarea-1-sistema-de-temas-dinámicos-darklight-mode) ✅ COMPLETADO
2. [Tarea 2: Separación de Entornos (Development/Production)](#tarea-2-separación-de-entornos-developmentproduction) ✅ COMPLETADO
3. [Tarea 3: Actualizar Sistema de Logos con Imágenes PNG](#tarea-3-actualizar-sistema-de-logos-con-imágenes-png)
4. [Tarea 4: Internacionalización (i18n) - Multi-idioma](#tarea-4-internacionalización-i18n---multi-idioma)
5. [Tarea 5: Corrección de Contrastes y Tipografía](#tarea-5-corrección-de-contrastes-y-tipografía)
6. [Tarea 6: Optimización de Componentes](#tarea-6-optimización-de-componentes)
7. [Tarea 7: Mejoras de Accesibilidad](#tarea-7-mejoras-de-accesibilidad)

---

## 📌 Tarea 3: Actualizar Sistema de Logos con Imágenes PNG

**Prioridad:** 🟠 ALTA  
**Estado:** ⬜ No iniciado  
**Estimación:** 2-3 horas  
**Responsable:** Frontend Team

### 🎯 Objetivo
Reemplazar los logos SVG dinámicos actuales por las nuevas imágenes PNG (white, black, footer, navigator) para mejorar la consistencia visual y el branding de la plataforma.

### 📝 Análisis Técnico

#### Archivos de Logo Disponibles:
1. **Logo Principal:**
   - `logo-white.png` - Modo oscuro / fondos oscuros
   - `logo-black.png` - Modo claro / fondos claros

2. **Logo Footer:**
   - `logo-footer.png` - Específico para pie de página

3. **Logo Navigator (Navegación):**
   - `logo-navigator-white.png` - Navegación en modo oscuro
   - `logo-navigator-black.png` - Navegación en modo claro

#### Ubicación de Archivos:
```
public/
├── logos/
│   ├── logo-white.png
│   ├── logo-black.png
│   ├── logo-footer.png
│   ├── logo-navigator-white.png
│   └── logo-navigator-black.png
```

### ✅ Subtareas

#### 3.1 Organizar Archivos de Logo
- [ ] **Acción:** Crear directorio `public/logos/`
- [ ] **Mover archivos:**
  ```bash
  mkdir -p public/logos
  mv logo-white.png public/logos/
  mv logo-black.png public/logos/
  mv logo-footer.png public/logos/
  mv logo-navigator-white.png public/logos/
  mv logo-navigator-black.png public/logos/
  ```
- [ ] **Verificar:** Que todas las imágenes estén en formato PNG optimizado
- [ ] **Tamaño recomendado:** 
  - Navigator: ~200x50px (ancho x alto)
  - Footer: ~180x45px
  - Principal: ~250x60px

#### 3.2 Actualizar Componente Logo
- [ ] **Archivo:** `src/components/Logo.tsx`
- [ ] **Reemplazar SVG por imágenes PNG:**
  ```typescript
  'use client';
  
  import Image from 'next/image';
  import Link from 'next/link';
  import { useTheme } from '@/hooks/useTheme';
  
  interface LogoProps {
    variant?: 'header' | 'footer' | 'navigator';
    size?: 'sm' | 'md' | 'lg';
  }
  
  export default function Logo({ variant = 'navigator', size = 'md' }: LogoProps) {
    const { effectiveTheme } = useTheme();
    
    // Determinar qué logo usar según variante y tema
    const getLogoSrc = () => {
      if (variant === 'footer') {
        return '/logos/logo-footer.png';
      }
      
      if (variant === 'navigator') {
        return effectiveTheme === 'dark' 
          ? '/logos/logo-navigator-white.png'
          : '/logos/logo-navigator-black.png';
      }
      
      // Variante 'header' o por defecto
      return effectiveTheme === 'dark'
        ? '/logos/logo-white.png'
        : '/logos/logo-black.png';
    };
    
    // Dimensiones según tamaño
    const dimensions = {
      sm: { width: 120, height: 32 },
      md: { width: 180, height: 48 },
      lg: { width: 240, height: 64 }
    };
    
    const { width, height } = dimensions[size];
    
    return (
      <Link href="/" className="inline-block">
        <Image
          src={getLogoSrc()}
          alt="Aitana Security Lab"
          width={width}
          height={height}
          priority
          className="transition-opacity hover:opacity-80"
        />
      </Link>
    );
  }
  ```

#### 3.3 Actualizar Navigation.tsx
- [ ] **Archivo:** `src/components/Navigation.tsx`
- [ ] **Cambiar variante a 'navigator':**
  ```typescript
  // En el header de Navigation.tsx
  <Logo variant="navigator" size="md" />
  ```
- [ ] **Verificar:** Que el logo se vea bien en dark/light mode
- [ ] **Testing:** Cambiar tema y verificar transición suave

#### 3.4 Actualizar Footer en page.tsx
- [ ] **Archivo:** `src/app/page.tsx`
- [ ] **Usar variante 'footer':**
  ```typescript
  // En la sección de footer
  <Logo variant="footer" size="md" />
  ```
- [ ] **Ajustar:** Espaciado si es necesario

#### 3.5 Optimizar Imágenes PNG
- [ ] **Herramienta:** TinyPNG o ImageOptim
- [ ] **Acción:** Optimizar todos los PNG sin pérdida de calidad
- [ ] **Objetivo:** Reducir tamaño de archivo en ~60-70%
- [ ] **Comando alternativo:**
  ```bash
  # Si tienes imagemagick instalado
  mogrify -strip -quality 85% public/logos/*.png
  ```

#### 3.6 Agregar Fallbacks y Alt Text
- [ ] **Actualizar componente con mejor accesibilidad:**
  ```typescript
  <Image
    src={getLogoSrc()}
    alt="Aitana Security Lab - Enterprise Security Training Platform"
    width={width}
    height={height}
    priority
    className="transition-opacity hover:opacity-80"
    onError={(e) => {
      // Fallback a logo por defecto si falla la carga
      e.currentTarget.src = '/logos/logo-white.png';
    }}
  />
  ```

#### 3.7 Actualizar Documentación
- [ ] **Archivo:** `LOGO_SYSTEM.md`
- [ ] **Agregar sección de imágenes PNG:**
  ```markdown
  ## Archivos de Logo PNG
  
  ### Variantes Disponibles
  
  1. **Navigator (Navegación)**
     - Ubicación: `/public/logos/logo-navigator-{white|black}.png`
     - Uso: Header de navegación
     - Tamaño: 180x48px
     - Adaptativo: Cambia según tema
  
  2. **Footer**
     - Ubicación: `/public/logos/logo-footer.png`
     - Uso: Pie de página
     - Tamaño: 180x48px
     - Color: Fijo (no cambia con tema)
  
  3. **Principal**
     - Ubicación: `/public/logos/logo-{white|black}.png`
     - Uso: General (splash screens, etc.)
     - Tamaño: 200x50px
     - Adaptativo: Cambia según tema
  ```

#### 3.8 Testing de Logos
- [ ] **Testing Visual:**
  - [ ] Logo navigator en modo oscuro (white)
  - [ ] Logo navigator en modo claro (black)
  - [ ] Logo footer en ambos modos
  - [ ] Transición suave al cambiar tema
  - [ ] Sin flash/parpadeo al cargar

- [ ] **Testing Responsive:**
  - [ ] Mobile (< 640px) - Logo se adapta
  - [ ] Tablet (640px - 1024px) - Tamaño correcto
  - [ ] Desktop (> 1024px) - Tamaño completo

- [ ] **Testing Performance:**
  - [ ] Next.js optimiza las imágenes automáticamente
  - [ ] Priority loading en logos above-the-fold
  - [ ] WebP automático si el navegador lo soporta

#### 3.9 Limpiar Código Antiguo
- [ ] **Eliminar:** SVG paths del componente Logo anterior
- [ ] **Eliminar:** Funciones de gradientes no usadas
- [ ] **Actualizar:** Imports innecesarios
- [ ] **Verificar:** No quedan referencias a logos SVG inline

#### 3.10 Agregar Favicon
- [ ] **Crear:** `favicon.ico` desde logo principal
- [ ] **Ubicación:** `public/favicon.ico`
- [ ] **Tamaños adicionales:**
  ```
  public/
  ├── favicon.ico (32x32)
  ├── apple-touch-icon.png (180x180)
  ├── icon-192.png (192x192)
  └── icon-512.png (512x512)
  ```
- [ ] **Actualizar layout.tsx:**
  ```typescript
  export const metadata: Metadata = {
    icons: {
      icon: '/favicon.ico',
      apple: '/apple-touch-icon.png',
    }
  };
  ```

### 📊 Criterios de Aceptación
- ✅ Logos PNG correctamente ubicados en `/public/logos/`
- ✅ Componente `Logo.tsx` usa `next/image` con las nuevas imágenes
- ✅ Logo navigator cambia según tema (white/black)
- ✅ Logo footer se muestra correctamente
- ✅ Sin flash/parpadeo al cargar o cambiar tema
- ✅ Imágenes optimizadas (tamaño de archivo < 50KB cada una)
- ✅ Alt text descriptivo para accesibilidad
- ✅ Priority loading en logos above-the-fold
- ✅ Responsive en todos los breakpoints
- ✅ Documentación actualizada

---

## 📌 Tarea 4: Internacionalización (i18n) - Multi-idioma

**Prioridad:** 🔴 CRÍTICA  
**Estado:** ⬜ No iniciado  
**Estimación:** 6-8 horas  
**Responsable:** Development Team

### 🎯 Objetivo
Implementar un sistema completo de temas (claro/oscuro) con detección automática de preferencias del sistema y persistencia de selección del usuario, solucionando el problema actual de texto negro sobre fondo oscuro.

### 📝 Análisis Técnico

#### Problemas Actuales Detectados:
1. **Texto invisible:** Clases como `text-black` en fondos `bg-cyber-dark-*`
2. **Sin gestión de tema:** No existe contexto global para el tema
3. **Colores hardcoded:** Variables CSS no adaptativas
4. **Sin persistencia:** El tema no se guarda entre sesiones

#### Arquitectura Propuesta:
```
src/
├── contexts/
│   └── ThemeContext.tsx          # Contexto global de tema
├── hooks/
│   └── useTheme.ts                # Hook personalizado
├── app/
│   ├── globals.css                # Variables CSS actualizadas
│   └── layout.tsx                 # Provider de tema
└── components/
    └── ThemeToggle.tsx            # Botón toggle
```

### ✅ Subtareas

#### 1.1 Crear ThemeContext y Provider
- [ ] **Archivo:** `src/contexts/ThemeContext.tsx`
- [ ] **Contenido técnico:**
  ```typescript
  import { createContext, useContext, useState, useEffect } from 'react';
  
  type Theme = 'light' | 'dark' | 'system';
  
  interface ThemeContextType {
    theme: Theme;
    effectiveTheme: 'light' | 'dark';
    setTheme: (theme: Theme) => void;
  }
  
  export const ThemeContext = createContext<ThemeContextType>({
    theme: 'system',
    effectiveTheme: 'dark',
    setTheme: () => {}
  });
  
  export function ThemeProvider({ children }: { children: React.ReactNode }) {
    const [theme, setThemeState] = useState<Theme>('system');
    const [effectiveTheme, setEffectiveTheme] = useState<'light' | 'dark'>('dark');
    
    // Detectar preferencia del sistema
    useEffect(() => {
      const mediaQuery = window.matchMedia('(prefers-color-scheme: dark)');
      const updateTheme = () => {
        if (theme === 'system') {
          setEffectiveTheme(mediaQuery.matches ? 'dark' : 'light');
        }
      };
      
      updateTheme();
      mediaQuery.addEventListener('change', updateTheme);
      return () => mediaQuery.removeEventListener('change', updateTheme);
    }, [theme]);
    
    // Persistir en localStorage
    useEffect(() => {
      const saved = localStorage.getItem('theme') as Theme;
      if (saved) setThemeState(saved);
    }, []);
    
    const setTheme = (newTheme: Theme) => {
      setThemeState(newTheme);
      localStorage.setItem('theme', newTheme);
      if (newTheme !== 'system') {
        setEffectiveTheme(newTheme);
      }
    };
    
    // Aplicar al document
    useEffect(() => {
      document.documentElement.classList.remove('light', 'dark');
      document.documentElement.classList.add(effectiveTheme);
    }, [effectiveTheme]);
    
    return (
      <ThemeContext.Provider value={{ theme, effectiveTheme, setTheme }}>
        {children}
      </ThemeContext.Provider>
    );
  }
  ```
- [ ] **Testing:** Verificar que detecta preferencias del sistema
- [ ] **Testing:** Verificar persistencia en localStorage

#### 1.2 Actualizar Variables CSS en globals.css
- [ ] **Archivo:** `src/app/globals.css`
- [ ] **Acción:** Añadir variables CSS adaptativas
- [ ] **Código técnico:**
  ```css
  @layer base {
    :root {
      /* Light Mode - CyberGuard Light */
      --bg-primary: 240 240 244;        /* #F0F0F4 */
      --bg-secondary: 255 255 255;      /* #FFFFFF */
      --bg-tertiary: 245 245 248;       /* #F5F5F8 */
      
      --text-primary: 30 30 30;         /* #1E1E1E */
      --text-secondary: 100 100 120;    /* #646478 */
      --text-muted: 120 120 140;        /* #78788C */
      
      --border-color: 220 220 230;      /* #DCDCE6 */
      --border-hover: 180 180 200;      /* #B4B4C8 */
      
      /* Accent Colors (same in both) */
      --accent-blue: 37 99 235;         /* #2563EB */
      --accent-purple: 139 92 246;      /* #8B5CF6 */
      --accent-green: 34 197 94;        /* #22C55E */
      --accent-red: 239 68 68;          /* #EF4444 */
    }
    
    .dark {
      /* Dark Mode - CyberGuard Dark */
      --bg-primary: 30 30 30;           /* #1E1E1E (cyber-dark-3) */
      --bg-secondary: 18 13 79;         /* #120D4F (cyber-dark-2) */
      --bg-tertiary: 27 22 99;          /* #1B1663 (cyber-dark-1) */
      
      --text-primary: 255 255 255;      /* #FFFFFF */
      --text-secondary: 200 200 210;    /* #C8C8D2 */
      --text-muted: 150 150 170;        /* #9696AA */
      
      --border-color: 60 60 80;         /* #3C3C50 */
      --border-hover: 100 100 130;      /* #646482 */
      
      /* Accent Colors (same in both) */
      --accent-blue: 59 130 246;        /* #3B82F6 */
      --accent-purple: 168 85 247;      /* #A855F7 */
      --accent-green: 34 197 94;        /* #22C55E */
      --accent-red: 248 113 113;        /* #F87171 */
    }
  }
  
  /* Utility Classes */
  .bg-primary { background-color: rgb(var(--bg-primary)); }
  .bg-secondary { background-color: rgb(var(--bg-secondary)); }
  .bg-tertiary { background-color: rgb(var(--bg-tertiary)); }
  
  .text-primary { color: rgb(var(--text-primary)); }
  .text-secondary { color: rgb(var(--text-secondary)); }
  .text-muted { color: rgb(var(--text-muted)); }
  
  .border-default { border-color: rgb(var(--border-color)); }
  ```
- [ ] **Testing:** Verificar contraste WCAG 2.1 AA (mínimo 4.5:1)

#### 1.3 Crear Hook useTheme
- [ ] **Archivo:** `src/hooks/useTheme.ts`
- [ ] **Código:**
  ```typescript
  import { useContext } from 'react';
  import { ThemeContext } from '@/contexts/ThemeContext';
  
  export function useTheme() {
    const context = useContext(ThemeContext);
    if (!context) {
      throw new Error('useTheme must be used within ThemeProvider');
    }
    return context;
  }
  ```

#### 1.4 Crear Componente ThemeToggle
- [ ] **Archivo:** `src/components/ThemeToggle.tsx`
- [ ] **Ubicación:** Añadir en Navigation.tsx (topbar derecha)
- [ ] **Código técnico:**
  ```typescript
  'use client';
  
  import { useTheme } from '@/hooks/useTheme';
  
  export default function ThemeToggle() {
    const { theme, effectiveTheme, setTheme } = useTheme();
    
    return (
      <button
        onClick={() => setTheme(effectiveTheme === 'dark' ? 'light' : 'dark')}
        className="p-2 rounded-cyber bg-primary hover:bg-secondary border border-default transition-all"
        aria-label="Toggle theme"
      >
        {effectiveTheme === 'dark' ? (
          <svg className="w-5 h-5 text-primary" fill="currentColor" viewBox="0 0 20 20">
            <path d="M17.293 13.293A8 8 0 016.707 2.707a8.001 8.001 0 1010.586 10.586z" />
          </svg>
        ) : (
          <svg className="w-5 h-5 text-primary" fill="currentColor" viewBox="0 0 20 20">
            <path fillRule="evenodd" d="M10 2a1 1 0 011 1v1a1 1 0 11-2 0V3a1 1 0 011-1zm4 8a4 4 0 11-8 0 4 4 0 018 0zm-.464 4.95l.707.707a1 1 0 001.414-1.414l-.707-.707a1 1 0 00-1.414 1.414zm2.12-10.607a1 1 0 010 1.414l-.706.707a1 1 0 11-1.414-1.414l.707-.707a1 1 0 011.414 0zM17 11a1 1 0 100-2h-1a1 1 0 100 2h1zm-7 4a1 1 0 011 1v1a1 1 0 11-2 0v-1a1 1 0 011-1zM5.05 6.464A1 1 0 106.465 5.05l-.708-.707a1 1 0 00-1.414 1.414l.707.707zm1.414 8.486l-.707.707a1 1 0 01-1.414-1.414l.707-.707a1 1 0 011.414 1.414zM4 11a1 1 0 100-2H3a1 1 0 000 2h1z" clipRule="evenodd" />
          </svg>
        )}
      </button>
    );
  }
  ```

#### 1.5 Actualizar layout.tsx
- [ ] **Archivo:** `src/app/layout.tsx`
- [ ] **Acción:** Envolver app con ThemeProvider
- [ ] **Código:**
  ```typescript
  import { ThemeProvider } from '@/contexts/ThemeContext';
  
  export default function RootLayout({ children }: { children: React.ReactNode }) {
    return (
      <html lang="es" suppressHydrationWarning>
        <body>
          <ThemeProvider>
            {children}
          </ThemeProvider>
        </body>
      </html>
    );
  }
  ```

#### 1.6 Migrar Clases de Color en Componentes
- [ ] **Archivos afectados:**
  - `src/app/page.tsx`
  - `src/components/Navigation.tsx`
  - Todos los archivos en `src/lab/**/page.tsx`
- [ ] **Acción:** Reemplazar clases hardcoded
- [ ] **Conversiones:**
  | Antes | Después |
  |-------|---------|
  | `bg-cyber-dark-3` | `bg-primary` |
  | `bg-cyber-dark-2` | `bg-secondary` |
  | `bg-cyber-dark-1` | `bg-tertiary` |
  | `text-white` | `text-primary` |
  | `text-white/80` | `text-secondary` |
  | `text-white/60` | `text-muted` |
  | `border-white/10` | `border-default` |

#### 1.7 Testing y QA
- [ ] **Verificar contraste:**
  - Light mode: Ratio mínimo 4.5:1
  - Dark mode: Ratio mínimo 4.5:1
- [ ] **Verificar persistencia:**
  - Recargar página mantiene tema
  - localStorage funciona correctamente
- [ ] **Verificar detección de sistema:**
  - Modo "system" cambia con preferencias OS
- [ ] **Testing en navegadores:**
  - Chrome/Edge
  - Firefox
  - Safari
- [ ] **Testing responsive:**
  - Mobile (iOS/Android)
  - Tablet
  - Desktop

### 📊 Criterios de Aceptación
- ✅ El usuario puede cambiar entre modo claro y oscuro
- ✅ El tema seleccionado persiste entre sesiones
- ✅ El modo "system" detecta automáticamente preferencias del OS
- ✅ Todos los textos son legibles (contraste WCAG AA)
- ✅ Las transiciones de tema son suaves (300ms)
- ✅ No hay flash de contenido incorrecto (FOUC)

---

## 📌 Tarea 2: Separación de Entornos (Development/Production)

**Prioridad:** 🔴 CRÍTICA  
**Estado:** ⬜ No iniciado  
**Estimación:** 8-10 horas  
**Responsable:** DevOps Team

### 🎯 Objetivo
Crear dos entornos completamente separados: uno de desarrollo con todas las funcionalidades y otro de producción únicamente con labs de Blue Team y Red Team (AI).

### 📝 Análisis Técnico

#### Arquitectura de Entornos:
```
Aitana.cloud/
├── .env.development          # Variables de desarrollo
├── .env.production           # Variables de producción
├── next.config.ts            # Configuración dual
├── src/
│   ├── config/
│   │   ├── features.ts       # Feature flags
│   │   └── routes.ts         # Rutas por entorno
│   ├── middleware.ts         # Protección de rutas
│   └── app/
│       ├── (dev)/            # Rutas solo desarrollo
│       └── (production)/     # Rutas producción
```

#### Features por Entorno:

| Feature | Development | Production |
|---------|-------------|------------|
| AI Red Team Lab | ✅ | ✅ |
| Prompt Injection (8 niveles) | ✅ | ✅ |
| Vulnerability Labs (14) | ✅ | ❌ |
| SSDLC Assessment | ✅ | ❌ |
| API Documentation | ✅ | ❌ |
| Matriz Normativas | ✅ | ❌ |
| Guías SSDLC | ✅ | ❌ |
| Analytics & Logs | ✅ | ✅ |

### ✅ Subtareas

#### 2.1 Crear Archivos de Configuración de Entorno
- [ ] **Archivo:** `.env.development`
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

- [ ] **Archivo:** `.env.production`
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

- [ ] **Testing:** Verificar variables en ambos entornos

#### 2.2 Crear Sistema de Feature Flags
- [ ] **Archivo:** `src/config/features.ts`
  ```typescript
  export const FEATURES = {
    // Blue Team Labs (Production + Development)
    BLUE_TEAM: process.env.NEXT_PUBLIC_ENV !== 'production' || true,
    
    // Red Team Labs - AI (Production + Development)
    RED_TEAM_AI: true,
    PROMPT_INJECTION: true,
    
    // Red Team Labs - Traditional (Solo Development)
    RED_TEAM_TRADITIONAL: process.env.NEXT_PUBLIC_ENABLE_ALL_LABS === 'true',
    SQLI: process.env.NEXT_PUBLIC_ENABLE_ALL_LABS === 'true',
    XSS: process.env.NEXT_PUBLIC_ENABLE_ALL_LABS === 'true',
    AUTH: process.env.NEXT_PUBLIC_ENABLE_ALL_LABS === 'true',
    SENSITIVE_DATA: process.env.NEXT_PUBLIC_ENABLE_ALL_LABS === 'true',
    ACCESS_CONTROL: process.env.NEXT_PUBLIC_ENABLE_ALL_LABS === 'true',
    MISCONFIG: process.env.NEXT_PUBLIC_ENABLE_ALL_LABS === 'true',
    COMMAND_INJECTION: process.env.NEXT_PUBLIC_ENABLE_ALL_LABS === 'true',
    XXE: process.env.NEXT_PUBLIC_ENABLE_ALL_LABS === 'true',
    LDAP: process.env.NEXT_PUBLIC_ENABLE_ALL_LABS === 'true',
    SSTI: process.env.NEXT_PUBLIC_ENABLE_ALL_LABS === 'true',
    SESSION_FIXATION: process.env.NEXT_PUBLIC_ENABLE_ALL_LABS === 'true',
    CSP: process.env.NEXT_PUBLIC_ENABLE_ALL_LABS === 'true',
    FILE_UPLOAD: process.env.NEXT_PUBLIC_ENABLE_ALL_LABS === 'true',
    
    // Other Features (Solo Development)
    SSDLC_ASSESSMENT: process.env.NEXT_PUBLIC_ENABLE_SSDLC === 'true',
    API_DOCS: process.env.NEXT_PUBLIC_ENABLE_DOCS === 'true',
    COMPLIANCE_MATRIX: process.env.NEXT_PUBLIC_ENABLE_MATRIX === 'true',
    SSDLC_GUIDES: process.env.NEXT_PUBLIC_ENABLE_GUIDES === 'true',
    
    // Analytics
    ANALYTICS: process.env.NEXT_PUBLIC_ANALYTICS === 'true'
  } as const;
  
  export function isFeatureEnabled(feature: keyof typeof FEATURES): boolean {
    return FEATURES[feature];
  }
  ```

- [ ] **Testing:** Verificar flags en desarrollo
- [ ] **Testing:** Verificar flags en producción

#### 2.3 Crear Configuración de Rutas
- [ ] **Archivo:** `src/config/routes.ts`
  ```typescript
  import { FEATURES } from './features';
  
  export interface Route {
    path: string;
    label: string;
    enabled: boolean;
    icon?: string;
    category: 'blue-team' | 'red-team' | 'tools' | 'docs';
  }
  
  export const ROUTES: Route[] = [
    // Blue Team (Siempre visible)
    {
      path: '/blue-team',
      label: 'Blue Team Defense',
      enabled: FEATURES.BLUE_TEAM,
      icon: '🛡️',
      category: 'blue-team'
    },
    
    // Red Team - AI (Producción + Desarrollo)
    {
      path: '/lab/prompt-injection',
      label: '🎯 AI Red Team Lab',
      enabled: FEATURES.PROMPT_INJECTION,
      icon: '🤖',
      category: 'red-team'
    },
    
    // Red Team - Traditional (Solo Desarrollo)
    {
      path: '/lab/sqli',
      label: 'SQL Injection',
      enabled: FEATURES.SQLI,
      icon: '🛡️',
      category: 'red-team'
    },
    {
      path: '/lab/xss',
      label: 'Cross-Site Scripting',
      enabled: FEATURES.XSS,
      icon: '⚡',
      category: 'red-team'
    },
    {
      path: '/lab/auth',
      label: 'Broken Authentication',
      enabled: FEATURES.AUTH,
      icon: '🔐',
      category: 'red-team'
    },
    {
      path: '/lab/sensitive-data',
      label: 'Sensitive Data Exposure',
      enabled: FEATURES.SENSITIVE_DATA,
      icon: '📡',
      category: 'red-team'
    },
    {
      path: '/lab/access-control',
      label: 'Broken Access Control',
      enabled: FEATURES.ACCESS_CONTROL,
      icon: '🔑',
      category: 'red-team'
    },
    {
      path: '/lab/misconfig',
      label: 'Security Misconfiguration',
      enabled: FEATURES.MISCONFIG,
      icon: '⚙️',
      category: 'red-team'
    },
    
    // Tools (Solo Desarrollo)
    {
      path: '/evaluacion-madurez',
      label: 'SSDLC Assessment',
      enabled: FEATURES.SSDLC_ASSESSMENT,
      icon: '📊',
      category: 'tools'
    },
    {
      path: '/matriz-normativas',
      label: 'Compliance Matrix',
      enabled: FEATURES.COMPLIANCE_MATRIX,
      icon: '📋',
      category: 'tools'
    },
    {
      path: '/guias',
      label: 'SSDLC Guides',
      enabled: FEATURES.SSDLC_GUIDES,
      icon: '📚',
      category: 'docs'
    },
    {
      path: '/docs',
      label: 'API Documentation',
      enabled: FEATURES.API_DOCS,
      icon: '📄',
      category: 'docs'
    }
  ];
  
  export function getEnabledRoutes(): Route[] {
    return ROUTES.filter(route => route.enabled);
  }
  
  export function getRoutesByCategory(category: Route['category']): Route[] {
    return getEnabledRoutes().filter(route => route.category === category);
  }
  ```

#### 2.4 Crear Middleware de Protección
- [ ] **Archivo:** `src/middleware.ts`
  ```typescript
  import { NextResponse } from 'next/server';
  import type { NextRequest } from 'next/server';
  
  const PROTECTED_ROUTES = [
    '/lab/sqli',
    '/lab/xss',
    '/lab/auth',
    '/lab/sensitive-data',
    '/lab/access-control',
    '/lab/misconfig',
    '/lab/command-injection',
    '/lab/xxe',
    '/lab/ldap',
    '/lab/ssti',
    '/lab/session-fixation',
    '/lab/csp',
    '/lab/file-upload',
    '/evaluacion-madurez',
    '/matriz-normativas',
    '/guias',
    '/docs'
  ];
  
  const ALWAYS_ALLOWED = [
    '/lab/prompt-injection',
    '/blue-team',
    '/',
    '/_next',
    '/api'
  ];
  
  export function middleware(request: NextRequest) {
    const { pathname } = request.nextUrl;
    const isProduction = process.env.NEXT_PUBLIC_ENV === 'production';
    
    // Permitir rutas siempre accesibles
    if (ALWAYS_ALLOWED.some(route => pathname.startsWith(route))) {
      return NextResponse.next();
    }
    
    // En producción, bloquear rutas protegidas
    if (isProduction && PROTECTED_ROUTES.some(route => pathname.startsWith(route))) {
      return NextResponse.redirect(new URL('/', request.url));
    }
    
    return NextResponse.next();
  }
  
  export const config = {
    matcher: [
      /*
       * Match all request paths except:
       * - _next/static (static files)
       * - _next/image (image optimization files)
       * - favicon.ico (favicon file)
       */
      '/((?!_next/static|_next/image|favicon.ico).*)',
    ],
  };
  ```

- [ ] **Testing:** Verificar redirección en producción
- [ ] **Testing:** Verificar acceso en desarrollo

#### 2.5 Actualizar Navigation Component
- [ ] **Archivo:** `src/components/Navigation.tsx`
- [ ] **Acción:** Filtrar menú dinámicamente
- [ ] **Código:**
  ```typescript
  import { getEnabledRoutes, getRoutesByCategory } from '@/config/routes';
  
  export default function Navigation() {
    const enabledRoutes = getEnabledRoutes();
    const redTeamRoutes = getRoutesByCategory('red-team');
    const toolsRoutes = getRoutesByCategory('tools');
    const docsRoutes = getRoutesByCategory('docs');
    
    return (
      <nav>
        {/* Mostrar solo rutas habilitadas */}
        {redTeamRoutes.length > 0 && (
          <div className="dropdown">
            <span>Red Team</span>
            <ul>
              {redTeamRoutes.map(route => (
                <li key={route.path}>
                  <Link href={route.path}>
                    {route.icon} {route.label}
                  </Link>
                </li>
              ))}
            </ul>
          </div>
        )}
        
        {toolsRoutes.length > 0 && (
          <div className="dropdown">
            <span>Tools</span>
            <ul>
              {toolsRoutes.map(route => (
                <li key={route.path}>
                  <Link href={route.path}>
                    {route.icon} {route.label}
                  </Link>
                </li>
              ))}
            </ul>
          </div>
        )}
      </nav>
    );
  }
  ```

#### 2.6 Actualizar Homepage
- [ ] **Archivo:** `src/app/page.tsx`
- [ ] **Acción:** Filtrar servicios mostrados
- [ ] **Código:**
  ```typescript
  import { FEATURES } from '@/config/features';
  import { getRoutesByCategory } from '@/config/routes';
  
  export default function Home() {
    const services = [
      { icon: "🛡️", title: "SQL Injection", path: "/lab/sqli", enabled: FEATURES.SQLI },
      { icon: "⚡", title: "XSS", path: "/lab/xss", enabled: FEATURES.XSS },
      // ... resto de servicios con su flag enabled
    ].filter(service => service.enabled);
    
    return (
      <div>
        {/* Solo mostrar servicios habilitados */}
        {services.map(service => (
          <ServiceCard key={service.path} {...service} />
        ))}
      </div>
    );
  }
  ```

#### 2.7 Scripts de Deployment
- [ ] **Archivo:** `package.json`
- [ ] **Actualizar scripts:**
  ```json
  {
    "scripts": {
      "dev": "next dev --turbo",
      "build:dev": "NEXT_PUBLIC_ENV=development next build",
      "build:prod": "NEXT_PUBLIC_ENV=production next build",
      "start": "next start",
      "preview:dev": "npm run build:dev && npm start",
      "preview:prod": "npm run build:prod && npm start",
      "deploy:dev": "vercel --env NEXT_PUBLIC_ENV=development",
      "deploy:prod": "vercel --prod --env NEXT_PUBLIC_ENV=production"
    }
  }
  ```

#### 2.8 Crear Componente de Badge de Entorno
- [ ] **Archivo:** `src/components/EnvironmentBadge.tsx`
- [ ] **Ubicación:** Mostrar en esquina inferior derecha solo en development
- [ ] **Código:**
  ```typescript
  'use client';
  
  export default function EnvironmentBadge() {
    const env = process.env.NEXT_PUBLIC_ENV;
    
    if (env === 'production') return null;
    
    return (
      <div className="fixed bottom-4 right-4 z-50 px-3 py-1 bg-yellow-500/90 text-black text-xs font-bold rounded-cyber shadow-lg">
        🔧 {env?.toUpperCase()} MODE
      </div>
    );
  }
  ```

#### 2.9 Documentación de Entornos
- [ ] **Archivo:** `ENVIRONMENTS.md`
- [ ] **Contenido:**
  ```markdown
  # Guía de Entornos - Aitana.cloud
  
  ## Development
  - URL: http://localhost:3000
  - Features: Todas habilitadas
  - Propósito: Testing y desarrollo de nuevas features
  - Comando: `npm run dev`
  
  ## Production
  - URL: https://aitana.cloud
  - Features: Solo Blue Team + AI Red Team
  - Propósito: Entrenamiento público estable
  - Comando: `npm run deploy:prod`
  
  ## Cambiar entre entornos
  ```bash
  # Desarrollo local
  npm run dev
  
  # Preview de producción local
  npm run preview:prod
  
  # Deploy a producción
  npm run deploy:prod
  ```
  ```

#### 2.10 Testing de Entornos
- [ ] **Testing Development:**
  - Todas las rutas accesibles
  - 14 vulnerability labs visibles
  - SSDLC Assessment visible
  - API Docs visible
  - Badge de entorno visible

- [ ] **Testing Production:**
  - Solo AI Red Team accesible
  - Blue Team accesible
  - Homepage sin labs tradicionales
  - Middleware redirige correctamente
  - No badge de entorno

### 📊 Criterios de Aceptación
- ✅ Desarrollo muestra todas las funcionalidades (14 labs + tools)
- ✅ Producción solo muestra Blue Team + AI Red Team
- ✅ El middleware bloquea rutas protegidas en producción
- ✅ La navegación se adapta dinámicamente al entorno
- ✅ Las variables de entorno se cargan correctamente
- ✅ Los builds son independientes (dev/prod)
- ✅ El badge de entorno solo aparece en development

---

## 📌 Tarea 5: Corrección de Contrastes y Tipografía

**Prioridad:** 🟡 MEDIA  
**Estado:** ⬜ No iniciado  
**Estimación:** 10-12 horas  
**Responsable:** Frontend Team

### 🎯 Objetivo
Implementar sistema de internacionalización que detecte automáticamente el idioma del usuario basándose en su ubicación/navegador y permita cambio manual entre idiomas.

### 📝 Análisis Técnico

#### Idiomas a Soportar (Fase 1):
1. **🇪🇸 Español (es)** - Por defecto (España)
2. **🇬🇧 Inglés (en)** - Internacional
3. **🇫🇷 Francés (fr)** - Europa
4. **🇩🇪 Alemán (de)** - Europa

#### Arquitectura Propuesta:
```
src/
├── i18n/
│   ├── config.ts                 # Configuración i18n
│   ├── locales/
│   │   ├── es.json              # Traducciones español
│   │   ├── en.json              # Traducciones inglés
│   │   ├── fr.json              # Traducciones francés
│   │   └── de.json              # Traducciones alemán
│   └── utils.ts                 # Utilidades i18n
├── contexts/
│   └── LanguageContext.tsx      # Context de idioma
├── hooks/
│   └── useTranslation.ts        # Hook t()
└── middleware.ts                # Detección de idioma
```

### ✅ Subtareas

#### 3.1 Instalar next-intl
- [ ] **Comando:**
  ```bash
  npm install next-intl
  ```
- [ ] **Configuración:** `next.config.ts`
  ```typescript
  import createNextIntlPlugin from 'next-intl/plugin';
  
  const withNextIntl = createNextIntlPlugin();
  
  export default withNextIntl({
    // next config
  });
  ```

#### 3.2 Crear Archivos de Traducción
- [ ] **Archivo:** `src/i18n/locales/es.json`
  ```json
  {
    "common": {
      "appName": "Aitana Security Lab",
      "tagline": "Plataforma de Entrenamiento en Seguridad"
    },
    "nav": {
      "home": "Inicio",
      "labs": "Laboratorios",
      "tools": "Herramientas",
      "guides": "Guías SSDLC",
      "docs": "Documentación API"
    },
    "home": {
      "hero": {
        "title": "Domina la Ciberseguridad a Través de la Práctica",
        "subtitle": "Plataforma de Entrenamiento Empresarial",
        "cta": "Comenzar Ahora"
      },
      "about": {
        "title": "Laboratorios Prácticos de Seguridad para Vulnerabilidades Modernas",
        "description": "Domina vulnerabilidades del mundo real a través de práctica hands-on..."
      }
    },
    "labs": {
      "sqli": {
        "title": "Inyección SQL",
        "description": "Manipulación de consultas de base de datos"
      },
      "xss": {
        "title": "Cross-Site Scripting",
        "description": "Inyección de código en el cliente"
      }
    }
  }
  ```

- [ ] **Archivo:** `src/i18n/locales/en.json`
  ```json
  {
    "common": {
      "appName": "Aitana Security Lab",
      "tagline": "Security Training Platform"
    },
    "nav": {
      "home": "Home",
      "labs": "Labs",
      "tools": "Tools",
      "guides": "SSDLC Guides",
      "docs": "API Docs"
    },
    "home": {
      "hero": {
        "title": "Master Cybersecurity Through Practice",
        "subtitle": "Enterprise Security Training Platform",
        "cta": "Start Learning Now"
      },
      "about": {
        "title": "Practical Security Labs for Modern Vulnerabilities",
        "description": "Master real-world security vulnerabilities through hands-on practice..."
      }
    },
    "labs": {
      "sqli": {
        "title": "SQL Injection",
        "description": "Database query manipulation"
      },
      "xss": {
        "title": "Cross-Site Scripting",
        "description": "Client-side code injection"
      }
    }
  }
  ```

- [ ] **Crear también:** `fr.json`, `de.json` (traducciones)

#### 3.3 Configurar i18n
- [ ] **Archivo:** `src/i18n/config.ts`
  ```typescript
  export const locales = ['es', 'en', 'fr', 'de'] as const;
  export type Locale = typeof locales[number];
  
  export const defaultLocale: Locale = 'es';
  
  export const localeNames: Record<Locale, string> = {
    es: 'Español',
    en: 'English',
    fr: 'Français',
    de: 'Deutsch'
  };
  
  export const localeFlags: Record<Locale, string> = {
    es: '🇪🇸',
    en: '🇬🇧',
    fr: '🇫🇷',
    de: '🇩🇪'
  };
  ```

#### 3.4 Middleware de Detección de Idioma
- [ ] **Archivo:** `src/middleware.ts`
- [ ] **Agregar lógica:**
  ```typescript
  import createMiddleware from 'next-intl/middleware';
  import { locales, defaultLocale } from './i18n/config';
  
  const intlMiddleware = createMiddleware({
    locales,
    defaultLocale,
    localePrefix: 'as-needed' // /es/labs o /labs (español por defecto)
  });
  
  export default async function middleware(request: NextRequest) {
    // Primero verificar idioma
    const response = intlMiddleware(request);
    
    // Luego aplicar feature flags (código existente)
    // ...
    
    return response;
  }
  ```

#### 3.5 LanguageContext y Hook
- [ ] **Archivo:** `src/contexts/LanguageContext.tsx`
  ```typescript
  'use client';
  
  import { createContext, useContext } from 'react';
  import { useRouter, usePathname } from 'next/navigation';
  import type { Locale } from '@/i18n/config';
  
  interface LanguageContextType {
    locale: Locale;
    setLocale: (locale: Locale) => void;
  }
  
  export const LanguageContext = createContext<LanguageContextType | undefined>(undefined);
  
  export function useLanguage() {
    const context = useContext(LanguageContext);
    if (!context) {
      throw new Error('useLanguage must be used within LanguageProvider');
    }
    return context;
  }
  ```

- [ ] **Archivo:** `src/hooks/useTranslation.ts`
  ```typescript
  import { useTranslations } from 'next-intl';
  
  export function useTranslation(namespace?: string) {
    return useTranslations(namespace);
  }
  ```

#### 3.6 Componente Language Selector
- [ ] **Archivo:** `src/components/LanguageSelector.tsx`
  ```typescript
  'use client';
  
  import { useRouter, usePathname } from 'next/navigation';
  import { locales, localeFlags, localeNames, type Locale } from '@/i18n/config';
  
  export default function LanguageSelector() {
    const router = useRouter();
    const pathname = usePathname();
    
    const handleLocaleChange = (locale: Locale) => {
      // Cambiar idioma manteniendo la ruta actual
      const newPath = pathname.replace(/^\/[a-z]{2}/, `/${locale}`);
      router.push(newPath);
    };
    
    return (
      <div className="relative group">
        <button className="flex items-center gap-2 px-3 py-2 bg-secondary rounded-cyber">
          <span>🌐</span>
          <svg className="w-4 h-4" /* chevron down */ />
        </button>
        
        <div className="absolute dropdown">
          {locales.map(locale => (
            <button
              key={locale}
              onClick={() => handleLocaleChange(locale)}
              className="flex items-center gap-2"
            >
              <span>{localeFlags[locale]}</span>
              <span>{localeNames[locale]}</span>
            </button>
          ))}
        </div>
      </div>
    );
  }
  ```

#### 3.7 Actualizar Navigation
- [ ] **Archivo:** `src/components/Navigation.tsx`
- [ ] **Agregar selector de idioma:**
  ```typescript
  import LanguageSelector from './LanguageSelector';
  import { useTranslation } from '@/hooks/useTranslation';
  
  export default function Navigation() {
    const t = useTranslation('nav');
    
    return (
      <nav>
        <Link href="/">{t('home')}</Link>
        <Link href="/labs">{t('labs')}</Link>
        {/* ... */}
        
        {/* Selector de idioma junto a ThemeToggle */}
        <LanguageSelector />
        <ThemeToggle />
      </nav>
    );
  }
  ```

#### 3.8 Actualizar Homepage
- [ ] **Archivo:** `src/app/[locale]/page.tsx`
- [ ] **Migrar de hardcoded a traducciones:**
  ```typescript
  import { useTranslation } from '@/hooks/useTranslation';
  
  export default function Home() {
    const t = useTranslation('home');
    
    return (
      <section>
        <h1>{t('hero.title')}</h1>
        <p>{t('hero.subtitle')}</p>
        <button>{t('hero.cta')}</button>
      </section>
    );
  }
  ```

#### 3.9 Detección Automática de Idioma
- [ ] **Métodos de detección (en orden):**
  1. **Cookie persistente:** `NEXT_LOCALE`
  2. **Header Accept-Language:** Del navegador
  3. **Geolocalización IP:** País del usuario
  4. **Fallback:** Español por defecto

- [ ] **Implementar en middleware:**
  ```typescript
  function detectLocale(request: NextRequest): Locale {
    // 1. Cookie
    const cookieLocale = request.cookies.get('NEXT_LOCALE')?.value;
    if (cookieLocale && locales.includes(cookieLocale as Locale)) {
      return cookieLocale as Locale;
    }
    
    // 2. Accept-Language header
    const acceptLanguage = request.headers.get('accept-language');
    if (acceptLanguage) {
      const browserLocale = acceptLanguage.split(',')[0].split('-')[0];
      if (locales.includes(browserLocale as Locale)) {
        return browserLocale as Locale;
      }
    }
    
    // 3. Fallback
    return defaultLocale;
  }
  ```

#### 3.10 Migrar Todo el Contenido
- [ ] **Componentes a migrar:**
  - [ ] `Navigation.tsx` - Menú principal
  - [ ] `page.tsx` - Homepage completa
  - [ ] `Footer` - Pie de página
  - [ ] Todos los labs (`/lab/**/page.tsx`)
  - [ ] SSDLC Assessment
  - [ ] Guías
  - [ ] API Docs

- [ ] **Crear archivos de traducción por sección:**
  - [ ] `common.json` - Textos comunes
  - [ ] `nav.json` - Navegación
  - [ ] `home.json` - Homepage
  - [ ] `labs.json` - Laboratorios
  - [ ] `tools.json` - Herramientas
  - [ ] `footer.json` - Footer

#### 3.11 SEO Multi-idioma
- [ ] **Archivo:** `src/app/[locale]/layout.tsx`
  ```typescript
  export function generateMetadata({ params }: { params: { locale: Locale } }) {
    const messages = await import(`@/i18n/locales/${params.locale}.json`);
    
    return {
      title: messages.common.appName,
      description: messages.common.tagline,
      alternates: {
        canonical: `https://aitana.cloud/${params.locale}`,
        languages: {
          'es': 'https://aitana.cloud/es',
          'en': 'https://aitana.cloud/en',
          'fr': 'https://aitana.cloud/fr',
          'de': 'https://aitana.cloud/de',
        }
      }
    };
  }
  ```

#### 3.12 Testing de Idiomas
- [ ] **Testing manual:**
  - Cambio de idioma desde selector
  - Persistencia tras recarga
  - Detección automática funciona
  - Todas las páginas traducidas
  - No hay textos hardcoded
  - SEO correcto (hreflang)

- [ ] **URLs a verificar:**
  - `/es` o `/` → Español
  - `/en` → Inglés
  - `/fr` → Francés
  - `/de` → Alemán
  - `/es/lab/prompt-injection` → Lab en español
  - `/en/lab/prompt-injection` → Lab en inglés

### 📊 Criterios de Aceptación
- ✅ Detección automática de idioma por navegador/ubicación
- ✅ Selector de idioma visible en navegación
- ✅ Cambio de idioma instantáneo sin recarga completa
- ✅ Persistencia del idioma elegido (cookie)
- ✅ Todas las páginas principales traducidas (4 idiomas)
- ✅ URLs amigables SEO (`/es/`, `/en/`, etc.)
- ✅ Metadata y hreflang correctos
- ✅ Sin textos hardcoded en componentes
- ✅ Fallback a español si idioma no soportado

---

## 📌 Tarea 4: Corrección de Contrastes y Tipografía

**Prioridad:** 🟠 ALTA  
**Estado:** ⬜ No iniciado  
**Estimación:** 4-6 horas  
**Responsable:** Frontend Team

### 🎯 Objetivo
Corregir todos los problemas de contraste detectados (texto negro en fondo oscuro) y asegurar legibilidad en todos los componentes.

### 📝 Análisis de Problemas

#### Problemas Detectados:
1. **Textos con color incorrecto:**
   - `.text-black` en fondos oscuros
   - Opacidades muy bajas (`text-white/10`)
   - Sin variación de color en temas

2. **Archivos afectados:**
   - `src/app/page.tsx` (múltiples secciones)
   - `src/components/Navigation.tsx`
   - `src/lab/prompt-injection/page.tsx`
   - Todos los labs

### ✅ Subtareas

#### 3.1 Auditoría de Contraste
- [ ] **Herramienta:** WebAIM Contrast Checker
- [ ] **Acción:** Revisar todos los componentes
- [ ] **Documentar:** Crear lista de elementos con contraste < 4.5:1
- [ ] **Archivo de reporte:** `CONTRAST_AUDIT.md`

#### 3.2 Actualizar Homepage
- [ ] **Archivo:** `src/app/page.tsx`
- [ ] **Reemplazos:**
  ```typescript
  // ANTES (problemas)
  <h2 className="text-white">        // ❌ Hardcoded
  <p className="text-white/80">      // ❌ Hardcoded
  <span className="text-black">     // ❌ Invisible en dark
  
  // DESPUÉS (correcto)
  <h2 className="text-primary">     // ✅ Adaptativo
  <p className="text-secondary">    // ✅ Adaptativo
  <span className="text-muted">     // ✅ Adaptativo
  ```

#### 3.3 Actualizar Navigation
- [ ] **Archivo:** `src/components/Navigation.tsx`
- [ ] **Verificar:**
  - Topbar: `text-primary` en lugar de `text-white/60`
  - Links: `text-primary hover:text-accent-blue`
  - Dropdowns: Fondo adaptativo

#### 3.4 Crear Paleta de Colores Semánticos
- [ ] **Archivo:** `src/styles/colors.ts`
  ```typescript
  export const SEMANTIC_COLORS = {
    // Backgrounds
    bgPrimary: 'bg-primary',
    bgSecondary: 'bg-secondary',
    bgTertiary: 'bg-tertiary',
    
    // Text
    textPrimary: 'text-primary',      // Títulos principales
    textSecondary: 'text-secondary',  // Párrafos
    textMuted: 'text-muted',          // Textos secundarios
    
    // States
    success: 'text-green-500',
    error: 'text-red-500',
    warning: 'text-yellow-500',
    info: 'text-blue-500',
    
    // Interactive
    link: 'text-accent-blue hover:text-accent-blue/80',
    linkMuted: 'text-muted hover:text-primary'
  } as const;
  ```

#### 3.5 Testing de Contraste
- [ ] **Light Mode:**
  - Verificar todos los textos sobre fondos claros
  - Ratio mínimo: 4.5:1 para texto normal
  - Ratio mínimo: 3:1 para texto grande (18pt+)

- [ ] **Dark Mode:**
  - Verificar todos los textos sobre fondos oscuros
  - Mismo ratios que light mode

#### 3.6 Documentar Guía de Estilo
- [ ] **Archivo:** `STYLE_GUIDE.md`
  ```markdown
  # Guía de Estilo - Colores y Tipografía
  
  ## Uso de Colores
  
  ### Backgrounds
  - Primario: `bg-primary` (Fondo principal de página)
  - Secundario: `bg-secondary` (Cards, secciones)
  - Terciario: `bg-tertiary` (Elementos destacados)
  
  ### Textos
  - Títulos: `text-primary font-urbanist font-bold`
  - Párrafos: `text-secondary font-dm-sans`
  - Textos secundarios: `text-muted font-dm-sans`
  
  ### Estados
  - Éxito: `text-green-500` + `bg-green-500/10`
  - Error: `text-red-500` + `bg-red-500/10`
  - Warning: `text-yellow-500` + `bg-yellow-500/10`
  
  ## ❌ NO USAR
  - `text-black` (nunca, usar `text-primary`)
  - `text-white` (nunca, usar `text-primary`)
  - Opacidades < 60% para textos principales
  ```

### 📊 Criterios de Aceptación
- ✅ Todos los textos cumplen WCAG AA (4.5:1)
- ✅ No hay `text-black` o `text-white` hardcoded
- ✅ Los colores se adaptan al tema actual
- ✅ La guía de estilo está documentada
- ✅ El equipo conoce las convenciones

---

## 📌 Tarea 5: Optimización de Componentes

**Prioridad:** 🟡 MEDIA  
**Estado:** ⬜ No iniciado  
**Estimación:** 6-8 horas  
**Responsable:** Frontend Team

### 🎯 Objetivo
Optimizar componentes para mejor performance, reducir re-renders innecesarios y mejorar la experiencia de usuario.

### ✅ Subtareas

#### 4.1 Implementar React.memo en Componentes Pesados
- [ ] **Componentes a optimizar:**
  - ServiceCard
  - VulnerabilityCard
  - StatCard
  - NavigationDropdown

- [ ] **Ejemplo:**
  ```typescript
  import { memo } from 'react';
  
  const ServiceCard = memo(({ icon, title, desc, path, cvss }) => {
    return (
      <Link href={path} className="...">
        {/* Contenido */}
      </Link>
    );
  });
  
  ServiceCard.displayName = 'ServiceCard';
  export default ServiceCard;
  ```

#### 4.2 Implementar useCallback para Funciones
- [ ] **Archivo:** `src/app/page.tsx`
- [ ] **Optimizar:**
  ```typescript
  import { useCallback } from 'react';
  
  const handleSlideChange = useCallback((index: number) => {
    setCurrentSlide(index);
  }, []);
  ```

#### 4.3 Lazy Loading de Secciones
- [ ] **Implementar:**
  ```typescript
  import dynamic from 'next/dynamic';
  
  const AIRedTeamSection = dynamic(() => import('@/components/sections/AIRedTeam'), {
    loading: () => <SkeletonLoader />
  });
  
  const ServicesGrid = dynamic(() => import('@/components/sections/ServicesGrid'), {
    loading: () => <SkeletonLoader />
  });
  ```

#### 4.4 Optimizar Imágenes
- [ ] **Usar next/image en todas las imágenes**
- [ ] **Configurar:**
  ```typescript
  import Image from 'next/image';
  
  <Image
    src="/path/to/image.webp"
    alt="Description"
    width={800}
    height={600}
    loading="lazy"
    placeholder="blur"
  />
  ```

#### 4.5 Code Splitting por Rutas
- [ ] **Verificar:** Next.js automáticamente hace code splitting
- [ ] **Confirmar:** Cada lab es un bundle separado
- [ ] **Analizar:** `npm run build` para ver bundle sizes

#### 4.6 Performance Metrics
- [ ] **Lighthouse Score:** > 90 en todas las categorías
- [ ] **First Contentful Paint:** < 1.8s
- [ ] **Time to Interactive:** < 3.8s
- [ ] **Cumulative Layout Shift:** < 0.1

### 📊 Criterios de Aceptación
- ✅ Lighthouse Score > 90
- ✅ No hay re-renders innecesarios
- ✅ Las imágenes están optimizadas
- ✅ El bundle size es óptimo (<200KB por ruta)

---

## 📌 Tarea 6: Mejoras de Accesibilidad

**Prioridad:** 🟡 MEDIA  
**Estado:** ⬜ No iniciado  
**Estimación:** 4-6 horas  
**Responsable:** Frontend Team

### 🎯 Objetivo
Garantizar que la aplicación cumple con WCAG 2.1 AA y es accesible para todos los usuarios.

### ✅ Subtareas

#### 5.1 Navegación por Teclado
- [ ] **Verificar focus visible en todos los elementos interactivos**
- [ ] **Implementar skip-to-content link:**
  ```typescript
  <a href="#main-content" className="sr-only focus:not-sr-only">
    Skip to main content
  </a>
  <main id="main-content">
    {/* Contenido */}
  </main>
  ```

#### 5.2 ARIA Labels
- [ ] **Añadir aria-labels a botones sin texto:**
  ```typescript
  <button aria-label="Toggle theme" onClick={toggleTheme}>
    <IconMoon />
  </button>
  ```

- [ ] **Añadir role y aria-expanded en dropdowns:**
  ```typescript
  <button
    role="button"
    aria-expanded={isOpen}
    aria-controls="dropdown-menu"
  >
    Menu
  </button>
  <ul id="dropdown-menu" role="menu">
    {/* Items */}
  </ul>
  ```

#### 5.3 Alt Text en Imágenes
- [ ] **Verificar todas las imágenes tienen alt descriptivo**
- [ ] **Imágenes decorativas:** `alt=""` para que screen readers las ignoren

#### 5.4 Semántica HTML
- [ ] **Usar elementos semánticos:**
  - `<header>` para navegación
  - `<main>` para contenido principal
  - `<section>` para secciones
  - `<article>` para contenido independiente
  - `<nav>` para navegación
  - `<footer>` para pie de página

#### 5.5 Testing con Screen Readers
- [ ] **NVDA (Windows)**
- [ ] **JAWS (Windows)**
- [ ] **VoiceOver (macOS/iOS)**
- [ ] **TalkBack (Android)**

#### 5.6 Color Contrast Analyzer
- [ ] **Usar herramienta automática:** axe DevTools
- [ ] **Verificar manualmente:** WebAIM Contrast Checker
- [ ] **Documentar excepciones:** Si las hay

### 📊 Criterios de Aceptación
- ✅ Se puede navegar completamente con teclado
- ✅ Screen readers pueden leer todo el contenido
- ✅ Todos los elementos interactivos tienen labels
- ✅ El contraste cumple WCAG AA
- ✅ La semántica HTML es correcta

---

## 📈 Métricas de Éxito del Proyecto

### KPIs Técnicos
- [ ] **Performance:** Lighthouse > 90
- [ ] **Accesibilidad:** WCAG 2.1 AA compliance
- [ ] **SEO:** Score > 95
- [ ] **Bundle Size:** < 200KB por ruta
- [ ] **Time to Interactive:** < 3.8s

### KPIs de Calidad
- [ ] **Test Coverage:** > 80%
- [ ] **TypeScript Strict:** Habilitado sin errores
- [ ] **ESLint:** 0 errores, 0 warnings
- [ ] **Contraste:** Todas las combinaciones > 4.5:1

### KPIs de Usuario
- [ ] **Theme Switch:** < 300ms transición
- [ ] **Page Load:** < 2s en 4G
- [ ] **Navigation:** Todas las rutas accesibles en < 3 clicks

---

## 📅 Cronograma Sugerido

| Semana | Tareas | Responsable |
|--------|--------|-------------|
| Semana 1 | Tarea 1: Sistema de Temas | Frontend Team |
| Semana 2 | Tarea 2: Separación de Entornos | DevOps + Frontend |
| Semana 3 | Tarea 3: Corrección de Contrastes | Frontend Team |
| Semana 4 | Tareas 4 y 5: Optimización + A11y | Frontend Team |

---

## 🔄 Proceso de Revisión

### Antes de marcar subtarea como completa:
1. ✅ **Testing local:** Funciona en desarrollo
2. ✅ **Code Review:** Aprobado por otro developer
3. ✅ **Testing manual:** QA verifica funcionamiento
4. ✅ **Documentation:** Código documentado
5. ✅ **Merge:** Pull request aprobado y mergeado

### Antes de marcar tarea como completa:
1. ✅ Todas las subtareas completadas
2. ✅ Criterios de aceptación cumplidos
3. ✅ Testing en staging aprobado
4. ✅ Documentación actualizada
5. ✅ Demo al equipo realizada

---

## 📝 Notas Finales

### Priorización
1. 🔴 **Crítico:** Tareas 1 y 2 (bloquean funcionalidad básica)
2. 🟠 **Alto:** Tarea 3 (afecta UX directamente)
3. 🟡 **Medio:** Tareas 4 y 5 (mejoras de calidad)

### Dependencias
- **Tarea 1** debe completarse antes de Tarea 3
- **Tarea 2** es independiente
- **Tareas 4 y 5** pueden hacerse en paralelo

### Recursos Necesarios
- [ ] Acceso a Vercel para deploys
- [ ] Credenciales de analytics (si se usa)
- [ ] Herramientas de testing (Lighthouse, axe DevTools)
- [ ] Tiempo de QA para testing manual

---

**Última actualización:** 4 de enero de 2026  
**Versión del documento:** 1.0.0  
**Próxima revisión:** Al completar cada tarea
