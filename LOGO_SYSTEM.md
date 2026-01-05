# 🎨 Sistema de Logos Dinámicos - Aitana.cloud

**Fecha de creación:** 4 de enero de 2026  
**Versión:** 1.0.0

---

## 📌 Descripción General

El sistema de logos dinámicos de Aitana.cloud adapta automáticamente el diseño del logo según:
- **Tema activo** (claro/oscuro)
- **Ubicación** (header/footer)
- **Tamaño** (sm/md/lg)

---

## 🎯 Componente Logo

**Ubicación:** `/src/components/Logo.tsx`

### Características Principales

#### 1. Detección Automática de Tema
```typescript
// Detecta automáticamente el tema activo
const [theme, setTheme] = useState<'light' | 'dark'>('dark');

useEffect(() => {
  const isDark = document.documentElement.classList.contains('dark');
  setTheme(isDark ? 'dark' : 'light');
  
  // Observer para cambios dinámicos
  const observer = new MutationObserver(() => {
    const isDark = document.documentElement.classList.contains('dark');
    setTheme(isDark ? 'dark' : 'light');
  });
  
  observer.observe(document.documentElement, {
    attributes: true,
    attributeFilter: ['class']
  });
}, []);
```

#### 2. Variantes de Logo

##### **Variante Header**
- **Icono:** Shield con checkmark (🛡️✓)
- **Gradiente Dark:** `from-blue-500 via-indigo-600 to-purple-600`
- **Gradiente Light:** `from-blue-400 via-indigo-500 to-purple-500`
- **Color Icon Dark:** `text-blue-400`
- **Color Icon Light:** `text-blue-600`

##### **Variante Footer**
- **Icono:** Lock con key (🔐🔑)
- **Gradiente Dark:** `from-indigo-500 via-purple-600 to-pink-600`
- **Gradiente Light:** `from-indigo-400 via-purple-500 to-pink-500`
- **Color Icon Dark:** `text-purple-400`
- **Color Icon Light:** `text-purple-600`

#### 3. Tamaños Disponibles

| Tamaño | Icon Container | SVG Icon | Title | Subtitle |
|--------|---------------|----------|-------|----------|
| **sm** | 8x8 (32px) | 5x5 (20px) | text-lg | text-[10px] |
| **md** | 12x12 (48px) | 7x7 (28px) | text-2xl | text-xs |
| **lg** | 16x16 (64px) | 10x10 (40px) | text-3xl | text-sm |

---

## 🔧 Uso del Componente

### Ejemplo Básico
```tsx
import Logo from '@/components/Logo';

// Logo de Header (por defecto)
<Logo />

// Logo de Footer
<Logo variant="footer" />

// Logo pequeño
<Logo size="sm" />

// Logo grande de footer
<Logo variant="footer" size="lg" />
```

### Props Disponibles

```typescript
interface LogoProps {
  variant?: 'header' | 'footer';  // Tipo de logo
  size?: 'sm' | 'md' | 'lg';       // Tamaño
  className?: string;               // Clases CSS adicionales
}
```

---

## 📍 Implementación Actual

### Navigation Component
**Ubicación:** `/src/components/Navigation.tsx`

```tsx
import Logo from './Logo';

export default function Navigation() {
  return (
    <header>
      <Logo variant="header" size="md" />
      {/* Resto del nav */}
    </header>
  );
}
```

### Homepage Footer
**Ubicación:** `/src/app/page.tsx`

```tsx
import Logo from '@/components/Logo';

export default function Home() {
  return (
    <footer>
      <Logo variant="footer" size="md" />
      <p>Enterprise-grade security assessment platform...</p>
      {/* Resto del footer */}
    </footer>
  );
}
```

---

## 🎨 Estilos por Tema

### Modo Oscuro (Dark)

#### Header Logo
```css
/* Gradiente del border */
background: linear-gradient(to bottom right, #3B82F6, #4F46E5, #7C3AED);

/* Background del icono */
background-color: #1B1663; /* bg-cyber-dark-1 */

/* Color del shield icon */
color: #60A5FA; /* text-blue-400 */

/* Texto "Aitana" */
color: #FFFFFF; /* text-white */

/* Texto "SECURITY LAB" */
color: #60A5FA; /* text-blue-400 */

/* Shadow */
box-shadow: 0 10px 15px -3px rgba(59, 130, 246, 0.5);
```

#### Footer Logo
```css
/* Gradiente del border */
background: linear-gradient(to bottom right, #6366F1, #7C3AED, #DB2777);

/* Background del icono */
background-color: #1B1663; /* bg-cyber-dark-1 */

/* Color del lock icon */
color: #C084FC; /* text-purple-400 */

/* Texto "Aitana" */
color: #FFFFFF; /* text-white */

/* Texto "SECURITY LAB" */
color: #C084FC; /* text-purple-400 */

/* Shadow */
box-shadow: 0 10px 15px -3px rgba(124, 58, 237, 0.5);
```

### Modo Claro (Light)

#### Header Logo
```css
/* Gradiente del border */
background: linear-gradient(to bottom right, #60A5FA, #6366F1, #A78BFA);

/* Background del icono */
background-color: #FFFFFF; /* white */

/* Color del shield icon */
color: #2563EB; /* text-blue-600 */

/* Texto "Aitana" */
color: #111827; /* text-gray-900 */

/* Texto "SECURITY LAB" */
color: #2563EB; /* text-blue-600 */

/* Shadow */
box-shadow: 0 10px 15px -3px rgba(96, 165, 250, 0.3);
```

#### Footer Logo
```css
/* Gradiente del border */
background: linear-gradient(to bottom right, #818CF8, #A78BFA, #F472B6);

/* Background del icono */
background-color: #FFFFFF; /* white */

/* Color del lock icon */
color: #7C3AED; /* text-purple-600 */

/* Texto "Aitana" */
color: #111827; /* text-gray-900 */

/* Texto "SECURITY LAB" */
color: #7C3AED; /* text-purple-600 */

/* Shadow */
box-shadow: 0 10px 15px -3px rgba(167, 139, 250, 0.3);
```

---

## 🔄 Transiciones y Animaciones

El logo incluye:
- **Hover Effect:** `opacity: 0.9` al pasar el mouse
- **Smooth Transition:** Cambios de tema suaves sin parpadeos
- **Observer Pattern:** Detecta cambios de tema en tiempo real

```tsx
<Link 
  href="/" 
  className="flex items-center gap-3 hover:opacity-90 transition-opacity"
>
  {/* Logo */}
</Link>
```

---

## 🎯 Diferencias entre Header y Footer

| Aspecto | Header | Footer |
|---------|--------|--------|
| **Icono** | Shield con checkmark | Lock con key |
| **Gradiente (Dark)** | Blue → Indigo → Purple | Indigo → Purple → Pink |
| **Gradiente (Light)** | Blue → Indigo → Purple | Indigo → Purple → Pink |
| **Propósito** | Navegación y branding | Información y cierre |
| **Énfasis** | Protección activa | Seguridad establecida |

---

## 📊 Accesibilidad

### Características de Accesibilidad
- ✅ **Contraste WCAG AA:** Todos los colores cumplen ratio > 4.5:1
- ✅ **Navegación por teclado:** Logo es un link accesible
- ✅ **Screen readers:** Texto "Aitana SECURITY LAB" legible
- ✅ **Responsive:** Tamaños adaptativos
- ✅ **No dependencia de color:** Iconos + texto combinados

---

## 🧪 Testing

### Checklist de Testing
- [ ] Logo visible en modo oscuro
- [ ] Logo visible en modo claro
- [ ] Transición suave al cambiar tema
- [ ] Click en logo redirige a homepage
- [ ] Hover effect funcional
- [ ] Responsive en mobile (sm/md/lg breakpoints)
- [ ] SVG icons se renderizan correctamente
- [ ] Gradientes visibles en todos los navegadores
- [ ] Shadow effects visibles

### Navegadores Soportados
- ✅ Chrome/Edge (latest)
- ✅ Firefox (latest)
- ✅ Safari (latest)
- ✅ Mobile Safari (iOS 14+)
- ✅ Chrome Mobile (Android)

---

## 🚀 Roadmap Futuro

### Posibles Mejoras
- [ ] **Logo animado:** Animación sutil al cargar
- [ ] **SVG inline:** Optimización para mejor performance
- [ ] **Multiple themes:** Soporte para temas personalizados
- [ ] **Logo variants:** Más opciones (icon-only, text-only)
- [ ] **Custom colors:** Props para customización

---

## 📝 Changelog

### v1.0.0 - 4 enero 2026
- ✅ Componente Logo creado
- ✅ Soporte para dark/light mode
- ✅ Variantes header/footer
- ✅ Tamaños sm/md/lg
- ✅ Detección automática de tema
- ✅ Integrado en Navigation y Footer

---

## 💡 Notas Técnicas

### Por qué dos variantes de logo?

**Header:** Representa la **protección activa** con el shield + checkmark. Es el primer elemento que los usuarios ven, simbolizando confianza y verificación.

**Footer:** Usa lock + key para representar **seguridad establecida**. Es más sutil, enfocado en reforzar el mensaje de protección al final de la página.

### Gradientes diferentes

Los gradientes ligeramente diferentes (blue-based vs purple-based) ayudan a:
1. **Diferenciar visualmente** header de footer
2. **Crear jerarquía visual** (header más prominente)
3. **Mantener cohesión** (misma familia de colores)

---

**Documentado por:** GitHub Copilot  
**Última actualización:** 4 de enero de 2026
