# 🎨 Ejemplos de Uso - Logo Component

Este documento muestra ejemplos prácticos de cómo usar el componente Logo en diferentes contextos.

---

## 📌 Ejemplo 1: Logo en Navigation (Header)

```tsx
// src/components/Navigation.tsx
import Logo from './Logo';

export default function Navigation() {
  return (
    <header className="bg-cyber-dark-1 sticky top-0 z-50">
      <div className="max-w-[1240px] mx-auto px-6">
        <div className="flex items-center justify-between h-20">
          {/* Logo Header - Tamaño Medium */}
          <Logo variant="header" size="md" />
          
          {/* Resto del nav */}
          <nav>...</nav>
        </div>
      </div>
    </header>
  );
}
```

**Resultado:**
- Shield icon con gradiente blue→indigo→purple
- Tamaño: 48x48px icon container
- Se adapta automáticamente al tema activo

---

## 📌 Ejemplo 2: Logo en Footer

```tsx
// src/app/page.tsx
import Logo from '@/components/Logo';

export default function Home() {
  return (
    <footer className="bg-cyber-dark-1 py-16">
      <div className="max-w-[1240px] mx-auto px-6">
        {/* Logo Footer con descripción */}
        <div className="mb-12 pb-12 border-b border-white/10">
          <Logo variant="footer" size="md" />
          <p className="font-dm-sans text-white/60 text-sm mt-4 max-w-md">
            Enterprise-grade security assessment platform for CISOs and security teams.
          </p>
        </div>
        
        {/* Resto del footer */}
      </div>
    </footer>
  );
}
```

**Resultado:**
- Lock icon con gradiente indigo→purple→pink
- Descripción contextual debajo
- Separador visual con border-b

---

## 📌 Ejemplo 3: Logo Small (Sidebar o Mobile)

```tsx
// Componente hipotético de Sidebar
import Logo from '@/components/Logo';

export default function Sidebar() {
  return (
    <aside className="w-64 bg-cyber-dark-2 h-screen">
      {/* Logo pequeño para sidebar */}
      <div className="p-4">
        <Logo variant="header" size="sm" />
      </div>
      
      {/* Menú de navegación */}
      <nav className="mt-6">
        {/* Items del menú */}
      </nav>
    </aside>
  );
}
```

**Resultado:**
- Icon: 32x32px (más compacto)
- Texto: text-lg (18px)
- Ideal para espacios reducidos

---

## 📌 Ejemplo 4: Logo Large (Landing Hero)

```tsx
// Componente de Hero Section
import Logo from '@/components/Logo';

export default function HeroSection() {
  return (
    <section className="min-h-screen flex items-center justify-center">
      <div className="text-center">
        {/* Logo grande y centrado */}
        <Logo variant="header" size="lg" className="justify-center mb-8" />
        
        <h1 className="text-6xl font-bold mb-4">
          Welcome to Aitana Security Lab
        </h1>
        <p className="text-xl text-white/70">
          Enterprise Cybersecurity Training Platform
        </p>
      </div>
    </section>
  );
}
```

**Resultado:**
- Icon: 64x64px (muy prominente)
- Texto: text-3xl (30px)
- Centrado con `justify-center`

---

## 📌 Ejemplo 5: Logo en Email Template

```tsx
// src/components/EmailTemplate.tsx
import Logo from '@/components/Logo';

export default function EmailTemplate() {
  return (
    <div style={{ backgroundColor: '#1B1663', padding: '40px' }}>
      {/* Logo para email (forzar dark mode) */}
      <div className="dark">
        <Logo variant="header" size="md" />
      </div>
      
      <h2 style={{ color: '#fff', marginTop: '20px' }}>
        Security Alert
      </h2>
      <p style={{ color: '#C8C8D2' }}>
        Your account activity requires attention...
      </p>
    </div>
  );
}
```

**Resultado:**
- Logo consistente en emails
- Wrapper `.dark` fuerza modo oscuro
- Branding profesional

---

## 📌 Ejemplo 6: Logo con Custom Classes

```tsx
import Logo from '@/components/Logo';

export default function CustomLogo() {
  return (
    <div className="flex items-center gap-4">
      {/* Logo con clases personalizadas */}
      <Logo 
        variant="footer" 
        size="sm" 
        className="opacity-80 hover:opacity-100 transition-all duration-300"
      />
      
      <div>
        <span className="text-sm text-white/60">Powered by</span>
      </div>
    </div>
  );
}
```

**Resultado:**
- Opacity reducida por defecto
- Hover aumenta opacity
- Transición suave (300ms)

---

## 📌 Ejemplo 7: Logo en 404 Page

```tsx
// src/app/not-found.tsx
import Logo from '@/components/Logo';
import Link from 'next/link';

export default function NotFound() {
  return (
    <div className="min-h-screen bg-cyber-dark-1 flex items-center justify-center">
      <div className="text-center">
        {/* Logo en página de error */}
        <Logo variant="header" size="lg" className="justify-center mb-8" />
        
        <h1 className="text-9xl font-bold text-white mb-4">404</h1>
        <p className="text-xl text-white/70 mb-8">
          Page Not Found
        </p>
        
        <Link 
          href="/"
          className="inline-flex items-center gap-2 px-6 py-3 bg-blue-600 text-white rounded-lg"
        >
          <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10 19l-7-7m0 0l7-7m-7 7h18" />
          </svg>
          Back to Home
        </Link>
      </div>
    </div>
  );
}
```

**Resultado:**
- Logo grande como elemento de branding
- Mensaje de error amigable
- Botón de retorno al home

---

## 📌 Ejemplo 8: Logo en Loading State

```tsx
import Logo from '@/components/Logo';

export default function LoadingScreen() {
  return (
    <div className="fixed inset-0 bg-cyber-dark-1 flex items-center justify-center z-50">
      <div className="text-center">
        {/* Logo con animación de loading */}
        <div className="animate-pulse">
          <Logo variant="header" size="lg" className="justify-center" />
        </div>
        
        <p className="text-white/60 mt-6 font-dm-sans">
          Loading security modules...
        </p>
        
        {/* Barra de progreso */}
        <div className="w-64 h-1 bg-white/10 rounded-full mt-4 mx-auto overflow-hidden">
          <div className="h-full bg-gradient-to-r from-blue-500 to-purple-600 animate-pulse" />
        </div>
      </div>
    </div>
  );
}
```

**Resultado:**
- Logo con pulse animation
- Indica carga en progreso
- Barra de progreso visual

---

## 📌 Ejemplo 9: Logo en Modal/Dialog

```tsx
import Logo from '@/components/Logo';

export default function WelcomeModal({ isOpen, onClose }) {
  if (!isOpen) return null;
  
  return (
    <div className="fixed inset-0 bg-black/80 flex items-center justify-center z-50">
      <div className="bg-cyber-dark-2 rounded-2xl p-8 max-w-md">
        {/* Logo pequeño en modal */}
        <Logo variant="header" size="sm" className="mb-6" />
        
        <h2 className="text-2xl font-bold text-white mb-4">
          Welcome to Aitana Security Lab
        </h2>
        
        <p className="text-white/70 mb-6">
          Start your cybersecurity training journey today.
        </p>
        
        <div className="flex gap-3">
          <button 
            onClick={onClose}
            className="px-4 py-2 bg-white/10 text-white rounded-lg"
          >
            Skip
          </button>
          <button className="px-4 py-2 bg-blue-600 text-white rounded-lg">
            Get Started
          </button>
        </div>
      </div>
    </div>
  );
}
```

**Resultado:**
- Logo pequeño en header del modal
- No domina visualmente
- Mantiene branding consistente

---

## 📌 Ejemplo 10: Logo en Print (PDF)

```tsx
import Logo from '@/components/Logo';

export default function CertificatePDF() {
  return (
    <div className="p-12 bg-white text-black" style={{ printColorAdjust: 'exact' }}>
      {/* Logo para impresión (forzar light mode) */}
      <div className="light mb-8">
        <Logo variant="header" size="lg" />
      </div>
      
      <h1 className="text-4xl font-bold mb-4">
        Certificate of Completion
      </h1>
      
      <p className="text-lg mb-8">
        This certifies that <strong>John Doe</strong> has successfully completed
        the Aitana Security Lab training program.
      </p>
      
      <div className="border-t-2 border-black pt-4 mt-12">
        <p className="text-sm text-gray-600">
          Issued on January 4, 2026
        </p>
      </div>
    </div>
  );
}
```

**Resultado:**
- Logo en modo claro para impresión
- printColorAdjust: exact preserva colores
- Documento profesional

---

## 🎨 Comparativa Visual de Tamaños

```tsx
import Logo from '@/components/Logo';

export default function LogoShowcase() {
  return (
    <div className="p-12 bg-cyber-dark-1">
      <h2 className="text-3xl font-bold text-white mb-8">Logo Sizes</h2>
      
      <div className="space-y-8">
        {/* Small */}
        <div className="flex items-center gap-4">
          <Logo variant="header" size="sm" />
          <span className="text-white/60">Small - Sidebar/Mobile</span>
        </div>
        
        {/* Medium */}
        <div className="flex items-center gap-4">
          <Logo variant="header" size="md" />
          <span className="text-white/60">Medium - Header/Footer (default)</span>
        </div>
        
        {/* Large */}
        <div className="flex items-center gap-4">
          <Logo variant="header" size="lg" />
          <span className="text-white/60">Large - Hero/Landing</span>
        </div>
      </div>
      
      <h2 className="text-3xl font-bold text-white mb-8 mt-16">Logo Variants</h2>
      
      <div className="space-y-8">
        {/* Header Variant */}
        <div className="flex items-center gap-4">
          <Logo variant="header" size="md" />
          <span className="text-white/60">Header - Shield Icon (Blue gradient)</span>
        </div>
        
        {/* Footer Variant */}
        <div className="flex items-center gap-4">
          <Logo variant="footer" size="md" />
          <span className="text-white/60">Footer - Lock Icon (Purple gradient)</span>
        </div>
      </div>
    </div>
  );
}
```

---

## 💡 Tips y Best Practices

### ✅ DO
- Usar `variant="header"` en navegación principal
- Usar `variant="footer"` en pie de página
- Usar `size="sm"` en espacios reducidos
- Usar `size="lg"` en hero sections
- Añadir `className` para ajustes específicos
- Dejar que el tema se detecte automáticamente

### ❌ DON'T
- No mezclar variantes sin razón
- No usar tamaños inconsistentes en la misma página
- No forzar colores manualmente (déjalo al tema)
- No usar logo como botón sin accesibilidad
- No modificar el SVG directamente

---

## 🔧 Troubleshooting

### El logo no cambia de tema
**Solución:** Verifica que `document.documentElement` tenga la clase `dark` o `light`

### El logo se ve borroso
**Solución:** Usa tamaños exactos (sm/md/lg) en lugar de clases personalizadas

### El gradiente no se ve en Safari
**Solución:** Ya está implementado con prefijos webkit, debería funcionar

### El logo no es clickeable en mobile
**Solución:** Verifica que el área de touch sea > 44x44px (cumplido con size="md")

---

**Última actualización:** 4 de enero de 2026
