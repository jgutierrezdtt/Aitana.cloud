'use client';

import { useEffect } from 'react';
import { useTheme } from '@/hooks/useTheme';

export default function DynamicFavicon() {
  const { effectiveTheme } = useTheme();

  useEffect(() => {
    // Obtener o crear el elemento link del favicon
    let link = document.querySelector("link[rel~='icon']") as HTMLLinkElement;
    
    if (!link) {
      link = document.createElement('link');
      link.rel = 'icon';
      document.head.appendChild(link);
    }

    // Cambiar el favicon según el tema
    if (effectiveTheme === 'dark') {
      link.href = '/logos/logo-navigator-white.png';
    } else {
      link.href = '/logos/logo-navigator-black.png';
    }

    // También actualizar apple-touch-icon si existe
    let appleTouchIcon = document.querySelector("link[rel='apple-touch-icon']") as HTMLLinkElement;
    if (appleTouchIcon) {
      appleTouchIcon.href = effectiveTheme === 'dark' 
        ? '/logos/logo-navigator-white.png'
        : '/logos/logo-navigator-black.png';
    }
  }, [effectiveTheme]);

  return null; // Este componente no renderiza nada visible
}
