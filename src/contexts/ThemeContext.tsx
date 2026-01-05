'use client';

import { createContext, useContext, useState, useEffect, ReactNode } from 'react';

type Theme = 'light' | 'dark' | 'system';

interface ThemeContextType {
  theme: Theme;
  effectiveTheme: 'light' | 'dark';
  setTheme: (theme: Theme) => void;
}

export const ThemeContext = createContext<ThemeContextType | undefined>(undefined);

export function ThemeProvider({ children }: { children: ReactNode }) {
  const [theme, setThemeState] = useState<Theme>('system');
  const [effectiveTheme, setEffectiveTheme] = useState<'light' | 'dark'>('dark');
  const [mounted, setMounted] = useState(false);

  // Detectar preferencia del sistema
  useEffect(() => {
    setMounted(true);
    
    // Cargar tema guardado de localStorage
    const savedTheme = localStorage.getItem('theme') as Theme | null;
    if (savedTheme) {
      setThemeState(savedTheme);
    }

    const mediaQuery = window.matchMedia('(prefers-color-scheme: dark)');
    
    const updateEffectiveTheme = () => {
      if (savedTheme && savedTheme !== 'system') {
        setEffectiveTheme(savedTheme);
      } else {
        setEffectiveTheme(mediaQuery.matches ? 'dark' : 'light');
      }
    };

    updateEffectiveTheme();

    // Listener para cambios en preferencias del sistema
    const handleChange = () => {
      if (theme === 'system') {
        setEffectiveTheme(mediaQuery.matches ? 'dark' : 'light');
      }
    };

    mediaQuery.addEventListener('change', handleChange);
    return () => mediaQuery.removeEventListener('change', handleChange);
  }, [theme]);

  // Actualizar tema cuando cambia
  useEffect(() => {
    if (!mounted) return;

    if (theme === 'system') {
      const mediaQuery = window.matchMedia('(prefers-color-scheme: dark)');
      setEffectiveTheme(mediaQuery.matches ? 'dark' : 'light');
    } else {
      setEffectiveTheme(theme);
    }
  }, [theme, mounted]);

  // Aplicar tema al document
  useEffect(() => {
    if (!mounted) return;

    const root = document.documentElement;
    
    // Remover clases anteriores
    root.classList.remove('light', 'dark');
    
    // Añadir clase del tema efectivo
    root.classList.add(effectiveTheme);
    
    // Actualizar meta theme-color para mobile
    const metaThemeColor = document.querySelector('meta[name="theme-color"]');
    if (metaThemeColor) {
      metaThemeColor.setAttribute(
        'content',
        effectiveTheme === 'dark' ? '#1B1663' : '#FFFFFF'
      );
    }
  }, [effectiveTheme, mounted]);

  const setTheme = (newTheme: Theme) => {
    setThemeState(newTheme);
    localStorage.setItem('theme', newTheme);
  };

  // Evitar flash de contenido sin estilo
  if (!mounted) {
    return <>{children}</>;
  }

  return (
    <ThemeContext.Provider value={{ theme, effectiveTheme, setTheme }}>
      {children}
    </ThemeContext.Provider>
  );
}

export function useTheme() {
  const context = useContext(ThemeContext);
  if (context === undefined) {
    // En lugar de lanzar error, retornar valores por defecto
    // Esto previene errores durante SSR o cuando el provider no está disponible
    return {
      theme: 'dark' as Theme,
      effectiveTheme: 'dark' as const,
      setTheme: () => {},
    };
  }
  return context;
}
