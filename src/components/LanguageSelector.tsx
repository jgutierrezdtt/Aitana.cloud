'use client';

import { useState, useRef, useEffect } from 'react';
import { useParams, usePathname, useRouter } from 'next/navigation';
import { locales, localeNames, localeFlags, localeCategories, type Locale } from '@/i18n/config';
import { Globe } from 'lucide-react';

/**
 * Componente selector de idioma mejorado
 * 
 * Permite cambiar entre 9 idiomas organizados por categorías:
 * - Español (es)
 * - Idiomas de España (eu, ca, gl, ic)
 * - Internacional (en, fr, de, zh)
 */
export default function LanguageSelector() {
  const [isOpen, setIsOpen] = useState(false);
  const dropdownRef = useRef<HTMLDivElement>(null);
  const params = useParams();
  const pathname = usePathname();
  const router = useRouter();
  
  const currentLocale = (params.locale as Locale) || 'es';

  // Cerrar dropdown al hacer click fuera
  useEffect(() => {
    function handleClickOutside(event: MouseEvent) {
      if (dropdownRef.current && !dropdownRef.current.contains(event.target as Node)) {
        setIsOpen(false);
      }
    }

    if (isOpen) {
      document.addEventListener('mousedown', handleClickOutside);
      return () => document.removeEventListener('mousedown', handleClickOutside);
    }
  }, [isOpen]);

  const handleLocaleChange = (newLocale: Locale) => {
    // Actualizar cookie
    document.cookie = `NEXT_LOCALE=${newLocale}; path=/; max-age=31536000; SameSite=Lax`;
    
    // Obtener la ruta sin el locale actual
    const pathWithoutLocale = pathname.replace(`/${currentLocale}`, '') || '/';
    
    // Redirigir a la nueva URL con el nuevo locale
    router.push(`/${newLocale}${pathWithoutLocale}`);
    
    setIsOpen(false);
  };

  return (
    <div className="relative" ref={dropdownRef}>
      {/* Botón selector compacto */}
      <button
        onClick={() => setIsOpen(!isOpen)}
        className="flex items-center gap-2 px-3 py-2 rounded-lg transition-colors
                   bg-gray-100 hover:bg-gray-200 dark:bg-white/5 dark:hover:bg-white/10
                   text-gray-700 dark:text-gray-300"
        aria-label="Cambiar idioma"
        aria-expanded={isOpen}
      >
        <Globe size={18} />
        <span className="hidden sm:inline text-sm font-medium">
          {localeFlags[currentLocale]} {localeNames[currentLocale]}
        </span>
        <span className="sm:hidden text-sm font-medium">
          {localeFlags[currentLocale]}
        </span>
        <svg
          className={`w-4 h-4 transition-transform ${isOpen ? 'rotate-180' : ''}`}
          fill="none"
          viewBox="0 0 24 24"
          stroke="currentColor"
        >
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
        </svg>
      </button>

      {/* Dropdown organizado por categorías */}
      {isOpen && (
        <div className="absolute right-0 mt-2 w-64 rounded-lg shadow-xl z-[100]
                       bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700
                       overflow-hidden animate-in fade-in slide-in-from-top-2 duration-200
                       max-h-[80vh] overflow-y-auto">
          <div className="py-1">
            {/* Español Principal */}
            {localeCategories.spanish.locales.map((locale) => (
              <button
                key={locale}
                onClick={() => handleLocaleChange(locale)}
                className={`w-full flex items-center gap-3 px-4 py-2.5 text-sm transition-colors
                           ${currentLocale === locale
                             ? 'bg-blue-50 dark:bg-blue-900/20 text-blue-600 dark:text-blue-400 font-medium'
                             : 'text-gray-700 dark:text-gray-300 hover:bg-gray-50 dark:hover:bg-gray-700/50'
                           }`}
              >
                <span className="text-lg">{localeFlags[locale]}</span>
                <span>{localeNames[locale]}</span>
                {currentLocale === locale && (
                  <svg className="w-4 h-4 ml-auto" fill="currentColor" viewBox="0 0 20 20">
                    <path fillRule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clipRule="evenodd" />
                  </svg>
                )}
              </button>
            ))}

            {/* Separador */}
            <div className="border-t border-gray-200 dark:border-gray-700 my-1"></div>

            {/* Idiomas de España */}
            <div className="px-4 py-2">
              <span className="text-xs font-semibold text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                {localeCategories.regionalSpanish.label}
              </span>
            </div>
            {localeCategories.regionalSpanish.locales.map((locale) => (
              <button
                key={locale}
                onClick={() => handleLocaleChange(locale)}
                className={`w-full flex items-center gap-3 px-4 py-2 text-sm transition-colors
                           ${currentLocale === locale
                             ? 'bg-blue-50 dark:bg-blue-900/20 text-blue-600 dark:text-blue-400 font-medium'
                             : 'text-gray-700 dark:text-gray-300 hover:bg-gray-50 dark:hover:bg-gray-700/50'
                           }`}
              >
                <span className="text-lg">{localeFlags[locale]}</span>
                <span className="text-sm">{localeNames[locale]}</span>
                {currentLocale === locale && (
                  <svg className="w-4 h-4 ml-auto" fill="currentColor" viewBox="0 0 20 20">
                    <path fillRule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clipRule="evenodd" />
                  </svg>
                )}
              </button>
            ))}

            {/* Separador */}
            <div className="border-t border-gray-200 dark:border-gray-700 my-1"></div>

            {/* Internacional */}
            <div className="px-4 py-2">
              <span className="text-xs font-semibold text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                {localeCategories.international.label}
              </span>
            </div>
            {localeCategories.international.locales.map((locale) => (
              <button
                key={locale}
                onClick={() => handleLocaleChange(locale)}
                className={`w-full flex items-center gap-3 px-4 py-2 text-sm transition-colors
                           ${currentLocale === locale
                             ? 'bg-blue-50 dark:bg-blue-900/20 text-blue-600 dark:text-blue-400 font-medium'
                             : 'text-gray-700 dark:text-gray-300 hover:bg-gray-50 dark:hover:bg-gray-700/50'
                           }`}
              >
                <span className="text-lg">{localeFlags[locale]}</span>
                <span className="text-sm">{localeNames[locale]}</span>
                {currentLocale === locale && (
                  <svg className="w-4 h-4 ml-auto" fill="currentColor" viewBox="0 0 20 20">
                    <path fillRule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clipRule="evenodd" />
                  </svg>
                )}
              </button>
            ))}
          </div>

          {/* Footer informativo */}
          <div className="border-t border-gray-200 dark:border-gray-700 px-4 py-2 bg-gray-50 dark:bg-gray-900/50">
            <p className="text-xs text-gray-500 dark:text-gray-400">
              9 idiomas disponibles
            </p>
          </div>
        </div>
      )}
    </div>
  );
}
