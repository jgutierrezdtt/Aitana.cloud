/**
 * Configuración de internacionalización (i18n)
 * 
 * Define los idiomas soportados, nombres localizados y banderas.
 */

export const locales = ['es', 'en', 'fr', 'de', 'eu', 'ca', 'gl', 'ic', 'zh'] as const;
export type Locale = typeof locales[number];

export const defaultLocale: Locale = 'es';

export const localeNames: Record<Locale, string> = {
  es: 'Español',
  en: 'English',
  fr: 'Français',
  de: 'Deutsch',
  eu: 'Euskera',
  ca: 'Català',
  gl: 'Galego',
  ic: 'Canario',
  zh: '中文'
};

export const localeFlags: Record<Locale, string> = {
  es: '🇪🇸',
  en: '🇬🇧',
  fr: '🇫🇷',
  de: '🇩🇪',
  eu: '🏴',  // Ikurriña (no hay emoji oficial, usamos bandera negra)
  ca: '🏴',  // Senyera
  gl: '🏴',  // Bandeira galega
  ic: '🇮🇨',  // Bandera de Canarias
  zh: '🇨🇳'
};

export const localeRegions: Record<Locale, string[]> = {
  es: ['ES', 'MX', 'AR', 'CO', 'CL', 'PE', 'VE', 'EC', 'GT', 'CU', 'BO', 'DO', 'HN', 'PY', 'SV', 'NI', 'CR', 'PA', 'UY'],
  en: ['US', 'GB', 'CA', 'AU', 'NZ', 'IE', 'ZA', 'IN', 'SG'],
  fr: ['FR', 'BE', 'CH', 'CA', 'LU', 'MC'],
  de: ['DE', 'AT', 'CH', 'LU', 'LI'],
  eu: ['ES'],  // País Vasco
  ca: ['ES'],  // Cataluña, Valencia, Baleares
  gl: ['ES'],  // Galicia
  ic: ['ES'],  // Islas Canarias
  zh: ['CN', 'TW', 'HK', 'SG']
};

// Categorías para organizar idiomas en el selector
export const localeCategories = {
  spanish: {
    label: 'Español',
    locales: ['es'] as const
  },
  regionalSpanish: {
    label: 'Idiomas de España',
    locales: ['eu', 'ca', 'gl', 'ic'] as const
  },
  international: {
    label: 'Internacional',
    locales: ['en', 'fr', 'de', 'zh'] as const
  }
} as const;

