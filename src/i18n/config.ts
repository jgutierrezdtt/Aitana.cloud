/**
 * Configuración de internacionalización (i18n)
 *
 * Define los idiomas soportados, nombres localizados y banderas.
 * 16 idiomas soportados
 */

export const locales = [
  'es', 'en', 'fr', 'de', 'eu', 'ca', 'gl', 'ic', 'zh',
  'it', 'pt', 'hi', 'ja', 'ko', 'ar', 'ru'
] as const;

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
  zh: '中文',
  it: 'Italiano',
  pt: 'Português',
  hi: 'हिन्दी',
  ja: '日本語',
  ko: '한국어',
  ar: 'العربية',
  ru: 'Русский'
};

export const localeFlags: Record<Locale, string> = {
  es: '🇪🇸',
  en: '🇬🇧',
  fr: '🇫🇷',
  de: '🇩🇪',
  eu: '🏴',
  ca: '🏴',
  gl: '🏴',
  ic: '🇮🇨',
  zh: '🇨🇳',
  it: '🇮🇹',
  pt: '🇧🇷',
  hi: '🇮🇳',
  ja: '🇯🇵',
  ko: '🇰🇷',
  ar: '🇸🇦',
  ru: '🇷🇺'
};

export const localeRegions: Record<Locale, string[]> = {
  es: ['ES', 'MX', 'AR', 'CO', 'CL', 'PE', 'VE', 'EC', 'GT', 'CU', 'BO', 'DO', 'HN', 'PY', 'SV', 'NI', 'CR', 'PA', 'UY'],
  en: ['US', 'GB', 'CA', 'AU', 'NZ', 'IE', 'ZA', 'SG'],
  fr: ['FR', 'BE', 'CH', 'CA', 'LU', 'MC'],
  de: ['DE', 'AT', 'CH', 'LU', 'LI'],
  eu: ['ES'],
  ca: ['ES'],
  gl: ['ES'],
  ic: ['ES'],
  zh: ['CN', 'TW', 'HK', 'SG'],
  it: ['IT', 'CH', 'SM', 'VA'],
  pt: ['BR', 'PT', 'AO', 'MZ'],
  hi: ['IN'],
  ja: ['JP'],
  ko: ['KR'],
  ar: ['SA', 'AE', 'EG', 'MA', 'DZ', 'TN', 'JO', 'LB', 'SY', 'IQ', 'KW', 'QA', 'BH', 'OM', 'YE'],
  ru: ['RU', 'BY', 'KZ', 'KG']
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
  european: {
    label: 'Europeos',
    locales: ['en', 'fr', 'de', 'it', 'pt', 'ru'] as const
  },
  asian: {
    label: 'Asiáticos',
    locales: ['zh', 'ja', 'ko', 'hi', 'ar'] as const
  }
} as const;
