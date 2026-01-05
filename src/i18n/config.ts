/**
 * Configuración de internacionalización (i18n)
 * 
 * Define los idiomas soportados, nombres localizados y banderas.
 */

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

export const localeRegions: Record<Locale, string[]> = {
  es: ['ES', 'MX', 'AR', 'CO', 'CL', 'PE', 'VE', 'EC', 'GT', 'CU', 'BO', 'DO', 'HN', 'PY', 'SV', 'NI', 'CR', 'PA', 'UY'],
  en: ['US', 'GB', 'CA', 'AU', 'NZ', 'IE', 'ZA', 'IN', 'SG'],
  fr: ['FR', 'BE', 'CH', 'CA', 'LU', 'MC'],
  de: ['DE', 'AT', 'CH', 'LU', 'LI']
};
