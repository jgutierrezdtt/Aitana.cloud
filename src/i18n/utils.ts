/**
 * Utilidades para internacionalización
 */

import { locales, defaultLocale, type Locale } from './config';

/**
 * Detecta el idioma preferido del usuario basándose en el navegador
 */
export function detectUserLocale(acceptLanguage?: string): Locale {
  if (!acceptLanguage) return defaultLocale;

  // Parsear el header Accept-Language
  const languages = acceptLanguage
    .split(',')
    .map(lang => {
      const [code, q = 'q=1'] = lang.trim().split(';');
      const quality = parseFloat(q.replace('q=', ''));
      return { code: code.split('-')[0], quality };
    })
    .sort((a, b) => b.quality - a.quality);

  // Encontrar el primer idioma soportado
  for (const { code } of languages) {
    const locale = code as Locale;
    if (locales.includes(locale)) {
      return locale;
    }
  }

  return defaultLocale;
}

/**
 * Valida si un locale es válido
 */
export function isValidLocale(locale: string): locale is Locale {
  return locales.includes(locale as Locale);
}

/**
 * Obtiene el locale desde una cookie
 */
export function getLocaleFromCookie(cookieValue?: string): Locale | null {
  if (!cookieValue) return null;
  return isValidLocale(cookieValue) ? cookieValue : null;
}

/**
 * Crea el valor de cookie para persistir el locale
 */
export function createLocaleCookie(locale: Locale): string {
  const maxAge = 60 * 60 * 24 * 365; // 1 año
  return `NEXT_LOCALE=${locale}; Path=/; Max-Age=${maxAge}; SameSite=Lax`;
}
