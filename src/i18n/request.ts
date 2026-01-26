import { getRequestConfig } from 'next-intl/server';

// 16 idiomas soportados
export const locales = [
  'es', 'en', 'fr', 'de', 'eu', 'ca', 'gl', 'ic', 'zh',
  'it', 'pt', 'hi', 'ja', 'ko', 'ar', 'ru'
] as const;

export const defaultLocale = 'es' as const;

export type Locale = (typeof locales)[number];

export default getRequestConfig(async ({ locale }) => {
  const validLocale = locale || defaultLocale;

  let messages;
  switch (validLocale) {
    case 'es':
      messages = (await import('./locales/es.json')).default;
      break;
    case 'en':
      messages = (await import('./locales/en.json')).default;
      break;
    case 'fr':
      messages = (await import('./locales/fr.json')).default;
      break;
    case 'de':
      messages = (await import('./locales/de.json')).default;
      break;
    case 'eu':
      messages = (await import('./locales/eu.json')).default;
      break;
    case 'ca':
      messages = (await import('./locales/ca.json')).default;
      break;
    case 'gl':
      messages = (await import('./locales/gl.json')).default;
      break;
    case 'ic':
      messages = (await import('./locales/ic.json')).default;
      break;
    case 'zh':
      messages = (await import('./locales/zh.json')).default;
      break;
    case 'it':
      messages = (await import('./locales/it.json')).default;
      break;
    case 'pt':
      messages = (await import('./locales/pt.json')).default;
      break;
    case 'hi':
      messages = (await import('./locales/hi.json')).default;
      break;
    case 'ja':
      messages = (await import('./locales/ja.json')).default;
      break;
    case 'ko':
      messages = (await import('./locales/ko.json')).default;
      break;
    case 'ar':
      messages = (await import('./locales/ar.json')).default;
      break;
    case 'ru':
      messages = (await import('./locales/ru.json')).default;
      break;
    default:
      messages = (await import('./locales/es.json')).default;
  }

  return {
    locale: validLocale,
    messages,
  };
});
