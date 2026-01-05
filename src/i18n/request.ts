import { getRequestConfig } from 'next-intl/server';

// Idiomas soportados
export const locales = ['es', 'en', 'fr', 'de'] as const;
export const defaultLocale = 'es' as const;

export type Locale = (typeof locales)[number];

export default getRequestConfig(async ({ locale }) => {
  // Asegurar que siempre tengamos un locale válido
  const validLocale = locale || defaultLocale;
  
  // Importar mensajes usando switch para evitar imports dinámicos
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
    default:
      messages = (await import('./locales/es.json')).default;
  }
  
  return {
    locale: validLocale,
    messages,
  };
});
