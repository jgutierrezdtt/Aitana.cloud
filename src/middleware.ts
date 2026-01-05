/**
 * Middleware para protección de rutas según entorno e i18n
 * 
 * Este middleware:
 * 1. Detecta y aplica el locale del usuario (navegador/cookie)
 * 2. Redirige a la home page si el usuario intenta acceder a una ruta protegida
 */

import createMiddleware from 'next-intl/middleware';
import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';
import { locales, defaultLocale } from './i18n/config';
import { detectUserLocale, getLocaleFromCookie } from './i18n/utils';

// Lista de rutas protegidas (solo disponibles en desarrollo)
const PROTECTED_ROUTES = [
  '/evaluacion-madurez',
  '/matriz-normativas',
  '/guias',
  '/docs',
];

// Rutas siempre permitidas (producción + desarrollo)
const ALLOWED_ROUTES = [
  '/',
  '/labs/blue-team',
  '/labs/ai-red-team',
  '/lab/prompt-injection',
  '/lab/sqli',
  '/lab/xss',
  '/lab/auth',
  '/lab/sensitive-data',
  '/lab/access-control',
  '/lab/misconfig',
  '/lab/command-injection',
  '/lab/xxe',
  '/lab/ldap',
  '/lab/ssti',
  '/lab/session-fixation',
  '/lab/csp',
  '/lab/file-upload',
];

// Middleware de next-intl
const intlMiddleware = createMiddleware({
  locales,
  defaultLocale,
  localePrefix: 'always', // Siempre mostrar el locale en la URL (/es, /en, etc.)
  localeDetection: true, // Detección automática habilitada
});

export function middleware(request: NextRequest) {
  const pathname = request.nextUrl.pathname;
  const isProduction = process.env.NEXT_PUBLIC_ENV === 'production';
  
  // Extraer locale de la URL (formato: /[locale]/path)
  const pathnameLocale = pathname.split('/')[1];
  const isLocaleInPath = locales.includes(pathnameLocale as any);
  
  // Obtener la ruta sin el locale
  const pathnameWithoutLocale = isLocaleInPath 
    ? pathname.slice(pathnameLocale.length + 1) || '/'
    : pathname;
  
  // Protección de rutas según entorno
  if (isProduction && PROTECTED_ROUTES.some(route => pathnameWithoutLocale.startsWith(route))) {
    // Redirigir a la home page manteniendo el locale
    const locale = isLocaleInPath ? pathnameLocale : defaultLocale;
    return NextResponse.redirect(new URL(`/${locale}`, request.url));
  }
  
  // Aplicar middleware de i18n
  return intlMiddleware(request);
}

// Configurar qué rutas pasan por el middleware
export const config = {
  matcher: [
    /*
     * Match all request paths except for the ones starting with:
     * - api (API routes)
     * - _next/static (static files)
     * - _next/image (image optimization files)
     * - favicon.ico (favicon file)
     * - public folder files
     */
    '/((?!api|_next/static|_next/image|favicon.ico|.*\\.(?:svg|png|jpg|jpeg|gif|webp|ico)$).*)',
  ],
};
