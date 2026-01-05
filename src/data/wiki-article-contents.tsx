/**
 * CARGADOR DINÁMICO DE CONTENIDOS DE ARTÍCULOS CON SOPORTE MULTI-IDIOMA
 * 
 * Este archivo importa contenidos desde archivos por idioma.
 * Cada artículo puede tener versiones en diferentes idiomas:
 * - src/content/wiki/{category}/{slug}.es.tsx (español - por defecto)
 * - src/content/wiki/{category}/{slug}.en.tsx (inglés - opcional)
 * - src/content/wiki/{category}/{slug}.fr.tsx (francés - opcional)
 * - src/content/wiki/{category}/{slug}.de.tsx (alemán - opcional)
 * 
 * ARQUITECTURA:
 * - Metadata → src/data/wiki-articles.ts
 * - Contenido → src/content/wiki/{category}/{slug}.{locale}.tsx
 * - Mapa → Este archivo mapea (ID, locale) → componente de contenido
 * 
 * FALLBACK:
 * - Si no existe traducción, se usa español (es) como fallback
 * 
 * VENTAJAS:
 * - Traducciones independientes por archivo
 * - Fácil colaboración (traductores trabajan en archivos separados)
 * - Git-friendly (no conflictos de merge)
 * - Lazy loading posible en el futuro
 */

import { ReactNode } from 'react';

// ============================================================================
// IMPORTACIONES DE CONTENIDOS - ESPAÑOL (DEFAULT)
// ============================================================================
import SqlInjectionAvanzadaContent from '@/content/wiki/bug-bounty/sql-injection-avanzada';
import MongodbInjectionContent from '@/content/wiki/bug-bounty/mongodb-injection';
import RedisRCEContent from '@/content/wiki/bug-bounty/redis-rce';
import CassandraInjectionContent from '@/content/wiki/bug-bounty/cassandra-injection';
import SqliteLocalInjectionContent from '@/content/wiki/bug-bounty/sqlite-local-injection';
import FirebaseMisconfigurationContent from '@/content/wiki/bug-bounty/firebase-misconfiguration';
import SSRFBasicoContent from '@/content/wiki/bug-bounty/ssrf-basico';
import SSRFToRCEContent from '@/content/wiki/bug-bounty/ssrf-to-rce';
import IDORContent from '@/content/wiki/bug-bounty/idor';
import RaceConditionsContent from '@/content/wiki/bug-bounty/race-conditions';
import JWTVulnerabilitiesContent from '@/content/wiki/bug-bounty/jwt-vulnerabilities';
import XSSStoredContent from '@/content/wiki/bug-bounty/xss-stored';
import XSSDOMBasedContent from '@/content/wiki/bug-bounty/xss-dom-based';
import CSPBypassContent from '@/content/wiki/bug-bounty/csp-bypass';
import XXEContent from '@/content/wiki/bug-bounty/xxe';
import SSTIContent from '@/content/wiki/bug-bounty/ssti';
import CommandInjectionContent from '@/content/wiki/bug-bounty/command-injection';
import PathTraversalContent from '@/content/wiki/bug-bounty/path-traversal';
import FileUploadContent from '@/content/wiki/bug-bounty/file-upload';
import GraphQLInjectionContent from '@/content/wiki/bug-bounty/graphql-injection';
import PrototypePollutionContent from '@/content/wiki/bug-bounty/prototype-pollution';
import CORSMisconfigurationContent from '@/content/wiki/bug-bounty/cors-misconfiguration';
import SubdomainTakeoverContent from '@/content/wiki/bug-bounty/subdomain-takeover';
import OpenRedirectContent from '@/content/wiki/bug-bounty/open-redirect';
import CSRFAdvancedContent from '@/content/wiki/bug-bounty/csrf-advanced';
import WebSocketHijackingContent from '@/content/wiki/bug-bounty/websocket-hijacking';
import HTTPRequestSmugglingContent from '@/content/wiki/bug-bounty/http-request-smuggling';
import OAuthAttacksContent from '@/content/wiki/bug-bounty/oauth-attacks';

// ============================================================================
// IMPORTACIONES - INGLÉS (EN) - Cuando estén disponibles
// ============================================================================
import SqlInjectionAvanzadaContentEN from '@/content/wiki/bug-bounty/sql-injection-avanzada.en';
import XSSStoredContentEN from '@/content/wiki/bug-bounty/xss-stored.en';
import CSRFAdvancedContentEN from '@/content/wiki/bug-bounty/csrf-advanced.en';
import SSRFBasicoContentEN from '@/content/wiki/bug-bounty/ssrf-basico.en';
import CORSMisconfigurationContentEN from '@/content/wiki/bug-bounty/cors-misconfiguration.en';
import MongodbInjectionContentEN from '@/content/wiki/bug-bounty/mongodb-injection.en';
import XSSDOMBasedContentEN from '@/content/wiki/bug-bounty/xss-dom-based.en';
import JWTVulnerabilitiesContentEN from '@/content/wiki/bug-bounty/jwt-vulnerabilities.en';
import IDORContentEN from '@/content/wiki/bug-bounty/idor.en';
import SubdomainTakeoverContentEN from '@/content/wiki/bug-bounty/subdomain-takeover.en';
// ... etc

// ============================================================================
// IMPORTACIONES - FRANCÉS (FR) - Cuando estén disponibles
// ============================================================================
// import SqlInjectionAvanzadaContentFR from '@/content/wiki/bug-bounty/sql-injection-avanzada.fr';
// ... etc

// ============================================================================
// IMPORTACIONES - ALEMÁN (DE) - Cuando estén disponibles
// ============================================================================
// import SqlInjectionAvanzadaContentDE from '@/content/wiki/bug-bounty/sql-injection-avanzada.de';
// ... etc

// ============================================================================
// TIPOS
// ============================================================================

interface ArticleContentProps {
  locale: string;
}

type ArticleContentFunction = (props: ArticleContentProps) => ReactNode;

// ============================================================================
// MAPA DE CONTENIDOS POR IDIOMA
// ============================================================================

/**
 * Mapa principal: (articleId, locale) → Componente
 * Si no existe traducción, devuelve versión en español
 */
export const articleContentMapByLocale: Record<string, Record<string, ArticleContentFunction>> = {
  // Bug Bounty - Bases de Datos (6/7)
  'sql-injection-avanzada': {
    es: SqlInjectionAvanzadaContent,
    en: SqlInjectionAvanzadaContentEN,
  },
  'mongodb-injection': {
    es: MongodbInjectionContent,
    en: MongodbInjectionContentEN,
  },
  'redis-rce': {
    es: RedisRCEContent,
  },
  'cassandra-injection': {
    es: CassandraInjectionContent,
  },
  'sqlite-local-injection': {
    es: SqliteLocalInjectionContent,
  },
  'firebase-misconfiguration': {
    es: FirebaseMisconfigurationContent,
  },
  
  // Bug Bounty - SSRF (2/4)
  'ssrf-basico': {
    es: SSRFBasicoContent,
    en: SSRFBasicoContentEN,
  },
  'ssrf-to-rce': {
    es: SSRFToRCEContent,
  },
  
  // Bug Bounty - Lógica de Negocio (3/4)
  'idor': {
    es: IDORContent,
    en: IDORContentEN,
  },
  'race-conditions': {
    es: RaceConditionsContent,
  },
  'jwt-vulnerabilities': {
    es: JWTVulnerabilitiesContent,
    en: JWTVulnerabilitiesContentEN,
  },
  
  // Bug Bounty - XSS (3/3) ✅
  'xss-stored': {
    es: XSSStoredContent,
    en: XSSStoredContentEN,
  },
  'xss-dom-based': {
    es: XSSDOMBasedContent,
    en: XSSDOMBasedContentEN,
  },
  'csp-bypass': {
    es: CSPBypassContent,
  },
  
  // Bug Bounty - Template & Injection (4/4) ✅
  'xxe': {
    es: XXEContent,
  },
  'ssti': {
    es: SSTIContent,
  },
  'command-injection': {
    es: CommandInjectionContent,
  },
  'path-traversal': {
    es: PathTraversalContent,
  },
  
  // Bug Bounty - File & Upload (1/1) ✅
  'file-upload': {
    es: FileUploadContent,
  },
  
  // Bug Bounty - API Security (2/2) ✅
  'graphql-injection': {
    es: GraphQLInjectionContent,
  },
  'prototype-pollution': {
    es: PrototypePollutionContent,
  },
  
  // Bug Bounty - Web Security (5/5) ✅
  'cors-misconfiguration': {
    es: CORSMisconfigurationContent,
    en: CORSMisconfigurationContentEN,
  },
  'subdomain-takeover': {
    es: SubdomainTakeoverContent,
    en: SubdomainTakeoverContentEN,
  },
  'open-redirect': {
    es: OpenRedirectContent,
  },
  'csrf-advanced': {
    es: CSRFAdvancedContent,
    en: CSRFAdvancedContentEN,
  },
  'websocket-hijacking': {
    es: WebSocketHijackingContent,
  },
  
  // Bug Bounty - HTTP Advanced (1/4)
  'http-request-smuggling': {
    es: HTTPRequestSmugglingContent,
  },
  
  // Bug Bounty - Authentication & Authorization (1/1) ✅
  'oauth-attacks': {
    es: OAuthAttacksContent,
  },
};

/**
 * Función helper para obtener contenido en el idioma solicitado
 * con fallback automático a español
 */
export function getArticleContent(
  articleId: string, 
  locale: string = 'es'
): ArticleContentFunction | null {
  const articleTranslations = articleContentMapByLocale[articleId];
  
  if (!articleTranslations) {
    return null; // Artículo no existe
  }
  
  // Intentar obtener en el idioma solicitado
  if (articleTranslations[locale]) {
    return articleTranslations[locale];
  }
  
  // Fallback a español
  return articleTranslations['es'] || null;
}

/**
 * Función para verificar si existe traducción en un idioma específico
 */
export function hasTranslation(articleId: string, locale: string): boolean {
  return !!(articleContentMapByLocale[articleId]?.[locale]);
}

/**
 * Obtener idiomas disponibles para un artículo
 */
export function getAvailableLocales(articleId: string): string[] {
  return Object.keys(articleContentMapByLocale[articleId] || {});
}

// ============================================================================
// COMPATIBILIDAD CON CÓDIGO EXISTENTE
// ============================================================================

/**
 * Mapa legacy para compatibilidad (siempre devuelve español)
 * @deprecated Usar getArticleContent() en su lugar
 */
export const articleContentMap: Record<string, ArticleContentFunction> = 
  Object.fromEntries(
    Object.entries(articleContentMapByLocale).map(([id, translations]) => [
      id,
      translations['es'] || (() => null)
    ])
  );

/**
 * CÓMO AGREGAR UN NUEVO ARTÍCULO:
 * 
 * 1. Crear archivo de contenido en ESPAÑOL (obligatorio):
 *    src/content/wiki/{category}/{slug}.tsx
 * 
 *    import { ReactNode } from 'react';
 *    import { Section, Paragraph, ... } from '@/components/WikiArticleComponents';
 *    
 *    export default function MiArticuloContent({ locale }: { locale: string }): ReactNode {
 *      return (
 *        <>
 *          <Section title="Introducción">
 *            <Paragraph>Contenido...</Paragraph>
 *          </Section>
 *        </>
 *      );
 *    }
 * 
 * 2. (OPCIONAL) Crear traducciones:
 *    src/content/wiki/{category}/{slug}.en.tsx  (inglés)
 *    src/content/wiki/{category}/{slug}.fr.tsx  (francés)
 *    src/content/wiki/{category}/{slug}.de.tsx  (alemán)
 * 
 * 3. Importarlo en este archivo:
 *    import MiArticuloContent from '@/content/wiki/{category}/{slug}';
 *    import MiArticuloContentEN from '@/content/wiki/{category}/{slug}.en';  // si existe
 * 
 * 4. Agregarlo al mapa:
 *    export const articleContentMapByLocale = {
 *      'mi-articulo': {
 *        es: MiArticuloContent,
 *        en: MiArticuloContentEN,  // si existe
 *      },
 *      ...
 *    };
 * 
 * 5. Asegurarse de que existe la metadata en src/data/wiki-articles.ts
 * 
 * NOTA: Si solo existe versión en español, el sistema automáticamente
 * mostrará esa versión con un banner de aviso en otros idiomas.
 */
