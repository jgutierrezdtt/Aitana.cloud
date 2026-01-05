/**
 * PÁGINA DINÁMICA DE ARTÍCULOS WIKI
 * 
 * Esta página renderiza TODOS los artículos de la wiki dinámicamente.
 * NO hay archivos individuales hardcodeados para cada artículo.
 * 
 * ARQUITECTURA:
 * 1. Metadata centralizada → src/data/wiki-articles.ts
 * 2. Contenido centralizado → src/data/wiki-article-contents.tsx
 * 3. Esta página combina ambos y renderiza
 * 
 * BENEFICIOS:
 * - Un solo archivo page.tsx para 60+ artículos
 * - Agregar artículo nuevo = agregar entrada en 2 archivos
 * - Cambiar diseño = editar solo WikiArticleLayout
 */

import { notFound } from 'next/navigation';
import WikiArticleLayout from '@/components/WikiArticleLayout';
import { getArticleBySlug, allArticles } from '@/data/wiki-articles';
import { getArticleContent, hasTranslation, getAvailableLocales } from '@/data/wiki-article-contents';

// ============================================================================
// GENERACIÓN ESTÁTICA DE RUTAS (Next.js SSG)
// ============================================================================

/**
 * Genera todas las rutas posibles en build time
 * Esto hace que todas las páginas sean estáticas (super rápido)
 */
export async function generateStaticParams() {
  return allArticles.map((article) => ({
    category: article.category,
    slug: article.slug,
  }));
}

// ============================================================================
// METADATA DINÁMICA (SEO)
// ============================================================================

export async function generateMetadata({ 
  params 
}: { 
  params: { locale: string; category: string; slug: string } 
}) {
  const article = getArticleBySlug(params.slug);

  if (!article) {
    return {
      title: 'Artículo no encontrado - Aitana Wiki',
    };
  }

  return {
    title: `${article.title} - Aitana Wiki`,
    description: article.description,
    keywords: article.tags.join(', '),
    openGraph: {
      title: article.title,
      description: article.description,
      type: 'article',
      tags: article.tags,
    },
  };
}

// ============================================================================
// COMPONENTE PRINCIPAL
// ============================================================================

export default function WikiArticlePage({
  params,
}: {
  params: { locale: string; category: string; slug: string };
}) {
  // 1. Obtener metadata del artículo
  const article = getArticleBySlug(params.slug);

  if (!article) {
    notFound(); // Muestra página 404
  }

  // 2. Obtener función de contenido en el idioma solicitado
  const ContentComponent = getArticleContent(article.id, params.locale);
  
  // Verificar si existe traducción en el idioma actual
  const isTranslated = hasTranslation(article.id, params.locale);
  const availableLocales = getAvailableLocales(article.id);

  if (!ContentComponent) {
    // Artículo existe en metadata pero no tiene contenido definido
    return (
      <WikiArticleLayout
        category={article.category}
        categoryColor={article.categoryColor}
        title={article.title}
        description={article.description}
        level={article.level}
        readTime={article.readTime}
        lastUpdated={article.lastUpdated}
        cvssScore={article.cvssScore}
        relatedArticles={article.relatedArticles}
      >
        <div className="bg-yellow-50 dark:bg-yellow-900/20 border-2 border-yellow-500 rounded-xl p-8 text-center">
          <h2 className="text-2xl font-bold text-yellow-900 dark:text-yellow-100 mb-4">
            🚧 Contenido en Construcción
          </h2>
          <p className="text-yellow-800 dark:text-yellow-200">
            Este artículo está planificado pero el contenido aún no ha sido escrito.
          </p>
          <p className="text-yellow-700 dark:text-yellow-300 mt-2 text-sm">
            <strong>Tema:</strong> {article.title}
          </p>
          <p className="text-yellow-700 dark:text-yellow-300 text-sm">
            <strong>Nivel:</strong> {article.level} • <strong>Categoría:</strong> {article.category}
          </p>
        </div>
      </WikiArticleLayout>
    );
  }

  // 3. Renderizar layout + contenido
  return (
    <WikiArticleLayout
      category={article.category}
      categoryColor={article.categoryColor}
      title={article.title}
      description={article.description}
      level={article.level}
      readTime={article.readTime}
      lastUpdated={article.lastUpdated}
      author={article.author}
      cvssScore={article.cvssScore}
      relatedArticles={article.relatedArticles}
    >
      {/* Aviso de idioma si no está traducido */}
      {!isTranslated && (
        <div className="mb-8 bg-blue-50 dark:bg-blue-900/20 border-2 border-blue-500 rounded-xl p-6">
          <div className="flex items-start gap-4">
            <div className="text-3xl">🌐</div>
            <div>
              <h3 className="text-lg font-bold text-blue-900 dark:text-blue-100 mb-2">
                {params.locale === 'en' && 'Content Available in Spanish Only'}
                {params.locale === 'fr' && 'Contenu disponible uniquement en espagnol'}
                {params.locale === 'de' && 'Inhalt nur auf Spanisch verfügbar'}
              </h3>
              <p className="text-blue-800 dark:text-blue-200 text-sm">
                {params.locale === 'en' && (
                  <>This article is currently available only in Spanish. We're working on translations.</>
                )}
                {params.locale === 'fr' && (
                  <>Cet article n'est actuellement disponible qu'en espagnol. Nous travaillons sur les traductions.</>
                )}
                {params.locale === 'de' && (
                  <>Dieser Artikel ist derzeit nur auf Spanisch verfügbar. Wir arbeiten an Übersetzungen.</>
                )}
              </p>
              <p className="text-blue-700 dark:text-blue-300 text-sm mt-2">
                {params.locale === 'en' && (
                  <>
                    <strong>Available in:</strong> {availableLocales.map(l => l.toUpperCase()).join(', ')} • 
                    <strong> Tip:</strong> Use your browser's translation feature or visit the{' '}
                    <a href={`/es/wiki/${article.category}/${article.slug}`} className="underline hover:text-blue-600 dark:hover:text-blue-400">
                      Spanish version
                    </a>
                  </>
                )}
                {params.locale === 'fr' && (
                  <>
                    <strong>Disponible en:</strong> {availableLocales.map(l => l.toUpperCase()).join(', ')} • 
                    <strong> Conseil:</strong> Utilisez la fonction de traduction de votre navigateur ou visitez la{' '}
                    <a href={`/es/wiki/${article.category}/${article.slug}`} className="underline hover:text-blue-600 dark:hover:text-blue-400">
                      version espagnole
                    </a>
                  </>
                )}
                {params.locale === 'de' && (
                  <>
                    <strong>Verfügbar in:</strong> {availableLocales.map(l => l.toUpperCase()).join(', ')} • 
                    <strong> Tipp:</strong> Verwenden Sie die Übersetzungsfunktion Ihres Browsers oder besuchen Sie die{' '}
                    <a href={`/es/wiki/${article.category}/${article.slug}`} className="underline hover:text-blue-600 dark:hover:text-blue-400">
                      spanische Version
                    </a>
                  </>
                )}
              </p>
            </div>
          </div>
        </div>
      )}
      
      {/* El contenido se renderiza en el idioma disponible (con fallback a español) */}
      <ContentComponent locale={params.locale} />
    </WikiArticleLayout>
  );
}

/**
 * CÓMO AGREGAR UN NUEVO ARTÍCULO:
 * 
 * 1. Agregar metadata en src/data/wiki-articles.ts:
 *    {
 *      id: 'mi-nuevo-articulo',
 *      slug: 'mi-nuevo-articulo',
 *      category: 'bug-bounty',
 *      title: 'Mi Nuevo Artículo',
 *      // ... resto de propiedades
 *    }
 * 
 * 2. Crear archivo de contenido en ESPAÑOL (obligatorio):
 *    src/content/wiki/bug-bounty/mi-nuevo-articulo.tsx
 * 
 *    export default function MiNuevoArticuloContent({ locale }: { locale: string }) {
 *      return (
 *        <>
 *          <Section title="Introducción">
 *            <Paragraph>Contenido...</Paragraph>
 *          </Section>
 *        </>
 *      );
 *    }
 * 
 * 3. (OPCIONAL) Crear traducciones:
 *    src/content/wiki/bug-bounty/mi-nuevo-articulo.en.tsx  (inglés)
 *    src/content/wiki/bug-bounty/mi-nuevo-articulo.fr.tsx  (francés)
 *    src/content/wiki/bug-bounty/mi-nuevo-articulo.de.tsx  (alemán)
 * 
 * 4. Agregar imports en src/data/wiki-article-contents.tsx:
 *    import MiNuevoArticuloContent from '@/content/wiki/bug-bounty/mi-nuevo-articulo';
 *    import MiNuevoArticuloContentEN from '@/content/wiki/bug-bounty/mi-nuevo-articulo.en';
 * 
 * 5. Agregar al mapa en wiki-article-contents.tsx:
 *    export const articleContentMapByLocale = {
 *      'mi-nuevo-articulo': {
 *        es: MiNuevoArticuloContent,
 *        en: MiNuevoArticuloContentEN,  // si existe
 *      },
 *      ...
 *    };
 * 
 * ¡Eso es todo! El sistema automáticamente:
 * - Detecta el idioma del usuario
 * - Muestra la traducción si existe
 * - Hace fallback a español con banner de aviso si no existe
 * - Genera rutas estáticas para todos los idiomas
 */
