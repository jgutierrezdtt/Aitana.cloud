'use client';

import Link from 'next/link';
import { useParams } from 'next/navigation';
import { Home, Shield, Code } from 'lucide-react';

export default function OutputEncodingPage() {
  const params = useParams();
  const locale = params.locale as string;

  return (
    <div className="min-h-screen">
      <div className="bg-white dark:bg-slate-900/50 border-b border-slate-200 dark:border-slate-700 px-8 py-4">
        <div className="max-w-5xl mx-auto flex items-center gap-2 text-sm">
          <Link href={`/${locale}/wiki`} className="text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:text-white transition-colors flex items-center gap-1">
            <Home className="w-4 h-4" />Wiki</Link>
          <span className="text-slate-600">/</span>
          <Link href={`/${locale}/wiki`} className="text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:text-white transition-colors">Defensas</Link>
          <span className="text-slate-600">/</span>
          <span className="text-white dark:text-white">Output Encoding</span>
        </div>
      </div>

      <div className="bg-gradient-to-r from-green-600 via-emerald-600 to-teal-600 px-8 py-12">
        <div className="max-w-5xl mx-auto">
          <div className="flex items-center gap-3 mb-4">
            <div className="px-3 py-1 bg-green-500/20 text-green-700 dark:text-green-300 rounded-lg text-sm font-medium border border-green-500/30">Principiante</div>
            <div className="px-3 py-1 bg-white/10 backdrop-blur-sm text-slate-900 dark:text-white rounded-lg text-sm">14 min</div>
          </div>
          <h1 className="text-4xl md:text-5xl font-bold text-slate-900 dark:text-white mb-4 flex items-center gap-4">
            <Shield className="w-12 h-12" />Output Encoding</h1>
          <p className="text-xl text-green-100">Escapar datos peligrosos antes de renderizarlos en HTML, JS, CSS o URLs</p>
        </div>
      </div>

      <div className="max-w-5xl mx-auto px-8 py-12">
        <div className="prose prose-invert prose-lg max-w-none">
          <section className="mb-12">
            <h2 className="text-3xl font-bold text-slate-900 dark:text-white mb-6">¿Qué es Output Encoding?</h2>
            <p className="text-slate-700 dark:text-slate-300 mb-6">
              Output Encoding (o escaping) es el proceso de convertir caracteres especiales en sus equivalentes seguros 
              para prevenir que sean interpretados como código ejecutable.
            </p>
            
            <div className="bg-green-500/10 border border-green-500/30 rounded-xl p-6 mb-6">
              <h3 className="text-xl font-semibold text-slate-900 dark:text-white mb-3">Defensa Principal contra XSS</h3>
              <p className="text-slate-700 dark:text-slate-300">
                Output encoding es la defensa más efectiva contra Cross-Site Scripting (XSS). 
                Se aplica cuando datos no confiables se insertan en diferentes contextos.
              </p>
            </div>
          </section>

          <section className="mb-12">
            <h2 className="text-3xl font-bold text-slate-900 dark:text-white mb-6">Tipos de Encoding por Contexto</h2>
            
            <div className="space-y-6">
              <div className="bg-white/5 border border-white/10 rounded-xl p-6">
                <h3 className="text-xl font-semibold text-slate-900 dark:text-white mb-4">1. HTML Entity Encoding</h3>
                <div className="bg-slate-100 dark:bg-slate-800/50 rounded-lg p-4 font-mono text-sm mb-4">
                  <pre className="text-green-600 dark:text-green-400">
{`// Convertir caracteres peligrosos a entities
& → &amp;
< → &lt;
> → &gt;
" → &quot;
' → &#x27;

// JavaScript
function escapeHtml(str) {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#x27;');
}

// React (auto-escaping)
<div>{userInput}</div>  // ✅ React escapa automáticamente

// Vue.js (auto-escaping)
<div>{{ userInput }}</div>  // ✅ Vue escapa automáticamente

// Handlebars
<div>{{userInput}}</div>  // ✅ Escapa por defecto
<div>{{{userInput}}}</div>  // ❌ Triple-mustache NO escapa`}
                  </pre>
                </div>
              </div>

              <div className="bg-white/5 border border-white/10 rounded-xl p-6">
                <h3 className="text-xl font-semibold text-slate-900 dark:text-white mb-4">2. JavaScript Encoding</h3>
                <div className="bg-slate-100 dark:bg-slate-800/50 rounded-lg p-4 font-mono text-sm">
                  <pre className="text-green-600 dark:text-green-400">
{`// Para insertar en bloques <script>
function escapeJs(str) {
  return str
    .replace(/\\\\/g, '\\\\\\\\')
    .replace(/'/g, "\\\\'")
    .replace(/"/g, '\\\\"')
    .replace(/\\n/g, '\\\\n')
    .replace(/\\r/g, '\\\\r');
}

// ❌ VULNERABLE
<script>
  var name = "${userInput}";
</script>

// ✅ MEJOR - usar JSON.stringify
<script>
  var name = ${JSON.stringify(userInput)};
</script>

// ✅ MÁS SEGURO - pasar datos via data attributes
<div id="app" data-name="${escapeHtml(userInput)}"></div>
<script>
  const name = document.getElementById('app').dataset.name;
</script>`}
                  </pre>
                </div>
              </div>

              <div className="bg-white/5 border border-white/10 rounded-xl p-6">
                <h3 className="text-xl font-semibold text-slate-900 dark:text-white mb-4">3. URL Encoding</h3>
                <div className="bg-slate-100 dark:bg-slate-800/50 rounded-lg p-4 font-mono text-sm">
                  <pre className="text-green-600 dark:text-green-400">
{`// Para URLs y parámetros de query
const encoded = encodeURIComponent(userInput);

// Ejemplo
const searchQuery = userInput;
const url = \`/search?q=\${encodeURIComponent(searchQuery)}\`;

// ❌ VULNERABLE
<a href="/search?q=${userInput}">Search</a>

// ✅ SEGURO
<a href="/search?q=${encodeURIComponent(userInput)}">Search</a>

// JavaScript href
// ❌ NUNCA permitir javascript: protocol
<a href="${userInput}">  // Puede ser javascript:alert(1)

// ✅ Validar protocolo
const url = userInput;
if (url.startsWith('http://') || url.startsWith('https://')) {
  link.href = url;
}`}
                  </pre>
                </div>
              </div>

              <div className="bg-white/5 border border-white/10 rounded-xl p-6">
                <h3 className="text-xl font-semibold text-slate-900 dark:text-white mb-4">4. CSS Encoding</h3>
                <div className="bg-slate-100 dark:bg-slate-800/50 rounded-lg p-4 font-mono text-sm">
                  <pre className="text-green-600 dark:text-green-400">
{`// ❌ VULNERABLE - input en style attributes
<div style="color: ${userInput}">

// Ataque: red; background: url('javascript:alert(1)')

// ✅ MEJOR - usar clases CSS predefinidas
const allowedColors = ['red', 'blue', 'green'];
if (allowedColors.includes(userColor)) {
  element.className = userColor;
}

// ✅ SEGURO - CSS.escape() (navegador moderno)
element.style.setProperty('color', CSS.escape(userInput));`}
                  </pre>
                </div>
              </div>
            </div>
          </section>

          <section className="mb-12">
            <h2 className="text-3xl font-bold text-slate-900 dark:text-white mb-6">Librerías de Sanitización</h2>
            <div className="bg-white/5 border border-white/10 rounded-xl p-6">
              <div className="bg-slate-100 dark:bg-slate-800/50 rounded-lg p-4 font-mono text-sm">
                <pre className="text-cyan-600 dark:text-cyan-400">
{`// DOMPurify - Sanitizar HTML
import DOMPurify from 'isomorphic-dompurify';

const dirty = '<img src=x onerror=alert(1)> Hello';
const clean = DOMPurify.sanitize(dirty);
// Output: '<img src="x"> Hello'

// Con configuración
const clean = DOMPurify.sanitize(dirty, {
  ALLOWED_TAGS: ['b', 'i', 'u', 'p', 'br'],
  ALLOWED_ATTR: []
});

// Lodash escape
import { escape } from 'lodash';
const safe = escape('<script>alert("XSS")</script>');
// Output: '&lt;script&gt;alert(&quot;XSS&quot;)&lt;/script&gt;'

// validator.js
import validator from 'validator';
const escaped = validator.escape(userInput);
const isEmail = validator.isEmail(input);`}
                </pre>
              </div>
            </div>
          </section>

          <section className="mb-12">
            <h2 className="text-3xl font-bold text-slate-900 dark:text-white mb-6">Mejores Prácticas</h2>
            <div className="bg-blue-500/10 border border-blue-500/30 rounded-xl p-6">
              <ul className="text-slate-700 dark:text-slate-300 space-y-3">
                <li>✓ <strong className="text-white dark:text-white">Escapar TODO output no confiable</strong> - Asumir que todos los datos son maliciosos</li>
                <li>✓ <strong className="text-white dark:text-white">Aplicar encoding correcto según contexto</strong> - HTML, JS, URL, CSS requieren diferentes métodos</li>
                <li>✓ <strong className="text-white dark:text-white">Usar frameworks con auto-escaping</strong> - React, Vue, Angular escapan por defecto</li>
                <li>✓ <strong className="text-white dark:text-white">Validar Y escapar</strong> - Defensa en profundidad</li>
                <li>✓ <strong className="text-white dark:text-white">NUNCA confiar en encoding del cliente</strong> - Siempre en el servidor</li>
                <li>✓ <strong className="text-white dark:text-white">Evitar insertar en contextos JavaScript</strong> - Usar data attributes en su lugar</li>
              </ul>
            </div>
          </section>

          <div className="bg-gradient-to-r from-green-600/20 to-emerald-600/20 border border-green-500/30 rounded-xl p-8 text-center">
            <h3 className="text-2xl font-bold text-slate-900 dark:text-white mb-4">Siguiente</h3>
            <Link href={`/${locale}/wiki/defensas/parameterized-queries`}
              className="inline-flex items-center gap-2 px-6 py-3 bg-green-600 hover:bg-green-700 text-slate-900 dark:text-white rounded-xl font-semibold transition-all">
              Parameterized Queries<span>→</span></Link>
          </div>
        </div>
      </div>
    </div>
  );
}
