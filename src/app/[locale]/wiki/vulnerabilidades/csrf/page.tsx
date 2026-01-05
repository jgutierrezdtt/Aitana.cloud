'use client';

import Link from 'next/link';
import { useParams } from 'next/navigation';
import { Home, AlertTriangle, Shield, Code } from 'lucide-react';

export default function CSRFPage() {
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
          <span className="text-white dark:text-white">Cross-Site Request Forgery (CSRF)</span>
        </div>
      </div>

      <div className="bg-gradient-to-r from-red-600 via-pink-600 to-purple-600 px-8 py-12">
        <div className="max-w-5xl mx-auto">
          <div className="flex items-center gap-3 mb-4">
            <div className="px-3 py-1 bg-green-500/20 text-green-700 dark:text-green-300 rounded-lg text-sm font-medium border border-green-500/30">
              Principiante
            </div>
            <div className="px-3 py-1 bg-orange-500/30 text-orange-200 rounded-lg text-sm font-medium border border-orange-400/40">
              CVSS 6.5 - Medio
            </div>
            <div className="px-3 py-1 bg-white/10 backdrop-blur-sm text-slate-900 dark:text-white rounded-lg text-sm">
              18 min lectura
            </div>
          </div>
          <h1 className="text-4xl md:text-5xl font-bold text-slate-900 dark:text-white mb-4 flex items-center gap-4">
            <AlertTriangle className="w-12 h-12" />
            Cross-Site Request Forgery (CSRF)
          </h1>
          <p className="text-xl text-pink-100">
            Fuerza a un usuario autenticado a ejecutar acciones no deseadas en una aplicación web
          </p>
        </div>
      </div>

      <div className="max-w-5xl mx-auto px-8 py-12">
        <div className="prose prose-invert prose-lg max-w-none">
          
          <section className="mb-12">
            <h2 className="text-3xl font-bold text-slate-900 dark:text-white mb-6">¿Qué es CSRF?</h2>
            <p className="text-slate-700 dark:text-slate-300 mb-6">
              CSRF es un ataque que engaña al navegador de un usuario autenticado para que envíe una petición HTTP 
              a una aplicación web en la que está autenticado, ejecutando una acción no autorizada.
            </p>
            
            <div className="bg-red-500/10 border border-red-500/30 rounded-xl p-6 mb-6">
              <h3 className="text-xl font-semibold text-red-600 dark:text-red-400 mb-3">Impacto</h3>
              <ul className="text-slate-700 dark:text-slate-300 space-y-2">
                <li>• Transferencias de dinero no autorizadas</li>
                <li>• Cambio de email/contraseña de la víctima</li>
                <li>• Creación/modificación/eliminación de datos</li>
                <li>• Cambios en configuración de cuenta</li>
                <li>• Acciones privilegiadas si la víctima es admin</li>
              </ul>
            </div>

            <h3 className="text-2xl font-semibold text-red-600 dark:text-red-400 mb-4">Ejemplo de Ataque</h3>
            <div className="bg-slate-100 dark:bg-slate-800/50 rounded-xl p-6 font-mono text-sm overflow-x-auto mb-6">
              <pre className="text-red-600 dark:text-red-400">
{`// 1. Sitio bancario vulnerable
// POST /transfer
// Cookie: sessionId=valid_user_session

// 2. Atacante crea página maliciosa
<!-- evil-site.com/attack.html -->
<html>
  <body onload="document.forms[0].submit()">
    <form action="https://bank.com/transfer" method="POST">
      <input type="hidden" name="to" value="attacker_account">
      <input type="hidden" name="amount" value="10000">
    </form>
  </body>
</html>

// 3. Víctima visita evil-site.com
// El navegador envía automáticamente la cookie de sesión
// La transferencia se ejecuta sin que la víctima lo sepa`}
              </pre>
            </div>
          </section>

          <section className="mb-12">
            <h2 className="text-3xl font-bold text-slate-900 dark:text-white mb-6">Vectores de Ataque</h2>
            
            <div className="space-y-4">
              <div className="bg-white/5 border border-white/10 rounded-xl p-6">
                <h3 className="text-xl font-semibold text-slate-900 dark:text-white mb-3">1. Formularios Auto-Submit</h3>
                <div className="bg-slate-100 dark:bg-slate-800/50 rounded-lg p-4 font-mono text-sm">
                  <pre className="text-red-600 dark:text-red-400">
{`<form action="https://target.com/delete-account" method="POST">
  <input type="hidden" name="confirm" value="yes">
</form>
<script>document.forms[0].submit();</script>`}
                  </pre>
                </div>
              </div>

              <div className="bg-white/5 border border-white/10 rounded-xl p-6">
                <h3 className="text-xl font-semibold text-slate-900 dark:text-white mb-3">2. IMG Tags con GET Requests</h3>
                <div className="bg-slate-100 dark:bg-slate-800/50 rounded-lg p-4 font-mono text-sm">
                  <pre className="text-red-600 dark:text-red-400">
{`<!-- En email o sitio malicioso -->
<img src="https://bank.com/transfer?to=attacker&amount=1000" 
     style="display:none">`}
                  </pre>
                </div>
              </div>

              <div className="bg-white/5 border border-white/10 rounded-xl p-6">
                <h3 className="text-xl font-semibold text-slate-900 dark:text-white mb-3">3. AJAX Cross-Origin (si CORS mal configurado)</h3>
                <div className="bg-slate-100 dark:bg-slate-800/50 rounded-lg p-4 font-mono text-sm">
                  <pre className="text-red-600 dark:text-red-400">
{`fetch('https://target.com/api/change-email', {
  method: 'POST',
  credentials: 'include', // enviar cookies
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ email: 'attacker@evil.com' })
});`}
                  </pre>
                </div>
              </div>
            </div>
          </section>

          <section className="mb-12">
            <h2 className="text-3xl font-bold text-slate-900 dark:text-white mb-6 flex items-center gap-3">
              <Shield className="w-8 h-8 text-green-600 dark:text-green-400" />
              Defensas contra CSRF
            </h2>
            
            <div className="space-y-6">
              <div className="bg-green-500/10 border border-green-500/30 rounded-xl p-6">
                <h3 className="text-xl font-semibold text-slate-900 dark:text-white mb-4">1. CSRF Tokens (Synchronizer Token)</h3>
                <p className="text-slate-700 dark:text-slate-300 mb-4">Token único y aleatorio en cada formulario/petición.</p>
                <div className="bg-slate-100 dark:bg-slate-800/50 rounded-lg p-4 font-mono text-sm">
                  <pre className="text-green-600 dark:text-green-400">
{`// Backend - Generar token
import csrf from 'csurf';
const csrfProtection = csrf({ cookie: true });

app.get('/form', csrfProtection, (req, res) => {
  res.render('form', { csrfToken: req.csrfToken() });
});

// HTML - Incluir token en formulario
<form method="POST" action="/transfer">
  <input type="hidden" name="_csrf" value="<%= csrfToken %>">
  <input name="to" placeholder="Destinatario">
  <input name="amount" placeholder="Cantidad">
  <button>Transferir</button>
</form>

// Backend - Verificar token
app.post('/transfer', csrfProtection, (req, res) => {
  // csurf middleware verifica automáticamente
  // Si el token no coincide, rechaza con 403
  processTransfer(req.body);
});

// Next.js API Route
import { getCsrfToken } from 'next-auth/csrf';

export default async function handler(req, res) {
  const csrfToken = await getCsrfToken({ req });
  
  if (req.method === 'POST') {
    if (req.body.csrfToken !== csrfToken) {
      return res.status(403).json({ error: 'Invalid CSRF token' });
    }
    // Procesar petición
  }
}`}
                  </pre>
                </div>
              </div>

              <div className="bg-green-500/10 border border-green-500/30 rounded-xl p-6">
                <h3 className="text-xl font-semibold text-slate-900 dark:text-white mb-4">2. SameSite Cookies</h3>
                <p className="text-slate-700 dark:text-slate-300 mb-4">Prevenir envío de cookies en peticiones cross-site.</p>
                <div className="bg-slate-100 dark:bg-slate-800/50 rounded-lg p-4 font-mono text-sm">
                  <pre className="text-green-600 dark:text-green-400">
{`// Express.js
res.cookie('sessionId', token, {
  httpOnly: true,
  secure: true,
  sameSite: 'strict' // o 'lax'
});

// SameSite=Strict: No envía cookie en ninguna petición cross-site
// SameSite=Lax: Envía cookie solo en navegación GET top-level
// SameSite=None: Requiere Secure (HTTPS)

// Next.js
export default function handler(req, res) {
  res.setHeader('Set-Cookie', 
    'session=abc123; HttpOnly; Secure; SameSite=Strict; Path=/'
  );
}`}
                  </pre>
                </div>
              </div>

              <div className="bg-green-500/10 border border-green-500/30 rounded-xl p-6">
                <h3 className="text-xl font-semibold text-slate-900 dark:text-white mb-4">3. Double Submit Cookie</h3>
                <div className="bg-slate-100 dark:bg-slate-800/50 rounded-lg p-4 font-mono text-sm">
                  <pre className="text-green-600 dark:text-green-400">
{`// 1. Servidor envía token en cookie
res.cookie('csrf-token', randomToken, { httpOnly: false });

// 2. Cliente lee cookie y envía en header
const csrfToken = getCookie('csrf-token');
fetch('/api/action', {
  method: 'POST',
  headers: {
    'X-CSRF-Token': csrfToken
  },
  body: JSON.stringify(data)
});

// 3. Servidor compara cookie vs header
app.post('/api/action', (req, res) => {
  const cookieToken = req.cookies['csrf-token'];
  const headerToken = req.headers['x-csrf-token'];
  
  if (cookieToken !== headerToken) {
    return res.status(403).json({ error: 'CSRF token mismatch' });
  }
  // Procesar
});`}
                  </pre>
                </div>
              </div>

              <div className="bg-green-500/10 border border-green-500/30 rounded-xl p-6">
                <h3 className="text-xl font-semibold text-slate-900 dark:text-white mb-4">4. Custom Request Headers</h3>
                <p className="text-slate-700 dark:text-slate-300 mb-4">AJAX requests con headers custom (navegador previene en cross-origin).</p>
                <div className="bg-slate-100 dark:bg-slate-800/50 rounded-lg p-4 font-mono text-sm">
                  <pre className="text-green-600 dark:text-green-400">
{`// Cliente
fetch('/api/action', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
    'X-Requested-With': 'XMLHttpRequest' // header custom
  },
  body: JSON.stringify(data)
});

// Servidor verifica presencia del header
app.post('/api/action', (req, res) => {
  if (!req.headers['x-requested-with']) {
    return res.status(403).json({ error: 'Missing custom header' });
  }
  // Procesar
});`}
                  </pre>
                </div>
              </div>

              <div className="bg-green-500/10 border border-green-500/30 rounded-xl p-6">
                <h3 className="text-xl font-semibold text-slate-900 dark:text-white mb-4">5. Verificar Origin/Referer Headers</h3>
                <div className="bg-slate-100 dark:bg-slate-800/50 rounded-lg p-4 font-mono text-sm">
                  <pre className="text-green-600 dark:text-green-400">
{`app.post('/api/action', (req, res) => {
  const origin = req.headers.origin || req.headers.referer;
  const allowedOrigins = ['https://myapp.com'];
  
  if (!origin || !allowedOrigins.some(o => origin.startsWith(o))) {
    return res.status(403).json({ error: 'Invalid origin' });
  }
  // Procesar
});`}
                  </pre>
                </div>
              </div>
            </div>
          </section>

          <section className="mb-12">
            <h2 className="text-3xl font-bold text-slate-900 dark:text-white mb-6">Mejores Prácticas</h2>
            <div className="bg-blue-500/10 border border-blue-500/30 rounded-xl p-6">
              <ul className="text-slate-700 dark:text-slate-300 space-y-3">
                <li className="flex items-start gap-3">
                  <Shield className="w-5 h-5 text-green-600 dark:text-green-400 flex-shrink-0 mt-1" />
                  <span><strong className="text-white dark:text-white">Nunca usar GET para acciones que cambian estado</strong> - Solo POST, PUT, DELETE</span>
                </li>
                <li className="flex items-start gap-3">
                  <Shield className="w-5 h-5 text-green-600 dark:text-green-400 flex-shrink-0 mt-1" />
                  <span><strong className="text-white dark:text-white">Implementar CSRF tokens en todos los formularios</strong> - Especialmente acciones sensibles</span>
                </li>
                <li className="flex items-start gap-3">
                  <Shield className="w-5 h-5 text-green-600 dark:text-green-400 flex-shrink-0 mt-1" />
                  <span><strong className="text-white dark:text-white">Usar SameSite=Strict o Lax en cookies</strong> - Defensa en profundidad</span>
                </li>
                <li className="flex items-start gap-3">
                  <Shield className="w-5 h-5 text-green-600 dark:text-green-400 flex-shrink-0 mt-1" />
                  <span><strong className="text-white dark:text-white">Re-autenticar para acciones críticas</strong> - Transferencias, cambio de password</span>
                </li>
                <li className="flex items-start gap-3">
                  <Shield className="w-5 h-5 text-green-600 dark:text-green-400 flex-shrink-0 mt-1" />
                  <span><strong className="text-white dark:text-white">Implementar rate limiting</strong> - Limitar peticiones sospechosas</span>
                </li>
              </ul>
            </div>
          </section>

          <section className="mb-12">
            <h2 className="text-3xl font-bold text-slate-900 dark:text-white mb-6">Recursos Adicionales</h2>
            <div className="bg-white/5 border border-white/10 rounded-xl p-6 space-y-3">
              <a href="https://owasp.org/www-community/attacks/csrf" target="_blank" rel="noopener noreferrer" 
                 className="block text-blue-600 dark:text-blue-400 hover:text-blue-700 dark:text-blue-300 hover:underline">
                → OWASP - Cross-Site Request Forgery (CSRF)
              </a>
              <a href="https://portswigger.net/web-security/csrf" target="_blank" rel="noopener noreferrer"
                 className="block text-blue-600 dark:text-blue-400 hover:text-blue-700 dark:text-blue-300 hover:underline">
                → PortSwigger Academy - CSRF
              </a>
            </div>
          </section>

          <div className="bg-gradient-to-r from-red-600/20 to-purple-600/20 border border-red-500/30 rounded-xl p-8 text-center">
            <h3 className="text-2xl font-bold text-slate-900 dark:text-white mb-4">Siguiente Paso</h3>
            <p className="text-slate-700 dark:text-slate-300 mb-6">
              Aprende sobre vulnerabilidades de control de acceso
            </p>
            <Link
              href={`/${locale}/wiki/vulnerabilidades/idor`}
              className="inline-flex items-center gap-2 px-6 py-3 bg-purple-600 hover:bg-purple-700 text-slate-900 dark:text-white rounded-xl font-semibold transition-all transform hover:scale-105"
            >
              Insecure Direct Object References (IDOR)
              <span>→</span>
            </Link>
          </div>
        </div>
      </div>
    </div>
  );
}
