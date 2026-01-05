'use client';

import Link from 'next/link';
import { useParams } from 'next/navigation';
import { Home, Shield, Clock } from 'lucide-react';

export default function SecureSessionsPage() {
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
          <span className="text-white dark:text-white">Secure Sessions</span>
        </div>
      </div>

      <div className="bg-gradient-to-r from-green-600 via-cyan-600 to-blue-600 px-8 py-12">
        <div className="max-w-5xl mx-auto">
          <div className="flex items-center gap-3 mb-4">
            <div className="px-3 py-1 bg-yellow-500/20 text-yellow-700 dark:text-yellow-300 rounded-lg text-sm font-medium border border-yellow-500/30">Intermedio</div>
            <div className="px-3 py-1 bg-white/10 backdrop-blur-sm text-slate-900 dark:text-white rounded-lg text-sm">24 min</div>
          </div>
          <h1 className="text-4xl md:text-5xl font-bold text-slate-900 dark:text-white mb-4 flex items-center gap-4">
            <Clock className="w-12 h-12" />Secure Session Management</h1>
          <p className="text-xl text-green-100">Gestión segura de sesiones con cookies, JWT y mejores prácticas</p>
        </div>
      </div>

      <div className="max-w-5xl mx-auto px-8 py-12">
        <div className="prose prose-invert prose-lg max-w-none">
          <section className="mb-12">
            <h2 className="text-3xl font-bold text-slate-900 dark:text-white mb-6">Sesiones vs JWT</h2>
            
            <div className="grid md:grid-cols-2 gap-6">
              <div className="bg-white/5 border border-white/10 rounded-xl p-6">
                <h3 className="text-xl font-semibold text-slate-900 dark:text-white mb-3">Session-Based (Cookies)</h3>
                <p className="text-slate-700 dark:text-slate-300 mb-4">Estado guardado en servidor, cookie contiene solo session ID.</p>
                <div className="bg-slate-100 dark:bg-slate-800/50 rounded-lg p-4 font-mono text-sm">
                  <pre className="text-blue-600 dark:text-blue-400">
{`const session = require('express-session');

app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure: true,  // HTTPS only
    sameSite: 'strict',
    maxAge: 3600000  // 1 hora
  },
  store: new RedisStore({
    client: redisClient
  })
}));

// Login
req.session.userId = user.id;

// Logout
req.session.destroy();`}
                  </pre>
                </div>
                <ul className="text-slate-700 dark:text-slate-300 space-y-2 mt-4">
                  <li>✅ Revocable (destroy session)</li>
                  <li>✅ Menos riesgo de exposición</li>
                  <li>❌ Requiere storage (Redis, DB)</li>
                </ul>
              </div>

              <div className="bg-white/5 border border-white/10 rounded-xl p-6">
                <h3 className="text-xl font-semibold text-slate-900 dark:text-white mb-3">JWT (Stateless)</h3>
                <p className="text-slate-700 dark:text-slate-300 mb-4">Token auto-contenido, estado en cliente.</p>
                <div className="bg-slate-100 dark:bg-slate-800/50 rounded-lg p-4 font-mono text-sm">
                  <pre className="text-purple-400">
{`const jwt = require('jsonwebtoken');

// Login - generar token
const token = jwt.sign(
  { 
    userId: user.id, 
    email: user.email 
  },
  process.env.JWT_SECRET,
  { 
    expiresIn: '1h',
    algorithm: 'HS256'
  }
);

// Verificar token
const decoded = jwt.verify(
  token, 
  process.env.JWT_SECRET
);

// No hay "logout" directo
// (token válido hasta expiración)`}
                  </pre>
                </div>
                <ul className="text-slate-700 dark:text-slate-300 space-y-2 mt-4">
                  <li>✅ Stateless (no storage)</li>
                  <li>✅ Escalable horizontalmente</li>
                  <li>❌ No revocable hasta expiración</li>
                </ul>
              </div>
            </div>
          </section>

          <section className="mb-12">
            <h2 className="text-3xl font-bold text-slate-900 dark:text-white mb-6">Atributos de Cookie Seguros</h2>
            
            <div className="bg-white/5 border border-white/10 rounded-xl p-6 mb-6">
              <div className="bg-slate-100 dark:bg-slate-800/50 rounded-lg p-4 font-mono text-sm">
                <pre className="text-green-600 dark:text-green-400">
{`res.cookie('session_id', sessionId, {
  httpOnly: true,        // No accesible desde JavaScript
  secure: true,          // Solo HTTPS
  sameSite: 'strict',    // Protección CSRF
  maxAge: 3600000,       // 1 hora
  domain: '.example.com',
  path: '/'
});`}
                </pre>
              </div>
            </div>

            <div className="grid md:grid-cols-2 gap-4">
              <div className="bg-blue-500/10 border border-blue-500/30 rounded-xl p-4">
                <h4 className="font-semibold text-slate-900 dark:text-white mb-2">httpOnly</h4>
                <p className="text-slate-700 dark:text-slate-300 text-sm">Previene XSS: cookie no accesible desde <code>document.cookie</code></p>
              </div>
              <div className="bg-green-500/10 border border-green-500/30 rounded-xl p-4">
                <h4 className="font-semibold text-slate-900 dark:text-white mb-2">secure</h4>
                <p className="text-slate-700 dark:text-slate-300 text-sm">Solo envía cookie en HTTPS, previene intercepción</p>
              </div>
              <div className="bg-purple-500/10 border border-purple-500/30 rounded-xl p-4">
                <h4 className="font-semibold text-slate-900 dark:text-white mb-2">sameSite</h4>
                <p className="text-slate-700 dark:text-slate-300 text-sm">Strict: solo same-site. Lax: permite GET top-level. None: permite cross-site (requiere secure)</p>
              </div>
              <div className="bg-cyan-500/10 border border-cyan-500/30 rounded-xl p-4">
                <h4 className="font-semibold text-slate-900 dark:text-white mb-2">maxAge</h4>
                <p className="text-slate-700 dark:text-slate-300 text-sm">Tiempo de vida en milisegundos. Usar valores cortos (15-60 min)</p>
              </div>
            </div>
          </section>

          <section className="mb-12">
            <h2 className="text-3xl font-bold text-slate-900 dark:text-white mb-6">Session Fixation Attack</h2>
            
            <div className="bg-red-500/10 border border-red-500/30 rounded-xl p-6 mb-6">
              <h3 className="text-xl font-semibold text-slate-900 dark:text-white mb-3">Vulnerable</h3>
              <div className="bg-slate-100 dark:bg-slate-800/50 rounded-lg p-4 font-mono text-sm">
                <pre className="text-red-600 dark:text-red-400">
{`// Atacante fija session ID
// http://site.com/login?session=FIXED_ID

app.post('/login', (req, res) => {
  const user = authenticate(req.body);
  
  // ¡NO regenerar session ID!
  req.session.userId = user.id;
  
  // Ahora atacante puede usar FIXED_ID
});`}
                </pre>
              </div>
            </div>

            <div className="bg-green-500/10 border border-green-500/30 rounded-xl p-6">
              <h3 className="text-xl font-semibold text-slate-900 dark:text-white mb-3">Seguro: Regenerar Session ID</h3>
              <div className="bg-slate-100 dark:bg-slate-800/50 rounded-lg p-4 font-mono text-sm">
                <pre className="text-green-600 dark:text-green-400">
{`app.post('/login', (req, res) => {
  const user = authenticate(req.body);
  
  // Regenerar session ID después de login
  req.session.regenerate((err) => {
    if (err) return res.status(500).send('Error');
    
    req.session.userId = user.id;
    res.send('Login exitoso');
  });
});`}
                </pre>
              </div>
            </div>
          </section>

          <section className="mb-12">
            <h2 className="text-3xl font-bold text-slate-900 dark:text-white mb-6">JWT Best Practices</h2>
            
            <div className="bg-white/5 border border-white/10 rounded-xl p-6">
              <div className="bg-slate-100 dark:bg-slate-800/50 rounded-lg p-4 font-mono text-sm">
                <pre className="text-cyan-600 dark:text-cyan-400">
{`const jwt = require('jsonwebtoken');

// 1. Secret fuerte (min 256 bits)
const SECRET = process.env.JWT_SECRET; // ej: openssl rand -base64 32

// 2. Expiración corta
const token = jwt.sign(payload, SECRET, {
  expiresIn: '15m',      // Token de corta vida
  algorithm: 'HS256',    // Especificar algoritmo
  issuer: 'api.example.com',
  audience: 'app.example.com'
});

// 3. Refresh token (larga vida)
const refreshToken = jwt.sign(
  { userId: user.id }, 
  REFRESH_SECRET, 
  { expiresIn: '7d' }
);

// 4. Almacenar refresh token en DB
await db.refreshTokens.create({
  userId: user.id,
  token: refreshToken,
  expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000)
});

// 5. Verificar con algoritmo específico
jwt.verify(token, SECRET, { 
  algorithms: ['HS256'],  // Prevenir 'none' algorithm attack
  issuer: 'api.example.com'
});`}
                </pre>
              </div>
            </div>
          </section>

          <section className="mb-12">
            <h2 className="text-3xl font-bold text-slate-900 dark:text-white mb-6">Refresh Token Pattern</h2>
            <div className="bg-white/5 border border-white/10 rounded-xl p-6">
              <div className="bg-slate-100 dark:bg-slate-800/50 rounded-lg p-4 font-mono text-sm">
                <pre className="text-purple-400">
{`// Login: enviar access + refresh token
app.post('/login', async (req, res) => {
  const user = authenticate(req.body);

  const accessToken = jwt.sign({ userId: user.id }, SECRET, { expiresIn: '15m' });
  const refreshToken = jwt.sign({ userId: user.id }, REFRESH_SECRET, { expiresIn: '7d' });

  await db.refreshTokens.create({ userId: user.id, token: refreshToken });

  res.json({ accessToken, refreshToken });
});

// Refresh: obtener nuevo access token
app.post('/refresh', async (req, res) => {
  const { refreshToken } = req.body;

  // 1. Verificar refresh token
  const decoded = jwt.verify(refreshToken, REFRESH_SECRET);

  // 2. Verificar en DB (no revocado)
  const storedToken = await db.refreshTokens.findOne({ 
    token: refreshToken, 
    userId: decoded.userId 
  });

  if (!storedToken) {
    return res.status(403).send('Refresh token inválido');
  }

  // 3. Generar nuevo access token
  const newAccessToken = jwt.sign({ userId: decoded.userId }, SECRET, { expiresIn: '15m' });

  res.json({ accessToken: newAccessToken });
});

// Logout: revocar refresh token
app.post('/logout', async (req, res) => {
  const { refreshToken } = req.body;
  await db.refreshTokens.delete({ token: refreshToken });
  res.send('Logout exitoso');
});`}
                </pre>
              </div>
            </div>
          </section>

          <section className="mb-12">
            <h2 className="text-3xl font-bold text-slate-900 dark:text-white mb-6">Mejores Prácticas</h2>
            <div className="grid md:grid-cols-2 gap-6">
              <div className="bg-green-500/10 border border-green-500/30 rounded-xl p-6">
                <h3 className="text-lg font-semibold text-slate-900 dark:text-white mb-3">✅ Hacer</h3>
                <ul className="text-slate-700 dark:text-slate-300 space-y-2">
                  <li>• Usar <code>httpOnly</code>, <code>secure</code>, <code>sameSite</code></li>
                  <li>• Regenerar session ID en login</li>
                  <li>• Expiración corta (15-60 min)</li>
                  <li>• HTTPS obligatorio</li>
                  <li>• Refresh tokens para UX</li>
                  <li>• Algoritmo específico en JWT</li>
                  <li>• Secret fuerte (&gt;256 bits)</li>
                </ul>
              </div>

              <div className="bg-red-500/10 border border-red-500/30 rounded-xl p-6">
                <h3 className="text-lg font-semibold text-slate-900 dark:text-white mb-3">❌ NO Hacer</h3>
                <ul className="text-slate-700 dark:text-slate-300 space-y-2">
                  <li>• NO almacenar tokens en localStorage</li>
                  <li>• NO usar algoritmo 'none' en JWT</li>
                  <li>• NO sessions sin expiración</li>
                  <li>• NO enviar cookies sin <code>secure</code></li>
                  <li>• NO compartir secret entre apps</li>
                  <li>• NO incluir datos sensibles en JWT</li>
                  <li>• NO confiar en client-side validation</li>
                </ul>
              </div>
            </div>
          </section>

          <div className="bg-gradient-to-r from-green-600/20 to-blue-600/20 border border-green-500/30 rounded-xl p-8 text-center">
            <h3 className="text-2xl font-bold text-slate-900 dark:text-white mb-4">Siguiente</h3>
            <Link href={`/${locale}/wiki/herramientas/burp-suite`}
              className="inline-flex items-center gap-2 px-6 py-3 bg-purple-600 hover:bg-purple-700 text-slate-900 dark:text-white rounded-xl font-semibold transition-all">
              Explorar Herramientas<span>→</span></Link>
          </div>
        </div>
      </div>
    </div>
  );
}
