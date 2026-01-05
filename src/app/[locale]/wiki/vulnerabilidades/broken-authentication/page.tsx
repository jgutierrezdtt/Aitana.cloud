'use client';

import Link from 'next/link';
import { useParams } from 'next/navigation';
import { Home, AlertTriangle, Lock, Shield } from 'lucide-react';

export default function BrokenAuthenticationPage() {
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
          <span className="text-white dark:text-white">Broken Authentication</span>
        </div>
      </div>

      <div className="bg-gradient-to-r from-red-600 via-orange-600 to-yellow-600 px-8 py-12">
        <div className="max-w-5xl mx-auto">
          <div className="flex items-center gap-3 mb-4">
            <div className="px-3 py-1 bg-green-500/20 text-green-700 dark:text-green-300 rounded-lg text-sm font-medium border border-green-500/30">Principiante</div>
            <div className="px-3 py-1 bg-red-500/30 text-red-200 rounded-lg text-sm font-medium border border-red-400/40">CVSS 8.1 - Alto</div>
            <div className="px-3 py-1 bg-white/10 backdrop-blur-sm text-slate-900 dark:text-white rounded-lg text-sm">19 min</div>
          </div>
          <h1 className="text-4xl md:text-5xl font-bold text-slate-900 dark:text-white mb-4 flex items-center gap-4">
            <Lock className="w-12 h-12" />Broken Authentication</h1>
          <p className="text-xl text-orange-100">Implementaciones débiles de autenticación y gestión de sesiones</p>
        </div>
      </div>

      <div className="max-w-5xl mx-auto px-8 py-12">
        <div className="prose prose-invert prose-lg max-w-none">
          <section className="mb-12">
            <h2 className="text-3xl font-bold text-slate-900 dark:text-white mb-6">¿Qué es Broken Authentication?</h2>
            <p className="text-slate-700 dark:text-slate-300 mb-6">
              Implementación incorrecta de autenticación que permite a atacantes comprometer contraseñas, tokens, 
              o explotar fallas de implementación para asumir la identidad de otros usuarios.
            </p>
            
            <div className="bg-red-500/10 border border-red-500/30 rounded-xl p-6 mb-6">
              <h3 className="text-xl font-semibold text-red-600 dark:text-red-400 mb-3">Vulnerabilidades Comunes</h3>
              <ul className="text-slate-700 dark:text-slate-300 space-y-2">
                <li>• Permitir ataques de fuerza bruta sin rate limiting</li>
                <li>• Contraseñas débiles o predeterminadas</li>
                <li>• Almacenar contraseñas en texto plano o con hash débil</li>
                <li>• Session fixation</li>
                <li>• Tokens predecibles o sin expiración</li>
                <li>• Falta de autenticación multi-factor</li>
              </ul>
            </div>
          </section>

          <section className="mb-12">
            <h2 className="text-3xl font-bold text-slate-900 dark:text-white mb-6">Ejemplos de Vulnerabilidades</h2>
            <div className="space-y-4">
              <div className="bg-white/5 border border-white/10 rounded-xl p-6">
                <h3 className="text-xl font-semibold text-slate-900 dark:text-white mb-3">1. Sin Rate Limiting</h3>
                <div className="bg-slate-100 dark:bg-slate-800/50 rounded-lg p-4 font-mono text-sm">
                  <pre className="text-red-600 dark:text-red-400">
{`// ❌ VULNERABLE
app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  const user = await db.users.findOne({ username });
  
  if (!user || !await bcrypt.compare(password, user.passwordHash)) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }
  
  res.json({ token: generateToken(user) });
});

// Atacante puede probar millones de contraseñas`}
                  </pre>
                </div>
              </div>

              <div className="bg-white/5 border border-white/10 rounded-xl p-6">
                <h3 className="text-xl font-semibold text-slate-900 dark:text-white mb-3">2. Session Fixation</h3>
                <div className="bg-slate-100 dark:bg-slate-800/50 rounded-lg p-4 font-mono text-sm">
                  <pre className="text-red-600 dark:text-red-400">
{`// ❌ VULNERABLE - no regenerar session ID después del login
app.post('/login', (req, res) => {
  // Autenticar usuario...
  req.session.userId = user.id;  // Usar mismo session ID
  res.json({ success: true });
});

// ✅ SEGURO - regenerar session
app.post('/login', (req, res) => {
  req.session.regenerate((err) => {
    req.session.userId = user.id;
    res.json({ success: true });
  });
});`}
                  </pre>
                </div>
              </div>

              <div className="bg-white/5 border border-white/10 rounded-xl p-6">
                <h3 className="text-xl font-semibold text-slate-900 dark:text-white mb-3">3. Contraseñas Débiles</h3>
                <div className="bg-slate-100 dark:bg-slate-800/50 rounded-lg p-4 font-mono text-sm">
                  <pre className="text-red-600 dark:text-red-400">
{`// ❌ VULNERABLE - sin validación de complejidad
app.post('/register', async (req, res) => {
  const { password } = req.body;
  const hash = await bcrypt.hash(password, 10);
  // Acepta "123" como contraseña
});

// ✅ SEGURO - validar complejidad
const passwordSchema = Joi.string()
  .min(12)
  .pattern(/[a-z]/) // lowercase
  .pattern(/[A-Z]/) // uppercase
  .pattern(/[0-9]/) // number
  .pattern(/[^a-zA-Z0-9]/) // special char
  .required();`}
                  </pre>
                </div>
              </div>
            </div>
          </section>

          <section className="mb-12">
            <h2 className="text-3xl font-bold text-slate-900 dark:text-white mb-6 flex items-center gap-3">
              <Shield className="w-8 h-8 text-green-600 dark:text-green-400" />Mejores Prácticas</h2>
            <div className="bg-green-500/10 border border-green-500/30 rounded-xl p-6 space-y-4">
              <div className="bg-slate-100 dark:bg-slate-800/50 rounded-lg p-4 font-mono text-sm">
                <pre className="text-green-600 dark:text-green-400">
{`// 1. Rate Limiting
const rateLimit = require('express-rate-limit');
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  message: 'Demasiados intentos'
});
app.post('/login', loginLimiter, loginHandler);

// 2. Password Hashing (bcrypt)
const bcrypt = require('bcrypt');
const saltRounds = 12;
const hash = await bcrypt.hash(password, saltRounds);

// 3. Multi-Factor Authentication
const speakeasy = require('speakeasy');
const verified = speakeasy.totp.verify({
  secret: user.twoFactorSecret,
  encoding: 'base32',
  token: req.body.totpCode
});

// 4. Secure Session Management
app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure: true,
    sameSite: 'strict',
    maxAge: 3600000 // 1 hora
  }
}));

// 5. Account Lockout
let failedAttempts = 0;
if (failedAttempts >= 5) {
  await db.users.update(userId, {
    lockedUntil: new Date(Date.now() + 15*60*1000)
  });
}`}
                </pre>
              </div>
            </div>
          </section>

          <div className="bg-gradient-to-r from-red-600/20 to-yellow-600/20 border border-red-500/30 rounded-xl p-8 text-center">
            <h3 className="text-2xl font-bold text-slate-900 dark:text-white mb-4">Siguiente Paso</h3>
            <p className="text-slate-700 dark:text-slate-300 mb-6">Aprende sobre defensas y mitigaciones</p>
            <Link href={`/${locale}/wiki/defensas/output-encoding`}
              className="inline-flex items-center gap-2 px-6 py-3 bg-green-600 hover:bg-green-700 text-slate-900 dark:text-white rounded-xl font-semibold transition-all">
              Ir a Defensas<span>→</span></Link>
          </div>
        </div>
      </div>
    </div>
  );
}
