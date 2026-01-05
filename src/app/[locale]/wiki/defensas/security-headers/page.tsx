'use client';

import Link from 'next/link';
import { useParams } from 'next/navigation';
import { Home, Shield, Lock } from 'lucide-react';

export default function SecurityHeadersPage() {
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
          <span className="text-white dark:text-white">Security Headers</span>
        </div>
      </div>

      <div className="bg-gradient-to-r from-green-600 via-blue-600 to-purple-600 px-8 py-12">
        <div className="max-w-5xl mx-auto">
          <div className="flex items-center gap-3 mb-4">
            <div className="px-3 py-1 bg-yellow-500/20 text-yellow-700 dark:text-yellow-300 rounded-lg text-sm font-medium border border-yellow-500/30">Intermedio</div>
            <div className="px-3 py-1 bg-white/10 backdrop-blur-sm text-slate-900 dark:text-white rounded-lg text-sm">18 min</div>
          </div>
          <h1 className="text-4xl md:text-5xl font-bold text-slate-900 dark:text-white mb-4 flex items-center gap-4">
            <Lock className="w-12 h-12" />Security Headers</h1>
          <p className="text-xl text-green-100">Headers HTTP esenciales para proteger tu aplicación web</p>
        </div>
      </div>

      <div className="max-w-5xl mx-auto px-8 py-12">
        <div className="prose prose-invert prose-lg max-w-none">
          <section className="mb-12">
            <h2 className="text-3xl font-bold text-slate-900 dark:text-white mb-6">Headers de Seguridad Esenciales</h2>
            
            <div className="space-y-6">
              <div className="bg-white/5 border border-white/10 rounded-xl p-6">
                <h3 className="text-xl font-semibold text-slate-900 dark:text-white mb-3">Strict-Transport-Security (HSTS)</h3>
                <p className="text-slate-700 dark:text-slate-300 mb-3">Fuerza HTTPS y previene downgrade attacks.</p>
                <div className="bg-slate-100 dark:bg-slate-800/50 rounded-lg p-4 font-mono text-sm">
                  <pre className="text-green-600 dark:text-green-400">
{`Strict-Transport-Security: max-age=31536000; includeSubDomains; preload

// Express
app.use(helmet.hsts({
  maxAge: 31536000,
  includeSubDomains: true,
  preload: true
}));`}
                  </pre>
                </div>
              </div>

              <div className="bg-white/5 border border-white/10 rounded-xl p-6">
                <h3 className="text-xl font-semibold text-slate-900 dark:text-white mb-3">X-Content-Type-Options</h3>
                <p className="text-slate-700 dark:text-slate-300 mb-3">Previene MIME sniffing.</p>
                <div className="bg-slate-100 dark:bg-slate-800/50 rounded-lg p-4 font-mono text-sm">
                  <pre className="text-green-600 dark:text-green-400">
{`X-Content-Type-Options: nosniff

res.setHeader('X-Content-Type-Options', 'nosniff');`}
                  </pre>
                </div>
              </div>

              <div className="bg-white/5 border border-white/10 rounded-xl p-6">
                <h3 className="text-xl font-semibold text-slate-900 dark:text-white mb-3">X-Frame-Options</h3>
                <p className="text-slate-700 dark:text-slate-300 mb-3">Previene clickjacking bloqueando iframes.</p>
                <div className="bg-slate-100 dark:bg-slate-800/50 rounded-lg p-4 font-mono text-sm">
                  <pre className="text-green-600 dark:text-green-400">
{`X-Frame-Options: DENY
// o
X-Frame-Options: SAMEORIGIN

res.setHeader('X-Frame-Options', 'DENY');`}
                  </pre>
                </div>
              </div>

              <div className="bg-white/5 border border-white/10 rounded-xl p-6">
                <h3 className="text-xl font-semibold text-slate-900 dark:text-white mb-3">Referrer-Policy</h3>
                <p className="text-slate-700 dark:text-slate-300 mb-3">Controla qué información de referrer se envía.</p>
                <div className="bg-slate-100 dark:bg-slate-800/50 rounded-lg p-4 font-mono text-sm">
                  <pre className="text-green-600 dark:text-green-400">
{`Referrer-Policy: strict-origin-when-cross-origin

res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');`}
                  </pre>
                </div>
              </div>

              <div className="bg-white/5 border border-white/10 rounded-xl p-6">
                <h3 className="text-xl font-semibold text-slate-900 dark:text-white mb-3">Permissions-Policy</h3>
                <p className="text-slate-700 dark:text-slate-300 mb-3">Controla qué features del navegador pueden usarse.</p>
                <div className="bg-slate-100 dark:bg-slate-800/50 rounded-lg p-4 font-mono text-sm">
                  <pre className="text-green-600 dark:text-green-400">
{`Permissions-Policy: geolocation=(), microphone=(), camera=()

res.setHeader('Permissions-Policy', 
  'geolocation=(), microphone=(), camera=()'
);`}
                  </pre>
                </div>
              </div>
            </div>
          </section>

          <section className="mb-12">
            <h2 className="text-3xl font-bold text-slate-900 dark:text-white mb-6">Implementación Completa</h2>
            
            <div className="bg-white/5 border border-white/10 rounded-xl p-6">
              <h3 className="text-xl font-semibold text-slate-900 dark:text-white mb-4">Helmet.js (Express)</h3>
              <div className="bg-slate-100 dark:bg-slate-800/50 rounded-lg p-4 font-mono text-sm">
                <pre className="text-blue-600 dark:text-blue-400">
{`const helmet = require('helmet');

app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", "data:", "https:"]
    }
  },
  hsts: {
    maxAge: 31536000,
    includeSubDomains: true,
    preload: true
  },
  frameguard: {
    action: 'deny'
  },
  referrerPolicy: {
    policy: 'strict-origin-when-cross-origin'
  }
}));`}
                </pre>
              </div>
            </div>
          </section>

          <section className="mb-12">
            <h2 className="text-3xl font-bold text-slate-900 dark:text-white mb-6">Next.js Configuration</h2>
            <div className="bg-white/5 border border-white/10 rounded-xl p-6">
              <div className="bg-slate-100 dark:bg-slate-800/50 rounded-lg p-4 font-mono text-sm">
                <pre className="text-cyan-600 dark:text-cyan-400">
{`// next.config.js
module.exports = {
  async headers() {
    return [
      {
        source: '/:path*',
        headers: [
          { key: 'X-DNS-Prefetch-Control', value: 'on' },
          { key: 'Strict-Transport-Security', value: 'max-age=31536000; includeSubDomains' },
          { key: 'X-Frame-Options', value: 'SAMEORIGIN' },
          { key: 'X-Content-Type-Options', value: 'nosniff' },
          { key: 'X-XSS-Protection', value: '1; mode=block' },
          { key: 'Referrer-Policy', value: 'strict-origin-when-cross-origin' },
          { key: 'Permissions-Policy', value: 'camera=(), microphone=(), geolocation=()' }
        ]
      }
    ];
  }
};`}
                </pre>
              </div>
            </div>
          </section>

          <div className="bg-gradient-to-r from-green-600/20 to-purple-600/20 border border-green-500/30 rounded-xl p-8 text-center">
            <h3 className="text-2xl font-bold text-slate-900 dark:text-white mb-4">Siguiente</h3>
            <Link href={`/${locale}/wiki/defensas/password-hashing`}
              className="inline-flex items-center gap-2 px-6 py-3 bg-green-600 hover:bg-green-700 text-slate-900 dark:text-white rounded-xl font-semibold transition-all">
              Password Hashing<span>→</span></Link>
          </div>
        </div>
      </div>
    </div>
  );
}
