'use client';

import Link from 'next/link';
import { useParams } from 'next/navigation';
import { Home, Terminal, Target } from 'lucide-react';

export default function BurpSuitePage() {
  const params = useParams();
  const locale = params.locale as string;

  return (
    <div className="min-h-screen">
      <div className="bg-white dark:bg-slate-900/50 border-b border-slate-200 dark:border-slate-700 px-8 py-4">
        <div className="max-w-5xl mx-auto flex items-center gap-2 text-sm">
          <Link href={`/${locale}/wiki`} className="text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:text-white transition-colors flex items-center gap-1">
            <Home className="w-4 h-4" />Wiki</Link>
          <span className="text-slate-600">/</span>
          <Link href={`/${locale}/wiki`} className="text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:text-white transition-colors">Herramientas</Link>
          <span className="text-slate-600">/</span>
          <span className="text-white dark:text-white">Burp Suite</span>
        </div>
      </div>

      <div className="bg-gradient-to-r from-purple-600 via-pink-600 to-red-600 px-8 py-12">
        <div className="max-w-5xl mx-auto">
          <div className="flex items-center gap-3 mb-4">
            <div className="px-3 py-1 bg-yellow-500/20 text-yellow-700 dark:text-yellow-300 rounded-lg text-sm font-medium border border-yellow-500/30">Intermedio</div>
            <div className="px-3 py-1 bg-white/10 backdrop-blur-sm text-slate-900 dark:text-white rounded-lg text-sm">25 min</div>
          </div>
          <h1 className="text-4xl md:text-5xl font-bold text-slate-900 dark:text-white mb-4 flex items-center gap-4">
            <Target className="w-12 h-12" />Burp Suite</h1>
          <p className="text-xl text-purple-100">La herramienta más popular para web application penetration testing</p>
        </div>
      </div>

      <div className="max-w-5xl mx-auto px-8 py-12">
        <div className="prose prose-invert prose-lg max-w-none">
          <section className="mb-12">
            <h2 className="text-3xl font-bold text-slate-900 dark:text-white mb-6">¿Qué es Burp Suite?</h2>
            <p className="text-slate-700 dark:text-slate-300 mb-6">
              Burp Suite es una plataforma integrada para realizar pruebas de seguridad en aplicaciones web. 
              Incluye herramientas para interceptar tráfico HTTP, escanear vulnerabilidades, y manipular requests.
            </p>
            
            <div className="grid md:grid-cols-2 gap-6 mb-6">
              <div className="bg-white/5 border border-white/10 rounded-xl p-6">
                <h3 className="text-xl font-semibold text-slate-900 dark:text-white mb-3">Community Edition (Gratis)</h3>
                <ul className="text-slate-700 dark:text-slate-300 space-y-2">
                  <li>• Proxy interceptor</li>
                  <li>• Repeater manual</li>
                  <li>• Decoder/Comparer</li>
                  <li>• Intruder básico (throttled)</li>
                </ul>
              </div>

              <div className="bg-white/5 border border-white/10 rounded-xl p-6">
                <h3 className="text-xl font-semibold text-slate-900 dark:text-white mb-3">Professional (Pago)</h3>
                <ul className="text-slate-700 dark:text-slate-300 space-y-2">
                  <li>• Scanner automático de vulnerabilidades</li>
                  <li>• Intruder sin límites</li>
                  <li>• Extensiones avanzadas</li>
                  <li>• Colaborador OAST</li>
                </ul>
              </div>
            </div>
          </section>

          <section className="mb-12">
            <h2 className="text-3xl font-bold text-slate-900 dark:text-white mb-6">Componentes Principales</h2>
            
            <div className="space-y-6">
              <div className="bg-white/5 border border-white/10 rounded-xl p-6">
                <h3 className="text-xl font-semibold text-slate-900 dark:text-white mb-3">1. Proxy</h3>
                <p className="text-slate-700 dark:text-slate-300 mb-4">
                  Interceptor de tráfico HTTP/HTTPS entre navegador y servidor. Permite modificar requests/responses en tiempo real.
                </p>
                <div className="bg-slate-100 dark:bg-slate-800/50 rounded-lg p-4 font-mono text-sm">
                  <pre className="text-blue-600 dark:text-blue-400">
{`# Configurar navegador
Proxy: 127.0.0.1:8080

# Certificado CA
1. Navegar a http://burp
2. Descargar CA certificate
3. Instalar en navegador (Firefox: about:preferences#privacy)

# Interceptar requests
Proxy > Intercept > Intercept is on
- Modificar headers, body, params
- Forward / Drop / Action`}
                  </pre>
                </div>
              </div>

              <div className="bg-white/5 border border-white/10 rounded-xl p-6">
                <h3 className="text-xl font-semibold text-slate-900 dark:text-white mb-3">2. Repeater</h3>
                <p className="text-slate-700 dark:text-slate-300 mb-4">
                  Permite enviar requests modificados repetidamente para probar payloads manualmente.
                </p>
                <div className="bg-slate-100 dark:bg-slate-800/50 rounded-lg p-4 font-mono text-sm">
                  <pre className="text-purple-400">
{`# Workflow
1. Click derecho en request > Send to Repeater
2. Modificar request (params, headers, body)
3. Click "Send"
4. Analizar response

# Ejemplo: Testing SQL injection
GET /users?id=1' OR '1'='1 HTTP/1.1
Host: vulnerable-site.com

# Ver si cambia la respuesta`}
                  </pre>
                </div>
              </div>

              <div className="bg-white/5 border border-white/10 rounded-xl p-6">
                <h3 className="text-xl font-semibold text-slate-900 dark:text-white mb-3">3. Intruder</h3>
                <p className="text-slate-700 dark:text-slate-300 mb-4">
                  Automatiza ataques de fuerza bruta, fuzzing, y enumeración con payloads personalizados.
                </p>
                <div className="bg-slate-100 dark:bg-slate-800/50 rounded-lg p-4 font-mono text-sm">
                  <pre className="text-green-600 dark:text-green-400">
{`# Attack types
- Sniper: 1 posición, 1 payload set
- Battering ram: N posiciones, mismo payload
- Pitchfork: N posiciones, N payload sets (paralelo)
- Cluster bomb: N posiciones, N payload sets (cartesiano)

# Ejemplo: Brute force login
POST /login HTTP/1.1
username=admin&password=§payload§

Payloads:
password123
admin123
qwerty
...

# Analizar resultados por status code, length`}
                  </pre>
                </div>
              </div>

              <div className="bg-white/5 border border-white/10 rounded-xl p-6">
                <h3 className="text-xl font-semibold text-slate-900 dark:text-white mb-3">4. Scanner (Pro)</h3>
                <p className="text-slate-700 dark:text-slate-300 mb-4">
                  Escáner automático que detecta SQLi, XSS, CSRF, SSRF, y más.
                </p>
                <div className="bg-slate-100 dark:bg-slate-800/50 rounded-lg p-4 font-mono text-sm">
                  <pre className="text-cyan-600 dark:text-cyan-400">
{`# Tipos de scan
- Passive: Analiza tráfico existente
- Active: Envía payloads de ataque

# Configuración
Target > Site map > Right click > Scan

# Issues detectados
- SQL injection points
- XSS vulnerabilities
- Missing security headers
- Sensitive data exposure`}
                  </pre>
                </div>
              </div>
            </div>
          </section>

          <section className="mb-12">
            <h2 className="text-3xl font-bold text-slate-900 dark:text-white mb-6">Workflow Típico</h2>
            <div className="bg-white/5 border border-white/10 rounded-xl p-6">
              <ol className="text-slate-700 dark:text-slate-300 space-y-4">
                <li><strong>1. Configurar Proxy:</strong> Navegador → Burp Proxy (127.0.0.1:8080)</li>
                <li><strong>2. Navegar sitio target:</strong> Burp registra todo el tráfico en HTTP history</li>
                <li><strong>3. Analizar sitemap:</strong> Target → Site map para ver estructura</li>
                <li><strong>4. Interceptar requests clave:</strong> Login, forms, APIs</li>
                <li><strong>5. Testing manual:</strong> Send to Repeater, modificar payloads (SQL, XSS, etc.)</li>
                <li><strong>6. Automatización:</strong> Send to Intruder para fuzzing o brute force</li>
                <li><strong>7. Scanner (Pro):</strong> Scan automático para detectar vulns</li>
                <li><strong>8. Reporte:</strong> Exportar findings con evidencia (screenshots, requests)</li>
              </ol>
            </div>
          </section>

          <section className="mb-12">
            <h2 className="text-3xl font-bold text-slate-900 dark:text-white mb-6">Extensiones Útiles</h2>
            <div className="grid md:grid-cols-2 gap-6">
              <div className="bg-purple-500/10 border border-purple-500/30 rounded-xl p-4">
                <h4 className="font-semibold text-slate-900 dark:text-white mb-2">Autorize</h4>
                <p className="text-slate-700 dark:text-slate-300 text-sm">Detecta broken access control automáticamente</p>
              </div>
              <div className="bg-pink-500/10 border border-pink-500/30 rounded-xl p-4">
                <h4 className="font-semibold text-slate-900 dark:text-white mb-2">Turbo Intruder</h4>
                <p className="text-slate-700 dark:text-slate-300 text-sm">Intruder ultra-rápido para race conditions</p>
              </div>
              <div className="bg-blue-500/10 border border-blue-500/30 rounded-xl p-4">
                <h4 className="font-semibold text-slate-900 dark:text-white mb-2">JWT Editor</h4>
                <p className="text-slate-700 dark:text-slate-300 text-sm">Decodifica y modifica JSON Web Tokens</p>
              </div>
              <div className="bg-green-500/10 border border-green-500/30 rounded-xl p-4">
                <h4 className="font-semibold text-slate-900 dark:text-white mb-2">Logger++</h4>
                <p className="text-slate-700 dark:text-slate-300 text-sm">Logging avanzado con filtros personalizados</p>
              </div>
            </div>
          </section>

          <div className="bg-gradient-to-r from-purple-600/20 to-pink-600/20 border border-purple-500/30 rounded-xl p-8 text-center">
            <h3 className="text-2xl font-bold text-slate-900 dark:text-white mb-4">Siguiente</h3>
            <Link href={`/${locale}/wiki/herramientas/owasp-zap`}
              className="inline-flex items-center gap-2 px-6 py-3 bg-purple-600 hover:bg-purple-700 text-slate-900 dark:text-white rounded-xl font-semibold transition-all">
              OWASP ZAP<span>→</span></Link>
          </div>
        </div>
      </div>
    </div>
  );
}
