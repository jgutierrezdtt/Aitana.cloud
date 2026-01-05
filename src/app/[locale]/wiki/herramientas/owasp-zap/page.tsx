'use client';

import Link from 'next/link';
import { useParams } from 'next/navigation';
import { Home, Terminal, Zap } from 'lucide-react';

export default function OWASPZAPPage() {
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
          <span className="text-white dark:text-white">OWASP ZAP</span>
        </div>
      </div>

      <div className="bg-gradient-to-r from-purple-600 via-indigo-600 to-blue-600 px-8 py-12">
        <div className="max-w-5xl mx-auto">
          <div className="flex items-center gap-3 mb-4">
            <div className="px-3 py-1 bg-green-500/20 text-green-700 dark:text-green-300 rounded-lg text-sm font-medium border border-green-500/30">Principiante</div>
            <div className="px-3 py-1 bg-white/10 backdrop-blur-sm text-slate-900 dark:text-white rounded-lg text-sm">20 min</div>
          </div>
          <h1 className="text-4xl md:text-5xl font-bold text-slate-900 dark:text-white mb-4 flex items-center gap-4">
            <Zap className="w-12 h-12" />OWASP ZAP</h1>
          <p className="text-xl text-purple-100">Zed Attack Proxy - Scanner de seguridad web open source</p>
        </div>
      </div>

      <div className="max-w-5xl mx-auto px-8 py-12">
        <div className="prose prose-invert prose-lg max-w-none">
          <section className="mb-12">
            <h2 className="text-3xl font-bold text-slate-900 dark:text-white mb-6">¿Qué es OWASP ZAP?</h2>
            <p className="text-slate-700 dark:text-slate-300 mb-6">
              ZAP (Zed Attack Proxy) es una herramienta gratuita y open source para encontrar vulnerabilidades en aplicaciones web. 
              Alternativa a Burp Suite Community, con potentes capacidades de automatización.
            </p>
            
            <div className="bg-green-500/10 border border-green-500/30 rounded-xl p-6">
              <h3 className="text-xl font-semibold text-slate-900 dark:text-white mb-3">Ventajas de ZAP</h3>
              <ul className="text-slate-700 dark:text-slate-300 space-y-2">
                <li>✅ 100% gratis y open source</li>
                <li>✅ Scanner automático incluido</li>
                <li>✅ API para CI/CD integration</li>
                <li>✅ AJAX Spider para SPAs</li>
                <li>✅ Fuzzer sin límites</li>
                <li>✅ Comunidad activa</li>
              </ul>
            </div>
          </section>

          <section className="mb-12">
            <h2 className="text-3xl font-bold text-slate-900 dark:text-white mb-6">Instalación</h2>
            <div className="bg-white/5 border border-white/10 rounded-xl p-6">
              <div className="bg-slate-100 dark:bg-slate-800/50 rounded-lg p-4 font-mono text-sm">
                <pre className="text-blue-600 dark:text-blue-400">
{`# Linux (Debian/Ubuntu)
sudo snap install zaproxy --classic

# macOS
brew install --cask owasp-zap

# Windows
# Descargar desde https://www.zaproxy.org/download/

# Docker
docker pull zaproxy/zap-stable
docker run -u zap -p 8080:8080 zaproxy/zap-stable zap.sh -daemon \
  -host 0.0.0.0 -port 8080 -config api.key=changeme`}
                </pre>
              </div>
            </div>
          </section>

          <section className="mb-12">
            <h2 className="text-3xl font-bold text-slate-900 dark:text-white mb-6">Modos de Uso</h2>
            
            <div className="space-y-6">
              <div className="bg-white/5 border border-white/10 rounded-xl p-6">
                <h3 className="text-xl font-semibold text-slate-900 dark:text-white mb-3">1. Automated Scan</h3>
                <p className="text-slate-700 dark:text-slate-300 mb-4">Escaneo automático ideal para principiantes.</p>
                <div className="bg-slate-100 dark:bg-slate-800/50 rounded-lg p-4 font-mono text-sm">
                  <pre className="text-green-600 dark:text-green-400">
{`# GUI
1. Open ZAP
2. "Automated Scan" tab
3. URL: https://target-site.com
4. "Attack" button
5. Esperar resultados en "Alerts" tab

# CLI
zap.sh -cmd -quickurl https://target-site.com \
  -quickout /tmp/zap-report.html`}
                  </pre>
                </div>
              </div>

              <div className="bg-white/5 border border-white/10 rounded-xl p-6">
                <h3 className="text-xl font-semibold text-slate-900 dark:text-white mb-3">2. Manual Explore</h3>
                <p className="text-slate-700 dark:text-slate-300 mb-4">Uso como proxy interceptor (como Burp).</p>
                <div className="bg-slate-100 dark:bg-slate-800/50 rounded-lg p-4 font-mono text-sm">
                  <pre className="text-purple-400">
{`# 1. Configurar proxy
Manual Explore > URL > Launch Browser
# ZAP abre navegador pre-configurado

# 2. Navegar sitio target
# ZAP registra todos los requests

# 3. Analizar
Sites tree > Right click > Attack
Active Scan > Start Scan

# 4. Ver vulnerabilidades
Alerts tab > Filter by Risk (High/Medium/Low)`}
                  </pre>
                </div>
              </div>

              <div className="bg-white/5 border border-white/10 rounded-xl p-6">
                <h3 className="text-xl font-semibold text-slate-900 dark:text-white mb-3">3. API Integration (CI/CD)</h3>
                <p className="text-slate-700 dark:text-slate-300 mb-4">Automatizar scans en pipelines.</p>
                <div className="bg-slate-100 dark:bg-slate-800/50 rounded-lg p-4 font-mono text-sm">
                  <pre className="text-cyan-600 dark:text-cyan-400">
{`# Docker ZAP en modo daemon
docker run -d -p 8080:8080 zaproxy/zap-stable \
  zap.sh -daemon -host 0.0.0.0 -port 8080 \
  -config api.key=my-api-key

# Python API
from zapv2 import ZAPv2

zap = ZAPv2(apikey='my-api-key', proxies={
  'http': 'http://127.0.0.1:8080',
  'https': 'http://127.0.0.1:8080'
})

# Spider sitio
zap.spider.scan('https://target.com')
# Active scan
zap.ascan.scan('https://target.com')
# Obtener alerts
alerts = zap.core.alerts()
for alert in alerts:
  print(f"{alert['risk']}: {alert['alert']}")`}
                  </pre>
                </div>
              </div>
            </div>
          </section>

          <section className="mb-12">
            <h2 className="text-3xl font-bold text-slate-900 dark:text-white mb-6">Scanners Incluidos</h2>
            
            <div className="grid md:grid-cols-2 gap-6">
              <div className="bg-white/5 border border-white/10 rounded-xl p-6">
                <h3 className="text-xl font-semibold text-slate-900 dark:text-white mb-3">Passive Scanner</h3>
                <p className="text-slate-700 dark:text-slate-300 mb-3">Analiza tráfico sin enviar requests adicionales.</p>
                <ul className="text-slate-700 dark:text-slate-300 space-y-1 text-sm">
                  <li>• Missing security headers</li>
                  <li>• Cookie flags (HttpOnly, Secure)</li>
                  <li>• Information disclosure</li>
                  <li>• Weak SSL/TLS config</li>
                </ul>
              </div>

              <div className="bg-white/5 border border-white/10 rounded-xl p-6">
                <h3 className="text-xl font-semibold text-slate-900 dark:text-white mb-3">Active Scanner</h3>
                <p className="text-slate-700 dark:text-slate-300 mb-3">Envía payloads de ataque (requiere permiso).</p>
                <ul className="text-slate-700 dark:text-slate-300 space-y-1 text-sm">
                  <li>• SQL injection</li>
                  <li>• XSS (Reflected, Stored)</li>
                  <li>• Path traversal</li>
                  <li>• Command injection</li>
                  <li>• CSRF</li>
                </ul>
              </div>

              <div className="bg-white/5 border border-white/10 rounded-xl p-6">
                <h3 className="text-xl font-semibold text-slate-900 dark:text-white mb-3">AJAX Spider</h3>
                <p className="text-slate-700 dark:text-slate-300 mb-3">Crawler para Single Page Applications.</p>
                <ul className="text-slate-700 dark:text-slate-300 space-y-1 text-sm">
                  <li>• Ejecuta JavaScript</li>
                  <li>• Click en elementos DOM</li>
                  <li>• Detecta rutas dinámicas</li>
                  <li>• Ideal para React/Vue/Angular</li>
                </ul>
              </div>

              <div className="bg-white/5 border border-white/10 rounded-xl p-6">
                <h3 className="text-xl font-semibold text-slate-900 dark:text-white mb-3">Fuzzer</h3>
                <p className="text-slate-700 dark:text-slate-300 mb-3">Envía payloads personalizados.</p>
                <ul className="text-slate-700 dark:text-slate-300 space-y-1 text-sm">
                  <li>• Custom wordlists</li>
                  <li>• Fuzzing de parámetros</li>
                  <li>• Headers, cookies, body</li>
                  <li>• Scripts de generación de payloads</li>
                </ul>
              </div>
            </div>
          </section>

          <section className="mb-12">
            <h2 className="text-3xl font-bold text-slate-900 dark:text-white mb-6">GitHub Actions Integration</h2>
            <div className="bg-white/5 border border-white/10 rounded-xl p-6">
              <div className="bg-slate-100 dark:bg-slate-800/50 rounded-lg p-4 font-mono text-sm">
                <pre className="text-yellow-400">
{`# .github/workflows/zap-scan.yml
name: ZAP Security Scan

on:
  pull_request:
    branches: [main]

jobs:
  zap_scan:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout
        uses: actions/checkout@v3

      - name: ZAP Baseline Scan
        uses: zaproxy/action-baseline@v0.7.0
        with:
          target: 'https://staging.example.com'
          rules_file_name: '.zap/rules.tsv'
          cmd_options: '-a'

      - name: Upload Report
        uses: actions/upload-artifact@v3
        with:
          name: zap-report
          path: report_html.html`}
                </pre>
              </div>
            </div>
          </section>

          <div className="bg-gradient-to-r from-purple-600/20 to-blue-600/20 border border-purple-500/30 rounded-xl p-8 text-center">
            <h3 className="text-2xl font-bold text-slate-900 dark:text-white mb-4">Siguiente</h3>
            <Link href={`/${locale}/wiki/herramientas/sqlmap`}
              className="inline-flex items-center gap-2 px-6 py-3 bg-purple-600 hover:bg-purple-700 text-slate-900 dark:text-white rounded-xl font-semibold transition-all">
              SQLMap<span>→</span></Link>
          </div>
        </div>
      </div>
    </div>
  );
}
