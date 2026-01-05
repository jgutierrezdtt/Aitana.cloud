'use client';

import Link from 'next/link';
import { useParams } from 'next/navigation';
import { Home, Terminal, Search } from 'lucide-react';

export default function NiktoPage() {
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
          <span className="text-white dark:text-white">Nikto</span>
        </div>
      </div>

      <div className="bg-gradient-to-r from-indigo-600 via-purple-600 to-pink-600 px-8 py-12">
        <div className="max-w-5xl mx-auto">
          <div className="flex items-center gap-3 mb-4">
            <div className="px-3 py-1 bg-green-500/20 text-green-700 dark:text-green-300 rounded-lg text-sm font-medium border border-green-500/30">Principiante</div>
            <div className="px-3 py-1 bg-white/10 backdrop-blur-sm text-slate-900 dark:text-white rounded-lg text-sm">18 min</div>
          </div>
          <h1 className="text-4xl md:text-5xl font-bold text-slate-900 dark:text-white mb-4 flex items-center gap-4">
            <Search className="w-12 h-12" />Nikto</h1>
          <p className="text-xl text-indigo-100">Scanner de vulnerabilidades de servidores web open source</p>
        </div>
      </div>

      <div className="max-w-5xl mx-auto px-8 py-12">
        <div className="prose prose-invert prose-lg max-w-none">
          <section className="mb-12">
            <h2 className="text-3xl font-bold text-slate-900 dark:text-white mb-6">¿Qué es Nikto?</h2>
            <p className="text-slate-700 dark:text-slate-300 mb-6">
              Nikto es un escáner de servidores web open source que realiza pruebas exhaustivas contra servidores web 
              para detectar archivos/CGIs peligrosos, versiones desactualizadas, y configuraciones inseguras.
            </p>
            
            <div className="bg-white/5 border border-white/10 rounded-xl p-6">
              <h3 className="text-xl font-semibold text-slate-900 dark:text-white mb-3">Qué detecta Nikto</h3>
              <ul className="text-slate-700 dark:text-slate-300 space-y-2">
                <li>✅ Versiones de servidor vulnerables</li>
                <li>✅ Archivos/directorios peligrosos</li>
                <li>✅ Configuraciones inseguras</li>
                <li>✅ Headers de seguridad faltantes</li>
                <li>✅ Plugins/módulos desactualizados</li>
                <li>✅ Default credentials</li>
                <li>✅ 6700+ plugins de checks</li>
              </ul>
            </div>
          </section>

          <section className="mb-12">
            <h2 className="text-3xl font-bold text-slate-900 dark:text-white mb-6">Instalación</h2>
            <div className="bg-white/5 border border-white/10 rounded-xl p-6">
              <div className="bg-slate-100 dark:bg-slate-800/50 rounded-lg p-4 font-mono text-sm">
                <pre className="text-blue-600 dark:text-blue-400">
{`# Linux (Debian/Ubuntu)
sudo apt install nikto

# Kali Linux (pre-instalado)
nikto -Version

# macOS
brew install nikto

# GitHub (última versión)
git clone https://github.com/sullo/nikto
cd nikto/program
perl nikto.pl -h`}
                </pre>
              </div>
            </div>
          </section>

          <section className="mb-12">
            <h2 className="text-3xl font-bold text-slate-900 dark:text-white mb-6">Uso Básico</h2>
            
            <div className="space-y-6">
              <div className="bg-white/5 border border-white/10 rounded-xl p-6">
                <h3 className="text-xl font-semibold text-slate-900 dark:text-white mb-3">Scan Simple</h3>
                <div className="bg-slate-100 dark:bg-slate-800/50 rounded-lg p-4 font-mono text-sm">
                  <pre className="text-green-600 dark:text-green-400">
{`# Scan básico
nikto -h http://target.com

# Output:
- Nikto v2.5.0
---------------------------------------------------------------------------
+ Target IP:          192.168.1.100
+ Target Hostname:    target.com
+ Target Port:        80
+ Start Time:         2024-01-15 10:00:00
---------------------------------------------------------------------------
+ Server: Apache/2.4.41 (Ubuntu)
+ The anti-clickjacking X-Frame-Options header is not present.
+ The X-Content-Type-Options header is not set.
+ No CGI Directories found
+ Apache/2.4.41 appears to be outdated (current is at least 2.4.54)
+ /admin/: Admin directory found
+ /phpinfo.php: Output from the phpinfo() function
+ 7500 requests: 0 error(s) and 12 item(s) reported`}
                  </pre>
                </div>
              </div>

              <div className="bg-white/5 border border-white/10 rounded-xl p-6">
                <h3 className="text-xl font-semibold text-slate-900 dark:text-white mb-3">Opciones Comunes</h3>
                <div className="bg-slate-100 dark:bg-slate-800/50 rounded-lg p-4 font-mono text-sm">
                  <pre className="text-purple-400">
{`# Especificar puerto
nikto -h http://target.com -p 8080

# HTTPS
nikto -h https://target.com -ssl

# Multiple puertos
nikto -h target.com -p 80,443,8080

# Guardar output
nikto -h target.com -o report.html -Format html

# Formato JSON
nikto -h target.com -o report.json -Format json

# Especificar User-Agent
nikto -h target.com -useragent "Mozilla/5.0 Custom"`}
                  </pre>
                </div>
              </div>

              <div className="bg-white/5 border border-white/10 rounded-xl p-6">
                <h3 className="text-xl font-semibold text-slate-900 dark:text-white mb-3">Tuning (Filtrar Tests)</h3>
                <div className="bg-slate-100 dark:bg-slate-800/50 rounded-lg p-4 font-mono text-sm">
                  <pre className="text-cyan-600 dark:text-cyan-400">
{`# -Tuning options:
# 1: Interesting files
# 2: Misconfiguration
# 3: Information disclosure
# 4: Injection (XSS/Script/HTML)
# 5: Remote file retrieval
# 6: Denial of service
# 7: Remote file retrieval (server wide)
# 8: Command execution
# 9: SQL injection
# 0: File upload
# a: Authentication bypass
# b: Software identification
# c: Remote source inclusion

# Solo buscar archivos interesantes
nikto -h target.com -Tuning 1

# Múltiples tunings
nikto -h target.com -Tuning 124

# Excluir tests
nikto -h target.com -Tuning x6  # excluir DoS tests`}
                  </pre>
                </div>
              </div>
            </div>
          </section>

          <section className="mb-12">
            <h2 className="text-3xl font-bold text-slate-900 dark:text-white mb-6">Plugins y Bases de Datos</h2>
            
            <div className="bg-white/5 border border-white/10 rounded-xl p-6 mb-6">
              <h3 className="text-xl font-semibold text-slate-900 dark:text-white mb-3">Actualizar Plugins</h3>
              <div className="bg-slate-100 dark:bg-slate-800/50 rounded-lg p-4 font-mono text-sm">
                <pre className="text-yellow-400">
{`# Actualizar bases de datos
nikto -update

# Listar plugins disponibles
nikto -list-plugins

# Output:
Plugin: apache_expect_xss
Plugin: cookies
Plugin: headers
Plugin: httpoptions
Plugin: ssl`}
                </pre>
              </div>
            </div>

            <div className="bg-white/5 border border-white/10 rounded-xl p-6">
              <h3 className="text-xl font-semibold text-slate-900 dark:text-white mb-3">Usar Plugins Específicos</h3>
              <div className="bg-slate-100 dark:bg-slate-800/50 rounded-lg p-4 font-mono text-sm">
                <pre className="text-green-600 dark:text-green-400">
{`# Solo plugin de headers
nikto -h target.com -Plugins headers

# Múltiples plugins
nikto -h target.com -Plugins "headers,cookies,ssl"`}
                </pre>
              </div>
            </div>
          </section>

          <section className="mb-12">
            <h2 className="text-3xl font-bold text-slate-900 dark:text-white mb-6">Evasión y Sigilo</h2>
            
            <div className="bg-white/5 border border-white/10 rounded-xl p-6">
              <div className="bg-slate-100 dark:bg-slate-800/50 rounded-lg p-4 font-mono text-sm">
                <pre className="text-red-600 dark:text-red-400">
{`# Evasion techniques
nikto -h target.com -evasion 1

# Evasion options:
# 1: Random URI encoding (non-UTF8)
# 2: Directory self-reference (/./,//)
# 3: Premature URL ending
# 4: Prepend long random string
# 5: Fake parameter
# 6: TAB as request spacer
# 7: Change case
# 8: Use Windows directory separator

# Throttle requests (menos agresivo)
nikto -h target.com -Pause 2  # 2 segundos entre requests

# No lookup hostname
nikto -h 192.168.1.100 -nolookup`}
                </pre>
              </div>
            </div>
          </section>

          <section className="mb-12">
            <h2 className="text-3xl font-bold text-slate-900 dark:text-white mb-6">Formatos de Reporte</h2>
            
            <div className="grid md:grid-cols-2 gap-6">
              <div className="bg-white/5 border border-white/10 rounded-xl p-6">
                <h3 className="text-xl font-semibold text-slate-900 dark:text-white mb-3">HTML Report</h3>
                <div className="bg-slate-100 dark:bg-slate-800/50 rounded-lg p-4 font-mono text-sm">
                  <pre className="text-blue-600 dark:text-blue-400">
{`nikto -h target.com \
  -o report.html \
  -Format html

# Genera reporte HTML
# navegable con hallazgos`}
                  </pre>
                </div>
              </div>

              <div className="bg-white/5 border border-white/10 rounded-xl p-6">
                <h3 className="text-xl font-semibold text-slate-900 dark:text-white mb-3">CSV Report</h3>
                <div className="bg-slate-100 dark:bg-slate-800/50 rounded-lg p-4 font-mono text-sm">
                  <pre className="text-green-600 dark:text-green-400">
{`nikto -h target.com \
  -o report.csv \
  -Format csv

# CSV para Excel/análisis`}
                  </pre>
                </div>
              </div>

              <div className="bg-white/5 border border-white/10 rounded-xl p-6">
                <h3 className="text-xl font-semibold text-slate-900 dark:text-white mb-3">JSON Report</h3>
                <div className="bg-slate-100 dark:bg-slate-800/50 rounded-lg p-4 font-mono text-sm">
                  <pre className="text-purple-400">
{`nikto -h target.com \
  -o report.json \
  -Format json

# JSON para parsear
# automáticamente`}
                  </pre>
                </div>
              </div>

              <div className="bg-white/5 border border-white/10 rounded-xl p-6">
                <h3 className="text-xl font-semibold text-slate-900 dark:text-white mb-3">XML Report</h3>
                <div className="bg-slate-100 dark:bg-slate-800/50 rounded-lg p-4 font-mono text-sm">
                  <pre className="text-cyan-600 dark:text-cyan-400">
{`nikto -h target.com \
  -o report.xml \
  -Format xml

# XML estructurado`}
                  </pre>
                </div>
              </div>
            </div>
          </section>

          <section className="mb-12">
            <h2 className="text-3xl font-bold text-slate-900 dark:text-white mb-6">Ejemplo Completo</h2>
            <div className="bg-white/5 border border-white/10 rounded-xl p-6">
              <div className="bg-slate-100 dark:bg-slate-800/50 rounded-lg p-4 font-mono text-sm">
                <pre className="text-green-600 dark:text-green-400">
{`# Scan completo con todas las opciones
nikto -h https://target.com \
  -ssl \
  -p 443 \
  -Tuning 123456789ab \
  -o nikto-report.html \
  -Format html \
  -useragent "Mozilla/5.0 (Windows NT 10.0; Win64; x64)" \
  -Pause 1

# Output:
- Nikto v2.5.0
---------------------------------------------------------------------------
+ Target IP:          203.0.113.50
+ Target Hostname:    target.com
+ Target Port:        443
+ SSL Info:           TLS 1.2, cipher TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
---------------------------------------------------------------------------
+ Server: nginx/1.18.0 (Ubuntu)
+ OSVDB-3233: /icons/README: Apache default file found.
+ OSVDB-3092: /phpmyadmin/: phpMyAdmin directory found
+ OSVDB-3268: /config/: Directory indexing enabled
+ OSVDB-3233: /admin/: Admin panel found
+ Cookie PHPSESSID created without the httponly flag
+ Missing X-Frame-Options header
+ 8765 requests: 0 error(s) and 45 item(s) reported
---------------------------------------------------------------------------
+ End Time:           2024-01-15 10:15:23 (923 seconds)
---------------------------------------------------------------------------`}
                </pre>
              </div>
            </div>
          </section>

          <section className="mb-12">
            <h2 className="text-3xl font-bold text-slate-900 dark:text-white mb-6">Limitaciones</h2>
            <div className="bg-yellow-500/10 border border-yellow-500/30 rounded-xl p-6">
              <ul className="text-slate-700 dark:text-slate-300 space-y-2">
                <li>⚠️ Muchos falsos positivos (verificar manualmente)</li>
                <li>⚠️ No detecta vulnerabilidades complejas (SQLi logic, business logic)</li>
                <li>⚠️ Muy ruidoso (genera muchos logs en servidor)</li>
                <li>⚠️ No reemplaza testing manual</li>
                <li>✅ Ideal para reconocimiento inicial rápido</li>
                <li>✅ Detecta low-hanging fruit y misconfigurations</li>
              </ul>
            </div>
          </section>

          <div className="bg-gradient-to-r from-indigo-600/20 to-pink-600/20 border border-indigo-500/30 rounded-xl p-8 text-center">
            <h3 className="text-2xl font-bold text-slate-900 dark:text-white mb-4">¡Wiki Completada!</h3>
            <p className="text-slate-700 dark:text-slate-300 mb-6">Has explorado todas las categorías de la Wiki de Seguridad Web</p>
            <Link href={`/${locale}/wiki`}
              className="inline-flex items-center gap-2 px-6 py-3 bg-gradient-to-r from-indigo-600 to-purple-600 hover:from-indigo-700 hover:to-purple-700 text-slate-900 dark:text-white rounded-xl font-semibold transition-all">
              ← Volver al Inicio de la Wiki</Link>
          </div>
        </div>
      </div>
    </div>
  );
}
