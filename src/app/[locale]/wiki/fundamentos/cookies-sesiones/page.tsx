'use client';

import Link from 'next/link';
import { useParams } from 'next/navigation';
import { ArrowLeft, BookOpen, Code, AlertCircle, CheckCircle, Cookie } from 'lucide-react';

export default function CookiesSesionesPage() {
  const params = useParams();
  const locale = params.locale as string;

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-950 via-slate-900 to-slate-950">
      {/* Breadcrumb */}
      <div className="bg-white/5 backdrop-blur-sm border-b border-white/10">
        <div className="max-w-4xl mx-auto px-6 py-4">
          <Link 
            href={`/${locale}/wiki`}
            className="inline-flex items-center gap-2 text-blue-400 hover:text-blue-300 transition-colors"
          >
            <ArrowLeft className="w-4 h-4" />
            <span>Volver a la Wiki</span>
          </Link>
        </div>
      </div>

      {/* Article Header */}
      <div className="bg-gradient-to-r from-blue-600 to-cyan-600 py-12">
        <div className="max-w-4xl mx-auto px-6">
          <div className="inline-flex items-center gap-2 bg-white/10 backdrop-blur-sm px-3 py-1 rounded-lg mb-4">
            <BookOpen className="w-4 h-4 text-white" />
            <span className="text-white text-sm font-medium">Fundamentos</span>
          </div>
          <h1 className="text-4xl md:text-5xl font-bold text-white mb-4">
            Cookies y Sesiones
          </h1>
          <div className="flex items-center gap-4 text-blue-100">
            <span className="bg-green-500/20 text-green-300 px-3 py-1 rounded-lg text-sm font-medium">
              Principiante
            </span>
            <span className="text-sm">⏱️ 15 minutos de lectura</span>
          </div>
        </div>
      </div>

      {/* Article Content */}
      <div className="max-w-4xl mx-auto px-6 py-12">
        <div className="bg-white/5 backdrop-blur-sm border border-white/10 rounded-2xl p-8 md:p-12 space-y-8">
          
          {/* Introducción */}
          <section>
            <h2 className="text-3xl font-bold text-white mb-4">¿Qué son las Cookies?</h2>
            <p className="text-slate-300 text-lg leading-relaxed mb-4">
              <strong className="text-white">Las cookies</strong> son pequeños archivos de texto que los sitios web guardan 
              en tu navegador. Permiten que el servidor "recuerde" información sobre el usuario entre diferentes peticiones HTTP.
            </p>
            <p className="text-slate-300 text-lg leading-relaxed">
              HTTP es un protocolo <strong className="text-white">stateless</strong> (sin estado), es decir, cada petición 
              es independiente. Las cookies resuelven este problema permitiendo mantener estado entre peticiones.
            </p>
          </section>

          {/* Cookies */}
          <section>
            <h2 className="text-3xl font-bold text-white mb-6">Cómo Funcionan las Cookies</h2>
            
            <div className="space-y-6">
              <div className="bg-blue-500/10 border border-blue-400/30 rounded-xl p-6">
                <h3 className="text-xl font-bold text-blue-300 mb-4 flex items-center gap-2">
                  <Cookie className="w-6 h-6" />
                  Proceso de Cookie
                </h3>
                
                <div className="space-y-4">
                  <div className="flex items-start gap-3">
                    <div className="w-8 h-8 rounded-full bg-blue-500 text-white flex items-center justify-center flex-shrink-0 font-bold">
                      1
                    </div>
                    <div>
                      <p className="text-white font-semibold">El servidor envía una cookie</p>
                      <code className="text-sm text-green-400 bg-slate-900 px-3 py-1 rounded mt-1 block">
                        Set-Cookie: session_id=abc123; HttpOnly; Secure
                      </code>
                    </div>
                  </div>

                  <div className="flex items-start gap-3">
                    <div className="w-8 h-8 rounded-full bg-blue-500 text-white flex items-center justify-center flex-shrink-0 font-bold">
                      2
                    </div>
                    <div>
                      <p className="text-white font-semibold">El navegador guarda la cookie</p>
                      <p className="text-slate-300 text-sm mt-1">
                        La cookie se almacena localmente en el navegador del usuario
                      </p>
                    </div>
                  </div>

                  <div className="flex items-start gap-3">
                    <div className="w-8 h-8 rounded-full bg-blue-500 text-white flex items-center justify-center flex-shrink-0 font-bold">
                      3
                    </div>
                    <div>
                      <p className="text-white font-semibold">El navegador envía la cookie en cada petición</p>
                      <code className="text-sm text-cyan-400 bg-slate-900 px-3 py-1 rounded mt-1 block">
                        Cookie: session_id=abc123
                      </code>
                    </div>
                  </div>

                  <div className="flex items-start gap-3">
                    <div className="w-8 h-8 rounded-full bg-blue-500 text-white flex items-center justify-center flex-shrink-0 font-bold">
                      4
                    </div>
                    <div>
                      <p className="text-white font-semibold">El servidor identifica al usuario</p>
                      <p className="text-slate-300 text-sm mt-1">
                        El servidor usa el session_id para recuperar los datos del usuario
                      </p>
                    </div>
                  </div>
                </div>
              </div>

              {/* Atributos de Cookies */}
              <div className="bg-purple-500/10 border border-purple-400/30 rounded-xl p-6">
                <h3 className="text-xl font-bold text-purple-300 mb-4">Atributos Importantes de Cookies</h3>
                
                <div className="space-y-3">
                  <div className="bg-white/5 rounded-lg p-4">
                    <div className="flex items-center gap-2 mb-2">
                      <CheckCircle className="w-5 h-5 text-green-400" />
                      <code className="text-yellow-400 font-mono">HttpOnly</code>
                    </div>
                    <p className="text-slate-300 text-sm">
                      Previene que JavaScript acceda a la cookie. Protege contra ataques XSS.
                    </p>
                  </div>

                  <div className="bg-white/5 rounded-lg p-4">
                    <div className="flex items-center gap-2 mb-2">
                      <CheckCircle className="w-5 h-5 text-green-400" />
                      <code className="text-yellow-400 font-mono">Secure</code>
                    </div>
                    <p className="text-slate-300 text-sm">
                      La cookie solo se envía por HTTPS. Previene interceptación en tráfico no cifrado.
                    </p>
                  </div>

                  <div className="bg-white/5 rounded-lg p-4">
                    <div className="flex items-center gap-2 mb-2">
                      <CheckCircle className="w-5 h-5 text-green-400" />
                      <code className="text-yellow-400 font-mono">SameSite</code>
                    </div>
                    <p className="text-slate-300 text-sm">
                      Controla si la cookie se envía en peticiones cross-site. Protege contra CSRF.
                    </p>
                    <div className="mt-2 text-xs space-y-1">
                      <p className="text-slate-400">• <code>Strict</code>: Solo peticiones del mismo sitio</p>
                      <p className="text-slate-400">• <code>Lax</code>: Permite navegación normal (por defecto)</p>
                      <p className="text-slate-400">• <code>None</code>: Permite cross-site (requiere Secure)</p>
                    </div>
                  </div>

                  <div className="bg-white/5 rounded-lg p-4">
                    <div className="flex items-center gap-2 mb-2">
                      <Code className="w-5 h-5 text-blue-400" />
                      <code className="text-yellow-400 font-mono">Max-Age / Expires</code>
                    </div>
                    <p className="text-slate-300 text-sm">
                      Define cuándo expira la cookie. Sin estos, la cookie se borra al cerrar el navegador.
                    </p>
                  </div>
                </div>
              </div>
            </div>
          </section>

          {/* Sesiones */}
          <section>
            <h2 className="text-3xl font-bold text-white mb-6">Sesiones del Lado del Servidor</h2>
            
            <p className="text-slate-300 text-lg leading-relaxed mb-6">
              Una <strong className="text-white">sesión</strong> es un mecanismo para almacenar datos del usuario 
              en el servidor, usando una cookie con un identificador de sesión (session ID) en el cliente.
            </p>

            <div className="bg-slate-800/50 rounded-xl p-6 space-y-4">
              <div className="grid md:grid-cols-2 gap-4">
                <div className="bg-green-500/10 border border-green-400/30 rounded-lg p-4">
                  <h4 className="text-green-400 font-bold mb-2">✅ Ventajas</h4>
                  <ul className="text-sm text-slate-300 space-y-1">
                    <li>• Datos sensibles en servidor (más seguro)</li>
                    <li>• Solo el ID viaja en cada petición</li>
                    <li>• Control total del servidor</li>
                    <li>• Invalidación fácil (logout)</li>
                  </ul>
                </div>

                <div className="bg-red-500/10 border border-red-400/30 rounded-lg p-4">
                  <h4 className="text-red-400 font-bold mb-2">⚠️ Desventajas</h4>
                  <ul className="text-sm text-slate-300 space-y-1">
                    <li>• Requiere almacenamiento en servidor</li>
                    <li>• Más difícil de escalar (múltiples servidores)</li>
                    <li>• Necesita Redis/DB para persistencia</li>
                  </ul>
                </div>
              </div>

              <div className="bg-blue-500/10 border border-blue-400/30 rounded-lg p-4">
                <h4 className="text-blue-300 font-bold mb-3">Ejemplo de Almacenamiento de Sesión</h4>
                <pre className="text-sm text-green-400 overflow-x-auto">
{`// En el servidor (ejemplo con Redis)
sessions = {
  "abc123": {
    userId: 42,
    username: "alice",
    role: "admin",
    createdAt: "2025-01-05T10:00:00Z"
  }
}

// Cookie enviada al cliente
Set-Cookie: session_id=abc123; HttpOnly; Secure; SameSite=Strict`}
                </pre>
              </div>
            </div>
          </section>

          {/* JWT como Alternativa */}
          <section>
            <h2 className="text-3xl font-bold text-white mb-6">JWT: Tokens Sin Estado</h2>
            
            <p className="text-slate-300 text-lg leading-relaxed mb-6">
              <strong className="text-white">JWT</strong> (JSON Web Token) es una alternativa a las sesiones tradicionales. 
              El servidor firma un token que contiene los datos del usuario, y el cliente lo envía en cada petición.
            </p>

            <div className="bg-purple-500/10 border border-purple-400/30 rounded-xl p-6">
              <h3 className="text-xl font-bold text-purple-300 mb-4">Estructura de un JWT</h3>
              
              <div className="space-y-3">
                <div className="bg-slate-900 rounded-lg p-4">
                  <code className="text-xs text-red-400 block mb-1">HEADER (algoritmo)</code>
                  <code className="text-sm text-slate-300">eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9</code>
                </div>
                <div className="text-center text-slate-500">.</div>
                <div className="bg-slate-900 rounded-lg p-4">
                  <code className="text-xs text-purple-400 block mb-1">PAYLOAD (datos del usuario)</code>
                  <code className="text-sm text-slate-300">eyJ1c2VySWQiOjQyLCJ1c2VybmFtZSI6ImFsaWNlIn0</code>
                </div>
                <div className="text-center text-slate-500">.</div>
                <div className="bg-slate-900 rounded-lg p-4">
                  <code className="text-xs text-blue-400 block mb-1">SIGNATURE (firma digital)</code>
                  <code className="text-sm text-slate-300">SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c</code>
                </div>
              </div>

              <div className="mt-6 grid md:grid-cols-2 gap-4">
                <div>
                  <h4 className="text-green-400 font-bold mb-2">✅ Ventajas</h4>
                  <ul className="text-sm text-slate-300 space-y-1">
                    <li>• Sin estado (stateless)</li>
                    <li>• Fácil de escalar</li>
                    <li>• No requiere almacenamiento en servidor</li>
                    <li>• Funciona entre dominios</li>
                  </ul>
                </div>
                <div>
                  <h4 className="text-red-400 font-bold mb-2">⚠️ Desventajas</h4>
                  <ul className="text-sm text-slate-300 space-y-1">
                    <li>• No se puede invalidar fácilmente</li>
                    <li>• Más datos en cada petición</li>
                    <li>• Vulnerable si se almacena en localStorage</li>
                  </ul>
                </div>
              </div>
            </div>
          </section>

          {/* Implicaciones de Seguridad */}
          <section>
            <div className="bg-red-500/10 border border-red-400/30 rounded-xl p-6">
              <div className="flex items-start gap-3">
                <AlertCircle className="w-6 h-6 text-red-400 flex-shrink-0 mt-1" />
                <div className="space-y-4">
                  <h3 className="text-xl font-bold text-red-300">Vulnerabilidades Comunes</h3>
                  
                  <div className="space-y-3">
                    <div>
                      <h4 className="text-white font-semibold mb-1">🔓 Session Hijacking</h4>
                      <p className="text-slate-300 text-sm">
                        Un atacante roba el session ID (por XSS o sniffing) y se hace pasar por el usuario.
                      </p>
                      <p className="text-green-400 text-sm mt-1">
                        <strong>Defensa:</strong> HttpOnly, Secure, regenerar session ID después del login
                      </p>
                    </div>

                    <div>
                      <h4 className="text-white font-semibold mb-1">🔓 Session Fixation</h4>
                      <p className="text-slate-300 text-sm">
                        Atacante fuerza un session ID conocido antes del login del usuario.
                      </p>
                      <p className="text-green-400 text-sm mt-1">
                        <strong>Defensa:</strong> Regenerar session ID en login/logout
                      </p>
                    </div>

                    <div>
                      <h4 className="text-white font-semibold mb-1">🔓 XSS robando cookies</h4>
                      <p className="text-slate-300 text-sm">
                        JavaScript malicioso lee document.cookie y envía las cookies al atacante.
                      </p>
                      <p className="text-green-400 text-sm mt-1">
                        <strong>Defensa:</strong> HttpOnly flag, sanitizar inputs, CSP
                      </p>
                    </div>

                    <div>
                      <h4 className="text-white font-semibold mb-1">🔓 JWT en localStorage</h4>
                      <p className="text-slate-300 text-sm">
                        Almacenar JWT en localStorage lo hace vulnerable a XSS.
                      </p>
                      <p className="text-green-400 text-sm mt-1">
                        <strong>Defensa:</strong> Usar cookies HttpOnly para JWT, o memoria (no persistente)
                      </p>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </section>

          {/* Ejemplo Práctico */}
          <section>
            <h2 className="text-3xl font-bold text-white mb-4">Cookie Segura vs Insegura</h2>
            
            <div className="grid md:grid-cols-2 gap-4">
              <div className="bg-red-500/5 border border-red-400/30 rounded-xl p-6">
                <h3 className="text-lg font-bold text-red-300 mb-3">❌ Cookie Insegura</h3>
                <pre className="text-sm text-red-400 overflow-x-auto">
{`Set-Cookie: session=abc123`}
                </pre>
                <ul className="mt-4 text-sm text-slate-300 space-y-2">
                  <li className="flex items-start gap-2">
                    <span className="text-red-400">⚠️</span>
                    <span>Sin HttpOnly (vulnerable a XSS)</span>
                  </li>
                  <li className="flex items-start gap-2">
                    <span className="text-red-400">⚠️</span>
                    <span>Sin Secure (viaja por HTTP)</span>
                  </li>
                  <li className="flex items-start gap-2">
                    <span className="text-red-400">⚠️</span>
                    <span>Sin SameSite (vulnerable a CSRF)</span>
                  </li>
                </ul>
              </div>

              <div className="bg-green-500/5 border border-green-400/30 rounded-xl p-6">
                <h3 className="text-lg font-bold text-green-300 mb-3">✅ Cookie Segura</h3>
                <pre className="text-sm text-green-400 overflow-x-auto">
{`Set-Cookie: session=abc123;
  HttpOnly;
  Secure;
  SameSite=Strict;
  Max-Age=3600;
  Path=/`}
                </pre>
                <ul className="mt-4 text-sm text-slate-300 space-y-2">
                  <li className="flex items-start gap-2">
                    <CheckCircle className="w-4 h-4 text-green-400 flex-shrink-0" />
                    <span>HttpOnly protege contra XSS</span>
                  </li>
                  <li className="flex items-start gap-2">
                    <CheckCircle className="w-4 h-4 text-green-400 flex-shrink-0" />
                    <span>Secure requiere HTTPS</span>
                  </li>
                  <li className="flex items-start gap-2">
                    <CheckCircle className="w-4 h-4 text-green-400 flex-shrink-0" />
                    <span>SameSite protege contra CSRF</span>
                  </li>
                </ul>
              </div>
            </div>
          </section>

          {/* Siguiente Paso */}
          <section className="border-t border-white/10 pt-8">
            <h2 className="text-2xl font-bold text-white mb-4">Siguiente Paso</h2>
            <Link
              href={`/${locale}/wiki/fundamentos/autenticacion`}
              className="inline-flex items-center gap-2 px-6 py-3 bg-gradient-to-r from-blue-600 to-purple-600 text-white rounded-xl font-semibold hover:scale-105 transition-transform"
            >
              <span>Autenticación vs Autorización</span>
              <Code className="w-5 h-5" />
            </Link>
          </section>
        </div>
      </div>
    </div>
  );
}
