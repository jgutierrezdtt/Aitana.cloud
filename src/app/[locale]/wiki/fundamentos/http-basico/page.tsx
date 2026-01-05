'use client';

import Link from 'next/link';
import { useParams } from 'next/navigation';
import { ArrowLeft, BookOpen, Code, AlertCircle, CheckCircle } from 'lucide-react';
import Navigation from '@/components/Navigation';

export default function HttpBasicoPage() {
  const params = useParams();
  const locale = params.locale as string;

  return (
    <>
      <Navigation />
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
            HTTP: El Protocolo de la Web
          </h1>
          <div className="flex items-center gap-4 text-blue-100">
            <span className="bg-green-500/20 text-green-300 px-3 py-1 rounded-lg text-sm font-medium">
              Principiante
            </span>
            <span className="text-sm">⏱️ 10 minutos de lectura</span>
          </div>
        </div>
      </div>

      {/* Article Content */}
      <div className="max-w-4xl mx-auto px-6 py-12">
        <div className="bg-white/5 backdrop-blur-sm border border-white/10 rounded-2xl p-8 md:p-12 space-y-8">
          
          {/* Introducción */}
          <section>
            <h2 className="text-3xl font-bold text-white mb-4">¿Qué es HTTP?</h2>
            <p className="text-slate-300 text-lg leading-relaxed mb-4">
              <strong className="text-white">HTTP</strong> (HyperText Transfer Protocol) es el protocolo que hace posible 
              la World Wide Web. Es el lenguaje que utilizan los navegadores (clientes) y los servidores web para comunicarse 
              entre sí.
            </p>
            <p className="text-slate-300 text-lg leading-relaxed">
              Cada vez que visitas una página web, tu navegador envía una petición HTTP al servidor, 
              y el servidor responde con el contenido solicitado (HTML, imágenes, CSS, JavaScript, etc.).
            </p>
          </section>

          {/* Conceptos Clave */}
          <section>
            <h2 className="text-3xl font-bold text-white mb-6">Conceptos Clave</h2>
            
            <div className="space-y-6">
              <div className="bg-blue-500/10 border border-blue-400/30 rounded-xl p-6">
                <h3 className="text-xl font-bold text-blue-300 mb-3">📤 Peticiones (Requests)</h3>
                <p className="text-slate-300 leading-relaxed mb-4">
                  El cliente (navegador) envía una <strong className="text-white">petición HTTP</strong> al servidor. 
                  Una petición incluye:
                </p>
                <ul className="space-y-2 text-slate-300">
                  <li className="flex items-start gap-2">
                    <CheckCircle className="w-5 h-5 text-green-400 flex-shrink-0 mt-0.5" />
                    <span><strong className="text-white">Método HTTP:</strong> GET, POST, PUT, DELETE, etc.</span>
                  </li>
                  <li className="flex items-start gap-2">
                    <CheckCircle className="w-5 h-5 text-green-400 flex-shrink-0 mt-0.5" />
                    <span><strong className="text-white">URL:</strong> La dirección del recurso solicitado</span>
                  </li>
                  <li className="flex items-start gap-2">
                    <CheckCircle className="w-5 h-5 text-green-400 flex-shrink-0 mt-0.5" />
                    <span><strong className="text-white">Headers:</strong> Metadatos (idioma, tipo de contenido, cookies)</span>
                  </li>
                  <li className="flex items-start gap-2">
                    <CheckCircle className="w-5 h-5 text-green-400 flex-shrink-0 mt-0.5" />
                    <span><strong className="text-white">Body:</strong> Datos enviados (en POST/PUT)</span>
                  </li>
                </ul>
              </div>

              <div className="bg-purple-500/10 border border-purple-400/30 rounded-xl p-6">
                <h3 className="text-xl font-bold text-purple-300 mb-3">📥 Respuestas (Responses)</h3>
                <p className="text-slate-300 leading-relaxed mb-4">
                  El servidor responde con una <strong className="text-white">respuesta HTTP</strong> que incluye:
                </p>
                <ul className="space-y-2 text-slate-300">
                  <li className="flex items-start gap-2">
                    <CheckCircle className="w-5 h-5 text-green-400 flex-shrink-0 mt-0.5" />
                    <span><strong className="text-white">Status Code:</strong> 200 (OK), 404 (Not Found), 500 (Error)...</span>
                  </li>
                  <li className="flex items-start gap-2">
                    <CheckCircle className="w-5 h-5 text-green-400 flex-shrink-0 mt-0.5" />
                    <span><strong className="text-white">Headers:</strong> Tipo de contenido, cookies, caché...</span>
                  </li>
                  <li className="flex items-start gap-2">
                    <CheckCircle className="w-5 h-5 text-green-400 flex-shrink-0 mt-0.5" />
                    <span><strong className="text-white">Body:</strong> El contenido solicitado (HTML, JSON, imágenes...)</span>
                  </li>
                </ul>
              </div>
            </div>
          </section>

          {/* Métodos HTTP */}
          <section>
            <h2 className="text-3xl font-bold text-white mb-6">Métodos HTTP Principales</h2>
            
            <div className="space-y-4">
              {[
                { 
                  method: 'GET', 
                  desc: 'Obtener datos del servidor (leer)', 
                  example: 'Cargar una página web, buscar usuarios',
                  color: 'blue'
                },
                { 
                  method: 'POST', 
                  desc: 'Enviar datos al servidor (crear)', 
                  example: 'Enviar un formulario, crear una cuenta',
                  color: 'green'
                },
                { 
                  method: 'PUT', 
                  desc: 'Actualizar datos existentes', 
                  example: 'Modificar perfil de usuario',
                  color: 'yellow'
                },
                { 
                  method: 'DELETE', 
                  desc: 'Eliminar datos', 
                  example: 'Borrar una publicación',
                  color: 'red'
                },
              ].map((item) => (
                <div key={item.method} className="bg-white/5 border border-white/10 rounded-xl p-4">
                  <div className="flex items-center gap-3 mb-2">
                    <span className={`px-3 py-1 rounded-lg bg-${item.color}-500/20 text-${item.color}-300 font-mono font-bold text-sm`}>
                      {item.method}
                    </span>
                    <span className="text-white font-semibold">{item.desc}</span>
                  </div>
                  <p className="text-slate-400 text-sm ml-20">Ejemplo: {item.example}</p>
                </div>
              ))}
            </div>
          </section>

          {/* Códigos de Estado */}
          <section>
            <h2 className="text-3xl font-bold text-white mb-6">Códigos de Estado HTTP</h2>
            
            <div className="bg-slate-800/50 rounded-xl p-6 space-y-3">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <h4 className="text-green-400 font-bold mb-2">2xx - Éxito ✅</h4>
                  <ul className="text-sm text-slate-300 space-y-1">
                    <li><code className="text-green-400">200 OK</code> - Petición exitosa</li>
                    <li><code className="text-green-400">201 Created</code> - Recurso creado</li>
                  </ul>
                </div>
                <div>
                  <h4 className="text-blue-400 font-bold mb-2">3xx - Redirección 🔄</h4>
                  <ul className="text-sm text-slate-300 space-y-1">
                    <li><code className="text-blue-400">301 Moved</code> - Redireccionado permanentemente</li>
                    <li><code className="text-blue-400">302 Found</code> - Redireccionado temporalmente</li>
                  </ul>
                </div>
                <div>
                  <h4 className="text-yellow-400 font-bold mb-2">4xx - Error del Cliente ⚠️</h4>
                  <ul className="text-sm text-slate-300 space-y-1">
                    <li><code className="text-yellow-400">400 Bad Request</code> - Petición inválida</li>
                    <li><code className="text-yellow-400">401 Unauthorized</code> - No autenticado</li>
                    <li><code className="text-yellow-400">403 Forbidden</code> - Sin permisos</li>
                    <li><code className="text-yellow-400">404 Not Found</code> - No encontrado</li>
                  </ul>
                </div>
                <div>
                  <h4 className="text-red-400 font-bold mb-2">5xx - Error del Servidor 🔥</h4>
                  <ul className="text-sm text-slate-300 space-y-1">
                    <li><code className="text-red-400">500 Internal Error</code> - Error del servidor</li>
                    <li><code className="text-red-400">502 Bad Gateway</code> - Gateway inválido</li>
                    <li><code className="text-red-400">503 Service Unavailable</code> - Servicio no disponible</li>
                  </ul>
                </div>
              </div>
            </div>
          </section>

          {/* Ejemplo Práctico */}
          <section>
            <h2 className="text-3xl font-bold text-white mb-4">Ejemplo Práctico</h2>
            
            <div className="space-y-4">
              <div className="bg-slate-900 rounded-xl p-6 border border-slate-700">
                <h3 className="text-lg font-bold text-blue-300 mb-3">📤 Petición HTTP GET</h3>
                <pre className="text-sm text-green-400 overflow-x-auto">
{`GET /api/users HTTP/1.1
Host: aitana.cloud
User-Agent: Mozilla/5.0
Accept: application/json
Cookie: session=abc123`}
                </pre>
              </div>

              <div className="bg-slate-900 rounded-xl p-6 border border-slate-700">
                <h3 className="text-lg font-bold text-purple-300 mb-3">📥 Respuesta HTTP</h3>
                <pre className="text-sm text-cyan-400 overflow-x-auto">
{`HTTP/1.1 200 OK
Content-Type: application/json
Set-Cookie: session=xyz789

{
  "users": [
    {"id": 1, "name": "Alice"},
    {"id": 2, "name": "Bob"}
  ]
}`}
                </pre>
              </div>
            </div>
          </section>

          {/* Implicaciones de Seguridad */}
          <section>
            <div className="bg-red-500/10 border border-red-400/30 rounded-xl p-6">
              <div className="flex items-start gap-3">
                <AlertCircle className="w-6 h-6 text-red-400 flex-shrink-0 mt-1" />
                <div>
                  <h3 className="text-xl font-bold text-red-300 mb-3">Implicaciones de Seguridad</h3>
                  <ul className="space-y-2 text-slate-300">
                    <li className="flex items-start gap-2">
                      <span className="text-red-400">⚠️</span>
                      <span><strong className="text-white">HTTP vs HTTPS:</strong> HTTP transmite datos en texto plano (inseguro). Siempre usa HTTPS en producción.</span>
                    </li>
                    <li className="flex items-start gap-2">
                      <span className="text-red-400">⚠️</span>
                      <span><strong className="text-white">Headers expuestos:</strong> Los headers pueden revelar información del servidor (versiones, tecnologías).</span>
                    </li>
                    <li className="flex items-start gap-2">
                      <span className="text-red-400">⚠️</span>
                      <span><strong className="text-white">Métodos no seguros:</strong> GET nunca debe modificar datos. POST/PUT/DELETE requieren validación estricta.</span>
                    </li>
                  </ul>
                </div>
              </div>
            </div>
          </section>

          {/* Siguiente Paso */}
          <section className="border-t border-white/10 pt-8">
            <h2 className="text-2xl font-bold text-white mb-4">Siguiente Paso</h2>
            <Link
              href={`/${locale}/wiki/fundamentos/cookies-sesiones`}
              className="inline-flex items-center gap-2 px-6 py-3 bg-gradient-to-r from-blue-600 to-purple-600 text-white rounded-xl font-semibold hover:scale-105 transition-transform"
            >
              <span>Cookies y Sesiones</span>
              <Code className="w-5 h-5" />
            </Link>
          </section>
        </div>
      </div>
      </div>
    </>
  );
}
