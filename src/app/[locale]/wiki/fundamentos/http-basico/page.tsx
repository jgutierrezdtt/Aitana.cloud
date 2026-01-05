'use client';'use client';



import WikiArticleLayout from '@/components/WikiArticleLayout';import WikiArticleLayout from '@/components/WikiArticleLayout';

import {import {

  Section,  Section,

  Paragraph,  Subsection,

  Strong,  Paragraph,

  InlineCode,  Strong,

  AlertInfo,  InlineCode,

  AlertWarning,  AlertInfo,

  AlertDanger,  AlertWarning,

  CodeBlock,  AlertSuccess,

  HighlightBox,  CodeBlock,

  ListItem  TerminalOutput,

} from '@/components/WikiArticleComponents';  HighlightBox,

import { Send, Database, Shield, ArrowRight } from 'lucide-react';  ListItem

import Link from 'next/link';} from '@/components/WikiArticleComponents';

import { useParams } from 'next/navigation';import { Globe, Send, Database, Shield, CheckCircle } from 'lucide-react';



export default function HttpBasicoPage() {export default function HttpBasicoPage() {

  const params = useParams();  const params = useParams();

  const locale = params.locale as string;  const locale = params.locale as string;



  return (  return (

    <WikiArticleLayout    <>

      category="Fundamentos"      <Navigation />

      categoryColor="blue"      <div className="min-h-screen bg-gradient-to-br from-slate-50 via-white to-slate-100 dark:from-slate-950 dark:via-slate-900 dark:to-slate-950">

      title="HTTP: El Protocolo de la Web"      {/* Breadcrumb */}

      description="Aprende los fundamentos del protocolo HTTP, la base de toda comunicación en la World Wide Web."      <div className="bg-slate-100 dark:bg-slate-800 backdrop-blur-sm border-b border-slate-200 dark:border-slate-700">

      level="Estudiante"        <div className="max-w-4xl mx-auto px-6 py-4">

      readTime="10 minutos"          <Link 

      lastUpdated="Enero 2026"            href={`/${locale}/wiki`}

    >            className="inline-flex items-center gap-2 text-blue-600 dark:text-blue-400 hover:text-blue-700 dark:text-blue-300 transition-colors"

                >

      {/* Introducción */}            <ArrowLeft className="w-4 h-4" />

      <Section id="introduccion" title="¿Qué es HTTP?">            <span>Volver a la Wiki</span>

        <Paragraph>          </Link>

          <Strong>HTTP</Strong> (HyperText Transfer Protocol) es el protocolo fundamental que hace posible         </div>

          la World Wide Web. Es el lenguaje que utilizan los navegadores (clientes) y los servidores web       </div>

          para comunicarse entre sí.

        </Paragraph>      {/* Article Header */}

      <div className="bg-gradient-to-r from-blue-600 to-cyan-600 py-12">

        <Paragraph>        <div className="max-w-4xl mx-auto px-6">

          Cada vez que visitas una página web, tu navegador envía una petición HTTP al servidor,           <div className="inline-flex items-center gap-2 bg-white/10 backdrop-blur-sm px-3 py-1 rounded-lg mb-4">

          y el servidor responde con el contenido solicitado (HTML, imágenes, CSS, JavaScript, etc.).            <BookOpen className="w-4 h-4 text-white dark:text-white" />

        </Paragraph>            <span className="text-slate-900 dark:text-white text-sm font-medium">Fundamentos</span>

          </div>

        <AlertInfo title="Dato curioso">          <h1 className="text-4xl md:text-5xl font-bold text-slate-900 dark:text-white mb-4">

          HTTP fue creado por Tim Berners-Lee en 1989 en el CERN. La primera versión (HTTP/0.9) solo             HTTP: El Protocolo de la Web

          soportaba el método GET y respondía únicamente con HTML. Hoy usamos HTTP/2 y HTTP/3.          </h1>

        </AlertInfo>          <div className="flex items-center gap-4 text-blue-100">

      </Section>            <span className="bg-green-500/20 text-green-700 dark:text-green-300 px-3 py-1 rounded-lg text-sm font-medium">

              Principiante

      {/* Conceptos Clave */}            </span>

      <Section id="conceptos" title="Conceptos Clave">            <span className="text-sm">⏱️ 10 minutos de lectura</span>

                  </div>

        <HighlightBox color="blue" title="📤 Peticiones (Requests)" icon={<Send className="w-6 h-6 text-blue-600 dark:text-blue-400" />}>        </div>

          <Paragraph className="mb-4">      </div>

            El cliente (navegador) envía una <Strong>petición HTTP</Strong> al servidor. 

            Una petición incluye:      {/* Article Content */}

          </Paragraph>      <div className="max-w-4xl mx-auto px-6 py-12">

          <ul className="space-y-3">        <div className="bg-white dark:bg-slate-900 backdrop-blur-sm border border-slate-200 dark:border-slate-700 rounded-2xl p-8 md:p-12 space-y-8">

            <ListItem>          

              <Strong>Método HTTP:</Strong> GET, POST, PUT, DELETE, etc.          {/* Introducción */}

            </ListItem>          <section>

            <ListItem>            <h2 className="text-3xl font-bold text-slate-900 dark:text-white mb-4">¿Qué es HTTP?</h2>

              <Strong>URL:</Strong> La dirección del recurso solicitado            <p className="text-slate-700 dark:text-slate-300 text-lg leading-relaxed mb-4">

            </ListItem>              <strong className="text-white dark:text-white">HTTP</strong> (HyperText Transfer Protocol) es el protocolo que hace posible 

            <ListItem>              la World Wide Web. Es el lenguaje que utilizan los navegadores (clientes) y los servidores web para comunicarse 

              <Strong>Headers:</Strong> Metadatos como idioma, tipo de contenido, cookies              entre sí.

            </ListItem>            </p>

            <ListItem>            <p className="text-slate-700 dark:text-slate-300 text-lg leading-relaxed">

              <Strong>Body:</Strong> Datos enviados al servidor (POST/PUT/PATCH)              Cada vez que visitas una página web, tu navegador envía una petición HTTP al servidor, 

            </ListItem>              y el servidor responde con el contenido solicitado (HTML, imágenes, CSS, JavaScript, etc.).

          </ul>            </p>

        </HighlightBox>          </section>



        <HighlightBox color="purple" title="📥 Respuestas (Responses)" icon={<Database className="w-6 h-6 text-purple-600 dark:text-purple-400" />}>          {/* Conceptos Clave */}

          <Paragraph className="mb-4">          <section>

            El servidor responde con una <Strong>respuesta HTTP</Strong> que incluye:            <h2 className="text-3xl font-bold text-slate-900 dark:text-white mb-6">Conceptos Clave</h2>

          </Paragraph>            

          <ul className="space-y-3">            <div className="space-y-6">

            <ListItem>              <div className="bg-blue-500/10 border border-blue-500 dark:border-blue-400/30 rounded-xl p-6">

              <Strong>Status Code:</Strong> 200 (OK), 404 (Not Found), 500 (Error)                <h3 className="text-xl font-bold text-blue-700 dark:text-blue-300 mb-3">📤 Peticiones (Requests)</h3>

            </ListItem>                <p className="text-slate-700 dark:text-slate-300 leading-relaxed mb-4">

            <ListItem>                  El cliente (navegador) envía una <strong className="text-white dark:text-white">petición HTTP</strong> al servidor. 

              <Strong>Headers:</Strong> Tipo de contenido, cookies, caché, CORS                  Una petición incluye:

            </ListItem>                </p>

            <ListItem>                <ul className="space-y-2 text-slate-700 dark:text-slate-300">

              <Strong>Body:</Strong> El contenido solicitado (HTML, JSON, imágenes...)                  <li className="flex items-start gap-2">

            </ListItem>                    <CheckCircle className="w-5 h-5 text-green-600 dark:text-green-400 flex-shrink-0 mt-0.5" />

          </ul>                    <span><strong className="text-white dark:text-white">Método HTTP:</strong> GET, POST, PUT, DELETE, etc.</span>

        </HighlightBox>                  </li>

      </Section>                  <li className="flex items-start gap-2">

                    <CheckCircle className="w-5 h-5 text-green-600 dark:text-green-400 flex-shrink-0 mt-0.5" />

      {/* Ejemplo Práctico */}                    <span><strong className="text-white dark:text-white">URL:</strong> La dirección del recurso solicitado</span>

      <Section id="ejemplo" title="Ejemplo Práctico">                  </li>

        <Paragraph>                  <li className="flex items-start gap-2">

          Veamos un ejemplo completo de una petición HTTP y su respuesta:                    <CheckCircle className="w-5 h-5 text-green-600 dark:text-green-400 flex-shrink-0 mt-0.5" />

        </Paragraph>                    <span><strong className="text-white dark:text-white">Headers:</strong> Metadatos (idioma, tipo de contenido, cookies)</span>

                  </li>

        <CodeBlock                  <li className="flex items-start gap-2">

          language="http"                    <CheckCircle className="w-5 h-5 text-green-600 dark:text-green-400 flex-shrink-0 mt-0.5" />

          title="Petición HTTP GET"                    <span><strong className="text-white dark:text-white">Body:</strong> Datos enviados (en POST/PUT)</span>

          code={`GET /api/users?page=1&limit=10 HTTP/1.1                  </li>

Host: api.aitana.cloud                </ul>

User-Agent: Mozilla/5.0              </div>

Accept: application/json

Authorization: Bearer eyJhbGc...              <div className="bg-purple-500/10 border border-purple-400/30 rounded-xl p-6">

Cookie: session=abc123`}                <h3 className="text-xl font-bold text-purple-700 dark:text-purple-300 mb-3">📥 Respuestas (Responses)</h3>

        />                <p className="text-slate-700 dark:text-slate-300 leading-relaxed mb-4">

                  El servidor responde con una <strong className="text-white dark:text-white">respuesta HTTP</strong> que incluye:

        <CodeBlock                </p>

          language="http"                <ul className="space-y-2 text-slate-700 dark:text-slate-300">

          title="Respuesta del Servidor"                  <li className="flex items-start gap-2">

          code={`HTTP/1.1 200 OK                    <CheckCircle className="w-5 h-5 text-green-600 dark:text-green-400 flex-shrink-0 mt-0.5" />

Content-Type: application/json                    <span><strong className="text-white dark:text-white">Status Code:</strong> 200 (OK), 404 (Not Found), 500 (Error)...</span>

Cache-Control: max-age=300                  </li>

Set-Cookie: session=xyz789; HttpOnly; Secure                  <li className="flex items-start gap-2">

                    <CheckCircle className="w-5 h-5 text-green-600 dark:text-green-400 flex-shrink-0 mt-0.5" />

{                    <span><strong className="text-white dark:text-white">Headers:</strong> Tipo de contenido, cookies, caché...</span>

  "users": [                  </li>

    {"id": 1, "name": "Alice"},                  <li className="flex items-start gap-2">

    {"id": 2, "name": "Bob"}                    <CheckCircle className="w-5 h-5 text-green-600 dark:text-green-400 flex-shrink-0 mt-0.5" />

  ]                    <span><strong className="text-white dark:text-white">Body:</strong> El contenido solicitado (HTML, JSON, imágenes...)</span>

}`}                  </li>

        />                </ul>

      </Section>              </div>

            </div>

      {/* Seguridad */}          </section>

      <Section id="seguridad" title="Implicaciones de Seguridad">

        <AlertDanger title="⚠️ Vulnerabilidades Comunes">          {/* Métodos HTTP */}

          <ul className="space-y-3 mt-3">          <section>

            <ListItem icon={<Shield className="w-5 h-5 text-red-600 dark:text-red-400 flex-shrink-0 mt-0.5" />}>            <h2 className="text-3xl font-bold text-slate-900 dark:text-white mb-6">Métodos HTTP Principales</h2>

              <Strong>HTTP vs HTTPS:</Strong> HTTP transmite datos en texto plano.             

              <Strong className="text-red-700 dark:text-red-300"> Siempre usa HTTPS en producción.</Strong>            <div className="space-y-4">

            </ListItem>              {[

            <ListItem icon={<Shield className="w-5 h-5 text-red-600 dark:text-red-400 flex-shrink-0 mt-0.5" />}>                { 

              <Strong>Headers expuestos:</Strong> Headers como <InlineCode>Server</InlineCode> revelan información útil para atacantes.                  method: 'GET', 

            </ListItem>                  desc: 'Obtener datos del servidor (leer)', 

            <ListItem icon={<Shield className="w-5 h-5 text-red-600 dark:text-red-400 flex-shrink-0 mt-0.5" />}>                  example: 'Cargar una página web, buscar usuarios',

              <Strong>Métodos inseguros:</Strong> GET nunca debe modificar datos. POST/PUT/DELETE requieren                   color: 'blue'

              validación estricta.                },

            </ListItem>                { 

          </ul>                  method: 'POST', 

        </AlertDanger>                  desc: 'Enviar datos al servidor (crear)', 

                  example: 'Enviar un formulario, crear una cuenta',

        <AlertWarning title="Buenas Prácticas">                  color: 'green'

          <ul className="space-y-2 mt-3">                },

            <ListItem>                { 

              Usa <Strong>HTTPS</Strong> siempre (TLS 1.2 o superior)                  method: 'PUT', 

            </ListItem>                  desc: 'Actualizar datos existentes', 

            <ListItem>                  example: 'Modificar perfil de usuario',

              Implementa <Strong>Security Headers</Strong> (CSP, HSTS, X-Frame-Options)                  color: 'yellow'

            </ListItem>                },

            <ListItem>                { 

              Valida <Strong>todos los inputs</Strong> (headers, body, query params)                  method: 'DELETE', 

            </ListItem>                  desc: 'Eliminar datos', 

            <ListItem>                  example: 'Borrar una publicación',

              Usa cookies con <InlineCode>HttpOnly</InlineCode> y <InlineCode>Secure</InlineCode>                  color: 'red'

            </ListItem>                },

          </ul>              ].map((item) => (

        </AlertWarning>                <div key={item.method} className="bg-white/5 border border-white/10 rounded-xl p-4">

      </Section>                  <div className="flex items-center gap-3 mb-2">

                    <span className={`px-3 py-1 rounded-lg bg-${item.color}-500/20 text-${item.color}-300 font-mono font-bold text-sm`}>

      {/* Siguiente Paso */}                      {item.method}

      <div className="mt-12 pt-8 border-t border-slate-200 dark:border-slate-800">                    </span>

        <h3 className="text-2xl font-bold text-slate-900 dark:text-white mb-4">Siguiente Paso</h3>                    <span className="text-slate-900 dark:text-white font-semibold">{item.desc}</span>

        <Link                  </div>

          href={`/${locale}/wiki/fundamentos/autenticacion-autorizacion`}                  <p className="text-slate-600 dark:text-slate-400 text-sm ml-20">Ejemplo: {item.example}</p>

          className="group inline-flex items-center gap-3 px-6 py-4 bg-gradient-to-r from-blue-600 to-purple-600 text-white rounded-xl font-semibold hover:shadow-xl hover:shadow-blue-500/50 transition-all"                </div>

        >              ))}

          <span>Aprende sobre Autenticación y Autorización</span>            </div>

          <ArrowRight className="w-5 h-5 group-hover:translate-x-1 transition-transform" />          </section>

        </Link>

      </div>          {/* Códigos de Estado */}

          <section>

    </WikiArticleLayout>            <h2 className="text-3xl font-bold text-slate-900 dark:text-white mb-6">Códigos de Estado HTTP</h2>

  );            

}            <div className="bg-slate-100 dark:bg-slate-800/50 rounded-xl p-6 space-y-3">

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <h4 className="text-green-600 dark:text-green-400 font-bold mb-2">2xx - Éxito ✅</h4>
                  <ul className="text-sm text-slate-700 dark:text-slate-300 space-y-1">
                    <li><code className="text-green-600 dark:text-green-400">200 OK</code> - Petición exitosa</li>
                    <li><code className="text-green-600 dark:text-green-400">201 Created</code> - Recurso creado</li>
                  </ul>
                </div>
                <div>
                  <h4 className="text-blue-600 dark:text-blue-400 font-bold mb-2">3xx - Redirección 🔄</h4>
                  <ul className="text-sm text-slate-700 dark:text-slate-300 space-y-1">
                    <li><code className="text-blue-600 dark:text-blue-400">301 Moved</code> - Redireccionado permanentemente</li>
                    <li><code className="text-blue-600 dark:text-blue-400">302 Found</code> - Redireccionado temporalmente</li>
                  </ul>
                </div>
                <div>
                  <h4 className="text-yellow-400 font-bold mb-2">4xx - Error del Cliente ⚠️</h4>
                  <ul className="text-sm text-slate-700 dark:text-slate-300 space-y-1">
                    <li><code className="text-yellow-400">400 Bad Request</code> - Petición inválida</li>
                    <li><code className="text-yellow-400">401 Unauthorized</code> - No autenticado</li>
                    <li><code className="text-yellow-400">403 Forbidden</code> - Sin permisos</li>
                    <li><code className="text-yellow-400">404 Not Found</code> - No encontrado</li>
                  </ul>
                </div>
                <div>
                  <h4 className="text-red-600 dark:text-red-400 font-bold mb-2">5xx - Error del Servidor 🔥</h4>
                  <ul className="text-sm text-slate-700 dark:text-slate-300 space-y-1">
                    <li><code className="text-red-600 dark:text-red-400">500 Internal Error</code> - Error del servidor</li>
                    <li><code className="text-red-600 dark:text-red-400">502 Bad Gateway</code> - Gateway inválido</li>
                    <li><code className="text-red-600 dark:text-red-400">503 Service Unavailable</code> - Servicio no disponible</li>
                  </ul>
                </div>
              </div>
            </div>
          </section>

          {/* Ejemplo Práctico */}
          <section>
            <h2 className="text-3xl font-bold text-slate-900 dark:text-white mb-4">Ejemplo Práctico</h2>
            
            <div className="space-y-4">
              <div className="bg-white dark:bg-slate-900 rounded-xl p-6 border border-slate-300 dark:border-slate-700">
                <h3 className="text-lg font-bold text-blue-700 dark:text-blue-300 mb-3">📤 Petición HTTP GET</h3>
                <pre className="text-sm text-green-600 dark:text-green-400 overflow-x-auto">
{`GET /api/users HTTP/1.1
Host: aitana.cloud
User-Agent: Mozilla/5.0
Accept: application/json
Cookie: session=abc123`}
                </pre>
              </div>

              <div className="bg-white dark:bg-slate-900 rounded-xl p-6 border border-slate-300 dark:border-slate-700">
                <h3 className="text-lg font-bold text-purple-700 dark:text-purple-300 mb-3">📥 Respuesta HTTP</h3>
                <pre className="text-sm text-cyan-600 dark:text-cyan-400 overflow-x-auto">
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
                <AlertCircle className="w-6 h-6 text-red-600 dark:text-red-400 flex-shrink-0 mt-1" />
                <div>
                  <h3 className="text-xl font-bold text-red-700 dark:text-red-300 mb-3">Implicaciones de Seguridad</h3>
                  <ul className="space-y-2 text-slate-700 dark:text-slate-300">
                    <li className="flex items-start gap-2">
                      <span className="text-red-600 dark:text-red-400">⚠️</span>
                      <span><strong className="text-white dark:text-white">HTTP vs HTTPS:</strong> HTTP transmite datos en texto plano (inseguro). Siempre usa HTTPS en producción.</span>
                    </li>
                    <li className="flex items-start gap-2">
                      <span className="text-red-600 dark:text-red-400">⚠️</span>
                      <span><strong className="text-white dark:text-white">Headers expuestos:</strong> Los headers pueden revelar información del servidor (versiones, tecnologías).</span>
                    </li>
                    <li className="flex items-start gap-2">
                      <span className="text-red-600 dark:text-red-400">⚠️</span>
                      <span><strong className="text-white dark:text-white">Métodos no seguros:</strong> GET nunca debe modificar datos. POST/PUT/DELETE requieren validación estricta.</span>
                    </li>
                  </ul>
                </div>
              </div>
            </div>
          </section>

          {/* Siguiente Paso */}
          <section className="border-t border-white/10 pt-8">
            <h2 className="text-2xl font-bold text-slate-900 dark:text-white mb-4">Siguiente Paso</h2>
            <Link
              href={`/${locale}/wiki/fundamentos/cookies-sesiones`}
              className="inline-flex items-center gap-2 px-6 py-3 bg-gradient-to-r from-blue-600 to-purple-600 text-slate-900 dark:text-white rounded-xl font-semibold hover:scale-105 transition-transform"
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
