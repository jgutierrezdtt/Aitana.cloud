'use client';

import Link from 'next/link';
import { useParams } from 'next/navigation';
import { Home, BookOpen, Globe, Lock, AlertTriangle, Shield, Code } from 'lucide-react';

export default function CORSSameOriginPage() {
  const params = useParams();
  const locale = params.locale as string;

  return (
    <div className="min-h-screen">
      <div className="bg-white dark:bg-slate-900/50 border-b border-slate-200 dark:border-slate-700 px-8 py-4">
        <div className="max-w-5xl mx-auto flex items-center gap-2 text-sm">
          <Link href={`/${locale}/wiki`} className="text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:text-white transition-colors flex items-center gap-1">
            <Home className="w-4 h-4" />
            Wiki
          </Link>
          <span className="text-slate-600">/</span>
          <Link href={`/${locale}/wiki`} className="text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:text-white transition-colors">
            Fundamentos
          </Link>
          <span className="text-slate-600">/</span>
          <span className="text-white dark:text-white">CORS y Same-Origin Policy</span>
        </div>
      </div>

      <div className="bg-gradient-to-r from-orange-600 via-red-600 to-pink-600 px-8 py-12">
        <div className="max-w-5xl mx-auto">
          <div className="flex items-center gap-3 mb-4">
            <div className="px-3 py-1 bg-green-500/20 text-green-700 dark:text-green-300 rounded-lg text-sm font-medium border border-green-500/30">
              Principiante
            </div>
            <div className="px-3 py-1 bg-white/10 backdrop-blur-sm text-slate-900 dark:text-white rounded-lg text-sm">
              16 min lectura
            </div>
          </div>
          <h1 className="text-4xl md:text-5xl font-bold text-slate-900 dark:text-white mb-4 flex items-center gap-4">
            <Globe className="w-12 h-12" />
            CORS y Same-Origin Policy
          </h1>
          <p className="text-xl text-orange-100">
            Mecanismos de seguridad del navegador para controlar peticiones entre diferentes orígenes
          </p>
        </div>
      </div>

      <div className="max-w-5xl mx-auto px-8 py-12">
        <div className="prose prose-invert prose-lg max-w-none">
          
          <section className="mb-12">
            <h2 className="text-3xl font-bold text-slate-900 dark:text-white mb-6">Same-Origin Policy (SOP)</h2>
            <p className="text-slate-700 dark:text-slate-300 mb-6">
              La Same-Origin Policy es una política de seguridad crítica implementada por los navegadores que 
              restringe cómo un documento o script de un origen puede interactuar con recursos de otro origen.
            </p>
            
            <div className="bg-white/5 border border-white/10 rounded-xl p-6 mb-6">
              <h3 className="text-xl font-semibold text-slate-900 dark:text-white mb-4">¿Qué es un "Origen"?</h3>
              <p className="text-slate-700 dark:text-slate-300 mb-4">Un origen está definido por tres componentes:</p>
              <div className="bg-slate-100 dark:bg-slate-800/50 rounded-lg p-4 font-mono text-sm mb-4">
                <pre className="text-cyan-600 dark:text-cyan-400">
{`Protocolo + Dominio + Puerto

https://example.com:443/path
└──┬──┘ └─────┬──────┘ └┬┘
Protocolo   Dominio    Puerto

Ejemplos:
https://example.com:443  ← Origen A
https://example.com:8080 ← Origen diferente (puerto distinto)
http://example.com:443   ← Origen diferente (protocolo distinto)
https://api.example.com  ← Origen diferente (subdominio distinto)`}
                </pre>
              </div>
              <div className="bg-yellow-500/10 border border-yellow-500/30 rounded-lg p-4">
                <p className="text-sm text-yellow-100">
                  <strong>Importante:</strong> Dos URLs tienen el MISMO origen solo si protocolo, dominio y puerto son idénticos.
                </p>
              </div>
            </div>

            <h3 className="text-2xl font-semibold text-blue-600 dark:text-blue-400 mb-4">Qué bloquea SOP</h3>
            <div className="bg-red-500/10 border border-red-500/30 rounded-xl p-6 mb-6">
              <ul className="text-slate-700 dark:text-slate-300 space-y-2">
                <li>• Lectura de respuestas de fetch/XMLHttpRequest cross-origin</li>
                <li>• Acceso al DOM de iframes de diferente origen</li>
                <li>• Lectura de cookies de otro dominio</li>
                <li>• Acceso a localStorage/sessionStorage de otro origen</li>
              </ul>
            </div>

            <h3 className="text-2xl font-semibold text-green-600 dark:text-green-400 mb-4">Qué permite SOP</h3>
            <div className="bg-green-500/10 border border-green-500/30 rounded-xl p-6">
              <ul className="text-slate-700 dark:text-slate-300 space-y-2">
                <li>• Cargar imágenes: <code className="text-green-600 dark:text-green-400">&lt;img src="https://other.com/img.jpg"&gt;</code></li>
                <li>• Cargar scripts: <code className="text-green-600 dark:text-green-400">&lt;script src="https://cdn.com/lib.js"&gt;</code></li>
                <li>• Cargar estilos: <code className="text-green-600 dark:text-green-400">&lt;link href="https://cdn.com/style.css"&gt;</code></li>
                <li>• Enviar formularios: <code className="text-green-600 dark:text-green-400">&lt;form action="https://other.com"&gt;</code></li>
              </ul>
            </div>
          </section>

          <section className="mb-12">
            <h2 className="text-3xl font-bold text-slate-900 dark:text-white mb-6">CORS - Cross-Origin Resource Sharing</h2>
            <p className="text-slate-700 dark:text-slate-300 mb-6">
              CORS es un mecanismo que permite a los servidores indicar qué orígenes tienen permiso para 
              leer sus recursos, relajando la Same-Origin Policy de manera controlada.
            </p>

            <h3 className="text-2xl font-semibold text-purple-400 mb-4">Flujo CORS Simple</h3>
            <div className="bg-slate-100 dark:bg-slate-800/50 rounded-xl p-6 mb-6">
              <pre className="text-blue-600 dark:text-blue-400 text-sm font-mono">
{`// 1. Frontend en https://app.com hace petición
fetch('https://api.example.com/data')
  .then(res => res.json())

// 2. Navegador añade header automáticamente
Origin: https://app.com

// 3. Servidor responde con headers CORS
HTTP/1.1 200 OK
Access-Control-Allow-Origin: https://app.com
Access-Control-Allow-Credentials: true
Content-Type: application/json

{"data": "..."}

// 4. Navegador comprueba headers y permite o bloquea la respuesta`}
              </pre>
            </div>

            <h3 className="text-2xl font-semibold text-orange-400 mb-4">Preflight Request</h3>
            <p className="text-slate-700 dark:text-slate-300 mb-4">
              Para peticiones "no simples" (PUT, DELETE, custom headers), el navegador envía primero una 
              petición OPTIONS para verificar permisos.
            </p>
            <div className="bg-slate-100 dark:bg-slate-800/50 rounded-xl p-6 mb-6">
              <pre className="text-orange-400 text-sm font-mono">
{`// 1. Navegador envía PREFLIGHT
OPTIONS /api/users/123
Origin: https://app.com
Access-Control-Request-Method: DELETE
Access-Control-Request-Headers: Authorization

// 2. Servidor responde
HTTP/1.1 200 OK
Access-Control-Allow-Origin: https://app.com
Access-Control-Allow-Methods: GET, POST, PUT, DELETE
Access-Control-Allow-Headers: Authorization, Content-Type
Access-Control-Max-Age: 3600

// 3. Si el preflight pasa, navegador envía la petición real
DELETE /api/users/123
Authorization: Bearer token123
Origin: https://app.com`}
              </pre>
            </div>
          </section>

          <section className="mb-12">
            <h2 className="text-3xl font-bold text-slate-900 dark:text-white mb-6">Configuración CORS en el Servidor</h2>
            
            <div className="space-y-6">
              <div className="bg-white/5 border border-white/10 rounded-xl p-6">
                <h3 className="text-xl font-semibold text-slate-900 dark:text-white mb-4">Express.js (Node.js)</h3>
                <div className="bg-slate-100 dark:bg-slate-800/50 rounded-lg p-4 font-mono text-sm">
                  <pre className="text-green-600 dark:text-green-400">
{`const express = require('express');
const cors = require('cors');

const app = express();

// Opción 1: Permitir TODOS los orígenes (¡INSEGURO!)
app.use(cors());

// Opción 2: Configuración específica (RECOMENDADO)
const corsOptions = {
  origin: ['https://app.com', 'https://www.app.com'],
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true, // permitir cookies
  maxAge: 3600 // cachear preflight por 1 hora
};
app.use(cors(corsOptions));

// Opción 3: Validación dinámica
app.use(cors({
  origin: function (origin, callback) {
    const allowedOrigins = ['https://app.com', 'https://admin.app.com'];
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error('CORS no permitido'));
    }
  }
}));`}
                  </pre>
                </div>
              </div>

              <div className="bg-white/5 border border-white/10 rounded-xl p-6">
                <h3 className="text-xl font-semibold text-slate-900 dark:text-white mb-4">Next.js API Routes</h3>
                <div className="bg-slate-100 dark:bg-slate-800/50 rounded-lg p-4 font-mono text-sm">
                  <pre className="text-blue-600 dark:text-blue-400">
{`// pages/api/data.ts
export default async function handler(req, res) {
  // Configurar CORS headers manualmente
  const origin = req.headers.origin;
  const allowedOrigins = ['https://app.com'];
  
  if (allowedOrigins.includes(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Access-Control-Allow-Credentials', 'true');
  }
  
  // Manejar preflight
  if (req.method === 'OPTIONS') {
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE');
    res.setHeader('Access-Control-Allow-Headers', 'Authorization, Content-Type');
    return res.status(200).end();
  }
  
  // Manejar petición normal
  res.json({ data: 'response' });
}

// O usar middleware
import Cors from 'cors';

const cors = Cors({
  origin: 'https://app.com',
  credentials: true,
});

function runMiddleware(req, res, fn) {
  return new Promise((resolve, reject) => {
    fn(req, res, (result) => {
      if (result instanceof Error) return reject(result);
      return resolve(result);
    });
  });
}

export default async function handler(req, res) {
  await runMiddleware(req, res, cors);
  res.json({ data: 'response' });
}`}
                  </pre>
                </div>
              </div>
            </div>
          </section>

          <section className="mb-12">
            <h2 className="text-3xl font-bold text-slate-900 dark:text-white mb-6 flex items-center gap-3">
              <AlertTriangle className="w-8 h-8 text-red-600 dark:text-red-400" />
              Vulnerabilidades CORS
            </h2>
            
            <div className="space-y-4">
              <div className="bg-red-500/10 border border-red-500/30 rounded-xl p-6">
                <h3 className="text-xl font-semibold text-red-600 dark:text-red-400 mb-3">1. Wildcard con Credentials</h3>
                <p className="text-slate-700 dark:text-slate-300 mb-4">
                  Usar <code className="text-red-600 dark:text-red-400">Access-Control-Allow-Origin: *</code> con 
                  <code className="text-red-600 dark:text-red-400">Access-Control-Allow-Credentials: true</code> NO está permitido.
                </p>
                <div className="bg-slate-100 dark:bg-slate-800/50 rounded-lg p-4 font-mono text-sm">
                  <pre className="text-red-600 dark:text-red-400">
{`// ❌ INVÁLIDO - El navegador lo rechazará
res.setHeader('Access-Control-Allow-Origin', '*');
res.setHeader('Access-Control-Allow-Credentials', 'true');

// ✅ VÁLIDO - Especificar origen exacto
res.setHeader('Access-Control-Allow-Origin', 'https://app.com');
res.setHeader('Access-Control-Allow-Credentials', 'true');`}
                  </pre>
                </div>
              </div>

              <div className="bg-red-500/10 border border-red-500/30 rounded-xl p-6">
                <h3 className="text-xl font-semibold text-red-600 dark:text-red-400 mb-3">2. Reflexión del Origin sin validación</h3>
                <p className="text-slate-700 dark:text-slate-300 mb-4">
                  Reflejar el header Origin recibido sin validar permite a cualquier sitio hacer peticiones.
                </p>
                <div className="bg-slate-100 dark:bg-slate-800/50 rounded-lg p-4 font-mono text-sm">
                  <pre className="text-red-600 dark:text-red-400">
{`// ❌ VULNERABLE
app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', req.headers.origin);
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  next();
});

// ✅ SEGURO - Validar contra whitelist
const allowedOrigins = ['https://app.com', 'https://admin.app.com'];
app.use((req, res, next) => {
  const origin = req.headers.origin;
  if (allowedOrigins.includes(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Access-Control-Allow-Credentials', 'true');
  }
  next();
});`}
                  </pre>
                </div>
              </div>

              <div className="bg-red-500/10 border border-red-500/30 rounded-xl p-6">
                <h3 className="text-xl font-semibold text-red-600 dark:text-red-400 mb-3">3. Validación de Origen débil</h3>
                <div className="bg-slate-100 dark:bg-slate-800/50 rounded-lg p-4 font-mono text-sm">
                  <pre className="text-red-600 dark:text-red-400">
{`// ❌ VULNERABLE - Regex débil
if (origin.match(/example\\.com$/)) {
  // Permite: evil-example.com
  // Permite: notexample.com
}

// ❌ VULNERABLE - includes() débil
if (origin.includes('example.com')) {
  // Permite: https://example.com.evil.com
  // Permite: https://evilexample.com
}

// ✅ SEGURO - Lista exacta
const allowedOrigins = [
  'https://example.com',
  'https://www.example.com',
  'https://api.example.com'
];
if (allowedOrigins.includes(origin)) {
  // Solo permite orígenes exactos
}`}
                  </pre>
                </div>
              </div>
            </div>
          </section>

          <section className="mb-12">
            <h2 className="text-3xl font-bold text-slate-900 dark:text-white mb-6 flex items-center gap-3">
              <Shield className="w-8 h-8 text-green-600 dark:text-green-400" />
              Mejores Prácticas
            </h2>
            
            <div className="bg-green-500/10 border border-green-500/30 rounded-xl p-6 space-y-3">
              <div className="flex items-start gap-3">
                <Code className="w-6 h-6 text-green-600 dark:text-green-400 flex-shrink-0 mt-1" />
                <div>
                  <h3 className="text-lg font-semibold text-slate-900 dark:text-white mb-1">Whitelist específica</h3>
                  <p className="text-sm text-slate-700 dark:text-slate-300">Nunca usar <code>*</code> en producción, especialmente con credentials</p>
                </div>
              </div>
              <div className="flex items-start gap-3">
                <Code className="w-6 h-6 text-green-600 dark:text-green-400 flex-shrink-0 mt-1" />
                <div>
                  <h3 className="text-lg font-semibold text-slate-900 dark:text-white mb-1">Validar orígenes correctamente</h3>
                  <p className="text-sm text-slate-700 dark:text-slate-300">Usar comparación exacta, no regex o includes débiles</p>
                </div>
              </div>
              <div className="flex items-start gap-3">
                <Code className="w-6 h-6 text-green-600 dark:text-green-400 flex-shrink-0 mt-1" />
                <div>
                  <h3 className="text-lg font-semibold text-slate-900 dark:text-white mb-1">Limitar métodos y headers</h3>
                  <p className="text-sm text-slate-700 dark:text-slate-300">Solo permitir los métodos HTTP y headers necesarios</p>
                </div>
              </div>
              <div className="flex items-start gap-3">
                <Code className="w-6 h-6 text-green-600 dark:text-green-400 flex-shrink-0 mt-1" />
                <div>
                  <h3 className="text-lg font-semibold text-slate-900 dark:text-white mb-1">Usar credentials solo cuando necesario</h3>
                  <p className="text-sm text-slate-700 dark:text-slate-300">Evitar <code>credentials: true</code> si no se necesitan cookies</p>
                </div>
              </div>
              <div className="flex items-start gap-3">
                <Code className="w-6 h-6 text-green-600 dark:text-green-400 flex-shrink-0 mt-1" />
                <div>
                  <h3 className="text-lg font-semibold text-slate-900 dark:text-white mb-1">Cachear preflight requests</h3>
                  <p className="text-sm text-slate-700 dark:text-slate-300">Usar <code>Access-Control-Max-Age</code> para mejorar performance</p>
                </div>
              </div>
            </div>
          </section>

          <section className="mb-12">
            <h2 className="text-3xl font-bold text-slate-900 dark:text-white mb-6">Recursos Adicionales</h2>
            <div className="bg-white/5 border border-white/10 rounded-xl p-6 space-y-3">
              <a href="https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS" target="_blank" rel="noopener noreferrer" 
                 className="block text-blue-600 dark:text-blue-400 hover:text-blue-700 dark:text-blue-300 hover:underline">
                → MDN - Cross-Origin Resource Sharing (CORS)
              </a>
              <a href="https://portswigger.net/web-security/cors" target="_blank" rel="noopener noreferrer"
                 className="block text-blue-600 dark:text-blue-400 hover:text-blue-700 dark:text-blue-300 hover:underline">
                → PortSwigger - CORS Vulnerabilities
              </a>
              <a href="https://www.youtube.com/watch?v=4KHiSt0oLJ0" target="_blank" rel="noopener noreferrer"
                 className="block text-blue-600 dark:text-blue-400 hover:text-blue-700 dark:text-blue-300 hover:underline">
                → Hussein Nasser - CORS Explained
              </a>
            </div>
          </section>

          <div className="bg-gradient-to-r from-orange-600/20 to-red-600/20 border border-orange-500/30 rounded-xl p-8 text-center">
            <h3 className="text-2xl font-bold text-slate-900 dark:text-white mb-4">Siguiente Paso</h3>
            <p className="text-slate-700 dark:text-slate-300 mb-6">
              Aprende sobre vulnerabilidades comunes en aplicaciones web
            </p>
            <Link
              href={`/${locale}/wiki/vulnerabilidades/xss`}
              className="inline-flex items-center gap-2 px-6 py-3 bg-red-600 hover:bg-red-700 text-slate-900 dark:text-white rounded-xl font-semibold transition-all transform hover:scale-105"
            >
              Cross-Site Scripting (XSS)
              <span>→</span>
            </Link>
          </div>
        </div>
      </div>
    </div>
  );
}
