'use client';

import Link from 'next/link';
import { useParams } from 'next/navigation';
import { Home, BookOpen, Code, Lock, AlertTriangle, Shield, CheckCircle } from 'lucide-react';

export default function APIsRESTSeguridadPage() {
  const params = useParams();
  const locale = params.locale as string;

  return (
    <div className="min-h-screen">
      {/* Breadcrumb */}
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
          <span className="text-white dark:text-white">APIs REST y Seguridad</span>
        </div>
      </div>

      {/* Article Header */}
      <div className="bg-gradient-to-r from-blue-600 via-indigo-600 to-purple-600 px-8 py-12">
        <div className="max-w-5xl mx-auto">
          <div className="flex items-center gap-3 mb-4">
            <div className="px-3 py-1 bg-green-500/20 text-green-700 dark:text-green-300 rounded-lg text-sm font-medium border border-green-500/30">
              Principiante
            </div>
            <div className="px-3 py-1 bg-white/10 backdrop-blur-sm text-slate-900 dark:text-white rounded-lg text-sm">
              20 min lectura
            </div>
          </div>
          <h1 className="text-4xl md:text-5xl font-bold text-slate-900 dark:text-white mb-4 flex items-center gap-4">
            <Code className="w-12 h-12" />
            APIs REST y Seguridad
          </h1>
          <p className="text-xl text-blue-100">
            Principios de diseño seguro para APIs RESTful y mejores prácticas de implementación
          </p>
        </div>
      </div>

      {/* Article Content */}
      <div className="max-w-5xl mx-auto px-8 py-12">
        <div className="prose prose-invert prose-lg max-w-none">
          
          {/* Introduction */}
          <section className="mb-12">
            <h2 className="text-3xl font-bold text-slate-900 dark:text-white mb-4 flex items-center gap-3">
              <BookOpen className="w-8 h-8 text-blue-600 dark:text-blue-400" />
              ¿Qué es una API REST?
            </h2>
            <p className="text-slate-700 dark:text-slate-300 mb-6">
              REST (Representational State Transfer) es un estilo arquitectónico para diseñar servicios web.
              Una API RESTful utiliza HTTP requests para realizar operaciones CRUD (Create, Read, Update, Delete).
            </p>
            
            <div className="bg-white/5 border border-white/10 rounded-xl p-6 mb-6">
              <h3 className="text-xl font-semibold text-slate-900 dark:text-white mb-4">Principios REST</h3>
              <div className="grid md:grid-cols-2 gap-4">
                <div className="bg-slate-100 dark:bg-slate-800/50 rounded-lg p-4">
                  <div className="text-blue-600 dark:text-blue-400 font-semibold mb-2">1. Stateless</div>
                  <p className="text-sm text-slate-700 dark:text-slate-300">Cada petición contiene toda la información necesaria</p>
                </div>
                <div className="bg-slate-100 dark:bg-slate-800/50 rounded-lg p-4">
                  <div className="text-blue-600 dark:text-blue-400 font-semibold mb-2">2. Cliente-Servidor</div>
                  <p className="text-sm text-slate-700 dark:text-slate-300">Separación de responsabilidades</p>
                </div>
                <div className="bg-slate-100 dark:bg-slate-800/50 rounded-lg p-4">
                  <div className="text-blue-600 dark:text-blue-400 font-semibold mb-2">3. Cacheable</div>
                  <p className="text-sm text-slate-700 dark:text-slate-300">Las respuestas pueden ser cacheadas</p>
                </div>
                <div className="bg-slate-100 dark:bg-slate-800/50 rounded-lg p-4">
                  <div className="text-blue-600 dark:text-blue-400 font-semibold mb-2">4. Uniform Interface</div>
                  <p className="text-sm text-slate-700 dark:text-slate-300">Interfaz consistente y predecible</p>
                </div>
              </div>
            </div>

            <h3 className="text-2xl font-semibold text-blue-600 dark:text-blue-400 mb-4">Métodos HTTP en REST</h3>
            <div className="bg-slate-100 dark:bg-slate-800/50 rounded-xl p-6 font-mono text-sm overflow-x-auto mb-6">
              <pre className="text-green-600 dark:text-green-400">
{`GET    /api/users        # Obtener lista de usuarios
GET    /api/users/123    # Obtener usuario específico
POST   /api/users        # Crear nuevo usuario
PUT    /api/users/123    # Actualizar usuario completo
PATCH  /api/users/123    # Actualizar campos específicos
DELETE /api/users/123    # Eliminar usuario`}
              </pre>
            </div>
          </section>

          {/* Autenticación en APIs */}
          <section className="mb-12">
            <h2 className="text-3xl font-bold text-slate-900 dark:text-white mb-6 flex items-center gap-3">
              <Lock className="w-8 h-8 text-cyan-600 dark:text-cyan-400" />
              Autenticación en APIs REST
            </h2>
            
            <div className="space-y-6">
              <div className="bg-white/5 border border-white/10 rounded-xl p-6">
                <h3 className="text-xl font-semibold text-slate-900 dark:text-white mb-4">1. API Keys</h3>
                <p className="text-slate-700 dark:text-slate-300 mb-4">
                  Claves únicas para identificar y autenticar a los clientes de la API.
                </p>
                <div className="bg-slate-100 dark:bg-slate-800/50 rounded-lg p-4 font-mono text-sm">
                  <pre className="text-blue-600 dark:text-blue-400">
{`// Cliente
fetch('https://api.example.com/data', {
  headers: {
    'X-API-Key': 'sk_live_abc123...'
  }
});

// Servidor (Express)
app.use('/api', (req, res, next) => {
  const apiKey = req.headers['x-api-key'];
  
  if (!apiKey || !validateApiKey(apiKey)) {
    return res.status(401).json({ error: 'API Key inválida' });
  }
  
  req.client = getClientByApiKey(apiKey);
  next();
});`}
                  </pre>
                </div>
                <div className="mt-4 bg-yellow-500/10 border border-yellow-500/30 rounded-lg p-4">
                  <div className="flex gap-2">
                    <AlertTriangle className="w-5 h-5 text-yellow-400 flex-shrink-0" />
                    <p className="text-sm text-yellow-100">
                      <strong>Limitación:</strong> Las API Keys no expiran automáticamente y pueden ser interceptadas si no se usa HTTPS.
                    </p>
                  </div>
                </div>
              </div>

              <div className="bg-white/5 border border-white/10 rounded-xl p-6">
                <h3 className="text-xl font-semibold text-slate-900 dark:text-white mb-4">2. Bearer Tokens (JWT)</h3>
                <p className="text-slate-700 dark:text-slate-300 mb-4">
                  Tokens JSON Web Tokens que contienen claims sobre el usuario.
                </p>
                <div className="bg-slate-100 dark:bg-slate-800/50 rounded-lg p-4 font-mono text-sm">
                  <pre className="text-purple-400">
{`// Cliente - Login
const response = await fetch('/api/auth/login', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ email, password })
});
const { token } = await response.json();

// Cliente - Usar token
fetch('/api/protected', {
  headers: {
    'Authorization': \`Bearer \${token}\`
  }
});

// Servidor - Verificar token
const jwt = require('jsonwebtoken');

function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  
  if (!token) {
    return res.status(401).json({ error: 'Token requerido' });
  }
  
  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Token inválido' });
    }
    req.user = user;
    next();
  });
}

app.get('/api/protected', authenticateToken, (req, res) => {
  res.json({ data: 'Contenido protegido', user: req.user });
});`}
                  </pre>
                </div>
              </div>

              <div className="bg-white/5 border border-white/10 rounded-xl p-6">
                <h3 className="text-xl font-semibold text-slate-900 dark:text-white mb-4">3. OAuth 2.0</h3>
                <p className="text-slate-700 dark:text-slate-300 mb-4">
                  Framework de autorización que permite acceso de terceros sin compartir credenciales.
                </p>
                <div className="bg-slate-100 dark:bg-slate-800/50 rounded-lg p-4 font-mono text-sm">
                  <pre className="text-green-600 dark:text-green-400">
{`// Flujo de autorización OAuth 2.0

// 1. Cliente redirige a servidor de autorización
window.location = \`https://oauth.example.com/authorize?
  client_id=YOUR_CLIENT_ID&
  redirect_uri=https://yourapp.com/callback&
  response_type=code&
  scope=read write\`;

// 2. Usuario se autentica y aprueba

// 3. Callback recibe código
// GET https://yourapp.com/callback?code=abc123

// 4. Intercambiar código por token
const tokenResponse = await fetch('https://oauth.example.com/token', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    grant_type: 'authorization_code',
    code: 'abc123',
    client_id: 'YOUR_CLIENT_ID',
    client_secret: 'YOUR_SECRET',
    redirect_uri: 'https://yourapp.com/callback'
  })
});

const { access_token } = await tokenResponse.json();

// 5. Usar access token para llamar a la API
fetch('https://api.example.com/user', {
  headers: { 'Authorization': \`Bearer \${access_token}\` }
});`}
                  </pre>
                </div>
              </div>
            </div>
          </section>

          {/* Rate Limiting */}
          <section className="mb-12">
            <h2 className="text-3xl font-bold text-slate-900 dark:text-white mb-6">Rate Limiting</h2>
            <p className="text-slate-700 dark:text-slate-300 mb-6">
              Limitar el número de peticiones que un cliente puede hacer en un período de tiempo.
            </p>
            
            <div className="bg-slate-100 dark:bg-slate-800/50 rounded-xl p-6 font-mono text-sm overflow-x-auto mb-6">
              <pre className="text-cyan-600 dark:text-cyan-400">
{`// Usando express-rate-limit
const rateLimit = require('express-rate-limit');

const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutos
  max: 100, // máximo 100 peticiones por ventana
  message: 'Demasiadas peticiones, intenta más tarde',
  standardHeaders: true, // Return rate limit info in headers
  legacyHeaders: false,
});

// Aplicar a todas las rutas /api
app.use('/api/', apiLimiter);

// Rate limit más estricto para login (prevenir brute force)
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5, // solo 5 intentos de login
  skipSuccessfulRequests: true, // no contar logins exitosos
});

app.post('/api/auth/login', loginLimiter, loginHandler);

// Headers de respuesta
// X-RateLimit-Limit: 100
// X-RateLimit-Remaining: 85
// X-RateLimit-Reset: 1640995200`}
              </pre>
            </div>
          </section>

          {/* Validación de Entrada */}
          <section className="mb-12">
            <h2 className="text-3xl font-bold text-slate-900 dark:text-white mb-6">Validación de Entrada en APIs</h2>
            
            <div className="bg-slate-100 dark:bg-slate-800/50 rounded-xl p-6 font-mono text-sm overflow-x-auto mb-6">
              <pre className="text-green-600 dark:text-green-400">
{`// Usando Joi para validación
const Joi = require('joi');

const userSchema = Joi.object({
  email: Joi.string().email().required(),
  password: Joi.string().min(8).required(),
  age: Joi.number().integer().min(18).max(120),
  role: Joi.string().valid('user', 'admin', 'editor')
});

function validateRequest(schema) {
  return (req, res, next) => {
    const { error, value } = schema.validate(req.body, {
      abortEarly: false, // reportar todos los errores
      stripUnknown: true // eliminar campos no definidos
    });
    
    if (error) {
      const errors = error.details.map(d => ({
        field: d.path.join('.'),
        message: d.message
      }));
      return res.status(400).json({ errors });
    }
    
    req.validatedBody = value;
    next();
  };
}

// Uso en rutas
app.post('/api/users', 
  validateRequest(userSchema),
  async (req, res) => {
    const user = await createUser(req.validatedBody);
    res.status(201).json(user);
  }
);`}
              </pre>
            </div>
          </section>

          {/* Vulnerabilidades Comunes */}
          <section className="mb-12">
            <h2 className="text-3xl font-bold text-slate-900 dark:text-white mb-6 flex items-center gap-3">
              <AlertTriangle className="w-8 h-8 text-red-600 dark:text-red-400" />
              Vulnerabilidades Comunes en APIs
            </h2>
            
            <div className="space-y-4">
              <div className="bg-red-500/10 border border-red-500/30 rounded-xl p-6">
                <h3 className="text-xl font-semibold text-red-600 dark:text-red-400 mb-3">1. Broken Object Level Authorization (BOLA)</h3>
                <p className="text-slate-700 dark:text-slate-300 mb-4">
                  No validar que el usuario tiene permisos para acceder al objeto solicitado.
                </p>
                <div className="grid md:grid-cols-2 gap-4">
                  <div>
                    <div className="text-sm font-semibold text-red-700 dark:text-red-300 mb-2">❌ Vulnerable</div>
                    <div className="bg-slate-100 dark:bg-slate-800/50 rounded-lg p-3 font-mono text-xs">
                      <pre className="text-red-600 dark:text-red-400">
{`app.get('/api/users/:id', (req, res) => {
  const user = db.users.findById(req.params.id);
  res.json(user); // ¡Sin verificar permisos!
});`}
                      </pre>
                    </div>
                  </div>
                  <div>
                    <div className="text-sm font-semibold text-green-700 dark:text-green-300 mb-2">✅ Seguro</div>
                    <div className="bg-slate-100 dark:bg-slate-800/50 rounded-lg p-3 font-mono text-xs">
                      <pre className="text-green-600 dark:text-green-400">
{`app.get('/api/users/:id', auth, (req, res) => {
  if (req.user.id !== req.params.id && 
      req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Forbidden' });
  }
  const user = db.users.findById(req.params.id);
  res.json(user);
});`}
                      </pre>
                    </div>
                  </div>
                </div>
              </div>

              <div className="bg-red-500/10 border border-red-500/30 rounded-xl p-6">
                <h3 className="text-xl font-semibold text-red-600 dark:text-red-400 mb-3">2. Excessive Data Exposure</h3>
                <p className="text-slate-700 dark:text-slate-300 mb-4">
                  Devolver más datos de los necesarios, confiando en que el cliente filtre.
                </p>
                <div className="grid md:grid-cols-2 gap-4">
                  <div>
                    <div className="text-sm font-semibold text-red-700 dark:text-red-300 mb-2">❌ Vulnerable</div>
                    <div className="bg-slate-100 dark:bg-slate-800/50 rounded-lg p-3 font-mono text-xs">
                      <pre className="text-red-600 dark:text-red-400">
{`app.get('/api/users/:id', (req, res) => {
  const user = db.users.findById(req.params.id);
  res.json(user); // Incluye password, token, etc
});`}
                      </pre>
                    </div>
                  </div>
                  <div>
                    <div className="text-sm font-semibold text-green-700 dark:text-green-300 mb-2">✅ Seguro</div>
                    <div className="bg-slate-100 dark:bg-slate-800/50 rounded-lg p-3 font-mono text-xs">
                      <pre className="text-green-600 dark:text-green-400">
{`app.get('/api/users/:id', (req, res) => {
  const user = db.users.findById(req.params.id);
  const safe = {
    id: user.id,
    name: user.name,
    email: user.email
  };
  res.json(safe);
});`}
                      </pre>
                    </div>
                  </div>
                </div>
              </div>

              <div className="bg-red-500/10 border border-red-500/30 rounded-xl p-6">
                <h3 className="text-xl font-semibold text-red-600 dark:text-red-400 mb-3">3. Mass Assignment</h3>
                <p className="text-slate-700 dark:text-slate-300 mb-4">
                  Permitir que el cliente modifique propiedades que no debería.
                </p>
                <div className="grid md:grid-cols-2 gap-4">
                  <div>
                    <div className="text-sm font-semibold text-red-700 dark:text-red-300 mb-2">❌ Vulnerable</div>
                    <div className="bg-slate-100 dark:bg-slate-800/50 rounded-lg p-3 font-mono text-xs">
                      <pre className="text-red-600 dark:text-red-400">
{`app.put('/api/users/:id', (req, res) => {
  db.users.update(req.params.id, req.body);
  // Cliente puede enviar { role: 'admin' }!
});`}
                      </pre>
                    </div>
                  </div>
                  <div>
                    <div className="text-sm font-semibold text-green-700 dark:text-green-300 mb-2">✅ Seguro</div>
                    <div className="bg-slate-100 dark:bg-slate-800/50 rounded-lg p-3 font-mono text-xs">
                      <pre className="text-green-600 dark:text-green-400">
{`app.put('/api/users/:id', (req, res) => {
  const allowed = ['name', 'email', 'bio'];
  const data = pick(req.body, allowed);
  db.users.update(req.params.id, data);
});`}
                      </pre>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </section>

          {/* Mejores Prácticas */}
          <section className="mb-12">
            <h2 className="text-3xl font-bold text-slate-900 dark:text-white mb-6 flex items-center gap-3">
              <Shield className="w-8 h-8 text-green-600 dark:text-green-400" />
              Mejores Prácticas de Seguridad
            </h2>
            
            <div className="bg-green-500/10 border border-green-500/30 rounded-xl p-6">
              <div className="space-y-4">
                <div className="flex items-start gap-3">
                  <CheckCircle className="w-6 h-6 text-green-600 dark:text-green-400 flex-shrink-0 mt-1" />
                  <div>
                    <h3 className="text-lg font-semibold text-slate-900 dark:text-white mb-1">Usar HTTPS siempre</h3>
                    <p className="text-sm text-slate-700 dark:text-slate-300">Nunca exponer APIs sobre HTTP sin cifrar</p>
                  </div>
                </div>
                <div className="flex items-start gap-3">
                  <CheckCircle className="w-6 h-6 text-green-600 dark:text-green-400 flex-shrink-0 mt-1" />
                  <div>
                    <h3 className="text-lg font-semibold text-slate-900 dark:text-white mb-1">Validar TODO input</h3>
                    <p className="text-sm text-slate-700 dark:text-slate-300">Type, format, length, range - validar cada campo</p>
                  </div>
                </div>
                <div className="flex items-start gap-3">
                  <CheckCircle className="w-6 h-6 text-green-600 dark:text-green-400 flex-shrink-0 mt-1" />
                  <div>
                    <h3 className="text-lg font-semibold text-slate-900 dark:text-white mb-1">Implementar autenticación y autorización</h3>
                    <p className="text-sm text-slate-700 dark:text-slate-300">Verificar identidad Y permisos en cada endpoint</p>
                  </div>
                </div>
                <div className="flex items-start gap-3">
                  <CheckCircle className="w-6 h-6 text-green-600 dark:text-green-400 flex-shrink-0 mt-1" />
                  <div>
                    <h3 className="text-lg font-semibold text-slate-900 dark:text-white mb-1">Rate limiting</h3>
                    <p className="text-sm text-slate-700 dark:text-slate-300">Prevenir abuso y ataques de fuerza bruta</p>
                  </div>
                </div>
                <div className="flex items-start gap-3">
                  <CheckCircle className="w-6 h-6 text-green-600 dark:text-green-400 flex-shrink-0 mt-1" />
                  <div>
                    <h3 className="text-lg font-semibold text-slate-900 dark:text-white mb-1">Logging y monitoreo</h3>
                    <p className="text-sm text-slate-700 dark:text-slate-300">Registrar accesos, errores y actividad sospechosa</p>
                  </div>
                </div>
                <div className="flex items-start gap-3">
                  <CheckCircle className="w-6 h-6 text-green-600 dark:text-green-400 flex-shrink-0 mt-1" />
                  <div>
                    <h3 className="text-lg font-semibold text-slate-900 dark:text-white mb-1">Versionado de API</h3>
                    <p className="text-sm text-slate-700 dark:text-slate-300">Usar /v1/, /v2/ para mantener compatibilidad</p>
                  </div>
                </div>
                <div className="flex items-start gap-3">
                  <CheckCircle className="w-6 h-6 text-green-600 dark:text-green-400 flex-shrink-0 mt-1" />
                  <div>
                    <h3 className="text-lg font-semibold text-slate-900 dark:text-white mb-1">Documentar con OpenAPI/Swagger</h3>
                    <p className="text-sm text-slate-700 dark:text-slate-300">Facilita testing y uso correcto de la API</p>
                  </div>
                </div>
              </div>
            </div>
          </section>

          {/* Recursos */}
          <section className="mb-12">
            <h2 className="text-3xl font-bold text-slate-900 dark:text-white mb-6">Recursos Adicionales</h2>
            <div className="bg-white/5 border border-white/10 rounded-xl p-6 space-y-3">
              <a href="https://owasp.org/API-Security/editions/2023/en/0x00-header/" target="_blank" rel="noopener noreferrer" 
                 className="block text-blue-600 dark:text-blue-400 hover:text-blue-700 dark:text-blue-300 hover:underline">
                → OWASP API Security Top 10
              </a>
              <a href="https://restfulapi.net/" target="_blank" rel="noopener noreferrer"
                 className="block text-blue-600 dark:text-blue-400 hover:text-blue-700 dark:text-blue-300 hover:underline">
                → RESTful API Design - Best Practices
              </a>
              <a href="https://swagger.io/specification/" target="_blank" rel="noopener noreferrer"
                 className="block text-blue-600 dark:text-blue-400 hover:text-blue-700 dark:text-blue-300 hover:underline">
                → OpenAPI Specification
              </a>
            </div>
          </section>

          {/* Next Steps */}
          <div className="bg-gradient-to-r from-blue-600/20 to-purple-600/20 border border-blue-500/30 rounded-xl p-8 text-center">
            <h3 className="text-2xl font-bold text-slate-900 dark:text-white mb-4">Siguiente Paso</h3>
            <p className="text-slate-700 dark:text-slate-300 mb-6">
              Aprende sobre CORS y la Same-Origin Policy
            </p>
            <Link
              href={`/${locale}/wiki/fundamentos/cors-same-origin`}
              className="inline-flex items-center gap-2 px-6 py-3 bg-blue-600 hover:bg-blue-700 text-slate-900 dark:text-white rounded-xl font-semibold transition-all transform hover:scale-105"
            >
              CORS y Same-Origin Policy
              <span>→</span>
            </Link>
          </div>
        </div>
      </div>
    </div>
  );
}
