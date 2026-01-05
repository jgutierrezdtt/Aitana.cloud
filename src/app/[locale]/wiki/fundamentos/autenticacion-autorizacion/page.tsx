'use client';

import Link from 'next/link';
import { useParams } from 'next/navigation';
import { Home, BookOpen, Lock, Key, Shield, AlertTriangle } from 'lucide-react';

export default function AutenticacionAutorizacionPage() {
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
          <span className="text-white dark:text-white">Autenticación y Autorización</span>
        </div>
      </div>

      {/* Article Header */}
      <div className="bg-gradient-to-r from-blue-600 via-cyan-600 to-blue-600 px-8 py-12">
        <div className="max-w-5xl mx-auto">
          <div className="flex items-center gap-3 mb-4">
            <div className="px-3 py-1 bg-green-500/20 text-green-700 dark:text-green-300 rounded-lg text-sm font-medium border border-green-500/30">
              Principiante
            </div>
            <div className="px-3 py-1 bg-white/10 backdrop-blur-sm text-slate-900 dark:text-white rounded-lg text-sm">
              18 min lectura
            </div>
          </div>
          <h1 className="text-4xl md:text-5xl font-bold text-slate-900 dark:text-white mb-4 flex items-center gap-4">
            <Lock className="w-12 h-12" />
            Autenticación y Autorización
          </h1>
          <p className="text-xl text-blue-100">
            Dos conceptos fundamentales de seguridad que a menudo se confunden pero tienen roles distintos
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
              ¿Qué son Autenticación y Autorización?
            </h2>
            <div className="bg-white/5 border border-white/10 rounded-xl p-6 mb-6">
              <div className="grid md:grid-cols-2 gap-6">
                <div className="space-y-3">
                  <div className="flex items-center gap-2 text-cyan-600 dark:text-cyan-400 font-semibold text-lg">
                    <Key className="w-6 h-6" />
                    Autenticación (AuthN)
                  </div>
                  <p className="text-slate-700 dark:text-slate-300">
                    <strong className="text-white dark:text-white">¿Quién eres?</strong> - Verificar la identidad del usuario.
                  </p>
                  <p className="text-sm text-slate-600 dark:text-slate-400">
                    Ejemplos: Login con usuario/contraseña, 2FA, biometría, OAuth
                  </p>
                </div>
                <div className="space-y-3">
                  <div className="flex items-center gap-2 text-green-600 dark:text-green-400 font-semibold text-lg">
                    <Shield className="w-6 h-6" />
                    Autorización (AuthZ)
                  </div>
                  <p className="text-slate-700 dark:text-slate-300">
                    <strong className="text-white dark:text-white">¿Qué puedes hacer?</strong> - Verificar los permisos del usuario.
                  </p>
                  <p className="text-sm text-slate-600 dark:text-slate-400">
                    Ejemplos: Roles, permisos, ACLs, RBAC, políticas de acceso
                  </p>
                </div>
              </div>
            </div>
            <div className="bg-yellow-500/10 border border-yellow-500/30 rounded-xl p-6">
              <div className="flex gap-3">
                <AlertTriangle className="w-6 h-6 text-yellow-400 flex-shrink-0 mt-1" />
                <div>
                  <h3 className="text-lg font-semibold text-yellow-700 dark:text-yellow-300 mb-2">Importante</h3>
                  <p className="text-yellow-100/90">
                    La autenticación siempre viene ANTES que la autorización. Primero verificamos quién eres, 
                    luego verificamos qué puedes hacer. No tiene sentido verificar permisos sin saber quién los solicita.
                  </p>
                </div>
              </div>
            </div>
          </section>

          {/* Autenticación */}
          <section className="mb-12">
            <h2 className="text-3xl font-bold text-slate-900 dark:text-white mb-6">Autenticación en Profundidad</h2>
            
            <h3 className="text-2xl font-semibold text-blue-600 dark:text-blue-400 mb-4">Factores de Autenticación</h3>
            <div className="space-y-4 mb-6">
              <div className="bg-white/5 border border-white/10 rounded-xl p-5">
                <h4 className="text-lg font-semibold text-slate-900 dark:text-white mb-2">1. Algo que sabes (Knowledge)</h4>
                <ul className="text-slate-700 dark:text-slate-300 space-y-2 ml-6">
                  <li>• Contraseñas, PINs</li>
                  <li>• Preguntas de seguridad</li>
                  <li>• Patrones de desbloqueo</li>
                </ul>
              </div>
              <div className="bg-white/5 border border-white/10 rounded-xl p-5">
                <h4 className="text-lg font-semibold text-slate-900 dark:text-white mb-2">2. Algo que tienes (Possession)</h4>
                <ul className="text-slate-700 dark:text-slate-300 space-y-2 ml-6">
                  <li>• Tokens de hardware (YubiKey)</li>
                  <li>• Teléfono móvil (SMS, apps)</li>
                  <li>• Tarjetas de acceso</li>
                </ul>
              </div>
              <div className="bg-white/5 border border-white/10 rounded-xl p-5">
                <h4 className="text-lg font-semibold text-slate-900 dark:text-white mb-2">3. Algo que eres (Inherence)</h4>
                <ul className="text-slate-700 dark:text-slate-300 space-y-2 ml-6">
                  <li>• Huellas dactilares</li>
                  <li>• Reconocimiento facial</li>
                  <li>• Escaneo de iris/retina</li>
                </ul>
              </div>
            </div>

            <h3 className="text-2xl font-semibold text-blue-600 dark:text-blue-400 mb-4">Ejemplo: Flujo de Autenticación</h3>
            <div className="bg-slate-100 dark:bg-slate-800/50 rounded-xl p-6 font-mono text-sm overflow-x-auto mb-6">
              <pre className="text-green-600 dark:text-green-400">
{`// Frontend - Login Request
async function login(username, password) {
  const response = await fetch('/api/auth/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, password })
  });
  
  const { token } = await response.json();
  // Guardar token (¡VULNERABLE si es localStorage!)
  localStorage.setItem('authToken', token);
  return token;
}

// Backend - Verificar Credenciales (Node.js/Express)
app.post('/api/auth/login', async (req, res) => {
  const { username, password } = req.body;
  
  // 1. Buscar usuario
  const user = await db.users.findOne({ username });
  if (!user) {
    return res.status(401).json({ error: 'Credenciales inválidas' });
  }
  
  // 2. Verificar contraseña (usando bcrypt)
  const isValid = await bcrypt.compare(password, user.passwordHash);
  if (!isValid) {
    return res.status(401).json({ error: 'Credenciales inválidas' });
  }
  
  // 3. Generar token JWT
  const token = jwt.sign(
    { userId: user.id, role: user.role },
    process.env.JWT_SECRET,
    { expiresIn: '24h' }
  );
  
  res.json({ token, user: { id: user.id, username: user.username } });
});`}
              </pre>
            </div>
          </section>

          {/* Autorización */}
          <section className="mb-12">
            <h2 className="text-3xl font-bold text-slate-900 dark:text-white mb-6">Autorización en Profundidad</h2>
            
            <h3 className="text-2xl font-semibold text-green-600 dark:text-green-400 mb-4">Modelos de Control de Acceso</h3>
            
            <div className="space-y-6 mb-6">
              <div className="bg-white/5 border border-white/10 rounded-xl p-6">
                <h4 className="text-xl font-semibold text-slate-900 dark:text-white mb-3">Role-Based Access Control (RBAC)</h4>
                <p className="text-slate-700 dark:text-slate-300 mb-4">
                  Los permisos se asignan a roles, y los usuarios son asignados a roles.
                </p>
                <div className="bg-slate-100 dark:bg-slate-800/50 rounded-lg p-4 font-mono text-sm">
                  <pre className="text-blue-600 dark:text-blue-400">
{`// Definir roles y permisos
const roles = {
  admin: ['read', 'write', 'delete', 'manage_users'],
  editor: ['read', 'write'],
  viewer: ['read']
};

// Middleware de autorización
function authorize(requiredPermission) {
  return (req, res, next) => {
    const userRole = req.user.role; // del token JWT
    const permissions = roles[userRole] || [];
    
    if (!permissions.includes(requiredPermission)) {
      return res.status(403).json({ 
        error: 'No tienes permisos para esta acción' 
      });
    }
    
    next();
  };
}

// Uso en rutas
app.delete('/api/posts/:id', 
  authenticate,  // primero autenticación
  authorize('delete'),  // luego autorización
  deletePost
);`}
                  </pre>
                </div>
              </div>

              <div className="bg-white/5 border border-white/10 rounded-xl p-6">
                <h4 className="text-xl font-semibold text-slate-900 dark:text-white mb-3">Attribute-Based Access Control (ABAC)</h4>
                <p className="text-slate-700 dark:text-slate-300 mb-4">
                  Los permisos se basan en atributos del usuario, recurso y contexto.
                </p>
                <div className="bg-slate-100 dark:bg-slate-800/50 rounded-lg p-4 font-mono text-sm">
                  <pre className="text-purple-400">
{`// Política ABAC
function canEditDocument(user, document, context) {
  return (
    // El usuario es el propietario
    document.ownerId === user.id ||
    // El usuario es admin
    user.role === 'admin' ||
    // El usuario está en el departamento y el doc no está bloqueado
    (user.department === document.department && 
     !document.locked &&
     context.time < document.deadline)
  );
}

// Uso
app.put('/api/documents/:id', authenticate, async (req, res) => {
  const document = await db.documents.findById(req.params.id);
  const context = { time: new Date(), ip: req.ip };
  
  if (!canEditDocument(req.user, document, context)) {
    return res.status(403).json({ error: 'Acceso denegado' });
  }
  
  // Proceder con la edición
});`}
                  </pre>
                </div>
              </div>
            </div>
          </section>

          {/* Vulnerabilidades Comunes */}
          <section className="mb-12">
            <h2 className="text-3xl font-bold text-slate-900 dark:text-white mb-6 flex items-center gap-3">
              <AlertTriangle className="w-8 h-8 text-red-600 dark:text-red-400" />
              Vulnerabilidades Comunes
            </h2>
            
            <div className="space-y-4">
              <div className="bg-red-500/10 border border-red-500/30 rounded-xl p-6">
                <h3 className="text-xl font-semibold text-red-600 dark:text-red-400 mb-3">Broken Authentication</h3>
                <ul className="text-slate-700 dark:text-slate-300 space-y-2 ml-6">
                  <li>• Contraseñas débiles o predeterminadas</li>
                  <li>• Tokens de sesión expuestos en URLs</li>
                  <li>• Falta de rate limiting en login</li>
                  <li>• Session fixation attacks</li>
                  <li>• Almacenamiento inseguro de credenciales</li>
                </ul>
              </div>

              <div className="bg-red-500/10 border border-red-500/30 rounded-xl p-6">
                <h3 className="text-xl font-semibold text-red-600 dark:text-red-400 mb-3">Broken Access Control</h3>
                <ul className="text-slate-700 dark:text-slate-300 space-y-2 ml-6">
                  <li>• <Link href={`/${locale}/wiki/vulnerabilidades/idor`} className="text-blue-600 dark:text-blue-400 hover:underline">IDOR (Insecure Direct Object References)</Link></li>
                  <li>• Falta de validación de permisos en APIs</li>
                  <li>• Privilege escalation (vertical/horizontal)</li>
                  <li>• Path traversal sin restricciones</li>
                  <li>• Missing function level access control</li>
                </ul>
              </div>
            </div>
          </section>

          {/* Mejores Prácticas */}
          <section className="mb-12">
            <h2 className="text-3xl font-bold text-slate-900 dark:text-white mb-6 flex items-center gap-3">
              <Shield className="w-8 h-8 text-green-600 dark:text-green-400" />
              Mejores Prácticas
            </h2>
            
            <div className="bg-green-500/10 border border-green-500/30 rounded-xl p-6 space-y-4">
              <h3 className="text-xl font-semibold text-green-700 dark:text-green-300 mb-3">Autenticación Segura</h3>
              <ul className="text-slate-700 dark:text-slate-300 space-y-2 ml-6">
                <li>✓ Implementar Multi-Factor Authentication (2FA/MFA)</li>
                <li>✓ Usar bcrypt/argon2 para hashear contraseñas</li>
                <li>✓ Implementar rate limiting y CAPTCHA</li>
                <li>✓ Usar HTTPS para todo el tráfico</li>
                <li>✓ Implementar account lockout tras intentos fallidos</li>
                <li>✓ Usar tokens seguros (JWT con firma HMAC/RSA)</li>
              </ul>

              <h3 className="text-xl font-semibold text-green-700 dark:text-green-300 mb-3 mt-6">Autorización Segura</h3>
              <ul className="text-slate-700 dark:text-slate-300 space-y-2 ml-6">
                <li>✓ Verificar permisos en CADA petición (server-side)</li>
                <li>✓ Usar principio de mínimo privilegio</li>
                <li>✓ Implementar separation of duties</li>
                <li>✓ Denegar por defecto (whitelist approach)</li>
                <li>✓ Registrar todos los eventos de autorización</li>
                <li>✓ Revisar y auditar permisos regularmente</li>
              </ul>
            </div>
          </section>

          {/* Ejemplo Completo */}
          <section className="mb-12">
            <h2 className="text-3xl font-bold text-slate-900 dark:text-white mb-6">Ejemplo: Sistema Completo</h2>
            <div className="bg-slate-100 dark:bg-slate-800/50 rounded-xl p-6 font-mono text-sm overflow-x-auto">
              <pre className="text-cyan-600 dark:text-cyan-400">
{`// middleware/auth.js
const jwt = require('jsonwebtoken');

// Middleware de autenticación
function authenticate(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  
  if (!token) {
    return res.status(401).json({ error: 'Token no proporcionado' });
  }
  
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch (error) {
    return res.status(401).json({ error: 'Token inválido' });
  }
}

// Middleware de autorización
function requireRole(...allowedRoles) {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({ error: 'No autenticado' });
    }
    
    if (!allowedRoles.includes(req.user.role)) {
      return res.status(403).json({ 
        error: 'No tienes permisos',
        required: allowedRoles,
        current: req.user.role
      });
    }
    
    next();
  };
}

// routes/posts.js
app.get('/api/posts', authenticate, getPosts);
app.post('/api/posts', authenticate, requireRole('editor', 'admin'), createPost);
app.delete('/api/posts/:id', authenticate, requireRole('admin'), deletePost);

// Resource-level authorization
app.put('/api/posts/:id', authenticate, async (req, res) => {
  const post = await db.posts.findById(req.params.id);
  
  // Solo el autor o admin puede editar
  if (post.authorId !== req.user.id && req.user.role !== 'admin') {
    return res.status(403).json({ error: 'No puedes editar este post' });
  }
  
  // Actualizar post
  await db.posts.update(req.params.id, req.body);
  res.json({ success: true });
});`}
              </pre>
            </div>
          </section>

          {/* Recursos */}
          <section className="mb-12">
            <h2 className="text-3xl font-bold text-slate-900 dark:text-white mb-6">Recursos Adicionales</h2>
            <div className="bg-white/5 border border-white/10 rounded-xl p-6 space-y-3">
              <a href="https://owasp.org/www-project-top-ten/" target="_blank" rel="noopener noreferrer" 
                 className="block text-blue-600 dark:text-blue-400 hover:text-blue-700 dark:text-blue-300 hover:underline">
                → OWASP Top 10 - Broken Access Control
              </a>
              <a href="https://jwt.io/introduction" target="_blank" rel="noopener noreferrer"
                 className="block text-blue-600 dark:text-blue-400 hover:text-blue-700 dark:text-blue-300 hover:underline">
                → JWT.io - Introduction to JSON Web Tokens
              </a>
              <a href="https://auth0.com/docs/authorization" target="_blank" rel="noopener noreferrer"
                 className="block text-blue-600 dark:text-blue-400 hover:text-blue-700 dark:text-blue-300 hover:underline">
                → Auth0 - Authorization Documentation
              </a>
            </div>
          </section>

          {/* Next Steps */}
          <div className="bg-gradient-to-r from-blue-600/20 to-purple-600/20 border border-blue-500/30 rounded-xl p-8 text-center">
            <h3 className="text-2xl font-bold text-slate-900 dark:text-white mb-4">Siguiente Paso</h3>
            <p className="text-slate-700 dark:text-slate-300 mb-6">
              Aprende sobre la implementación segura de sesiones y tokens
            </p>
            <Link
              href={`/${locale}/wiki/defensas/secure-sessions`}
              className="inline-flex items-center gap-2 px-6 py-3 bg-blue-600 hover:bg-blue-700 text-slate-900 dark:text-white rounded-xl font-semibold transition-all transform hover:scale-105"
            >
              Secure Session Management
              <span>→</span>
            </Link>
          </div>
        </div>
      </div>
    </div>
  );
}
