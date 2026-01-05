'use client';

import Link from 'next/link';
import { useParams } from 'next/navigation';
import { Home, BookOpen, Server, Monitor, Database, Code } from 'lucide-react';

export default function ArquitecturaClienteServidorPage() {
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
          <span className="text-white dark:text-white">Arquitectura Cliente-Servidor</span>
        </div>
      </div>

      <div className="bg-gradient-to-r from-blue-600 via-purple-600 to-indigo-600 px-8 py-12">
        <div className="max-w-5xl mx-auto">
          <div className="flex items-center gap-3 mb-4">
            <div className="px-3 py-1 bg-green-500/20 text-green-700 dark:text-green-300 rounded-lg text-sm font-medium border border-green-500/30">
              Principiante
            </div>
            <div className="px-3 py-1 bg-white/10 backdrop-blur-sm text-slate-900 dark:text-white rounded-lg text-sm">
              15 min lectura
            </div>
          </div>
          <h1 className="text-4xl md:text-5xl font-bold text-slate-900 dark:text-white mb-4 flex items-center gap-4">
            <Server className="w-12 h-12" />
            Arquitectura Cliente-Servidor
          </h1>
          <p className="text-xl text-blue-100">
            Fundamentos de la comunicación web y cómo interactúan navegadores con servidores
          </p>
        </div>
      </div>

      <div className="max-w-5xl mx-auto px-8 py-12">
        <div className="prose prose-invert prose-lg max-w-none">
          
          <section className="mb-12">
            <h2 className="text-3xl font-bold text-slate-900 dark:text-white mb-6">Modelo Cliente-Servidor</h2>
            <p className="text-slate-700 dark:text-slate-300 mb-6">
              La arquitectura cliente-servidor es un modelo de diseño de software donde las tareas se reparten entre
              proveedores de recursos o servicios (servidores) y demandantes de servicios (clientes).
            </p>
            
            <div className="bg-white/5 border border-white/10 rounded-xl p-8 mb-6">
              <div className="grid md:grid-cols-2 gap-8">
                <div className="space-y-4">
                  <div className="flex items-center gap-3 text-cyan-600 dark:text-cyan-400 font-semibold text-xl">
                    <Monitor className="w-8 h-8" />
                    Cliente
                  </div>
                  <ul className="text-slate-700 dark:text-slate-300 space-y-2">
                    <li>• Navegador web (Chrome, Firefox, Safari)</li>
                    <li>• Aplicación móvil</li>
                    <li>• Aplicación de escritorio</li>
                    <li>• CLI tools</li>
                  </ul>
                  <div className="bg-cyan-500/10 border border-cyan-500/30 rounded-lg p-4">
                    <p className="text-sm text-cyan-100">
                      <strong>Función:</strong> Solicita recursos, muestra información, interactúa con el usuario
                    </p>
                  </div>
                </div>
                <div className="space-y-4">
                  <div className="flex items-center gap-3 text-purple-400 font-semibold text-xl">
                    <Server className="w-8 h-8" />
                    Servidor
                  </div>
                  <ul className="text-slate-700 dark:text-slate-300 space-y-2">
                    <li>• Servidor web (Node.js, Apache, Nginx)</li>
                    <li>• Servidor de aplicaciones</li>
                    <li>• Servidor de base de datos</li>
                    <li>• Servidor de archivos</li>
                  </ul>
                  <div className="bg-purple-500/10 border border-purple-500/30 rounded-lg p-4">
                    <p className="text-sm text-purple-100">
                      <strong>Función:</strong> Procesa peticiones, ejecuta lógica de negocio, almacena datos
                    </p>
                  </div>
                </div>
              </div>
            </div>

            <h3 className="text-2xl font-semibold text-blue-600 dark:text-blue-400 mb-4">Flujo de Comunicación</h3>
            <div className="bg-slate-100 dark:bg-slate-800/50 rounded-xl p-6 mb-6">
              <pre className="text-green-600 dark:text-green-400 text-sm font-mono">
{`┌─────────────┐                          ┌─────────────┐
│   CLIENTE   │                          │  SERVIDOR   │
│  (Browser)  │                          │  (Node.js)  │
└──────┬──────┘                          └──────┬──────┘
       │                                        │
       │  1. HTTP Request                       │
       │  GET /api/users                        │
       ├───────────────────────────────────────>│
       │                                        │
       │                           2. Procesar  │
       │                              petición  │
       │                           3. Consultar │
       │                              DB        │
       │                                        │
       │  4. HTTP Response                      │
       │  200 OK + JSON                         │
       │<───────────────────────────────────────┤
       │                                        │
       │  5. Renderizar datos                   │
       │                                        │`}
              </pre>
            </div>
          </section>

          <section className="mb-12">
            <h2 className="text-3xl font-bold text-slate-900 dark:text-white mb-6">Arquitectura de 3 Capas</h2>
            <div className="space-y-4">
              <div className="bg-blue-500/10 border border-blue-500/30 rounded-xl p-6">
                <div className="flex items-center gap-3 mb-3">
                  <Monitor className="w-6 h-6 text-blue-600 dark:text-blue-400" />
                  <h3 className="text-xl font-semibold text-white dark:text-white">1. Capa de Presentación (Frontend)</h3>
                </div>
                <p className="text-slate-700 dark:text-slate-300 mb-3">Interfaz de usuario que muestra datos y captura inputs.</p>
                <div className="bg-slate-100 dark:bg-slate-800/50 rounded-lg p-4 font-mono text-sm">
                  <pre className="text-blue-600 dark:text-blue-400">
{`// React Component
function UserList() {
  const [users, setUsers] = useState([]);
  
  useEffect(() => {
    fetch('/api/users')
      .then(res => res.json())
      .then(data => setUsers(data));
  }, []);
  
  return (
    <div>
      {users.map(user => (
        <div key={user.id}>{user.name}</div>
      ))}
    </div>
  );
}`}
                  </pre>
                </div>
              </div>

              <div className="bg-purple-500/10 border border-purple-500/30 rounded-xl p-6">
                <div className="flex items-center gap-3 mb-3">
                  <Code className="w-6 h-6 text-purple-400" />
                  <h3 className="text-xl font-semibold text-white dark:text-white">2. Capa de Lógica de Negocio (Backend)</h3>
                </div>
                <p className="text-slate-700 dark:text-slate-300 mb-3">Procesa peticiones, aplica reglas de negocio y validaciones.</p>
                <div className="bg-slate-100 dark:bg-slate-800/50 rounded-lg p-4 font-mono text-sm">
                  <pre className="text-purple-400">
{`// Express API Route
app.get('/api/users', authenticate, async (req, res) => {
  // Validar permisos
  if (!req.user.canViewUsers) {
    return res.status(403).json({ error: 'Forbidden' });
  }
  
  // Lógica de negocio
  const users = await userService.getActiveUsers();
  
  // Transformar datos
  const sanitized = users.map(u => ({
    id: u.id,
    name: u.name,
    email: u.email
    // NO incluir password, tokens, etc
  }));
  
  res.json(sanitized);
});`}
                  </pre>
                </div>
              </div>

              <div className="bg-green-500/10 border border-green-500/30 rounded-xl p-6">
                <div className="flex items-center gap-3 mb-3">
                  <Database className="w-6 h-6 text-green-600 dark:text-green-400" />
                  <h3 className="text-xl font-semibold text-white dark:text-white">3. Capa de Datos (Database)</h3>
                </div>
                <p className="text-slate-700 dark:text-slate-300 mb-3">Almacena y recupera datos de forma persistente.</p>
                <div className="bg-slate-100 dark:bg-slate-800/50 rounded-lg p-4 font-mono text-sm">
                  <pre className="text-green-600 dark:text-green-400">
{`// User Service (con Prisma ORM)
class UserService {
  async getActiveUsers() {
    return await prisma.user.findMany({
      where: { 
        isActive: true,
        deletedAt: null
      },
      orderBy: { createdAt: 'desc' },
      take: 100
    });
  }
  
  async createUser(data) {
    // Validaciones
    if (!data.email || !data.password) {
      throw new Error('Email y password requeridos');
    }
    
    // Hash password
    const passwordHash = await bcrypt.hash(data.password, 10);
    
    return await prisma.user.create({
      data: {
        ...data,
        passwordHash,
        isActive: true
      }
    });
  }
}`}
                  </pre>
                </div>
              </div>
            </div>
          </section>

          <section className="mb-12">
            <h2 className="text-3xl font-bold text-slate-900 dark:text-white mb-6">Implicaciones de Seguridad</h2>
            <div className="space-y-4">
              <div className="bg-red-500/10 border border-red-500/30 rounded-xl p-6">
                <h3 className="text-xl font-semibold text-red-600 dark:text-red-400 mb-3">⚠️ Nunca confíes en el cliente</h3>
                <p className="text-slate-700 dark:text-slate-300 mb-3">
                  El cliente puede ser modificado, inspeccionado y manipulado. TODA validación y seguridad debe implementarse en el servidor.
                </p>
                <div className="bg-slate-100 dark:bg-slate-800/50 rounded-lg p-4 font-mono text-sm">
                  <pre className="text-red-600 dark:text-red-400">
{`// ❌ MAL: Validación solo en cliente
// Frontend
if (user.role === 'admin') {
  showDeleteButton(); // El usuario puede modificar esto en DevTools
}

// ✅ BIEN: Validación en servidor
// Backend
app.delete('/api/users/:id', authenticate, (req, res) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Forbidden' });
  }
  // Proceder con eliminación
});`}
                  </pre>
                </div>
              </div>

              <div className="bg-yellow-500/10 border border-yellow-500/30 rounded-xl p-6">
                <h3 className="text-xl font-semibold text-yellow-400 mb-3">🔒 Principio de separación</h3>
                <ul className="text-slate-700 dark:text-slate-300 space-y-2">
                  <li>• Frontend solo debe manejar UI/UX</li>
                  <li>• Backend maneja autenticación, autorización y lógica crítica</li>
                  <li>• Base de datos solo accesible desde backend (nunca directamente desde cliente)</li>
                  <li>• Secrets y API keys NUNCA en código frontend</li>
                </ul>
              </div>
            </div>
          </section>

          <div className="bg-gradient-to-r from-blue-600/20 to-purple-600/20 border border-blue-500/30 rounded-xl p-8 text-center">
            <h3 className="text-2xl font-bold text-slate-900 dark:text-white mb-4">Siguiente Paso</h3>
            <p className="text-slate-700 dark:text-slate-300 mb-6">
              Aprende sobre HTTP, el protocolo que hace posible esta comunicación
            </p>
            <Link
              href={`/${locale}/wiki/fundamentos/http-basico`}
              className="inline-flex items-center gap-2 px-6 py-3 bg-blue-600 hover:bg-blue-700 text-slate-900 dark:text-white rounded-xl font-semibold transition-all transform hover:scale-105"
            >
              HTTP: El Protocolo de la Web
              <span>→</span>
            </Link>
          </div>
        </div>
      </div>
    </div>
  );
}
