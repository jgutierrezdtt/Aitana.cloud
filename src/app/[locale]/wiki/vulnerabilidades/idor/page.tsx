'use client';

import Link from 'next/link';
import { useParams } from 'next/navigation';
import { Home, AlertTriangle, Key, Lock } from 'lucide-react';

export default function IDORPage() {
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
            Vulnerabilidades
          </Link>
          <span className="text-slate-600">/</span>
          <span className="text-white dark:text-white">IDOR</span>
        </div>
      </div>

      <div className="bg-gradient-to-r from-purple-600 via-pink-600 to-red-600 px-8 py-12">
        <div className="max-w-5xl mx-auto">
          <div className="flex items-center gap-3 mb-4">
            <div className="px-3 py-1 bg-green-500/20 text-green-700 dark:text-green-300 rounded-lg text-sm font-medium border border-green-500/30">
              Principiante
            </div>
            <div className="px-3 py-1 bg-yellow-500/30 text-yellow-200 rounded-lg text-sm font-medium border border-yellow-400/40">
              CVSS 5.3 - Medio
            </div>
            <div className="px-3 py-1 bg-white/10 backdrop-blur-sm text-slate-900 dark:text-white rounded-lg text-sm">
              15 min lectura
            </div>
          </div>
          <h1 className="text-4xl md:text-5xl font-bold text-slate-900 dark:text-white mb-4 flex items-center gap-4">
            <Key className="w-12 h-12" />
            Insecure Direct Object References (IDOR)
          </h1>
          <p className="text-xl text-pink-100">
            Acceso no autorizado a objetos modificando parámetros de referencia
          </p>
        </div>
      </div>

      <div className="max-w-5xl mx-auto px-8 py-12">
        <div className="prose prose-invert prose-lg max-w-none">
          
          <section className="mb-12">
            <h2 className="text-3xl font-bold text-slate-900 dark:text-white mb-6">¿Qué es IDOR?</h2>
            <p className="text-slate-700 dark:text-slate-300 mb-6">
              IDOR ocurre cuando una aplicación expone una referencia a un objeto interno (archivo, directorio, registro de base de datos) 
              y no verifica adecuadamente si el usuario tiene permiso para acceder a ese objeto.
            </p>
            
            <div className="bg-red-500/10 border border-red-500/30 rounded-xl p-6 mb-6">
              <h3 className="text-xl font-semibold text-red-600 dark:text-red-400 mb-3">Ejemplo Clásico</h3>
              <div className="bg-slate-100 dark:bg-slate-800/50 rounded-lg p-4 font-mono text-sm">
                <pre className="text-red-600 dark:text-red-400">
{`// Usuario autenticado como ID=123
GET /api/users/123/profile → ✅ Su propio perfil

// Cambiar ID en la URL
GET /api/users/124/profile → ❌ Debería rechazar
GET /api/users/125/profile → ❌ Perfil de otro usuario

// Código vulnerable
app.get('/api/users/:id/profile', authenticate, async (req, res) => {
  const user = await db.users.findById(req.params.id);
  res.json(user); // ¡Sin verificar si req.user.id === req.params.id!
});`}
                </pre>
              </div>
            </div>
          </section>

          <section className="mb-12">
            <h2 className="text-3xl font-bold text-slate-900 dark:text-white mb-6">Ejemplos Reales</h2>
            
            <div className="space-y-4">
              <div className="bg-white/5 border border-white/10 rounded-xl p-6">
                <h3 className="text-xl font-semibold text-slate-900 dark:text-white mb-3">1. Documentos/Archivos</h3>
                <div className="bg-slate-100 dark:bg-slate-800/50 rounded-lg p-4 font-mono text-sm">
                  <pre className="text-red-600 dark:text-red-400">
{`GET /api/documents/456/download
GET /invoices/invoice_123.pdf
GET /files?id=789

// Atacante prueba IDs secuenciales
for (let i = 1; i <= 1000; i++) {
  fetch(\`/api/documents/\${i}/download\`);
}`}
                  </pre>
                </div>
              </div>

              <div className="bg-white/5 border border-white/10 rounded-xl p-6">
                <h3 className="text-xl font-semibold text-slate-900 dark:text-white mb-3">2. Modificación de Datos</h3>
                <div className="bg-slate-100 dark:bg-slate-800/50 rounded-lg p-4 font-mono text-sm">
                  <pre className="text-red-600 dark:text-red-400">
{`PUT /api/orders/456
{
  "status": "shipped",
  "address": "attacker address"
}

DELETE /api/posts/789
POST /api/admin/users/123/promote`}
                  </pre>
                </div>
              </div>

              <div className="bg-white/5 border border-white/10 rounded-xl p-6">
                <h3 className="text-xl font-semibold text-slate-900 dark:text-white mb-3">3. APIs con UUIDs (menos obvios)</h3>
                <div className="bg-slate-100 dark:bg-slate-800/50 rounded-lg p-4 font-mono text-sm">
                  <pre className="text-red-600 dark:text-red-400">
{`// UUIDs son más seguros pero NO suficientes
GET /api/files/a1b2c3d4-e5f6-7890-abcd-ef1234567890

// Si se exponen en respuestas, pueden ser enumerados
GET /api/users/me/documents
{
  "documents": [
    {"id": "uuid-123", "name": "doc1.pdf"},
    {"id": "uuid-456", "name": "doc2.pdf"}
  ]
}

// Atacante puede intentar acceder a uuid-456 de otro usuario`}
                  </pre>
                </div>
              </div>
            </div>
          </section>

          <section className="mb-12">
            <h2 className="text-3xl font-bold text-slate-900 dark:text-white mb-6 flex items-center gap-3">
              <Lock className="w-8 h-8 text-green-600 dark:text-green-400" />
              Mitigación
            </h2>
            
            <div className="space-y-6">
              <div className="bg-green-500/10 border border-green-500/30 rounded-xl p-6">
                <h3 className="text-xl font-semibold text-slate-900 dark:text-white mb-4">1. Verificar Autorización</h3>
                <div className="bg-slate-100 dark:bg-slate-800/50 rounded-lg p-4 font-mono text-sm">
                  <pre className="text-green-600 dark:text-green-400">
{`// ✅ SEGURO
app.get('/api/users/:id/profile', authenticate, async (req, res) => {
  // Verificar que el usuario solo acceda a su propio perfil
  if (req.user.id !== parseInt(req.params.id) && req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Forbidden' });
  }
  
  const user = await db.users.findById(req.params.id);
  res.json(user);
});

// Para documentos
app.get('/api/documents/:id', authenticate, async (req, res) => {
  const doc = await db.documents.findById(req.params.id);
  
  if (!doc) {
    return res.status(404).json({ error: 'Not found' });
  }
  
  // Verificar ownership
  if (doc.userId !== req.user.id) {
    return res.status(403).json({ error: 'Forbidden' });
  }
  
  res.json(doc);
});`}
                  </pre>
                </div>
              </div>

              <div className="bg-green-500/10 border border-green-500/30 rounded-xl p-6">
                <h3 className="text-xl font-semibold text-slate-900 dark:text-white mb-4">2. Usar Referencias Indirectas</h3>
                <div className="bg-slate-100 dark:bg-slate-800/50 rounded-lg p-4 font-mono text-sm">
                  <pre className="text-green-600 dark:text-green-400">
{`// En lugar de exponer IDs directos, usar mapeo
// GET /api/documents/doc_abc123 (token de sesión)

const session = {
  userId: 123,
  documentMap: {
    'doc_abc123': 456, // ID real en DB
    'doc_xyz789': 457
  }
};

app.get('/api/documents/:token', (req, res) => {
  const realId = req.session.documentMap[req.params.token];
  if (!realId) {
    return res.status(404).json({ error: 'Not found' });
  }
  
  const doc = await db.documents.findById(realId);
  res.json(doc);
});`}
                  </pre>
                </div>
              </div>

              <div className="bg-green-500/10 border border-green-500/30 rounded-xl p-6">
                <h3 className="text-xl font-semibold text-slate-900 dark:text-white mb-4">3. Filtrar por Usuario en Queries</h3>
                <div className="bg-slate-100 dark:bg-slate-800/50 rounded-lg p-4 font-mono text-sm">
                  <pre className="text-green-600 dark:text-green-400">
{`// ✅ Siempre incluir userId en la query
app.get('/api/orders/:id', authenticate, async (req, res) => {
  const order = await db.orders.findOne({
    where: {
      id: req.params.id,
      userId: req.user.id  // ¡Filtrar por usuario!
    }
  });
  
  if (!order) {
    return res.status(404).json({ error: 'Order not found' });
  }
  
  res.json(order);
});

// Con Prisma
const order = await prisma.order.findFirst({
  where: {
    id: parseInt(req.params.id),
    userId: req.user.id
  }
});`}
                  </pre>
                </div>
              </div>

              <div className="bg-green-500/10 border border-green-500/30 rounded-xl p-6">
                <h3 className="text-xl font-semibold text-slate-900 dark:text-white mb-4">4. UUIDs + Autorización</h3>
                <div className="bg-slate-100 dark:bg-slate-800/50 rounded-lg p-4 font-mono text-sm">
                  <pre className="text-green-600 dark:text-green-400">
{`// UUIDs reducen enumeración pero NO son suficientes
import { v4 as uuidv4 } from 'uuid';

// Usar UUID como ID
const doc = await db.documents.create({
  id: uuidv4(), // "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
  userId: req.user.id,
  content: req.body.content
});

// ¡Aún así verificar autorización!
app.get('/api/documents/:uuid', authenticate, async (req, res) => {
  const doc = await db.documents.findOne({
    where: {
      id: req.params.uuid,
      userId: req.user.id  // ¡Verificar ownership!
    }
  });
  
  if (!doc) return res.status(404).json({ error: 'Not found' });
  res.json(doc);
});`}
                  </pre>
                </div>
              </div>
            </div>
          </section>

          <section className="mb-12">
            <h2 className="text-3xl font-bold text-slate-900 dark:text-white mb-6">Checklist de Seguridad</h2>
            <div className="bg-blue-500/10 border border-blue-500/30 rounded-xl p-6">
              <ul className="text-slate-700 dark:text-slate-300 space-y-3">
                <li>✓ Verificar autorización en CADA endpoint que accede a recursos</li>
                <li>✓ Nunca confiar en parámetros del cliente (IDs, UUIDs, etc)</li>
                <li>✓ Usar filtros WHERE con userId en todas las queries</li>
                <li>✓ Implementar RBAC (Role-Based Access Control) para recursos compartidos</li>
                <li>✓ Logging de intentos de acceso no autorizados</li>
                <li>✓ Usar UUIDs en lugar de IDs secuenciales (reduce enumeración)</li>
                <li>✓ Testing: Intentar acceder a recursos de otros usuarios en QA</li>
              </ul>
            </div>
          </section>

          <div className="bg-gradient-to-r from-purple-600/20 to-pink-600/20 border border-purple-500/30 rounded-xl p-8 text-center">
            <h3 className="text-2xl font-bold text-slate-900 dark:text-white mb-4">Siguiente Paso</h3>
            <p className="text-slate-700 dark:text-slate-300 mb-6">
              Aprende sobre vulnerabilidades en procesamiento de XML
            </p>
            <Link
              href={`/${locale}/wiki/vulnerabilidades/xxe`}
              className="inline-flex items-center gap-2 px-6 py-3 bg-purple-600 hover:bg-purple-700 text-slate-900 dark:text-white rounded-xl font-semibold transition-all transform hover:scale-105"
            >
              XML External Entity (XXE)
              <span>→</span>
            </Link>
          </div>
        </div>
      </div>
    </div>
  );
}
