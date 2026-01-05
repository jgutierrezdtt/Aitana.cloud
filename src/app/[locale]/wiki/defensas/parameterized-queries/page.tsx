'use client';

import Link from 'next/link';
import { useParams } from 'next/navigation';
import { Home, Shield, Database } from 'lucide-react';

export default function ParameterizedQueriesPage() {
  const params = useParams();
  const locale = params.locale as string;

  return (
    <div className="min-h-screen">
      <div className="bg-white dark:bg-slate-900/50 border-b border-slate-200 dark:border-slate-700 px-8 py-4">
        <div className="max-w-5xl mx-auto flex items-center gap-2 text-sm">
          <Link href={`/${locale}/wiki`} className="text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:text-white transition-colors flex items-center gap-1">
            <Home className="w-4 h-4" />Wiki</Link>
          <span className="text-slate-600">/</span>
          <Link href={`/${locale}/wiki`} className="text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:text-white transition-colors">Defensas</Link>
          <span className="text-slate-600">/</span>
          <span className="text-white dark:text-white">Parameterized Queries</span>
        </div>
      </div>

      <div className="bg-gradient-to-r from-green-600 via-teal-600 to-cyan-600 px-8 py-12">
        <div className="max-w-5xl mx-auto">
          <div className="flex items-center gap-3 mb-4">
            <div className="px-3 py-1 bg-green-500/20 text-green-700 dark:text-green-300 rounded-lg text-sm font-medium border border-green-500/30">Principiante</div>
            <div className="px-3 py-1 bg-white/10 backdrop-blur-sm text-slate-900 dark:text-white rounded-lg text-sm">16 min</div>
          </div>
          <h1 className="text-4xl md:text-5xl font-bold text-slate-900 dark:text-white mb-4 flex items-center gap-4">
            <Database className="w-12 h-12" />Parameterized Queries</h1>
          <p className="text-xl text-green-100">Prevención efectiva de SQL Injection mediante prepared statements</p>
        </div>
      </div>

      <div className="max-w-5xl mx-auto px-8 py-12">
        <div className="prose prose-invert prose-lg max-w-none">
          <section className="mb-12">
            <h2 className="text-3xl font-bold text-slate-900 dark:text-white mb-6">¿Qué son Parameterized Queries?</h2>
            <p className="text-slate-700 dark:text-slate-300 mb-6">
              Las consultas parametrizadas (o prepared statements) separan el código SQL de los datos, 
              impidiendo que input malicioso sea interpretado como comandos SQL.
            </p>
            
            <div className="bg-green-500/10 border border-green-500/30 rounded-xl p-6 mb-6">
              <h3 className="text-xl font-semibold text-slate-900 dark:text-white mb-3">Defensa #1 contra SQL Injection</h3>
              <p className="text-slate-700 dark:text-slate-300">
                Es la defensa MÁS efectiva contra SQL Injection. Los parámetros se tratan siempre como datos, 
                nunca como código ejecutable.
              </p>
            </div>
          </section>

          <section className="mb-12">
            <h2 className="text-3xl font-bold text-slate-900 dark:text-white mb-6">Comparación: Vulnerable vs Seguro</h2>
            
            <div className="grid md:grid-cols-2 gap-6 mb-6">
              <div className="bg-red-500/10 border border-red-500/30 rounded-xl p-6">
                <h3 className="text-lg font-semibold text-red-600 dark:text-red-400 mb-3">❌ String Concatenation (VULNERABLE)</h3>
                <div className="bg-slate-100 dark:bg-slate-800/50 rounded-lg p-4 font-mono text-sm">
                  <pre className="text-red-600 dark:text-red-400">
{`// Node.js
const query = \`
  SELECT * FROM users 
  WHERE username = '\${username}'
  AND password = '\${password}'
\`;
db.query(query);

// Input malicioso:
// username = "admin' --"
// Query final:
// SELECT * FROM users 
// WHERE username = 'admin' --'
// AND password = ''`}
                  </pre>
                </div>
              </div>

              <div className="bg-green-500/10 border border-green-500/30 rounded-xl p-6">
                <h3 className="text-lg font-semibold text-green-600 dark:text-green-400 mb-3">✅ Parameterized Query (SEGURO)</h3>
                <div className="bg-slate-100 dark:bg-slate-800/50 rounded-lg p-4 font-mono text-sm">
                  <pre className="text-green-600 dark:text-green-400">
{`// Node.js con mysql2
const query = \`
  SELECT * FROM users 
  WHERE username = ?
  AND password = ?
\`;
db.query(query, [username, password]);

// Los parámetros se escapan automáticamente
// El input malicioso se trata como literal:
// username = "admin' --"
// Se busca literalmente ese string`}
                  </pre>
                </div>
              </div>
            </div>
          </section>

          <section className="mb-12">
            <h2 className="text-3xl font-bold text-slate-900 dark:text-white mb-6">Implementación por Tecnología</h2>
            
            <div className="space-y-6">
              <div className="bg-white/5 border border-white/10 rounded-xl p-6">
                <h3 className="text-xl font-semibold text-slate-900 dark:text-white mb-4">Node.js - mysql2</h3>
                <div className="bg-slate-100 dark:bg-slate-800/50 rounded-lg p-4 font-mono text-sm">
                  <pre className="text-green-600 dark:text-green-400">
{`const mysql = require('mysql2/promise');

// Placeholders con ?
const [rows] = await db.query(
  'SELECT * FROM users WHERE email = ?',
  [email]
);

// Múltiples parámetros
const [result] = await db.query(
  'INSERT INTO posts (title, content, userId) VALUES (?, ?, ?)',
  [title, content, userId]
);

// Named placeholders
const [rows] = await db.query(
  'SELECT * FROM users WHERE email = :email AND status = :status',
  { email, status: 'active' }
);`}
                  </pre>
                </div>
              </div>

              <div className="bg-white/5 border border-white/10 rounded-xl p-6">
                <h3 className="text-xl font-semibold text-slate-900 dark:text-white mb-4">Prisma ORM (Recomendado)</h3>
                <div className="bg-slate-100 dark:bg-slate-800/50 rounded-lg p-4 font-mono text-sm">
                  <pre className="text-green-600 dark:text-green-400">
{`// Prisma usa prepared statements automáticamente
const user = await prisma.user.findUnique({
  where: { email: userEmail }
});

const post = await prisma.post.create({
  data: {
    title: userTitle,
    content: userContent,
    authorId: userId
  }
});

// Query raw (cuando sea necesario)
const users = await prisma.$queryRaw\`
  SELECT * FROM users 
  WHERE email = \${email}
  AND status = \${status}
\`;  // ✅ Usa prepared statements internamente`}
                  </pre>
                </div>
              </div>

              <div className="bg-white/5 border border-white/10 rounded-xl p-6">
                <h3 className="text-xl font-semibold text-slate-900 dark:text-white mb-4">PostgreSQL - node-postgres</h3>
                <div className="bg-slate-100 dark:bg-slate-800/50 rounded-lg p-4 font-mono text-sm">
                  <pre className="text-green-600 dark:text-green-400">
{`const { Pool } = require('pg');
const pool = new Pool();

// Placeholders con $1, $2, etc
const result = await pool.query(
  'SELECT * FROM users WHERE email = $1 AND active = $2',
  [email, true]
);

// Prepared statements nombrados
const preparedQuery = {
  name: 'fetch-user',
  text: 'SELECT * FROM users WHERE id = $1',
  values: [userId]
};
const result = await pool.query(preparedQuery);`}
                  </pre>
                </div>
              </div>

              <div className="bg-white/5 border border-white/10 rounded-xl p-6">
                <h3 className="text-xl font-semibold text-slate-900 dark:text-white mb-4">Python - psycopg2</h3>
                <div className="bg-slate-100 dark:bg-slate-800/50 rounded-lg p-4 font-mono text-sm">
                  <pre className="text-green-600 dark:text-green-400">
{`import psycopg2

conn = psycopg2.connect(database="mydb")
cur = conn.cursor()

# Placeholders con %s
cur.execute(
    "SELECT * FROM users WHERE email = %s AND active = %s",
    (email, True)
)

# Diccionario
cur.execute(
    "SELECT * FROM users WHERE email = %(email)s",
    {'email': email}
)`}
                  </pre>
                </div>
              </div>

              <div className="bg-white/5 border border-white/10 rounded-xl p-6">
                <h3 className="text-xl font-semibold text-slate-900 dark:text-white mb-4">PHP - PDO</h3>
                <div className="bg-slate-100 dark:bg-slate-800/50 rounded-lg p-4 font-mono text-sm">
                  <pre className="text-green-600 dark:text-green-400">
{`<?php
$pdo = new PDO('mysql:host=localhost;dbname=test', 'user', 'pass');

// Named placeholders
$stmt = $pdo->prepare('SELECT * FROM users WHERE email = :email');
$stmt->execute(['email' => $email]);

// Positional placeholders
$stmt = $pdo->prepare('SELECT * FROM users WHERE email = ? AND status = ?');
$stmt->execute([$email, 'active']);
?>`}
                  </pre>
                </div>
              </div>
            </div>
          </section>

          <section className="mb-12">
            <h2 className="text-3xl font-bold text-slate-900 dark:text-white mb-6">Casos Especiales</h2>
            
            <div className="bg-yellow-500/10 border border-yellow-500/30 rounded-xl p-6 mb-6">
              <h3 className="text-xl font-semibold text-yellow-400 mb-3">⚠️ Identificadores NO pueden ser parametrizados</h3>
              <p className="text-slate-700 dark:text-slate-300 mb-4">
                Nombres de tablas, columnas, ORDER BY, etc. NO pueden usar placeholders.
                Deben validarse con whitelist.
              </p>
              <div className="bg-slate-100 dark:bg-slate-800/50 rounded-lg p-4 font-mono text-sm">
                <pre className="text-orange-400">
{`// ❌ NO FUNCIONA
const query = 'SELECT * FROM ?? ORDER BY ??';
db.query(query, [tableName, columnName]);  // Placeholders no válidos aquí

// ✅ SOLUCIÓN: Whitelist
const allowedTables = ['users', 'posts', 'comments'];
const allowedColumns = ['id', 'created_at', 'title'];

if (!allowedTables.includes(tableName) || 
    !allowedColumns.includes(sortColumn)) {
  throw new Error('Invalid table or column');
}

// Ahora es seguro (después de validar)
const query = \`SELECT * FROM \${tableName} ORDER BY \${sortColumn}\`;`}
                </pre>
              </div>
            </div>

            <div className="bg-yellow-500/10 border border-yellow-500/30 rounded-xl p-6">
              <h3 className="text-xl font-semibold text-yellow-400 mb-3">⚠️ IN clauses</h3>
              <div className="bg-slate-100 dark:bg-slate-800/50 rounded-lg p-4 font-mono text-sm">
                <pre className="text-green-600 dark:text-green-400">
{`// ✅ Generar placeholders dinámicamente
const ids = [1, 2, 3, 4, 5];
const placeholders = ids.map(() => '?').join(',');
const query = \`SELECT * FROM users WHERE id IN (\${placeholders})\`;
const [rows] = await db.query(query, ids);

// Con Prisma (más simple)
const users = await prisma.user.findMany({
  where: {
    id: { in: ids }
  }
});`}
                </pre>
              </div>
            </div>
          </section>

          <section className="mb-12">
            <h2 className="text-3xl font-bold text-slate-900 dark:text-white mb-6">Mejores Prácticas</h2>
            <div className="bg-blue-500/10 border border-blue-500/30 rounded-xl p-6">
              <ul className="text-slate-700 dark:text-slate-300 space-y-3">
                <li>✓ <strong className="text-white dark:text-white">SIEMPRE usar prepared statements</strong> - No hay excusa válida para concatenación</li>
                <li>✓ <strong className="text-white dark:text-white">Preferir ORMs modernos</strong> - Prisma, TypeORM, Sequelize usan prepared statements por defecto</li>
                <li>✓ <strong className="text-white dark:text-white">Validar identificadores con whitelist</strong> - Tablas, columnas, ORDER BY</li>
                <li>✓ <strong className="text-white dark:text-white">Principle of Least Privilege</strong> - Usuario DB con permisos mínimos</li>
                <li>✓ <strong className="text-white dark:text-white">Code review</strong> - Detectar concatenación de SQL en reviews</li>
                <li>✓ <strong className="text-white dark:text-white">Usar herramientas de análisis estático</strong> - ESLint, SonarQube detectan SQL injection</li>
              </ul>
            </div>
          </section>

          <div className="bg-gradient-to-r from-green-600/20 to-cyan-600/20 border border-green-500/30 rounded-xl p-8 text-center">
            <h3 className="text-2xl font-bold text-slate-900 dark:text-white mb-4">Siguiente</h3>
            <Link href={`/${locale}/wiki/defensas/csp`}
              className="inline-flex items-center gap-2 px-6 py-3 bg-green-600 hover:bg-green-700 text-slate-900 dark:text-white rounded-xl font-semibold transition-all">
              Content Security Policy (CSP)<span>→</span></Link>
          </div>
        </div>
      </div>
    </div>
  );
}
