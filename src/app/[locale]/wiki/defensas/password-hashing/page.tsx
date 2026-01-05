'use client';

import Link from 'next/link';
import { useParams } from 'next/navigation';
import { Home, Shield, Key } from 'lucide-react';

export default function PasswordHashingPage() {
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
          <span className="text-white dark:text-white">Password Hashing</span>
        </div>
      </div>

      <div className="bg-gradient-to-r from-green-600 via-emerald-600 to-teal-600 px-8 py-12">
        <div className="max-w-5xl mx-auto">
          <div className="flex items-center gap-3 mb-4">
            <div className="px-3 py-1 bg-green-500/20 text-green-700 dark:text-green-300 rounded-lg text-sm font-medium border border-green-500/30">Principiante</div>
            <div className="px-3 py-1 bg-white/10 backdrop-blur-sm text-slate-900 dark:text-white rounded-lg text-sm">20 min</div>
          </div>
          <h1 className="text-4xl md:text-5xl font-bold text-slate-900 dark:text-white mb-4 flex items-center gap-4">
            <Key className="w-12 h-12" />Password Hashing</h1>
          <p className="text-xl text-green-100">Almacenamiento seguro de contraseñas usando bcrypt y Argon2</p>
        </div>
      </div>

      <div className="max-w-5xl mx-auto px-8 py-12">
        <div className="prose prose-invert prose-lg max-w-none">
          <section className="mb-12">
            <h2 className="text-3xl font-bold text-slate-900 dark:text-white mb-6">¿Por qué Hashing?</h2>
            <p className="text-slate-700 dark:text-slate-300 mb-6">
              Las contraseñas NUNCA deben almacenarse en texto plano. Un hash es una función unidireccional que 
              convierte la contraseña en un string irreversible.
            </p>
            
            <div className="bg-red-500/10 border border-red-500/30 rounded-xl p-6 mb-6">
              <h3 className="text-xl font-semibold text-slate-900 dark:text-white mb-3">❌ Vulnerable: Texto Plano</h3>
              <div className="bg-slate-100 dark:bg-slate-800/50 rounded-lg p-4 font-mono text-sm">
                <pre className="text-red-600 dark:text-red-400">
{`// NUNCA hagas esto
const user = {
  email: 'alice@example.com',
  password: 'MyPassword123'  // ¡Visible en DB!
};

// Si la DB se compromete, todas las passwords se exponen
db.users.insert(user);`}
                </pre>
              </div>
            </div>

            <div className="bg-green-500/10 border border-green-500/30 rounded-xl p-6">
              <h3 className="text-xl font-semibold text-slate-900 dark:text-white mb-3">✅ Seguro: Bcrypt con Salt</h3>
              <div className="bg-slate-100 dark:bg-slate-800/50 rounded-lg p-4 font-mono text-sm">
                <pre className="text-green-600 dark:text-green-400">
{`const bcrypt = require('bcrypt');

// Hash password con salt automático
const saltRounds = 12;
const hashedPassword = await bcrypt.hash('MyPassword123', saltRounds);

// Guardar en DB (hash es unidireccional)
const user = {
  email: 'alice@example.com',
  password: hashedPassword  // $2b$12$LmVf...
};

// Verificar password en login
const match = await bcrypt.compare(inputPassword, user.password);
if (match) {
  // Login exitoso
}`}
                </pre>
              </div>
            </div>
          </section>

          <section className="mb-12">
            <h2 className="text-3xl font-bold text-slate-900 dark:text-white mb-6">Bcrypt vs Argon2</h2>
            
            <div className="grid md:grid-cols-2 gap-6 mb-6">
              <div className="bg-white/5 border border-white/10 rounded-xl p-6">
                <h3 className="text-xl font-semibold text-slate-900 dark:text-white mb-3">Bcrypt</h3>
                <ul className="text-slate-700 dark:text-slate-300 space-y-2 mb-4">
                  <li>• Probado y maduro (desde 1999)</li>
                  <li>• Resistente a GPU/ASIC attacks</li>
                  <li>• Work factor ajustable (saltRounds)</li>
                  <li>• Incluye salt automático</li>
                </ul>
                <div className="bg-slate-100 dark:bg-slate-800/50 rounded-lg p-4 font-mono text-sm">
                  <pre className="text-blue-600 dark:text-blue-400">
{`const bcrypt = require('bcrypt');

// Registro
const hash = await bcrypt.hash(
  password, 
  12  // cost factor
);

// Login
const match = await bcrypt.compare(
  inputPassword, 
  hash
);`}
                  </pre>
                </div>
              </div>

              <div className="bg-white/5 border border-white/10 rounded-xl p-6">
                <h3 className="text-xl font-semibold text-slate-900 dark:text-white mb-3">Argon2</h3>
                <ul className="text-slate-700 dark:text-slate-300 space-y-2 mb-4">
                  <li>• Ganador Password Hashing Competition (2015)</li>
                  <li>• Resistente a ataques de memoria</li>
                  <li>• Memoria + tiempo configurables</li>
                  <li>• Más seguro que bcrypt</li>
                </ul>
                <div className="bg-slate-100 dark:bg-slate-800/50 rounded-lg p-4 font-mono text-sm">
                  <pre className="text-purple-400">
{`const argon2 = require('argon2');

// Registro
const hash = await argon2.hash(
  password, 
  {
    type: argon2.argon2id,
    memoryCost: 65536,  // 64 MB
    timeCost: 3,
    parallelism: 4
  }
);

// Login
const match = await argon2.verify(
  hash, 
  inputPassword
);`}
                  </pre>
                </div>
              </div>
            </div>
          </section>

          <section className="mb-12">
            <h2 className="text-3xl font-bold text-slate-900 dark:text-white mb-6">Salt: Defensa contra Rainbow Tables</h2>
            <p className="text-slate-700 dark:text-slate-300 mb-4">
              Un <strong>salt</strong> es un string aleatorio único que se añade a cada password antes de hashear. 
              Previene ataques con rainbow tables precalculadas.
            </p>

            <div className="bg-white/5 border border-white/10 rounded-xl p-6">
              <h3 className="text-xl font-semibold text-slate-900 dark:text-white mb-4">Sin Salt (Vulnerable)</h3>
              <div className="bg-slate-100 dark:bg-slate-800/50 rounded-lg p-4 font-mono text-sm mb-4">
                <pre className="text-red-600 dark:text-red-400">
{`const hash1 = sha256('password123');
const hash2 = sha256('password123');

// Mismo hash = mismo password
hash1 === hash2  // true

// Atacante puede usar rainbow table:
// "password123" -> "ef92b778bafe7..."
`}
                </pre>
              </div>

              <h3 className="text-xl font-semibold text-slate-900 dark:text-white mb-4">Con Salt (Seguro)</h3>
              <div className="bg-slate-100 dark:bg-slate-800/50 rounded-lg p-4 font-mono text-sm">
                <pre className="text-green-600 dark:text-green-400">
{`const salt1 = crypto.randomBytes(16);
const hash1 = sha256('password123' + salt1);

const salt2 = crypto.randomBytes(16);
const hash2 = sha256('password123' + salt2);

// Hashes diferentes por salt único
hash1 !== hash2  // true

// Rainbow tables inútiles, cada hash es único
`}
                </pre>
              </div>
            </div>
          </section>

          <section className="mb-12">
            <h2 className="text-3xl font-bold text-slate-900 dark:text-white mb-6">Ejemplo Completo: Registro y Login</h2>
            <div className="bg-white/5 border border-white/10 rounded-xl p-6">
              <div className="bg-slate-100 dark:bg-slate-800/50 rounded-lg p-4 font-mono text-sm">
                <pre className="text-cyan-600 dark:text-cyan-400">
{`const bcrypt = require('bcrypt');
const SALT_ROUNDS = 12;

// Registro
async function registerUser(email, password) {
  // 1. Validar password (longitud, complejidad)
  if (password.length < 8) {
    throw new Error('Password muy corta');
  }

  // 2. Hash password
  const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS);

  // 3. Guardar en DB
  const user = await db.users.create({
    email,
    password: hashedPassword
  });

  return user;
}

// Login
async function loginUser(email, password) {
  // 1. Buscar usuario
  const user = await db.users.findOne({ email });
  if (!user) {
    throw new Error('Usuario no encontrado');
  }

  // 2. Comparar passwords
  const match = await bcrypt.compare(password, user.password);
  if (!match) {
    throw new Error('Password incorrecta');
  }

  // 3. Generar JWT
  const token = jwt.sign({ userId: user.id }, SECRET_KEY);
  return { token, user };
}`}
                </pre>
              </div>
            </div>
          </section>

          <section className="mb-12">
            <h2 className="text-3xl font-bold text-slate-900 dark:text-white mb-6">Mejores Prácticas</h2>
            <div className="grid md:grid-cols-2 gap-6">
              <div className="bg-green-500/10 border border-green-500/30 rounded-xl p-6">
                <h3 className="text-lg font-semibold text-slate-900 dark:text-white mb-3">✅ Hacer</h3>
                <ul className="text-slate-700 dark:text-slate-300 space-y-2">
                  <li>• Usar bcrypt o Argon2</li>
                  <li>• Salt automático incluido</li>
                  <li>• Work factor &gt;= 12 (bcrypt)</li>
                  <li>• Rehash si work factor aumenta</li>
                  <li>• Validar complejidad de password</li>
                </ul>
              </div>

              <div className="bg-red-500/10 border border-red-500/30 rounded-xl p-6">
                <h3 className="text-lg font-semibold text-slate-900 dark:text-white mb-3">❌ NO Hacer</h3>
                <ul className="text-slate-700 dark:text-slate-300 space-y-2">
                  <li>• NUNCA almacenar passwords en texto plano</li>
                  <li>• NO usar MD5 o SHA1 (rápidos = inseguros)</li>
                  <li>• NO implementar tu propio algoritmo</li>
                  <li>• NO usar salt global (uno por password)</li>
                  <li>• NO enviar passwords por email</li>
                </ul>
              </div>
            </div>
          </section>

          <div className="bg-gradient-to-r from-green-600/20 to-teal-600/20 border border-green-500/30 rounded-xl p-8 text-center">
            <h3 className="text-2xl font-bold text-slate-900 dark:text-white mb-4">Siguiente</h3>
            <Link href={`/${locale}/wiki/defensas/secure-sessions`}
              className="inline-flex items-center gap-2 px-6 py-3 bg-green-600 hover:bg-green-700 text-slate-900 dark:text-white rounded-xl font-semibold transition-all">
              Secure Session Management<span>→</span></Link>
          </div>
        </div>
      </div>
    </div>
  );
}
