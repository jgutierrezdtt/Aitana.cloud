'use client';

import Link from 'next/link';
import { useParams } from 'next/navigation';
import { ArrowLeft, Database, AlertTriangle, Code, Shield, Terminal } from 'lucide-react';
import Navigation from '@/components/Navigation';

export default function SqlInjectionPage() {
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
      <div className="bg-gradient-to-r from-red-600 to-orange-600 py-12">
        <div className="max-w-4xl mx-auto px-6">
          <div className="inline-flex items-center gap-2 bg-white/10 backdrop-blur-sm px-3 py-1 rounded-lg mb-4">
            <AlertTriangle className="w-4 h-4 text-white" />
            <span className="text-white text-sm font-medium">Vulnerabilidades</span>
          </div>
          <h1 className="text-4xl md:text-5xl font-bold text-white mb-4">
            SQL Injection (SQLi)
          </h1>
          <div className="flex items-center gap-4 text-red-100">
            <span className="bg-red-500/20 text-red-200 px-3 py-1 rounded-lg text-sm font-medium">
              Principiante
            </span>
            <span className="bg-red-900/40 px-3 py-1 rounded-lg text-sm font-bold">
              ⚠️ CRÍTICO - CVSS 9.8
            </span>
            <span className="text-sm">⏱️ 20 minutos</span>
          </div>
        </div>
      </div>

      {/* Article Content */}
      <div className="max-w-4xl mx-auto px-6 py-12">
        <div className="bg-white/5 backdrop-blur-sm border border-white/10 rounded-2xl p-8 md:p-12 space-y-8">
          
          {/* Introducción */}
          <section>
            <h2 className="text-3xl font-bold text-white mb-4">¿Qué es SQL Injection?</h2>
            <p className="text-slate-300 text-lg leading-relaxed mb-4">
              <strong className="text-white">SQL Injection</strong> es una vulnerabilidad que permite a un atacante 
              ejecutar código SQL arbitrario en la base de datos de una aplicación web.
            </p>
            <p className="text-slate-300 text-lg leading-relaxed">
              Ocurre cuando la aplicación concatena directamente input del usuario en una consulta SQL 
              sin validación ni sanitización adecuada, permitiendo que el atacante "inyecte" código malicioso.
            </p>
          </section>

          {/* Impacto */}
          <section>
            <div className="bg-red-500/10 border border-red-400/30 rounded-xl p-6">
              <h3 className="text-2xl font-bold text-red-300 mb-4 flex items-center gap-2">
                <AlertTriangle className="w-6 h-6" />
                Impacto de un Ataque SQLi
              </h3>
              <div className="grid md:grid-cols-2 gap-4">
                <ul className="space-y-2 text-slate-300">
                  <li className="flex items-start gap-2">
                    <span className="text-red-400 font-bold">🔓</span>
                    <span><strong className="text-white">Extracción de datos:</strong> Robo de usuarios, contraseñas, tarjetas de crédito</span>
                  </li>
                  <li className="flex items-start gap-2">
                    <span className="text-red-400 font-bold">🔥</span>
                    <span><strong className="text-white">Modificación:</strong> Alterar o eliminar registros de la BD</span>
                  </li>
                  <li className="flex items-start gap-2">
                    <span className="text-red-400 font-bold">👤</span>
                    <span><strong className="text-white">Bypass de autenticación:</strong> Login sin credenciales</span>
                  </li>
                </ul>
                <ul className="space-y-2 text-slate-300">
                  <li className="flex items-start gap-2">
                    <span className="text-red-400 font-bold">💀</span>
                    <span><strong className="text-white">Escalada de privilegios:</strong> Convertirse en administrador</span>
                  </li>
                  <li className="flex items-start gap-2">
                    <span className="text-red-400 font-bold">💻</span>
                    <span><strong className="text-white">Ejecución de comandos:</strong> En algunos casos, control total del servidor</span>
                  </li>
                  <li className="flex items-start gap-2">
                    <span className="text-red-400 font-bold">📋</span>
                    <span><strong className="text-white">Enumeración del sistema:</strong> Descubrir estructura de BD</span>
                  </li>
                </ul>
              </div>
            </div>
          </section>

          {/* Código Vulnerable */}
          <section>
            <h2 className="text-3xl font-bold text-white mb-6">Ejemplo de Código Vulnerable</h2>
            
            <div className="space-y-4">
              <div className="bg-red-500/5 border border-red-400/30 rounded-xl p-6">
                <div className="flex items-center gap-2 mb-3">
                  <AlertTriangle className="w-5 h-5 text-red-400" />
                  <h3 className="text-lg font-bold text-red-300">❌ CÓDIGO VULNERABLE</h3>
                </div>
                
                <pre className="bg-slate-900 rounded-lg p-4 overflow-x-auto text-sm">
<code className="text-red-400">{`// ❌ Concatenación directa de input del usuario
const email = req.body.email;
const password = req.body.password;

const query = \`
  SELECT * FROM users 
  WHERE email = '\${email}' 
  AND password = '\${password}'
\`;

const result = await db.query(query);`}</code>
                </pre>

                <div className="mt-4 bg-red-900/20 rounded-lg p-4">
                  <p className="text-red-300 font-semibold mb-2">⚠️ Problema:</p>
                  <p className="text-slate-300 text-sm">
                    El input del usuario se concatena directamente en el SQL. Un atacante puede inyectar 
                    código SQL modificando los valores de <code className="text-yellow-400">email</code> o <code className="text-yellow-400">password</code>.
                  </p>
                </div>
              </div>
            </div>
          </section>

          {/* Explotación */}
          <section>
            <h2 className="text-3xl font-bold text-white mb-6">Cómo se Explota</h2>
            
            <div className="space-y-6">
              <div className="bg-slate-800/50 rounded-xl p-6">
                <h3 className="text-xl font-bold text-orange-300 mb-4">1. Bypass de Autenticación</h3>
                
                <div className="space-y-3">
                  <div>
                    <p className="text-slate-300 mb-2">Atacante envía:</p>
                    <div className="bg-slate-900 rounded-lg p-4">
                      <code className="text-cyan-400 text-sm">
                        Email: <span className="text-red-400">admin' OR '1'='1' --</span><br />
                        Password: <span className="text-slate-500">cualquier cosa</span>
                      </code>
                    </div>
                  </div>

                  <div>
                    <p className="text-slate-300 mb-2">La consulta SQL resultante:</p>
                    <div className="bg-slate-900 rounded-lg p-4">
                      <pre className="text-green-400 text-sm overflow-x-auto">{`SELECT * FROM users 
WHERE email = 'admin' OR '1'='1' --' 
AND password = 'cualquier cosa'`}</pre>
                    </div>
                  </div>

                  <div className="bg-red-900/20 border border-red-500/30 rounded-lg p-4">
                    <p className="text-red-300 font-semibold mb-2">🚨 Resultado:</p>
                    <ul className="text-sm text-slate-300 space-y-1">
                      <li>• <code className="text-white">OR '1'='1'</code> siempre es verdadero</li>
                      <li>• <code className="text-white">--</code> comenta el resto (incluido el password)</li>
                      <li>• ✅ Login exitoso sin saber la contraseña</li>
                    </ul>
                  </div>
                </div>
              </div>

              <div className="bg-slate-800/50 rounded-xl p-6">
                <h3 className="text-xl font-bold text-orange-300 mb-4">2. Extracción de Datos con UNION</h3>
                
                <div className="space-y-3">
                  <div>
                    <p className="text-slate-300 mb-2">Búsqueda vulnerable:</p>
                    <div className="bg-slate-900 rounded-lg p-4">
                      <code className="text-cyan-400 text-sm">
                        Búsqueda: <span className="text-red-400">' UNION SELECT username, password FROM users --</span>
                      </code>
                    </div>
                  </div>

                  <div>
                    <p className="text-slate-300 mb-2">Query resultante:</p>
                    <div className="bg-slate-900 rounded-lg p-4">
                      <pre className="text-green-400 text-sm overflow-x-auto">{`SELECT title, content FROM notes 
WHERE title LIKE '%' 
UNION SELECT username, password FROM users -- %'`}</pre>
                    </div>
                  </div>

                  <div className="bg-red-900/20 border border-red-500/30 rounded-lg p-4">
                    <p className="text-red-300 font-semibold mb-2">🚨 Resultado:</p>
                    <p className="text-sm text-slate-300">
                      La query devuelve todas las notas Y todos los usuarios con sus contraseñas.
                    </p>
                  </div>
                </div>
              </div>

              <div className="bg-slate-800/50 rounded-xl p-6">
                <h3 className="text-xl font-bold text-orange-300 mb-4">3. Blind SQLi (Inferencia Booleana)</h3>
                
                <div className="space-y-3">
                  <p className="text-slate-300">
                    Cuando la aplicación no muestra errores SQL, se puede usar <strong className="text-white">blind SQLi</strong> 
                    para extraer datos carácter por carácter.
                  </p>

                  <div className="bg-slate-900 rounded-lg p-4">
                    <pre className="text-cyan-400 text-sm overflow-x-auto">{`' AND (SELECT SUBSTRING(password,1,1) FROM users WHERE id=1) = 'a' --`}</pre>
                  </div>

                  <p className="text-sm text-slate-400">
                    Si la página se comporta diferente (error, carga lenta, contenido diferente), 
                    el atacante sabe si el primer carácter de la contraseña es 'a'.
                  </p>
                </div>
              </div>
            </div>
          </section>

          {/* Tipos de SQLi */}
          <section>
            <h2 className="text-3xl font-bold text-white mb-6">Tipos de SQL Injection</h2>
            
            <div className="grid md:grid-cols-2 gap-4">
              <div className="bg-white/5 border border-white/10 rounded-xl p-5">
                <h4 className="text-lg font-bold text-blue-300 mb-2">In-Band SQLi</h4>
                <p className="text-slate-300 text-sm mb-3">
                  El atacante ve la respuesta de la BD en la misma petición.
                </p>
                <ul className="text-sm text-slate-400 space-y-1">
                  <li>• Error-based: Errores SQL revelan info</li>
                  <li>• UNION-based: Combina queries</li>
                </ul>
              </div>

              <div className="bg-white/5 border border-white/10 rounded-xl p-5">
                <h4 className="text-lg font-bold text-purple-300 mb-2">Blind SQLi</h4>
                <p className="text-slate-300 text-sm mb-3">
                  No hay output directo, se infiere por el comportamiento.
                </p>
                <ul className="text-sm text-slate-400 space-y-1">
                  <li>• Boolean-based: Verdadero/Falso</li>
                  <li>• Time-based: SLEEP() delays</li>
                </ul>
              </div>

              <div className="bg-white/5 border border-white/10 rounded-xl p-5">
                <h4 className="text-lg font-bold text-orange-300 mb-2">Out-of-Band SQLi</h4>
                <p className="text-slate-300 text-sm mb-3">
                  Datos se exfiltran por otro canal (DNS, HTTP).
                </p>
                <ul className="text-sm text-slate-400 space-y-1">
                  <li>• DNS exfiltration</li>
                  <li>• HTTP callbacks</li>
                </ul>
              </div>

              <div className="bg-white/5 border border-white/10 rounded-xl p-5">
                <h4 className="text-lg font-bold text-red-300 mb-2">Second-Order SQLi</h4>
                <p className="text-slate-300 text-sm mb-3">
                  El payload se almacena y ejecuta después.
                </p>
                <ul className="text-sm text-slate-400 space-y-1">
                  <li>• Input guardado en BD</li>
                  <li>• Ejecutado en otra función</li>
                </ul>
              </div>
            </div>
          </section>

          {/* Defensa */}
          <section>
            <div className="bg-green-500/10 border border-green-400/30 rounded-xl p-6">
              <div className="flex items-start gap-3">
                <Shield className="w-6 h-6 text-green-400 flex-shrink-0 mt-1" />
                <div className="space-y-4 flex-1">
                  <h3 className="text-2xl font-bold text-green-300">Cómo Prevenir SQL Injection</h3>
                  
                  <div className="space-y-6">
                    <div>
                      <h4 className="text-lg font-bold text-white mb-3">✅ 1. Consultas Parametrizadas (Prepared Statements)</h4>
                      <p className="text-slate-300 text-sm mb-3">
                        La solución más efectiva. Los parámetros se escapan automáticamente.
                      </p>
                      
                      <div className="bg-slate-900 rounded-lg p-4">
                        <pre className="text-green-400 text-sm overflow-x-auto">{`// ✅ SEGURO - Prepared statement
const query = 'SELECT * FROM users WHERE email = ? AND password = ?';
const result = await db.query(query, [email, password]);

// ✅ SEGURO - Parameterized query (Node.js)
const query = {
  text: 'SELECT * FROM users WHERE email = $1 AND password = $2',
  values: [email, password]
};
const result = await db.query(query);`}</pre>
                      </div>
                    </div>

                    <div>
                      <h4 className="text-lg font-bold text-white mb-3">✅ 2. ORM/Query Builders</h4>
                      <p className="text-slate-300 text-sm mb-3">
                        Herramientas como Prisma, TypeORM, Sequelize escapan automáticamente.
                      </p>
                      
                      <div className="bg-slate-900 rounded-lg p-4">
                        <pre className="text-cyan-400 text-sm overflow-x-auto">{`// ✅ SEGURO - Prisma ORM
const user = await prisma.user.findFirst({
  where: {
    email: email,
    password: password
  }
});`}</pre>
                      </div>
                    </div>

                    <div>
                      <h4 className="text-lg font-bold text-white mb-3">✅ 3. Validación de Input</h4>
                      <ul className="text-sm text-slate-300 space-y-2">
                        <li className="flex items-start gap-2">
                          <span className="text-green-400">•</span>
                          <span>Whitelist de caracteres permitidos</span>
                        </li>
                        <li className="flex items-start gap-2">
                          <span className="text-green-400">•</span>
                          <span>Validar tipos de datos (números, emails, etc.)</span>
                        </li>
                        <li className="flex items-start gap-2">
                          <span className="text-green-400">•</span>
                          <span>Limitar longitud de inputs</span>
                        </li>
                      </ul>
                    </div>

                    <div>
                      <h4 className="text-lg font-bold text-white mb-3">✅ 4. Principio de Menor Privilegio</h4>
                      <p className="text-slate-300 text-sm">
                        El usuario de BD de la aplicación no debe ser admin. Solo permisos necesarios (SELECT, INSERT, UPDATE).
                      </p>
                    </div>

                    <div>
                      <h4 className="text-lg font-bold text-white mb-3">✅ 5. WAF y Monitorización</h4>
                      <ul className="text-sm text-slate-300 space-y-2">
                        <li className="flex items-start gap-2">
                          <span className="text-green-400">•</span>
                          <span>Web Application Firewall (WAF) para detectar patrones SQLi</span>
                        </li>
                        <li className="flex items-start gap-2">
                          <span className="text-green-400">•</span>
                          <span>Logs de queries sospechosas</span>
                        </li>
                        <li className="flex items-start gap-2">
                          <span className="text-green-400">•</span>
                          <span>Rate limiting en endpoints de búsqueda/login</span>
                        </li>
                      </ul>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </section>

          {/* Práctica */}
          <section>
            <div className="bg-blue-500/10 border border-blue-400/30 rounded-xl p-6">
              <div className="flex items-start gap-3">
                <Terminal className="w-6 h-6 text-blue-400 flex-shrink-0 mt-1" />
                <div>
                  <h3 className="text-xl font-bold text-blue-300 mb-3">Practica SQL Injection</h3>
                  <p className="text-slate-300 mb-4">
                    Pon a prueba lo aprendido en nuestro laboratorio vulnerable de SQLi:
                  </p>
                  <Link
                    href={`/${locale}/lab/sqli`}
                    className="inline-flex items-center gap-2 px-6 py-3 bg-gradient-to-r from-blue-600 to-cyan-600 text-white rounded-xl font-semibold hover:scale-105 transition-transform"
                  >
                    <Database className="w-5 h-5" />
                    <span>Ir al Lab de SQLi</span>
                  </Link>
                </div>
              </div>
            </div>
          </section>

          {/* Recursos */}
          <section className="border-t border-white/10 pt-8">
            <h2 className="text-2xl font-bold text-white mb-4">Recursos Adicionales</h2>
            <div className="grid md:grid-cols-2 gap-4">
              <a 
                href="https://owasp.org/www-community/attacks/SQL_Injection" 
                target="_blank" 
                rel="noopener noreferrer"
                className="bg-white/5 border border-white/10 rounded-xl p-4 hover:bg-white/10 transition-colors"
              >
                <h4 className="text-white font-semibold mb-1">OWASP SQLi Guide</h4>
                <p className="text-slate-400 text-sm">Documentación oficial de OWASP</p>
              </a>
              <a 
                href="https://portswigger.net/web-security/sql-injection" 
                target="_blank" 
                rel="noopener noreferrer"
                className="bg-white/5 border border-white/10 rounded-xl p-4 hover:bg-white/10 transition-colors"
              >
                <h4 className="text-white font-semibold mb-1">PortSwigger Academy</h4>
                <p className="text-slate-400 text-sm">Labs interactivos de SQLi</p>
              </a>
            </div>
          </section>
        </div>
      </div>
      </div>
    </>
  );
}
