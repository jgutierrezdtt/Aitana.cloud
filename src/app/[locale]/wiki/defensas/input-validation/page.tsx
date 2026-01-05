'use client';

import Link from 'next/link';
import { useParams } from 'next/navigation';
import { ArrowLeft, Shield, Code, CheckCircle, AlertTriangle, Lock } from 'lucide-react';
import Navigation from '@/components/Navigation';

export default function InputValidationPage() {
  const params = useParams();
  const locale = params.locale as string;

  return (
    <>
      <Navigation />
      <div className="min-h-screen bg-gradient-to-br from-slate-50 via-white to-slate-100 dark:from-slate-950 dark:via-slate-900 dark:to-slate-950">
      {/* Breadcrumb */}
      <div className="bg-slate-100 dark:bg-slate-800 backdrop-blur-sm border-b border-slate-200 dark:border-slate-700">
        <div className="max-w-4xl mx-auto px-6 py-4">
          <Link 
            href={`/${locale}/wiki`}
            className="inline-flex items-center gap-2 text-blue-600 dark:text-blue-400 hover:text-blue-700 dark:text-blue-300 transition-colors"
          >
            <ArrowLeft className="w-4 h-4" />
            <span>Volver a la Wiki</span>
          </Link>
        </div>
      </div>

      {/* Article Header */}
      <div className="bg-gradient-to-r from-green-600 to-emerald-600 py-12">
        <div className="max-w-4xl mx-auto px-6">
          <div className="inline-flex items-center gap-2 bg-white/10 backdrop-blur-sm px-3 py-1 rounded-lg mb-4">
            <Shield className="w-4 h-4 text-white dark:text-white" />
            <span className="text-slate-900 dark:text-white text-sm font-medium">Defensas</span>
          </div>
          <h1 className="text-4xl md:text-5xl font-bold text-slate-900 dark:text-white mb-4">
            Validación de Entrada
          </h1>
          <div className="flex items-center gap-4 text-green-100">
            <span className="bg-green-500/20 text-green-200 px-3 py-1 rounded-lg text-sm font-medium">
              Principiante
            </span>
            <span className="text-sm">⏱️ 15 minutos</span>
          </div>
        </div>
      </div>

      {/* Article Content */}
      <div className="max-w-4xl mx-auto px-6 py-12">
        <div className="bg-white dark:bg-slate-900 backdrop-blur-sm border border-slate-200 dark:border-slate-700 rounded-2xl p-8 md:p-12 space-y-8">
          
          {/* Introducción */}
          <section>
            <h2 className="text-3xl font-bold text-slate-900 dark:text-white mb-4">¿Qué es la Validación de Entrada?</h2>
            <p className="text-slate-700 dark:text-slate-300 text-lg leading-relaxed mb-4">
              La <strong className="text-white dark:text-white">validación de entrada</strong> es el proceso de verificar que 
              los datos proporcionados por el usuario cumplen con criterios específicos antes de ser procesados 
              por la aplicación.
            </p>
            <p className="text-slate-700 dark:text-slate-300 text-lg leading-relaxed">
              Es la <strong className="text-green-600 dark:text-green-400">primera línea de defensa</strong> contra la mayoría de 
              las vulnerabilidades web, incluyendo SQLi, XSS, Command Injection, y muchas otras.
            </p>
          </section>

          {/* Principio */}
          <section>
            <div className="bg-blue-500/10 border border-blue-500 dark:border-blue-400/30 rounded-xl p-6">
              <h3 className="text-2xl font-bold text-blue-700 dark:text-blue-300 mb-4">Principio Fundamental</h3>
              <div className="bg-white dark:bg-slate-900 rounded-lg p-6 border-l-4 border-blue-500 dark:border-blue-400">
                <p className="text-xl text-slate-900 dark:text-white font-semibold mb-2">
                  "Never Trust User Input"
                </p>
                <p className="text-slate-700 dark:text-slate-300">
                  Nunca confíes en los datos que provienen del usuario. Cualquier input puede ser malicioso, 
                  incluso de fuentes aparentemente "confiables" como cookies, headers, o URLs.
                </p>
              </div>
            </div>
          </section>

          {/* Tipos de Validación */}
          <section>
            <h2 className="text-3xl font-bold text-slate-900 dark:text-white mb-6">Tipos de Validación</h2>
            
            <div className="space-y-6">
              <div className="bg-white/5 border border-white/10 rounded-xl p-6">
                <div className="flex items-start gap-3 mb-4">
                  <div className="w-10 h-10 rounded-xl bg-green-500 flex items-center justify-center flex-shrink-0">
                    <CheckCircle className="w-6 h-6 text-white dark:text-white" />
                  </div>
                  <div className="flex-1">
                    <h3 className="text-xl font-bold text-green-700 dark:text-green-300 mb-2">1. Whitelist (Lista Blanca) - RECOMENDADO ✅</h3>
                    <p className="text-slate-700 dark:text-slate-300 mb-3">
                      Solo permite valores específicos o patrones conocidos como válidos. <strong className="text-white dark:text-white">Más seguro</strong> 
                      porque asumes que todo es malicioso hasta que se demuestre lo contrario.
                    </p>
                    
                    <div className="bg-white dark:bg-slate-900 rounded-lg p-4">
                      <p className="text-sm text-slate-600 dark:text-slate-400 mb-2">Ejemplo: Validar tipo de archivo</p>
                      <pre className="text-green-600 dark:text-green-400 text-sm overflow-x-auto">{`// ✅ Whitelist - Solo permite extensiones específicas
const allowedExtensions = ['.jpg', '.png', '.gif', '.webp'];
const fileExtension = path.extname(filename).toLowerCase();

if (!allowedExtensions.includes(fileExtension)) {
  throw new Error('Tipo de archivo no permitido');
}`}</pre>
                    </div>
                  </div>
                </div>
              </div>

              <div className="bg-white/5 border border-white/10 rounded-xl p-6">
                <div className="flex items-start gap-3 mb-4">
                  <div className="w-10 h-10 rounded-xl bg-yellow-500 flex items-center justify-center flex-shrink-0">
                    <AlertTriangle className="w-6 h-6 text-white dark:text-white" />
                  </div>
                  <div className="flex-1">
                    <h3 className="text-xl font-bold text-yellow-700 dark:text-yellow-300 mb-2">2. Blacklist (Lista Negra) - EVITAR ⚠️</h3>
                    <p className="text-slate-700 dark:text-slate-300 mb-3">
                      Bloquea valores específicos o patrones conocidos como maliciosos. <strong className="text-white dark:text-white">Menos seguro</strong> 
                      porque es imposible anticipar todos los posibles ataques.
                    </p>
                    
                    <div className="bg-white dark:bg-slate-900 rounded-lg p-4">
                      <p className="text-sm text-slate-600 dark:text-slate-400 mb-2">Ejemplo: Bloquear palabras SQL (INSEGURO)</p>
                      <pre className="text-red-600 dark:text-red-400 text-sm overflow-x-auto">{`// ❌ Blacklist - Fácilmente bypasseable
const blockedWords = ['SELECT', 'DROP', 'UNION'];
let input = req.body.search;

blockedWords.forEach(word => {
  input = input.replace(word, '');
});

// Bypass: "SELSELECTECT" → "SELECT"`}</pre>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </section>

          {/* Categorías de Validación */}
          <section>
            <h2 className="text-3xl font-bold text-slate-900 dark:text-white mb-6">Categorías de Validación</h2>
            
            <div className="grid md:grid-cols-2 gap-6">
              <div className="bg-blue-500/10 border border-blue-500 dark:border-blue-400/30 rounded-xl p-5">
                <h4 className="text-lg font-bold text-blue-700 dark:text-blue-300 mb-3">📝 Tipo de Dato</h4>
                <p className="text-slate-700 dark:text-slate-300 text-sm mb-3">Verifica que el dato sea del tipo esperado</p>
                <div className="bg-white dark:bg-slate-900 rounded-lg p-3">
                  <pre className="text-cyan-600 dark:text-cyan-400 text-xs overflow-x-auto">{`const age = parseInt(req.body.age);
if (isNaN(age) || age < 0 || age > 150) {
  throw new Error('Edad inválida');
}`}</pre>
                </div>
              </div>

              <div className="bg-purple-500/10 border border-purple-400/30 rounded-xl p-5">
                <h4 className="text-lg font-bold text-purple-700 dark:text-purple-300 mb-3">📏 Longitud</h4>
                <p className="text-slate-700 dark:text-slate-300 text-sm mb-3">Limita el tamaño del input</p>
                <div className="bg-white dark:bg-slate-900 rounded-lg p-3">
                  <pre className="text-cyan-600 dark:text-cyan-400 text-xs overflow-x-auto">{`const username = req.body.username;
if (username.length < 3 || 
    username.length > 20) {
  throw new Error('Username: 3-20 caracteres');
}`}</pre>
                </div>
              </div>

              <div className="bg-green-500/10 border border-green-400/30 rounded-xl p-5">
                <h4 className="text-lg font-bold text-green-700 dark:text-green-300 mb-3">🔤 Formato</h4>
                <p className="text-slate-700 dark:text-slate-300 text-sm mb-3">Valida patrones con RegEx</p>
                <div className="bg-white dark:bg-slate-900 rounded-lg p-3">
                  <pre className="text-cyan-600 dark:text-cyan-400 text-xs overflow-x-auto">{`const emailRegex = /^[^@]+@[^@]+\\.[^@]+$/;
if (!emailRegex.test(email)) {
  throw new Error('Email inválido');
}`}</pre>
                </div>
              </div>

              <div className="bg-orange-500/10 border border-orange-400/30 rounded-xl p-5">
                <h4 className="text-lg font-bold text-orange-700 dark:text-orange-300 mb-3">🎯 Rango</h4>
                <p className="text-slate-700 dark:text-slate-300 text-sm mb-3">Valores dentro de límites</p>
                <div className="bg-white dark:bg-slate-900 rounded-lg p-3">
                  <pre className="text-cyan-600 dark:text-cyan-400 text-xs overflow-x-auto">{`const score = req.body.score;
if (score < 0 || score > 100) {
  throw new Error('Score: 0-100');
}`}</pre>
                </div>
              </div>
            </div>
          </section>

          {/* Validación en Diferentes Capas */}
          <section>
            <h2 className="text-3xl font-bold text-slate-900 dark:text-white mb-6">Defensa en Profundidad</h2>
            
            <div className="bg-slate-100 dark:bg-slate-800/50 rounded-xl p-6 space-y-4">
              <p className="text-slate-700 dark:text-slate-300">
                La validación debe ocurrir en <strong className="text-white dark:text-white">múltiples capas</strong>:
              </p>

              <div className="space-y-3">
                <div className="flex items-start gap-3">
                  <div className="w-8 h-8 rounded-full bg-blue-500 text-slate-900 dark:text-white flex items-center justify-center flex-shrink-0 text-sm font-bold">
                    1
                  </div>
                  <div>
                    <h4 className="text-slate-900 dark:text-white font-semibold">Cliente (Frontend)</h4>
                    <p className="text-slate-700 dark:text-slate-300 text-sm">
                      Validación en JavaScript para <strong className="text-yellow-400">mejorar UX</strong>, 
                      NO para seguridad (fácilmente bypasseable).
                    </p>
                  </div>
                </div>

                <div className="flex items-start gap-3">
                  <div className="w-8 h-8 rounded-full bg-green-500 text-slate-900 dark:text-white flex items-center justify-center flex-shrink-0 text-sm font-bold">
                    2
                  </div>
                  <div>
                    <h4 className="text-slate-900 dark:text-white font-semibold">Servidor (Backend) ⭐</h4>
                    <p className="text-slate-700 dark:text-slate-300 text-sm">
                      <strong className="text-green-600 dark:text-green-400">Validación obligatoria</strong>. 
                      Nunca confíes en validaciones del cliente.
                    </p>
                  </div>
                </div>

                <div className="flex items-start gap-3">
                  <div className="w-8 h-8 rounded-full bg-purple-500 text-slate-900 dark:text-white flex items-center justify-center flex-shrink-0 text-sm font-bold">
                    3
                  </div>
                  <div>
                    <h4 className="text-slate-900 dark:text-white font-semibold">Base de Datos</h4>
                    <p className="text-slate-700 dark:text-slate-300 text-sm">
                      Constraints en BD (NOT NULL, CHECK, UNIQUE) como última línea de defensa.
                    </p>
                  </div>
                </div>
              </div>

              <div className="bg-red-500/10 border border-red-400/30 rounded-lg p-4 mt-4">
                <div className="flex items-start gap-2">
                  <AlertTriangle className="w-5 h-5 text-red-600 dark:text-red-400 flex-shrink-0 mt-0.5" />
                  <p className="text-red-700 dark:text-red-300 text-sm">
                    <strong>⚠️ Importante:</strong> La validación del cliente es solo para UX. 
                    Un atacante puede enviar peticiones HTTP directamente sin pasar por tu frontend.
                  </p>
                </div>
              </div>
            </div>
          </section>

          {/* Ejemplos Prácticos */}
          <section>
            <h2 className="text-3xl font-bold text-slate-900 dark:text-white mb-6">Ejemplos Prácticos</h2>
            
            <div className="space-y-6">
              {/* Email */}
              <div className="bg-white/5 border border-white/10 rounded-xl p-6">
                <h3 className="text-xl font-bold text-blue-700 dark:text-blue-300 mb-4">Validar Email</h3>
                <div className="space-y-4">
                  <div className="bg-white dark:bg-slate-900 rounded-lg p-4">
                    <p className="text-sm text-slate-600 dark:text-slate-400 mb-2">JavaScript (Cliente)</p>
                    <pre className="text-cyan-600 dark:text-cyan-400 text-sm overflow-x-auto">{`function validateEmail(email) {
  const regex = /^[^\\s@]+@[^\\s@]+\\.[^\\s@]+$/;
  return regex.test(email);
}`}</pre>
                  </div>

                  <div className="bg-white dark:bg-slate-900 rounded-lg p-4">
                    <p className="text-sm text-slate-600 dark:text-slate-400 mb-2">Node.js (Servidor) - Con librería</p>
                    <pre className="text-green-600 dark:text-green-400 text-sm overflow-x-auto">{`import validator from 'validator';

if (!validator.isEmail(email)) {
  throw new Error('Email inválido');
}`}</pre>
                  </div>
                </div>
              </div>

              {/* Password */}
              <div className="bg-white/5 border border-white/10 rounded-xl p-6">
                <h3 className="text-xl font-bold text-purple-700 dark:text-purple-300 mb-4">Validar Contraseña Fuerte</h3>
                <div className="bg-white dark:bg-slate-900 rounded-lg p-4">
                  <pre className="text-cyan-600 dark:text-cyan-400 text-sm overflow-x-auto">{`function validatePassword(password) {
  const minLength = 8;
  const hasUppercase = /[A-Z]/.test(password);
  const hasLowercase = /[a-z]/.test(password);
  const hasNumber = /[0-9]/.test(password);
  const hasSpecial = /[!@#$%^&*]/.test(password);
  
  return password.length >= minLength &&
         hasUppercase &&
         hasLowercase &&
         hasNumber &&
         hasSpecial;
}`}</pre>
                </div>
              </div>

              {/* Alfanumérico */}
              <div className="bg-white/5 border border-white/10 rounded-xl p-6">
                <h3 className="text-xl font-bold text-green-700 dark:text-green-300 mb-4">Solo Alfanuméricos</h3>
                <div className="bg-white dark:bg-slate-900 rounded-lg p-4">
                  <pre className="text-cyan-600 dark:text-cyan-400 text-sm overflow-x-auto">{`function isAlphanumeric(str) {
  return /^[a-zA-Z0-9]+$/.test(str);
}

// Uso
const username = req.body.username;
if (!isAlphanumeric(username)) {
  throw new Error('Solo letras y números permitidos');
}`}</pre>
                </div>
              </div>
            </div>
          </section>

          {/* Librerías Recomendadas */}
          <section>
            <h2 className="text-3xl font-bold text-slate-900 dark:text-white mb-6">Librerías Recomendadas</h2>
            
            <div className="grid md:grid-cols-2 gap-4">
              <div className="bg-blue-500/10 border border-blue-500 dark:border-blue-400/30 rounded-xl p-5">
                <h4 className="text-lg font-bold text-blue-700 dark:text-blue-300 mb-2">Zod (TypeScript)</h4>
                <p className="text-slate-700 dark:text-slate-300 text-sm mb-3">Schema validation con inferencia de tipos</p>
                <div className="bg-white dark:bg-slate-900 rounded-lg p-3">
                  <pre className="text-cyan-600 dark:text-cyan-400 text-xs overflow-x-auto">{`import { z } from 'zod';

const schema = z.object({
  email: z.string().email(),
  age: z.number().min(18).max(120)
});

const data = schema.parse(req.body);`}</pre>
                </div>
              </div>

              <div className="bg-purple-500/10 border border-purple-400/30 rounded-xl p-5">
                <h4 className="text-lg font-bold text-purple-700 dark:text-purple-300 mb-2">Joi</h4>
                <p className="text-slate-700 dark:text-slate-300 text-sm mb-3">Schema validation para JavaScript/Node.js</p>
                <div className="bg-white dark:bg-slate-900 rounded-lg p-3">
                  <pre className="text-cyan-600 dark:text-cyan-400 text-xs overflow-x-auto">{`const Joi = require('joi');

const schema = Joi.object({
  username: Joi.string().alphanum().min(3).max(20),
  password: Joi.string().pattern(/^[a-zA-Z0-9]{8,30}$/)
});

const { error } = schema.validate(req.body);`}</pre>
                </div>
              </div>

              <div className="bg-green-500/10 border border-green-400/30 rounded-xl p-5">
                <h4 className="text-lg font-bold text-green-700 dark:text-green-300 mb-2">validator.js</h4>
                <p className="text-slate-700 dark:text-slate-300 text-sm mb-3">Funciones de validación individuales</p>
                <div className="bg-white dark:bg-slate-900 rounded-lg p-3">
                  <pre className="text-cyan-600 dark:text-cyan-400 text-xs overflow-x-auto">{`import validator from 'validator';

validator.isEmail('foo@bar.com');
validator.isURL('https://aitana.cloud');
validator.isInt('123');
validator.isCreditCard('4242424242424242');`}</pre>
                </div>
              </div>

              <div className="bg-orange-500/10 border border-orange-400/30 rounded-xl p-5">
                <h4 className="text-lg font-bold text-orange-700 dark:text-orange-300 mb-2">express-validator</h4>
                <p className="text-slate-700 dark:text-slate-300 text-sm mb-3">Middleware de validación para Express.js</p>
                <div className="bg-white dark:bg-slate-900 rounded-lg p-3">
                  <pre className="text-cyan-600 dark:text-cyan-400 text-xs overflow-x-auto">{`const { body, validationResult } = require('express-validator');

app.post('/user', 
  body('email').isEmail(),
  body('password').isLength({ min: 8 }),
  (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors });
    }
  }
);`}</pre>
                </div>
              </div>
            </div>
          </section>

          {/* Mejores Prácticas */}
          <section>
            <div className="bg-green-500/10 border border-green-400/30 rounded-xl p-6">
              <h3 className="text-2xl font-bold text-green-700 dark:text-green-300 mb-4 flex items-center gap-2">
                <CheckCircle className="w-6 h-6" />
                Mejores Prácticas
              </h3>
              
              <ul className="space-y-3 text-slate-700 dark:text-slate-300">
                <li className="flex items-start gap-2">
                  <span className="text-green-600 dark:text-green-400 font-bold">✅</span>
                  <span><strong className="text-white dark:text-white">Valida en el servidor SIEMPRE</strong> - Nunca confíes solo en validación del cliente</span>
                </li>
                <li className="flex items-start gap-2">
                  <span className="text-green-600 dark:text-green-400 font-bold">✅</span>
                  <span><strong className="text-white dark:text-white">Usa whitelist</strong> - Permite solo lo que conoces como seguro</span>
                </li>
                <li className="flex items-start gap-2">
                  <span className="text-green-600 dark:text-green-400 font-bold">✅</span>
                  <span><strong className="text-white dark:text-white">Normaliza primero</strong> - Trim, lowercase, remove Unicode antes de validar</span>
                </li>
                <li className="flex items-start gap-2">
                  <span className="text-green-600 dark:text-green-400 font-bold">✅</span>
                  <span><strong className="text-white dark:text-white">Mensajes de error genéricos</strong> - No reveles estructura de BD o lógica interna</span>
                </li>
                <li className="flex items-start gap-2">
                  <span className="text-green-600 dark:text-green-400 font-bold">✅</span>
                  <span><strong className="text-white dark:text-white">Valida TODO</strong> - Headers, cookies, query params, body, files</span>
                </li>
                <li className="flex items-start gap-2">
                  <span className="text-green-600 dark:text-green-400 font-bold">✅</span>
                  <span><strong className="text-white dark:text-white">Usa librerías probadas</strong> - No reinventes la rueda</span>
                </li>
                <li className="flex items-start gap-2">
                  <span className="text-green-600 dark:text-green-400 font-bold">✅</span>
                  <span><strong className="text-white dark:text-white">Combina con sanitización</strong> - Validar + sanitizar = mejor defensa</span>
                </li>
              </ul>
            </div>
          </section>

          {/* Siguiente Paso */}
          <section className="border-t border-white/10 pt-8">
            <h2 className="text-2xl font-bold text-slate-900 dark:text-white mb-4">Siguiente Paso</h2>
            <div className="flex flex-col sm:flex-row gap-4">
              <Link
                href={`/${locale}/wiki/vulnerabilidades/sql-injection`}
                className="inline-flex items-center gap-2 px-6 py-3 bg-gradient-to-r from-green-600 to-emerald-600 text-slate-900 dark:text-white rounded-xl font-semibold hover:scale-105 transition-transform"
              >
                <Lock className="w-5 h-5" />
                <span>SQL Injection (Vulnerabilidad)</span>
              </Link>
              <Link
                href={`/${locale}/lab/xss`}
                className="inline-flex items-center gap-2 px-6 py-3 bg-white/10 backdrop-blur-sm text-slate-900 dark:text-white rounded-xl font-semibold hover:bg-white/20 transition-all border border-white/20"
              >
                <span>Practicar XSS en el Lab</span>
              </Link>
            </div>
          </section>
        </div>
      </div>
      </div>
    </>
  );
}
