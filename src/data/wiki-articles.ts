/**
 * CENTRALIZACIÓN DE ARTÍCULOS DE LA WIKI
 * 
 * Este archivo contiene TODOS los artículos de la Wiki en una estructura de datos.
 * Los artículos se renderizan dinámicamente desde aquí.
 * 
 * BENEFICIOS:
 * - Un solo lugar para agregar/editar artículos
 * - Metadata centralizada (categoría, nivel, CVSS, etc.)
 * - Rutas generadas automáticamente
 * - Fácil de mantener y escalar
 */

export interface WikiArticle {
  // Identificación
  id: string;
  slug: string;
  category: 'fundamentos' | 'vulnerabilidades' | 'defensas' | 'herramientas' | 'bug-bounty';
  
  // Metadata principal
  title: string;
  description: string;
  level: 'Estudiante' | 'Junior Developer' | 'Pentester' | 'Security Expert';
  
  // Metadata adicional
  readTime: string;
  lastUpdated: string;
  author?: string;
  cvssScore?: number;
  
  // Contenido
  tags: string[];
  relatedArticles?: string[]; // IDs de artículos relacionados
  
  // Visual
  categoryColor: 'blue' | 'red' | 'green' | 'purple' | 'orange';
  icon?: string;
}

// ============================================================================
// FUNDAMENTOS (16 artículos - Nivel: Estudiante)
// ============================================================================

export const fundamentosArticles: WikiArticle[] = [
  {
    id: 'http-basico',
    slug: 'http-basico',
    category: 'fundamentos',
    title: 'HTTP: El Protocolo de la Web',
    description: 'Aprende los fundamentos del protocolo HTTP, la base de toda comunicación en la World Wide Web.',
    level: 'Estudiante',
    readTime: '10 minutos',
    lastUpdated: 'Enero 2026',
    categoryColor: 'blue',
    tags: ['HTTP', 'Protocolos', 'Web', 'Básico'],
    relatedArticles: ['https-ssl-tls', 'autenticacion-autorizacion']
  },
  {
    id: 'https-ssl-tls',
    slug: 'https-ssl-tls',
    category: 'fundamentos',
    title: 'HTTPS, SSL y TLS',
    description: 'Entiende cómo funciona el cifrado en la web y por qué HTTPS es fundamental para la seguridad.',
    level: 'Estudiante',
    readTime: '12 minutos',
    lastUpdated: 'Enero 2026',
    categoryColor: 'blue',
    tags: ['HTTPS', 'SSL', 'TLS', 'Cifrado', 'Certificados'],
    relatedArticles: ['http-basico', 'certificate-pinning']
  },
  {
    id: 'autenticacion-autorizacion',
    slug: 'autenticacion-autorizacion',
    category: 'fundamentos',
    title: 'Autenticación vs Autorización',
    description: 'Diferencia entre autenticación (quién eres) y autorización (qué puedes hacer).',
    level: 'Estudiante',
    readTime: '8 minutos',
    lastUpdated: 'Enero 2026',
    categoryColor: 'blue',
    tags: ['Autenticación', 'Autorización', 'Sesiones', 'JWT'],
    relatedArticles: ['jwt-attacks', 'oauth-misconfigurations']
  },
  {
    id: 'cookies-sesiones',
    slug: 'cookies-sesiones',
    category: 'fundamentos',
    title: 'Cookies y Gestión de Sesiones',
    description: 'Cómo las aplicaciones web mantienen el estado del usuario mediante cookies y sesiones.',
    level: 'Estudiante',
    readTime: '10 minutos',
    lastUpdated: 'Enero 2026',
    categoryColor: 'blue',
    tags: ['Cookies', 'Sesiones', 'HTTP', 'Seguridad'],
    relatedArticles: ['http-basico', 'csrf']
  },
  {
    id: 'apis-rest-seguridad',
    slug: 'apis-rest-seguridad',
    category: 'fundamentos',
    title: 'APIs REST y Seguridad',
    description: 'Principios de diseño seguro de APIs RESTful y mejores prácticas.',
    level: 'Estudiante',
    readTime: '15 minutos',
    lastUpdated: 'Enero 2026',
    categoryColor: 'blue',
    tags: ['REST', 'API', 'Seguridad', 'JSON'],
    relatedArticles: ['rate-limiting', 'api-security-headers']
  },
  {
    id: 'owasp-top-10',
    slug: 'owasp-top-10',
    category: 'fundamentos',
    title: 'OWASP Top 10',
    description: 'Las 10 vulnerabilidades más críticas en aplicaciones web según OWASP.',
    level: 'Estudiante',
    readTime: '20 minutos',
    lastUpdated: 'Enero 2026',
    categoryColor: 'blue',
    tags: ['OWASP', 'Vulnerabilidades', 'Top 10', 'Estándares'],
    relatedArticles: ['sql-injection', 'xss', 'csrf']
  },
  // ... agregar más fundamentos
];

// ============================================================================
// VULNERABILIDADES (9 artículos - Nivel: Junior Developer)
// ============================================================================

export const vulnerabilidadesArticles: WikiArticle[] = [
  {
    id: 'sql-injection',
    slug: 'sql-injection',
    category: 'vulnerabilidades',
    title: 'SQL Injection',
    description: 'Guía completa sobre ataques de inyección SQL: cómo funcionan, ejemplos y cómo prevenirlos.',
    level: 'Junior Developer',
    readTime: '20 minutos',
    lastUpdated: 'Enero 2026',
    categoryColor: 'red',
    cvssScore: 9.8,
    tags: ['SQL Injection', 'Bases de Datos', 'OWASP', 'Crítico'],
    relatedArticles: ['parameterized-queries', 'sql-injection-avanzada']
  },
  {
    id: 'xss',
    slug: 'xss',
    category: 'vulnerabilidades',
    title: 'Cross-Site Scripting (XSS)',
    description: 'Ataques XSS: tipos, vectores de ataque y técnicas de prevención.',
    level: 'Junior Developer',
    readTime: '18 minutos',
    lastUpdated: 'Enero 2026',
    categoryColor: 'red',
    cvssScore: 7.4,
    tags: ['XSS', 'JavaScript', 'DOM', 'OWASP'],
    relatedArticles: ['csp', 'input-validation']
  },
  {
    id: 'csrf',
    slug: 'csrf',
    category: 'vulnerabilidades',
    title: 'Cross-Site Request Forgery (CSRF)',
    description: 'Ataques CSRF: cómo funcionan y cómo proteger tus aplicaciones.',
    level: 'Junior Developer',
    readTime: '15 minutos',
    lastUpdated: 'Enero 2026',
    categoryColor: 'red',
    cvssScore: 6.5,
    tags: ['CSRF', 'Tokens', 'Seguridad Web', 'OWASP'],
    relatedArticles: ['csrf-tokens', 'same-site-cookies']
  },
  {
    id: 'idor',
    slug: 'idor',
    category: 'vulnerabilidades',
    title: 'Insecure Direct Object Reference (IDOR)',
    description: 'Vulnerabilidades de acceso directo a objetos y cómo explotarlas.',
    level: 'Junior Developer',
    readTime: '12 minutos',
    lastUpdated: 'Enero 2026',
    categoryColor: 'red',
    cvssScore: 8.1,
    tags: ['IDOR', 'Autorización', 'API', 'Bug Bounty'],
    relatedArticles: ['autenticacion-autorizacion', 'race-conditions']
  },
  // ... agregar más vulnerabilidades
];

// ============================================================================
// BUG BOUNTY (35 artículos - Nivel: Pentester)
// ============================================================================

export const bugBountyArticles: WikiArticle[] = [
  // --- Base de Datos Avanzadas ---
  {
    id: 'sql-injection-avanzada',
    slug: 'sql-injection-avanzada',
    category: 'bug-bounty',
    title: 'SQL Injection Manual Avanzada',
    description: 'Técnicas Union, Error-based y Time-blind para exfiltrar datos sin herramientas automáticas.',
    level: 'Pentester',
    readTime: '25 minutos',
    lastUpdated: 'Enero 2026',
    categoryColor: 'orange',
    cvssScore: 9.8,
    tags: ['SQL Injection', 'Union-based', 'Time-blind', 'Error-based', 'Bug Bounty'],
    relatedArticles: ['sql-injection', 'parameterized-queries']
  },
  {
    id: 'mongodb-injection',
    slug: 'mongodb-injection',
    category: 'bug-bounty',
    title: 'MongoDB Operator Injection',
    description: 'Uso de operadores NoSQL ($gt, $ne) para bypass de autenticación y extracción de datos.',
    level: 'Pentester',
    readTime: '20 minutos',
    lastUpdated: 'Enero 2026',
    categoryColor: 'orange',
    cvssScore: 8.9,
    tags: ['MongoDB', 'NoSQL Injection', 'Operadores', 'Bug Bounty'],
    relatedArticles: ['nosql-injection', 'redis-rce']
  },
  {
    id: 'redis-rce',
    slug: 'redis-rce',
    category: 'bug-bounty',
    title: 'Redis RCE via Lua Sandboxing',
    description: 'Ejecución remota de comandos mediante el motor de scripts Lua en Redis.',
    level: 'Pentester',
    readTime: '22 minutos',
    lastUpdated: 'Enero 2026',
    categoryColor: 'orange',
    cvssScore: 9.6,
    tags: ['Redis', 'RCE', 'Lua', 'Sandbox Escape', 'Bug Bounty'],
    relatedArticles: ['mongodb-injection', 'command-injection']
  },
  {
    id: 'cassandra-injection',
    slug: 'cassandra-injection',
    category: 'bug-bounty',
    title: 'Cassandra (CQL) Injection',
    description: 'Bypass de filtros y extracción de keyspaces en arquitecturas NewSQL.',
    level: 'Pentester',
    readTime: '18 minutos',
    lastUpdated: 'Enero 2026',
    categoryColor: 'orange',
    cvssScore: 8.2,
    tags: ['Cassandra', 'CQL', 'NewSQL', 'Injection', 'Bug Bounty'],
    relatedArticles: ['sql-injection-avanzada', 'mongodb-injection']
  },
  {
    id: 'sqlite-local-injection',
    slug: 'sqlite-local-injection',
    category: 'bug-bounty',
    title: 'SQLite Local Injections',
    description: 'Ataques a bases de datos locales desde apps maliciosas en dispositivos rooteados.',
    level: 'Pentester',
    readTime: '16 minutos',
    lastUpdated: 'Enero 2026',
    categoryColor: 'orange',
    cvssScore: 7.8,
    tags: ['SQLite', 'Mobile', 'Local Injection', 'Root', 'Bug Bounty'],
    relatedArticles: ['mobile-forensics', 'realm-coredata']
  },
  {
    id: 'firebase-misconfiguration',
    slug: 'firebase-misconfiguration',
    category: 'bug-bounty',
    title: 'Firebase Realtime DB Misconfiguration',
    description: 'Localización de bases de datos abiertas y extracción de datos por falta de reglas.',
    level: 'Pentester',
    readTime: '14 minutos',
    lastUpdated: 'Enero 2026',
    categoryColor: 'orange',
    cvssScore: 9.1,
    tags: ['Firebase', 'Misconfiguration', 'NoSQL', 'Cloud', 'Bug Bounty'],
    relatedArticles: ['cloud-metadata-ssrf', 'mongodb-injection']
  },
  {
    id: 'realm-coredata',
    slug: 'realm-coredata',
    category: 'bug-bounty',
    title: 'Realm & CoreData Forensics',
    description: 'Extracción de bases de datos móviles desde volcados de memoria y backups.',
    level: 'Pentester',
    readTime: '20 minutos',
    lastUpdated: 'Enero 2026',
    categoryColor: 'orange',
    cvssScore: 7.5,
    tags: ['Realm', 'CoreData', 'Mobile', 'Forensics', 'Bug Bounty'],
    relatedArticles: ['sqlite-local-injection', 'mobile-forensics']
  },

  // --- Alfabetos y Unicode ---
  {
    id: 'homograph-attacks',
    slug: 'homograph-attacks',
    category: 'bug-bounty',
    title: 'Homograph Attacks (IDN)',
    description: 'Suplantación de dominios usando caracteres visualmente idénticos de alfabetos Cirílico o Griego.',
    level: 'Pentester',
    readTime: '12 minutos',
    lastUpdated: 'Enero 2026',
    categoryColor: 'orange',
    cvssScore: 7.3,
    tags: ['IDN', 'Homograph', 'Phishing', 'Unicode', 'Bug Bounty'],
    relatedArticles: ['unicode-normalization', 'phishing-techniques']
  },
  {
    id: 'unicode-normalization',
    slug: 'unicode-normalization',
    category: 'bug-bounty',
    title: 'Unicode Normalization Bypass',
    description: 'Uso de toLowerCase() para transformar caracteres que saltan filtros (ẞ → SS).',
    level: 'Pentester',
    readTime: '15 minutos',
    lastUpdated: 'Enero 2026',
    categoryColor: 'orange',
    cvssScore: 6.8,
    tags: ['Unicode', 'Normalization', 'Bypass', 'Filter Evasion', 'Bug Bounty'],
    relatedArticles: ['homograph-attacks', 'utf8-smuggling']
  },
  {
    id: 'utf8-smuggling',
    slug: 'utf8-smuggling',
    category: 'bug-bounty',
    title: 'Smuggling via Overlong UTF-8',
    description: 'Secuencias de bytes extendidas para ocultar caracteres peligrosos de los WAF.',
    level: 'Pentester',
    readTime: '18 minutos',
    lastUpdated: 'Enero 2026',
    categoryColor: 'orange',
    cvssScore: 7.6,
    tags: ['UTF-8', 'Smuggling', 'WAF Bypass', 'Encoding', 'Bug Bounty'],
    relatedArticles: ['unicode-normalization', 'waf-bypass']
  },
  {
    id: 'sqli-small-windows',
    slug: 'sqli-small-windows',
    category: 'bug-bounty',
    title: 'SQLi en "Small Windows"',
    description: 'Inyecciones SQL optimizadas para campos con límites severos de caracteres.',
    level: 'Pentester',
    readTime: '16 minutos',
    lastUpdated: 'Enero 2026',
    categoryColor: 'orange',
    cvssScore: 8.7,
    tags: ['SQL Injection', 'Length Limit', 'Optimization', 'Bug Bounty'],
    relatedArticles: ['sql-injection-avanzada', 'multi-stage-payload']
  },
  {
    id: 'multi-stage-payload',
    slug: 'multi-stage-payload',
    category: 'bug-bounty',
    title: 'Multi-stage Payload (Fragmentación)',
    description: 'Dividir un ataque en varios campos cortos que se ejecutan al renderizarse juntos.',
    level: 'Pentester',
    readTime: '14 minutos',
    lastUpdated: 'Enero 2026',
    categoryColor: 'orange',
    cvssScore: 8.2,
    tags: ['Payload Fragmentation', 'Multi-stage', 'XSS', 'Bug Bounty'],
    relatedArticles: ['sqli-small-windows', 'xss-advanced']
  },

  // --- SSRF (Server-Side Request Forgery) ---
  {
    id: 'cloud-metadata-ssrf',
    slug: 'cloud-metadata-ssrf',
    category: 'bug-bounty',
    title: 'SSRF en Cloud Metadata',
    description: 'Robo de credenciales en AWS/GCP/Azure vía 169.254.169.254.',
    level: 'Pentester',
    readTime: '20 minutos',
    lastUpdated: 'Enero 2026',
    categoryColor: 'orange',
    cvssScore: 9.3,
    tags: ['SSRF', 'AWS', 'GCP', 'Azure', 'Cloud', 'Bug Bounty'],
    relatedArticles: ['ssrf-basics', 'dns-rebinding']
  },
  {
    id: 'dns-rebinding',
    slug: 'dns-rebinding',
    category: 'bug-bounty',
    title: 'DNS Rebinding',
    description: 'Saltar validaciones de IP interna cambiando la resolución DNS en milisegundos.',
    level: 'Pentester',
    readTime: '22 minutos',
    lastUpdated: 'Enero 2026',
    categoryColor: 'orange',
    cvssScore: 8.8,
    tags: ['DNS Rebinding', 'SSRF', 'IP Validation', 'Bug Bounty'],
    relatedArticles: ['cloud-metadata-ssrf', 'gopher-protocol']
  },
  {
    id: 'gopher-protocol',
    slug: 'gopher-protocol',
    category: 'bug-bounty',
    title: 'Gopher Protocol Smuggling',
    description: 'Enviar tráfico binario crudo para atacar Redis/MySQL internos desde una URL.',
    level: 'Pentester',
    readTime: '18 minutos',
    lastUpdated: 'Enero 2026',
    categoryColor: 'orange',
    cvssScore: 9.0,
    tags: ['Gopher', 'Protocol Smuggling', 'SSRF', 'Redis', 'Bug Bounty'],
    relatedArticles: ['redis-rce', 'dns-rebinding']
  },
  {
    id: 'ssrf-pdf-renderers',
    slug: 'ssrf-pdf-renderers',
    category: 'bug-bounty',
    title: 'SSRF via PDF/Image Renderers',
    description: 'Inyección de HTML para leer archivos locales (/etc/passwd) mediante conversores.',
    level: 'Pentester',
    readTime: '16 minutos',
    lastUpdated: 'Enero 2026',
    categoryColor: 'orange',
    cvssScore: 8.5,
    tags: ['SSRF', 'PDF', 'File Read', 'LFI', 'Bug Bounty'],
    relatedArticles: ['cloud-metadata-ssrf', 'xxe']
  },

  // --- IA en Apps Móviles ---
  {
    id: 'prompt-injection-mobile',
    slug: 'prompt-injection-mobile',
    category: 'bug-bounty',
    title: 'Prompt Injection en Interfaces Móviles',
    description: 'Saltar System Prompts para revelar datos o ejecutar acciones no autorizadas.',
    level: 'Pentester',
    readTime: '14 minutos',
    lastUpdated: 'Enero 2026',
    categoryColor: 'orange',
    cvssScore: 7.9,
    tags: ['Prompt Injection', 'AI', 'Mobile', 'LLM', 'Bug Bounty'],
    relatedArticles: ['coreml-hijacking', 'intent-injection']
  },
  {
    id: 'coreml-hijacking',
    slug: 'coreml-hijacking',
    category: 'bug-bounty',
    title: 'CoreML/ML Kit Model Hijacking',
    description: 'Reemplazo de archivos .mlmodelc o .tflite para alterar la lógica de decisión de la app.',
    level: 'Pentester',
    readTime: '20 minutos',
    lastUpdated: 'Enero 2026',
    categoryColor: 'orange',
    cvssScore: 8.3,
    tags: ['CoreML', 'ML Kit', 'Model Hijacking', 'AI', 'Bug Bounty'],
    relatedArticles: ['prompt-injection-mobile', 'app-intents-abuse']
  },
  {
    id: 'app-intents-abuse',
    slug: 'app-intents-abuse',
    category: 'bug-bounty',
    title: 'Abuso de App Intents (Apple Intelligence)',
    description: 'Manipulación de acciones expuestas a Siri/Shortcuts para exfiltrar datos privados.',
    level: 'Pentester',
    readTime: '16 minutos',
    lastUpdated: 'Enero 2026',
    categoryColor: 'orange',
    cvssScore: 7.7,
    tags: ['App Intents', 'Siri', 'Shortcuts', 'Apple', 'Bug Bounty'],
    relatedArticles: ['coreml-hijacking', 'intent-injection-gemini']
  },
  {
    id: 'intent-injection-gemini',
    slug: 'intent-injection-gemini',
    category: 'bug-bounty',
    title: 'Intent Injection en Gemini Nano',
    description: 'Engañar a la IA de Google para que extraiga contextos de la app hacia servidores externos.',
    level: 'Pentester',
    readTime: '18 minutos',
    lastUpdated: 'Enero 2026',
    categoryColor: 'orange',
    cvssScore: 8.1,
    tags: ['Gemini', 'Intent Injection', 'AI', 'Google', 'Bug Bounty'],
    relatedArticles: ['prompt-injection-mobile', 'app-intents-abuse']
  },
  {
    id: 'npu-sidechannel',
    slug: 'npu-sidechannel',
    category: 'bug-bounty',
    title: 'Side-channel Attacks en NPU',
    description: 'Análisis de consumo en el Neural Engine para inferir datos procesados por la IA.',
    level: 'Security Expert',
    readTime: '22 minutos',
    lastUpdated: 'Enero 2026',
    categoryColor: 'orange',
    cvssScore: 6.9,
    tags: ['Side-channel', 'NPU', 'Neural Engine', 'AI', 'Bug Bounty'],
    relatedArticles: ['coreml-hijacking', 'crypto-sidechannel']
  },

  // --- Comunicaciones y Certificados ---
  {
    id: 'ssl-pinning-bypass',
    slug: 'ssl-pinning-bypass',
    category: 'bug-bounty',
    title: 'SSL/TLS Pinning Bypass',
    description: 'Uso de Frida u Objection para deshabilitar la validación de certificados en tiempo de ejecución.',
    level: 'Pentester',
    readTime: '20 minutos',
    lastUpdated: 'Enero 2026',
    categoryColor: 'orange',
    cvssScore: 8.6,
    tags: ['SSL Pinning', 'Frida', 'Objection', 'MitM', 'Bug Bounty'],
    relatedArticles: ['broken-cert-validation', 'mitm-non-http']
  },
  {
    id: 'broken-cert-validation',
    slug: 'broken-cert-validation',
    category: 'bug-bounty',
    title: 'Broken Certificate Validation',
    description: 'Explotación de apps que aceptan certificados auto-firmados o con nombres incorrectos.',
    level: 'Pentester',
    readTime: '15 minutos',
    lastUpdated: 'Enero 2026',
    categoryColor: 'orange',
    cvssScore: 8.2,
    tags: ['Certificates', 'Validation', 'MitM', 'SSL/TLS', 'Bug Bounty'],
    relatedArticles: ['ssl-pinning-bypass', 'https-ssl-tls']
  },
  {
    id: 'mitm-non-http',
    slug: 'mitm-non-http',
    category: 'bug-bounty',
    title: 'Man-in-the-Middle en protocolos no-HTTP',
    description: 'Interceptación de tráfico crudo (TCP/UDP) que no usa TLS estándar.',
    level: 'Pentester',
    readTime: '18 minutos',
    lastUpdated: 'Enero 2026',
    categoryColor: 'orange',
    cvssScore: 7.8,
    tags: ['MitM', 'TCP', 'UDP', 'Non-HTTP', 'Bug Bounty'],
    relatedArticles: ['ssl-pinning-bypass', 'protocol-analysis']
  },
  {
    id: 'ct-log-monitoring',
    slug: 'ct-log-monitoring',
    category: 'bug-bounty',
    title: 'Certificate Transparency Log Monitoring',
    description: 'Uso de registros públicos para encontrar subdominios olvidados o entornos de staging.',
    level: 'Pentester',
    readTime: '12 minutos',
    lastUpdated: 'Enero 2026',
    categoryColor: 'orange',
    cvssScore: 6.5,
    tags: ['Certificate Transparency', 'Subdomain Enum', 'Recon', 'Bug Bounty'],
    relatedArticles: ['subdomain-takeover', 'recon-techniques']
  },

  // --- Integridad y Criptografía ---
  {
    id: 'broken-integrity-checks',
    slug: 'broken-integrity-checks',
    category: 'bug-bounty',
    title: 'Broken Integrity Checks (APK/IPA)',
    description: 'Modificación del binario de la app y re-firmado para saltar protecciones de integridad.',
    level: 'Pentester',
    readTime: '20 minutos',
    lastUpdated: 'Enero 2026',
    categoryColor: 'orange',
    cvssScore: 7.9,
    tags: ['Integrity', 'APK', 'IPA', 'Re-signing', 'Bug Bounty'],
    relatedArticles: ['insecure-key-storage', 'mobile-forensics']
  },
  {
    id: 'insecure-key-storage',
    slug: 'insecure-key-storage',
    category: 'bug-bounty',
    title: 'Insecure Key Storage',
    description: 'Localización de llaves criptográficas en Keystore/Keychain mal configurado.',
    level: 'Pentester',
    readTime: '16 minutos',
    lastUpdated: 'Enero 2026',
    categoryColor: 'orange',
    cvssScore: 8.7,
    tags: ['Key Storage', 'Keystore', 'Keychain', 'Crypto', 'Bug Bounty'],
    relatedArticles: ['weak-cryptography', 'broken-integrity-checks']
  },
  {
    id: 'weak-cryptography',
    slug: 'weak-cryptography',
    category: 'bug-bounty',
    title: 'Weak Cryptography',
    description: 'Ataques contra implementaciones que usan IVs estáticos, AES-ECB o MD5/SHA1.',
    level: 'Pentester',
    readTime: '18 minutos',
    lastUpdated: 'Enero 2026',
    categoryColor: 'orange',
    cvssScore: 8.4,
    tags: ['Cryptography', 'AES-ECB', 'MD5', 'SHA1', 'Bug Bounty'],
    relatedArticles: ['insecure-key-storage', 'crypto-sidechannel']
  },
  {
    id: 'crypto-sidechannel',
    slug: 'crypto-sidechannel',
    category: 'bug-bounty',
    title: 'Side-Channel en Criptografía',
    description: 'Extracción de secretos analizando tiempos de respuesta o errores detallados.',
    level: 'Security Expert',
    readTime: '22 minutos',
    lastUpdated: 'Enero 2026',
    categoryColor: 'orange',
    cvssScore: 7.3,
    tags: ['Side-channel', 'Timing Attack', 'Cryptography', 'Bug Bounty'],
    relatedArticles: ['weak-cryptography', 'npu-sidechannel']
  },
  {
    id: 'whitebox-crypto-re',
    slug: 'whitebox-crypto-re',
    category: 'bug-bounty',
    title: 'White-box Cryptography Reverse Engineering',
    description: 'Técnicas para extraer llaves ocultas dentro del código ofuscado de la app.',
    level: 'Security Expert',
    readTime: '25 minutos',
    lastUpdated: 'Enero 2026',
    categoryColor: 'orange',
    cvssScore: 8.0,
    tags: ['White-box', 'Reverse Engineering', 'Obfuscation', 'Bug Bounty'],
    relatedArticles: ['insecure-key-storage', 'code-obfuscation']
  },

  // --- Lógica de Negocio y Sesión ---
  {
    id: 'idor',
    slug: 'idor',
    category: 'bug-bounty',
    title: 'IDOR (Insecure Direct Object Reference)',
    description: 'Acceso a recursos de otros usuarios cambiando IDs en parámetros.',
    level: 'Pentester',
    readTime: '14 minutos',
    lastUpdated: 'Enero 2026',
    categoryColor: 'orange',
    cvssScore: 8.1,
    tags: ['IDOR', 'Authorization', 'API', 'Bug Bounty'],
    relatedArticles: ['race-conditions', 'autenticacion-autorizacion']
  },
  {
    id: 'race-conditions',
    slug: 'race-conditions',
    category: 'bug-bounty',
    title: 'Race Conditions',
    description: 'Explotación de concurrencia para duplicar acciones (pagos, votos, cupones).',
    level: 'Pentester',
    readTime: '18 minutos',
    lastUpdated: 'Enero 2026',
    categoryColor: 'orange',
    cvssScore: 7.5,
    tags: ['Race Condition', 'Concurrency', 'Business Logic', 'Bug Bounty'],
    relatedArticles: ['idor', 'toctou']
  },
  {
    id: 'jwt-attacks',
    slug: 'jwt-attacks',
    category: 'bug-bounty',
    title: 'JWT Attacks',
    description: 'Bypass de firmas (algoritmo none) y secuestro de sesiones JWT.',
    level: 'Pentester',
    readTime: '20 minutos',
    lastUpdated: 'Enero 2026',
    categoryColor: 'orange',
    cvssScore: 9.1,
    tags: ['JWT', 'Authentication', 'None Algorithm', 'Bug Bounty'],
    relatedArticles: ['autenticacion-autorizacion', 'oauth-misconfigurations']
  },
  {
    id: 'oauth-misconfigurations',
    slug: 'oauth-misconfigurations',
    category: 'bug-bounty',
    title: 'OAuth Misconfigurations',
    description: 'Robo de tokens mediante la manipulación de redirect_uri.',
    level: 'Pentester',
    readTime: '16 minutos',
    lastUpdated: 'Enero 2026',
    categoryColor: 'orange',
    cvssScore: 8.3,
    tags: ['OAuth', 'redirect_uri', 'Token Theft', 'Bug Bounty'],
    relatedArticles: ['jwt-attacks', 'open-redirect']
  },
];

// ============================================================================
// DEFENSAS (Nivel: Junior Developer)
// ============================================================================

export const defensasArticles: WikiArticle[] = [
  {
    id: 'input-validation',
    slug: 'input-validation',
    category: 'defensas',
    title: 'Validación de Inputs',
    description: 'Mejores prácticas para validar y sanitizar datos de usuario.',
    level: 'Junior Developer',
    readTime: '12 minutos',
    lastUpdated: 'Enero 2026',
    categoryColor: 'green',
    tags: ['Validación', 'Sanitización', 'Seguridad', 'Defensas'],
    relatedArticles: ['xss', 'sql-injection']
  },
  {
    id: 'parameterized-queries',
    slug: 'parameterized-queries',
    category: 'defensas',
    title: 'Consultas Parametrizadas',
    description: 'Cómo prevenir SQL Injection usando prepared statements.',
    level: 'Junior Developer',
    readTime: '10 minutos',
    lastUpdated: 'Enero 2026',
    categoryColor: 'green',
    tags: ['SQL', 'Prepared Statements', 'Defensas', 'Seguridad'],
    relatedArticles: ['sql-injection', 'orm-security']
  },
  // ... más defensas
];

// ============================================================================
// HERRAMIENTAS (Nivel: Junior Developer)
// ============================================================================

export const herramientasArticles: WikiArticle[] = [
  {
    id: 'burp-suite',
    slug: 'burp-suite',
    category: 'herramientas',
    title: 'Burp Suite',
    description: 'Guía completa de Burp Suite para testing de aplicaciones web.',
    level: 'Junior Developer',
    readTime: '25 minutos',
    lastUpdated: 'Enero 2026',
    categoryColor: 'purple',
    tags: ['Burp Suite', 'Proxy', 'Testing', 'Herramientas'],
    relatedArticles: ['owasp-zap', 'intercepting-proxies']
  },
  // ... más herramientas
];

// ============================================================================
// EXPORTACIONES Y UTILIDADES
// ============================================================================

// Todos los artículos en un solo array
export const allArticles: WikiArticle[] = [
  ...fundamentosArticles,
  ...vulnerabilidadesArticles,
  ...bugBountyArticles,
  ...defensasArticles,
  ...herramientasArticles,
];

// Función para obtener artículo por slug
export function getArticleBySlug(slug: string): WikiArticle | undefined {
  return allArticles.find(article => article.slug === slug);
}

// Función para obtener artículos por categoría
export function getArticlesByCategory(category: WikiArticle['category']): WikiArticle[] {
  return allArticles.filter(article => article.category === category);
}

// Función para obtener artículos por nivel
export function getArticlesByLevel(level: WikiArticle['level']): WikiArticle[] {
  return allArticles.filter(article => article.level === level);
}

// Función para obtener artículos relacionados
export function getRelatedArticles(articleId: string): WikiArticle[] {
  const article = allArticles.find(a => a.id === articleId);
  if (!article || !article.relatedArticles) return [];
  
  return article.relatedArticles
    .map(id => getArticleBySlug(id))
    .filter((a): a is WikiArticle => a !== undefined);
}

// Estadísticas
export const wikiStats = {
  total: allArticles.length,
  porCategoria: {
    fundamentos: fundamentosArticles.length,
    vulnerabilidades: vulnerabilidadesArticles.length,
    bugBounty: bugBountyArticles.length,
    defensas: defensasArticles.length,
    herramientas: herramientasArticles.length,
  },
  porNivel: {
    estudiante: allArticles.filter(a => a.level === 'Estudiante').length,
    juniorDeveloper: allArticles.filter(a => a.level === 'Junior Developer').length,
    pentester: allArticles.filter(a => a.level === 'Pentester').length,
    securityExpert: allArticles.filter(a => a.level === 'Security Expert').length,
  }
};
