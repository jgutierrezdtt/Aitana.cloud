// Modelo de datos para evaluación de madurez SSDLC
// Basado en OWASP SAMM, BSIMM, NIST SSDF, frameworks regulatorios

export type MaturityLevel = 0 | 1 | 2 | 3 | 4 | 5;

export interface AssessmentQuestion {
  id: string;
  question: string;
  description: string;
  level: MaturityLevel;
  evidence: string[];
  frameworks: string[]; // OWASP SAMM, BSIMM, NIST SSDF, ISO 27034, etc.
  regulations: string[]; // IDs de normativas relacionadas
  mitigates: string[]; // MITRE ATT&CK techniques, OWASP Top 10
}

export interface AssessmentDomain {
  id: string;
  name: string;
  icon: string;
  description: string;
  color: string;
  practices: AssessmentPractice[];
}

export interface AssessmentPractice {
  id: string;
  name: string;
  description: string;
  ssdlcPhases: string[];
  questions: AssessmentQuestion[];
}

// 4 Pilares CISO + SSDLC
export const maturityDomains: AssessmentDomain[] = [
  {
    id: 'governance',
    name: 'Gobernanza y Estrategia',
    icon: '🎯',
    description: 'Estrategia de seguridad, políticas, gestión de riesgos y cumplimiento normativo',
    color: 'from-blue-600 to-cyan-600',
    practices: [
      {
        id: 'strategy',
        name: 'Estrategia de Seguridad',
        description: 'Definición de estrategia y objetivos de seguridad alineados con el negocio',
        ssdlcPhases: ['requirements'],
        questions: [
          {
            id: 'gov-str-1',
            question: '¿Existe una estrategia de seguridad de aplicaciones documentada y aprobada por la dirección?',
            description: 'Debe incluir visión, objetivos, métricas y alineación con riesgos de negocio',
            level: 1,
            evidence: ['Documento de estrategia', 'Aprobación del comité ejecutivo', 'Revisión anual'],
            frameworks: ['OWASP SAMM - Governance > Strategy & Metrics', 'BSIMM - Governance', 'ISO 27034 ONF'],
            regulations: ['iso27001', 'ens', 'ccn-stic'],
            mitigates: []
          },
          {
            id: 'gov-str-2',
            question: '¿Se realiza clasificación de aplicaciones según criticidad de negocio y riesgo?',
            description: 'Clasificación basada en impacto (CIA), datos sensibles, exposición',
            level: 2,
            evidence: ['Inventario de aplicaciones', 'Matriz de criticidad', 'Criterios de clasificación'],
            frameworks: ['OWASP SAMM', 'NIST SSDF - PO.3', 'ISO 27001 A.8.2'],
            regulations: ['gdpr', 'dora', 'nis2', 'ens'],
            mitigates: []
          },
          {
            id: 'gov-str-3',
            question: '¿Se miden y reportan métricas de seguridad de aplicaciones (KPIs/KRIs) a la dirección?',
            description: 'Dashboards con métricas de vulnerabilidades, cobertura de testing, tiempo de remediación',
            level: 3,
            evidence: ['Dashboard de métricas', 'Informes ejecutivos mensuales', 'Trending histórico'],
            frameworks: ['OWASP SAMM - Strategy & Metrics', 'BSIMM SM', 'NIST SSDF - PO.5'],
            regulations: ['iso27001', 'soc2', 'dora'],
            mitigates: []
          },
          {
            id: 'gov-str-4',
            question: '¿Existe un roadmap de seguridad de aplicaciones con objetivos trimestrales/anuales?',
            description: 'Planificación de iniciativas, proyectos de mejora, adopción de herramientas',
            level: 3,
            evidence: ['Roadmap publicado', 'Objetivos SMART', 'Seguimiento de hitos'],
            frameworks: ['OWASP SAMM', 'BSIMM'],
            regulations: ['iso27001'],
            mitigates: []
          },
          {
            id: 'gov-str-5',
            question: '¿Se realiza benchmarking con industria y se optimiza continuamente el programa de seguridad?',
            description: 'Comparación con peers, adopción de mejores prácticas emergentes',
            level: 4,
            evidence: ['Informes de benchmarking', 'Análisis de gaps', 'Plan de optimización'],
            frameworks: ['BSIMM', 'OWASP SAMM Level 3'],
            regulations: [],
            mitigates: []
          }
        ]
      },
      {
        id: 'policy',
        name: 'Políticas y Cumplimiento',
        description: 'Políticas de desarrollo seguro y cumplimiento normativo',
        ssdlcPhases: ['requirements'],
        questions: [
          {
            id: 'gov-pol-1',
            question: '¿Existe una política de desarrollo seguro (SSDLC) documentada y comunicada?',
            description: 'Define requisitos mínimos de seguridad en cada fase del SDLC',
            level: 1,
            evidence: ['Política publicada', 'Formación a equipos', 'Portal de políticas'],
            frameworks: ['OWASP SAMM - Policy & Compliance', 'NIST SSDF - PO.1', 'ISO 27034'],
            regulations: ['ens', 'ccn-stic', 'iso27001', 'cra'],
            mitigates: []
          },
          {
            id: 'gov-pol-2',
            question: '¿Se han mapeado requisitos normativos (GDPR, NIS2, DORA, etc.) a controles técnicos?',
            description: 'Matriz de cumplimiento normativa → controles SSDLC',
            level: 2,
            evidence: ['Matriz de cumplimiento', 'Controles por normativa', 'Evidencias de cumplimiento'],
            frameworks: ['NIST SSDF - PO.2', 'ISO 27001'],
            regulations: ['gdpr', 'nis2', 'dora', 'cra', 'ai-act', 'ens', 'pci-dss', 'hipaa'],
            mitigates: []
          },
          {
            id: 'gov-pol-3',
            question: '¿Se realizan auditorías internas/externas del programa de seguridad de aplicaciones?',
            description: 'Auditorías de cumplimiento de políticas, controles técnicos y gestión de vulnerabilidades',
            level: 3,
            evidence: ['Informes de auditoría', 'Planes de acción', 'Seguimiento de hallazgos'],
            frameworks: ['ISO 27001 A.18.2', 'OWASP SAMM'],
            regulations: ['iso27001', 'ens', 'ccn-stic', 'soc2', 'pci-dss'],
            mitigates: []
          },
          {
            id: 'gov-pol-4',
            question: '¿Se gestionan excepciones a políticas con proceso formal de aprobación y seguimiento?',
            description: 'Registro de excepciones, análisis de riesgos, compensaciones, expiración temporal',
            level: 3,
            evidence: ['Registro de excepciones', 'Aprobaciones formales', 'Revisiones periódicas'],
            frameworks: ['OWASP SAMM', 'ISO 27001'],
            regulations: ['iso27001', 'soc2'],
            mitigates: []
          }
        ]
      },
      {
        id: 'training',
        name: 'Formación y Concienciación',
        description: 'Capacitación en desarrollo seguro para todos los roles',
        ssdlcPhases: ['requirements', 'design', 'development'],
        questions: [
          {
            id: 'gov-tra-1',
            question: '¿Todos los desarrolladores reciben formación básica anual en seguridad de aplicaciones?',
            description: 'Formación en OWASP Top 10, secure coding, principios de seguridad',
            level: 1,
            evidence: ['Plan de formación', 'Registro de asistencia', 'Evaluaciones post-formación'],
            frameworks: ['OWASP SAMM - Education & Guidance', 'NIST SSDF - PO.4', 'BSIMM T'],
            regulations: ['nis2', 'ens', 'ccn-stic', 'cra'],
            mitigates: ['OWASP Top 10 (todos)']
          },
          {
            id: 'gov-tra-2',
            question: '¿Existe formación específica por tecnología/lenguaje (Java, .NET, React, etc.)?',
            description: 'Material adaptado a stack tecnológico de la organización',
            level: 2,
            evidence: ['Catálogo de formaciones', 'Contenido por tecnología', 'Labs prácticos'],
            frameworks: ['OWASP SAMM', 'BSIMM'],
            regulations: ['ccn-stic'],
            mitigates: []
          },
          {
            id: 'gov-tra-3',
            question: '¿Se realizan ejercicios prácticos (CTFs, secure coding challenges, hands-on labs)?',
            description: 'Gamificación y práctica real, no solo teoría',
            level: 3,
            evidence: ['Plataforma de CTFs', 'Resultados de competiciones', 'Labs internos'],
            frameworks: ['OWASP SAMM Level 2', 'BSIMM'],
            regulations: [],
            mitigates: []
          },
          {
            id: 'gov-tra-4',
            question: '¿Existe programa de Security Champions con formación avanzada y certificaciones?',
            description: 'Red de campeones de seguridad embebidos en equipos de desarrollo',
            level: 4,
            evidence: ['Lista de champions', 'Certificaciones (CSSLP, etc.)', 'Reuniones periódicas'],
            frameworks: ['BSIMM T2.5', 'OWASP Security Champions'],
            regulations: [],
            mitigates: []
          }
        ]
      }
    ]
  },
  {
    id: 'design',
    name: 'Seguridad por Diseño',
    icon: '🎨',
    description: 'Threat modeling, arquitectura segura y diseño defensivo',
    color: 'from-purple-600 to-pink-600',
    practices: [
      {
        id: 'threat-modeling',
        name: 'Threat Modeling',
        description: 'Análisis de amenazas en fase de diseño',
        ssdlcPhases: ['requirements', 'design'],
        questions: [
          {
            id: 'des-thr-1',
            question: '¿Se realiza threat modeling en aplicaciones críticas/nuevas?',
            description: 'Identificación de amenazas mediante STRIDE, PASTA, Attack Trees',
            level: 2,
            evidence: ['Documentos de threat models', 'Diagramas DFD', 'Lista de amenazas'],
            frameworks: ['OWASP SAMM - Threat Assessment', 'NIST SSDF - PW.1', 'ISO 27034'],
            regulations: ['gdpr', 'nis2', 'dora', 'iso21434', 'iec81001'],
            mitigates: ['MITRE ATT&CK (múltiples técnicas)', 'OWASP Top 10']
          },
          {
            id: 'des-thr-2',
            question: '¿El threat modeling incluye análisis de MITRE ATT&CK y ATT&CK for Cloud?',
            description: 'Mapeo de técnicas de ataque relevantes para la aplicación',
            level: 3,
            evidence: ['Threat models con MITRE TTPs', 'Controles vs técnicas', 'Priorización de riesgos'],
            frameworks: ['MITRE ATT&CK', 'NIST SSDF'],
            regulations: ['nis2', 'dora'],
            mitigates: ['MITRE ATT&CK Tactics: Initial Access, Execution, Persistence, Privilege Escalation']
          },
          {
            id: 'des-thr-3',
            question: '¿Para sistemas de IA/ML se realiza threat modeling específico (MITRE ATLAS)?',
            description: 'Amenazas específicas de ML: data poisoning, model inversion, adversarial examples',
            level: 4,
            evidence: ['Threat models IA', 'ATLAS matrix', 'Controles ML-specific'],
            frameworks: ['MITRE ATLAS', 'NIST AI RMF'],
            regulations: ['ai-act'],
            mitigates: ['ATLAS: AML.T0043 (Data Poisoning), AML.T0051 (Model Inversion)']
          },
          {
            id: 'des-thr-4',
            question: '¿El threat modeling se actualiza ante cambios arquitectónicos significativos?',
            description: 'Proceso de re-evaluación continua, no solo inicial',
            level: 3,
            evidence: ['Política de actualización', 'Versionado de threat models', 'Registro de cambios'],
            frameworks: ['OWASP SAMM', 'NIST SSDF'],
            regulations: ['dora', 'cra'],
            mitigates: []
          }
        ]
      },
      {
        id: 'secure-architecture',
        name: 'Arquitectura Segura',
        description: 'Principios de diseño seguro y patrones arquitectónicos',
        ssdlcPhases: ['design'],
        questions: [
          {
            id: 'des-arc-1',
            question: '¿Se aplican principios de defensa en profundidad (defense in depth)?',
            description: 'Múltiples capas de seguridad, principio de least privilege, segregación',
            level: 2,
            evidence: ['Diagramas de arquitectura', 'Documentación de capas de seguridad', 'Revisiones de arquitectura'],
            frameworks: ['OWASP ASVS', 'NIST SSDF - PW.2', 'ISO 27034'],
            regulations: ['nis2', 'ens', 'iso27001'],
            mitigates: ['MITRE ATT&CK: Lateral Movement, Privilege Escalation']
          },
          {
            id: 'des-arc-2',
            question: '¿Se utilizan patrones de diseño seguro (OAuth2, OIDC, SAML, Zero Trust)?',
            description: 'Frameworks y protocolos estándar en lugar de desarrollos custom',
            level: 2,
            evidence: ['Arquitectura de autenticación', 'Implementación de estándares', 'Configuraciones'],
            frameworks: ['OWASP ASVS V2-V3', 'NIST 800-63'],
            regulations: ['gdpr', 'pci-dss', 'hipaa'],
            mitigates: ['OWASP A07:2021 - Identification and Authentication Failures']
          },
          {
            id: 'des-arc-3',
            question: '¿Existe revisión de arquitectura de seguridad para proyectos críticos?',
            description: 'Security Architecture Review formal con checklist y aprobación',
            level: 3,
            evidence: ['Checklist de revisión', 'Actas de aprobación', 'Recomendaciones documentadas'],
            frameworks: ['OWASP SAMM - Design Review', 'BSIMM AA'],
            regulations: ['dora', 'ens', 'iso27001'],
            mitigates: []
          },
          {
            id: 'des-arc-4',
            question: '¿Se documentan y mantienen patrones de referencia (reference architectures)?',
            description: 'Blueprints seguros reutilizables para arquitecturas comunes',
            level: 4,
            evidence: ['Biblioteca de patrones', 'Documentación técnica', 'Casos de uso'],
            frameworks: ['OWASP SAMM', 'BSIMM'],
            regulations: [],
            mitigates: []
          }
        ]
      },
      {
        id: 'requirements',
        name: 'Requisitos de Seguridad',
        description: 'Definición y gestión de requisitos de seguridad',
        ssdlcPhases: ['requirements'],
        questions: [
          {
            id: 'des-req-1',
            question: '¿Se definen requisitos de seguridad específicos en cada proyecto?',
            description: 'Requisitos funcionales y no funcionales de seguridad documentados',
            level: 1,
            evidence: ['User stories de seguridad', 'Requisitos en backlog', 'Criterios de aceptación'],
            frameworks: ['OWASP ASVS', 'NIST SSDF - PW.1', 'ISO 27034'],
            regulations: ['gdpr', 'ens', 'cra', 'ai-act'],
            mitigates: []
          },
          {
            id: 'des-req-2',
            question: '¿Se utilizan frameworks estándar como OWASP ASVS para definir requisitos?',
            description: 'Niveles ASVS 1, 2 o 3 según criticidad de aplicación',
            level: 2,
            evidence: ['Mapeo a ASVS', 'Nivel de verificación definido', 'Checklist de requisitos'],
            frameworks: ['OWASP ASVS', 'ISO 27034 ASC'],
            regulations: ['pci-dss', 'hipaa'],
            mitigates: ['OWASP Top 10 (compliance)']
          },
          {
            id: 'des-req-3',
            question: '¿Para aplicaciones reguladas se mapean requisitos normativos a user stories?',
            description: 'Trazabilidad regulación → requisito → implementación → testing',
            level: 3,
            evidence: ['Matriz de trazabilidad', 'Tags en tickets', 'Informes de cobertura'],
            frameworks: ['ISO 27001', 'NIST SSDF'],
            regulations: ['gdpr', 'nis2', 'dora', 'pci-dss', 'hipaa', 'ens'],
            mitigates: []
          }
        ]
      }
    ]
  },
  {
    id: 'devsecops',
    name: 'DevSecOps y Automatización',
    icon: '⚙️',
    description: 'Integración de seguridad en pipelines CI/CD, testing automatizado',
    color: 'from-green-600 to-emerald-600',
    practices: [
      {
        id: 'sast',
        name: 'Static Application Security Testing (SAST)',
        description: 'Análisis estático de código fuente',
        ssdlcPhases: ['development'],
        questions: [
          {
            id: 'dev-sas-1',
            question: '¿Se ejecuta SAST automáticamente en cada commit/PR?',
            description: 'Integrado en pipeline CI con reglas configuradas',
            level: 2,
            evidence: ['Configuración pipeline', 'Logs de ejecución', 'Reportes SAST'],
            frameworks: ['OWASP SAMM - Security Testing', 'NIST SSDF - PW.7', 'ISO 27034'],
            regulations: ['ens', 'ccn-stic', 'pci-dss', 'cra'],
            mitigates: ['OWASP A03:2021 - Injection', 'OWASP A01:2021 - Broken Access Control', 'CWE Top 25']
          },
          {
            id: 'dev-sas-2',
            question: '¿Se bloquean builds con vulnerabilidades críticas/altas según política?',
            description: 'Quality gates automáticos, no solo reporting',
            level: 3,
            evidence: ['Políticas de quality gates', 'Builds bloqueados', 'Umbrales configurados'],
            frameworks: ['OWASP SAMM', 'NIST SSDF'],
            regulations: ['pci-dss', 'cra'],
            mitigates: []
          },
          {
            id: 'dev-sas-3',
            question: '¿Se realiza tuning de reglas SAST para reducir falsos positivos?',
            description: 'Customización por proyecto, supresión justificada de falsos positivos',
            level: 3,
            evidence: ['Documentación de tuning', 'Tasa de falsos positivos', 'Revisiones periódicas'],
            frameworks: ['OWASP SAMM', 'BSIMM CR'],
            regulations: [],
            mitigates: []
          },
          {
            id: 'dev-sas-4',
            question: '¿Se utilizan múltiples motores SAST o análisis con IA/ML para mayor cobertura?',
            description: 'Combinación de herramientas comerciales y open source',
            level: 4,
            evidence: ['Lista de herramientas', 'Comparativa de cobertura', 'Resultados combinados'],
            frameworks: ['BSIMM CR', 'OWASP SAMM Level 3'],
            regulations: [],
            mitigates: []
          }
        ]
      },
      {
        id: 'sca',
        name: 'Software Composition Analysis (SCA)',
        description: 'Gestión de dependencias y componentes de terceros',
        ssdlcPhases: ['development', 'testing'],
        questions: [
          {
            id: 'dev-sca-1',
            question: '¿Se escanean dependencias automáticamente en busca de vulnerabilidades conocidas?',
            description: 'Integración de SCA en pipeline (Snyk, Dependabot, OWASP Dependency-Check)',
            level: 2,
            evidence: ['Configuración SCA', 'Reportes de vulnerabilidades', 'Alertas automatizadas'],
            frameworks: ['OWASP SAMM - Security Testing', 'NIST SSDF - PW.4', 'NIST 800-161'],
            regulations: ['cra', 'nis2', 'dora'],
            mitigates: ['OWASP A06:2021 - Vulnerable and Outdated Components']
          },
          {
            id: 'dev-sca-2',
            question: '¿Se genera y mantiene un SBOM (Software Bill of Materials)?',
            description: 'SBOM en formato estándar (SPDX, CycloneDX) para cada release',
            level: 3,
            evidence: ['SBOMs generados', 'Formato estándar', 'Versionado de SBOMs'],
            frameworks: ['NIST SSDF - PS.3', 'NIST 800-161r1'],
            regulations: ['cra', 'ai-act', 'nis2'],
            mitigates: []
          },
          {
            id: 'dev-sca-3',
            question: '¿Existe proceso de aprobación de nuevas dependencias (whitelist/blacklist)?',
            description: 'Revisión de licencias, seguridad y mantenimiento de librerías',
            level: 3,
            evidence: ['Política de dependencias', 'Proceso de aprobación', 'Registro de decisiones'],
            frameworks: ['OWASP SAMM', 'BSIMM SR'],
            regulations: ['cra', 'nis2'],
            mitigates: []
          },
          {
            id: 'dev-sca-4',
            question: '¿Se monitoriza la cadena de suministro de software (supply chain attacks)?',
            description: 'Detección de dependencias comprometidas, typosquatting, dependency confusion',
            level: 4,
            evidence: ['Herramientas de monitorización', 'Alertas de supply chain', 'Incident response plan'],
            frameworks: ['NIST SSDF - PS.1', 'SLSA Framework'],
            regulations: ['cra', 'nis2', 'dora'],
            mitigates: ['MITRE ATT&CK T1195 - Supply Chain Compromise']
          }
        ]
      },
      {
        id: 'dast',
        name: 'Dynamic Application Security Testing (DAST)',
        description: 'Testing dinámico en runtime',
        ssdlcPhases: ['testing'],
        questions: [
          {
            id: 'dev-das-1',
            question: '¿Se ejecuta DAST automáticamente en entornos de QA/staging?',
            description: 'Escaneo de aplicación en ejecución con herramientas como OWASP ZAP, Burp',
            level: 2,
            evidence: ['Configuración DAST', 'Reportes de escaneos', 'Integración en pipeline'],
            frameworks: ['OWASP SAMM - Security Testing', 'NIST SSDF - PW.8'],
            regulations: ['pci-dss', 'ens', 'ccn-stic'],
            mitigates: ['OWASP Top 10 (runtime vulnerabilities)', 'OWASP A05:2021 - Security Misconfiguration']
          },
          {
            id: 'dev-das-2',
            question: '¿El DAST incluye autenticación y coverage de funcionalidades críticas?',
            description: 'No solo escaneo de superficie, sino testing de lógica de negocio',
            level: 3,
            evidence: ['Configuración de autenticación', 'Cobertura funcional', 'Test cases específicos'],
            frameworks: ['OWASP SAMM', 'OWASP ASVS'],
            regulations: ['pci-dss'],
            mitigates: ['OWASP A01:2021 - Broken Access Control', 'Business Logic Flaws']
          },
          {
            id: 'dev-das-3',
            question: '¿Se combinan DAST + IAST (Interactive Application Security Testing)?',
            description: 'Instrumentación de aplicación para mayor precisión y cobertura',
            level: 4,
            evidence: ['Herramientas IAST configuradas', 'Resultados combinados', 'Reducción de falsos positivos'],
            frameworks: ['OWASP SAMM Level 3', 'BSIMM ST'],
            regulations: [],
            mitigates: []
          }
        ]
      },
      {
        id: 'secrets',
        name: 'Gestión de Secretos',
        description: 'Prevención de exposición de credenciales y secretos',
        ssdlcPhases: ['development', 'deployment'],
        questions: [
          {
            id: 'dev-sec-1',
            question: '¿Se escanea código y commits en busca de secretos hardcodeados?',
            description: 'Pre-commit hooks y escaneo de repositorios con TruffleHog, git-secrets, GitGuardian',
            level: 2,
            evidence: ['Herramientas de detección', 'Alertas de secretos', 'Remediación'],
            frameworks: ['OWASP SAMM', 'NIST SSDF - PS.2'],
            regulations: ['gdpr', 'pci-dss', 'hipaa'],
            mitigates: ['OWASP A07:2021 - Identification and Authentication Failures', 'MITRE ATT&CK T1552 - Unsecured Credentials']
          },
          {
            id: 'dev-sec-2',
            question: '¿Se utiliza un sistema centralizado de gestión de secretos (Vault, AWS Secrets Manager)?',
            description: 'No almacenar secretos en código, config files, env vars sin cifrar',
            level: 3,
            evidence: ['Sistema de secretos implementado', 'Rotación automática', 'Auditoría de accesos'],
            frameworks: ['OWASP ASVS V2.10', 'NIST SSDF', 'CIS Controls'],
            regulations: ['pci-dss', 'hipaa', 'nis2'],
            mitigates: ['MITRE ATT&CK T1552', 'OWASP A02:2021 - Cryptographic Failures']
          },
          {
            id: 'dev-sec-3',
            question: '¿Los secretos se rotan automáticamente y tienen ciclo de vida gestionado?',
            description: 'Rotación programada, expiración, revocación',
            level: 4,
            evidence: ['Políticas de rotación', 'Logs de rotación', 'Alertas de expiración'],
            frameworks: ['NIST 800-57', 'CIS Controls'],
            regulations: ['pci-dss', 'nis2', 'dora'],
            mitigates: []
          }
        ]
      },
      {
        id: 'containers',
        name: 'Seguridad de Contenedores e IaC',
        description: 'Docker, Kubernetes, Infrastructure as Code',
        ssdlcPhases: ['development', 'deployment'],
        questions: [
          {
            id: 'dev-con-1',
            question: '¿Se escanean imágenes de contenedores en busca de vulnerabilidades?',
            description: 'Integración de Trivy, Grype, Snyk Container en pipeline',
            level: 2,
            evidence: ['Escaneos de imágenes', 'Reportes de CVEs', 'Policy enforcement'],
            frameworks: ['NIST SSDF', 'CIS Docker Benchmark', 'CIS Kubernetes Benchmark'],
            regulations: ['nis2', 'cra'],
            mitigates: ['OWASP A06:2021 - Vulnerable Components']
          },
          {
            id: 'dev-con-2',
            question: '¿Se aplican políticas de seguridad en Kubernetes (Pod Security Standards, Network Policies)?',
            description: 'Restricted PSS, segregación de red, RBAC, secrets management',
            level: 3,
            evidence: ['Configuraciones K8s', 'Políticas aplicadas', 'Auditorías de compliance'],
            frameworks: ['CIS Kubernetes Benchmark', 'NSA/CISA Kubernetes Hardening Guide'],
            regulations: ['nis2', 'ens'],
            mitigates: ['MITRE ATT&CK for Containers', 'Kubernetes-specific threats']
          },
          {
            id: 'dev-con-3',
            question: '¿Se escanea Infrastructure as Code (Terraform, CloudFormation) con herramientas de seguridad?',
            description: 'Checkov, tfsec, Terrascan para detectar misconfigurations',
            level: 3,
            evidence: ['IaC scanning configurado', 'Reportes de misconfigurations', 'Remediation'],
            frameworks: ['NIST SSDF', 'CIS Benchmarks'],
            regulations: ['nis2', 'ens'],
            mitigates: ['OWASP A05:2021 - Security Misconfiguration', 'Cloud misconfigurations']
          },
          {
            id: 'dev-con-4',
            question: '¿Se firma y verifica integridad de imágenes de contenedores (Sigstore, Notary)?',
            description: 'Supply chain security para containers',
            level: 4,
            evidence: ['Firma de imágenes', 'Verificación en deployment', 'Políticas de admisión'],
            frameworks: ['SLSA Framework', 'NIST SSDF'],
            regulations: ['cra', 'nis2'],
            mitigates: ['MITRE ATT&CK T1525 - Implant Container Image']
          }
        ]
      }
    ]
  },
  {
    id: 'controls',
    name: 'Controles de Seguridad',
    icon: '🛡️',
    description: 'Testing avanzado, pentesting, gestión de vulnerabilidades',
    color: 'from-orange-600 to-red-600',
    practices: [
      {
        id: 'pentesting',
        name: 'Penetration Testing',
        description: 'Testing manual por expertos',
        ssdlcPhases: ['testing'],
        questions: [
          {
            id: 'con-pen-1',
            question: '¿Se realizan pentests en aplicaciones críticas antes de cada release mayor?',
            description: 'Pentesting manual por equipo interno o externo',
            level: 2,
            evidence: ['Informes de pentesting', 'Alcance definido', 'Remediación de hallazgos'],
            frameworks: ['OWASP SAMM - Security Testing', 'NIST SSDF - PW.9', 'PTES'],
            regulations: ['pci-dss', 'dora', 'ens', 'ccn-stic'],
            mitigates: ['OWASP Top 10', 'MITRE ATT&CK (múltiples técnicas)']
          },
          {
            id: 'con-pen-2',
            question: '¿El pentesting incluye testing de lógica de negocio y casos de abuso?',
            description: 'No solo vulnerabilidades técnicas, sino también business logic flaws',
            level: 3,
            evidence: ['Test cases de lógica', 'Abuse cases', 'Resultados específicos'],
            frameworks: ['OWASP ASVS V4', 'OWASP Testing Guide'],
            regulations: ['pci-dss'],
            mitigates: ['Business Logic Flaws', 'OWASP A04:2021 - Insecure Design']
          },
          {
            id: 'con-pen-3',
            question: '¿Para sistemas financieros se realizan TLPT (Threat-Led Penetration Testing)?',
            description: 'Red team exercises simulando adversarios reales (DORA requirement)',
            level: 4,
            evidence: ['Informes TLPT', 'Escenarios de amenaza', 'Remediación'],
            frameworks: ['TIBER-EU', 'CBEST'],
            regulations: ['dora'],
            mitigates: ['APT tactics', 'MITRE ATT&CK (advanced)']
          }
        ]
      },
      {
        id: 'vuln-management',
        name: 'Gestión de Vulnerabilidades',
        description: 'Proceso de remediación y seguimiento',
        ssdlcPhases: ['testing', 'operations', 'monitoring'],
        questions: [
          {
            id: 'con-vul-1',
            question: '¿Existe proceso formal de gestión de vulnerabilidades con SLAs por severidad?',
            description: 'Críticas: 7 días, Altas: 30 días, Medias: 90 días (ejemplo)',
            level: 2,
            evidence: ['Política de SLAs', 'Dashboard de vulnerabilidades', 'Tracking en backlog'],
            frameworks: ['OWASP SAMM - Defect Management', 'NIST SSDF - RV.1', 'ISO 27001 A.12.6'],
            regulations: ['nis2', 'cra', 'ens', 'pci-dss'],
            mitigates: []
          },
          {
            id: 'con-vul-2',
            question: '¿Se priorizan vulnerabilidades usando scoring contextual (CVSS + explotabilidad + criticidad activo)?',
            description: 'No solo CVSS base, sino CVSS temporal y environmental',
            level: 3,
            evidence: ['Metodología de priorización', 'Risk scoring', 'Decisiones documentadas'],
            frameworks: ['OWASP Risk Rating', 'CVSS v4.0'],
            regulations: ['nis2', 'dora'],
            mitigates: []
          },
          {
            id: 'con-vul-3',
            question: '¿Se realiza análisis de causa raíz de vulnerabilidades recurrentes?',
            description: 'Identificar patrones, capacitar, mejorar controles preventivos',
            level: 4,
            evidence: ['Informes de RCA', 'Trending de vulnerabilidades', 'Acciones correctivas'],
            frameworks: ['OWASP SAMM', 'BSIMM CMVM'],
            regulations: [],
            mitigates: []
          },
          {
            id: 'con-vul-4',
            question: '¿Existe proceso de divulgación responsable de vulnerabilidades (coordinated disclosure)?',
            description: 'VDP (Vulnerability Disclosure Policy) o Bug Bounty program',
            level: 4,
            evidence: ['VDP publicado', 'Bug bounty platform', 'Proceso de triaje'],
            frameworks: ['ISO 29147', 'ISO 30111'],
            regulations: ['cra', 'nis2'],
            mitigates: []
          }
        ]
      },
      {
        id: 'monitoring',
        name: 'Monitorización y Respuesta',
        description: 'Detección de amenazas y respuesta a incidentes',
        ssdlcPhases: ['operations', 'monitoring'],
        questions: [
          {
            id: 'con-mon-1',
            question: '¿Se monitorizan logs de seguridad de aplicaciones en SIEM/SOAR?',
            description: 'Logs de autenticación, autorización, inyección, errores críticos',
            level: 2,
            evidence: ['Integración con SIEM', 'Dashboards de seguridad', 'Alertas configuradas'],
            frameworks: ['OWASP ASVS V7', 'NIST SSDF - RV.2', 'ISO 27001 A.12.4'],
            regulations: ['nis2', 'dora', 'ens', 'pci-dss', 'hipaa'],
            mitigates: ['MITRE ATT&CK: Defense Evasion, Credential Access']
          },
          {
            id: 'con-mon-2',
            question: '¿Existe detección de comportamiento anómalo (UEBA, anomaly detection)?',
            description: 'ML/AI para detectar patrones inusuales de uso',
            level: 3,
            evidence: ['Herramientas UEBA', 'Modelos de ML', 'Alertas de anomalías'],
            frameworks: ['MITRE ATT&CK', 'NIST CSF - Detect'],
            regulations: ['dora', 'nis2'],
            mitigates: ['MITRE ATT&CK: Lateral Movement, Exfiltration']
          },
          {
            id: 'con-mon-3',
            question: '¿Se realizan ejercicios de respuesta a incidentes (tabletop, simulacros)?',
            description: 'Preparación del equipo para incidentes de seguridad de aplicaciones',
            level: 3,
            evidence: ['Plan de respuesta a incidentes', 'Ejercicios realizados', 'Lecciones aprendidas'],
            frameworks: ['NIST 800-61', 'ISO 27035'],
            regulations: ['nis2', 'dora', 'ens'],
            mitigates: []
          },
          {
            id: 'con-mon-4',
            question: '¿Existe Runtime Application Self-Protection (RASP) o WAF con ML?',
            description: 'Protección en tiempo real contra ataques',
            level: 4,
            evidence: ['RASP/WAF configurado', 'Reglas personalizadas', 'Análisis de tráfico'],
            frameworks: ['OWASP SAMM', 'NIST CSF - Protect'],
            regulations: ['pci-dss'],
            mitigates: ['OWASP Top 10 (runtime protection)', 'Zero-day exploits']
          }
        ]
      },
      {
        id: 'incident-response',
        name: 'Respuesta a Incidentes',
        description: 'Proceso de gestión y respuesta a incidentes de seguridad',
        ssdlcPhases: ['operations', 'monitoring'],
        questions: [
          {
            id: 'con-inc-1',
            question: '¿Existe un plan de respuesta a incidentes de seguridad de aplicaciones?',
            description: 'Procedimientos de detección, contención, erradicación, recuperación',
            level: 2,
            evidence: ['Plan de IR documentado', 'Roles y responsabilidades', 'Procedimientos de escalado'],
            frameworks: ['NIST 800-61', 'ISO 27035', 'SANS IR'],
            regulations: ['nis2', 'dora', 'ens', 'gdpr'],
            mitigates: []
          },
          {
            id: 'con-inc-2',
            question: '¿Se cumple con plazos de notificación de incidentes según regulaciones (24h-72h)?',
            description: 'GDPR 72h, NIS2 24h alerta + 72h informe, DORA inmediato',
            level: 3,
            evidence: ['Proceso de notificación', 'Templates de comunicación', 'Registro de incidentes'],
            frameworks: ['ISO 27035'],
            regulations: ['gdpr', 'nis2', 'dora', 'cra'],
            mitigates: []
          },
          {
            id: 'con-inc-3',
            question: '¿Se realiza análisis forense y post-mortem de incidentes?',
            description: 'Root cause analysis, timeline reconstruction, lecciones aprendidas',
            level: 3,
            evidence: ['Informes post-mortem', 'Evidencias preservadas', 'Mejoras implementadas'],
            frameworks: ['NIST 800-61', 'SANS FOR'],
            regulations: ['nis2', 'dora'],
            mitigates: []
          }
        ]
      }
    ]
  },
  
  // ==================== NUEVO DOMINIO: AI SECURITY ====================
  {
    id: 'ai-security',
    name: 'Seguridad de IA y LLMs',
    icon: '🤖',
    description: 'Seguridad de sistemas de IA, LLMs y protección contra ataques de prompt injection',
    color: 'from-purple-600 to-pink-600',
    practices: [
      {
        id: 'llm-security',
        name: 'Seguridad de Large Language Models',
        description: 'Protección contra ataques específicos de LLMs según OWASP LLM Top 10',
        ssdlcPhases: ['design', 'implementation', 'testing'],
        questions: [
          {
            id: 'ai-llm-1',
            question: '¿Se validan y sanitizan los inputs de usuario antes de pasarlos a LLMs?',
            description: 'Prevención de prompt injection mediante validación, límites de caracteres y detección de patrones maliciosos',
            level: 1,
            evidence: ['Reglas de validación documentadas', 'Filters implementados', 'Logs de inputs bloqueados'],
            frameworks: ['OWASP LLM01 - Prompt Injection', 'MITRE ATLAS', 'NIST AI RMF'],
            regulations: ['ai-act', 'gdpr'],
            mitigates: ['OWASP LLM Top 10 - LLM01 Prompt Injection', 'Data exfiltration via prompts']
          },
          {
            id: 'ai-llm-2',
            question: '¿Los system prompts están protegidos contra extracción (prompt leaking)?',
            description: 'Técnicas de hardening: instrucciones inmutables, detección de intentos de extracción, separación de contextos',
            level: 2,
            evidence: ['System prompts securizados', 'Detección de leaking attempts', 'Logs de alertas'],
            frameworks: ['OWASP LLM01', 'Prompt Engineering Security'],
            regulations: ['ai-act'],
            mitigates: ['OWASP LLM Top 10 - LLM01', 'Intellectual property theft']
          },
          {
            id: 'ai-llm-3',
            question: '¿Se implementa validación de outputs del LLM antes de mostrarlos al usuario?',
            description: 'Filtrado de información sensible, detección de hallucinations, validación de formato',
            level: 2,
            evidence: ['Output filtering', 'Sensitive data detection', 'Hallucination mitigation'],
            frameworks: ['OWASP LLM02 - Insecure Output Handling', 'OWASP LLM09 - Overreliance'],
            regulations: ['gdpr', 'ai-act'],
            mitigates: ['OWASP LLM02 Insecure Output Handling', 'XSS via LLM outputs', 'Data leakage']
          },
          {
            id: 'ai-llm-4',
            question: '¿Se evita el training data poisoning mediante validación de datasets?',
            description: 'Auditoría de fuentes de datos, detección de backdoors, validación de calidad',
            level: 3,
            evidence: ['Data provenance tracking', 'Dataset validation', 'Backdoor detection'],
            frameworks: ['OWASP LLM03 - Training Data Poisoning', 'MITRE ATLAS AML.T0018'],
            regulations: ['ai-act'],
            mitigates: ['OWASP LLM03 Training Data Poisoning', 'Backdoor attacks', 'Bias injection']
          },
          {
            id: 'ai-llm-5',
            question: '¿Existe control de acceso granular a funciones y plugins del LLM?',
            description: 'Least privilege para function calling, validación de permisos, audit logs',
            level: 2,
            evidence: ['RBAC para plugins', 'Permission validation', 'Function call logs'],
            frameworks: ['OWASP LLM07 - Insecure Plugin Design', 'OWASP LLM08 - Excessive Agency'],
            regulations: ['iso-27001', 'ai-act'],
            mitigates: ['OWASP LLM07', 'OWASP LLM08', 'Unauthorized actions', 'Privilege escalation']
          },
          {
            id: 'ai-llm-6',
            question: '¿Se implementa rate limiting y detección de DoS en endpoints de IA?',
            description: 'Límites por usuario/IP, detección de abuse, throttling inteligente',
            level: 2,
            evidence: ['Rate limits configurados', 'Abuse detection', 'Cost monitoring'],
            frameworks: ['OWASP LLM04 - Model Denial of Service', 'OWASP API Security'],
            regulations: ['nis2'],
            mitigates: ['OWASP LLM04 DoS', 'Resource exhaustion', 'Cost overflow']
          },
          {
            id: 'ai-llm-7',
            question: '¿Se protegen los datos sensibles en el contexto del LLM (RAG, embeddings)?',
            description: 'Encriptación de vectores, anonimización, control de acceso a knowledge bases',
            level: 3,
            evidence: ['Encryption at rest', 'Access controls', 'Data anonymization'],
            frameworks: ['OWASP LLM06 - Sensitive Information Disclosure', 'OWASP LLM10 - Model Theft'],
            regulations: ['gdpr', 'hipaa', 'ai-act'],
            mitigates: ['OWASP LLM06 Data Disclosure', 'OWASP LLM10 Model Theft', 'PII leakage']
          },
          {
            id: 'ai-llm-8',
            question: '¿Se validan las dependencias y supply chain de modelos y librerías de IA?',
            description: 'SBOM de modelos, verificación de checksums, fuentes confiables',
            level: 3,
            evidence: ['Model SBOM', 'Checksum verification', 'Trusted sources only'],
            frameworks: ['OWASP LLM05 - Supply Chain Vulnerabilities', 'SLSA', 'NIST SSDF'],
            regulations: ['cra', 'ai-act'],
            mitigates: ['OWASP LLM05 Supply Chain', 'Compromised models', 'Malicious libraries']
          }
        ]
      },
      {
        id: 'ai-red-teaming',
        name: 'Red Teaming de IA',
        description: 'Testing adversarial y evaluación de robustez contra ataques',
        ssdlcPhases: ['testing', 'operations'],
        questions: [
          {
            id: 'ai-red-1',
            question: '¿Se realizan ejercicios de red teaming específicos para LLMs?',
            description: 'Testing de jailbreak, prompt injection, data extraction, adversarial prompts',
            level: 3,
            evidence: ['Red team exercises', 'Attack scenarios documented', 'Vulnerabilities found & fixed'],
            frameworks: ['OWASP LLM Testing Guide', 'MITRE ATLAS', 'AI Red Teaming Guide'],
            regulations: ['ai-act'],
            mitigates: ['All OWASP LLM Top 10', 'Zero-day prompt attacks']
          },
          {
            id: 'ai-red-2',
            question: '¿Existe un programa de bug bounty o VDP para sistemas de IA?',
            description: 'Recompensas por encontrar vulnerabilidades en prompts, modelo, outputs',
            level: 4,
            evidence: ['Bug bounty program', 'VDP publicado', 'Researcher engagement'],
            frameworks: ['ISO 29147', 'ISO 30111'],
            regulations: ['ai-act', 'cra'],
            mitigates: ['Unknown vulnerabilities', 'Community-driven security']
          },
          {
            id: 'ai-red-3',
            question: '¿Se miden métricas de robustez del modelo (adversarial accuracy, ASR)?',
            description: 'Attack Success Rate, Robustness Score, Prompt Injection Detection Rate',
            level: 3,
            evidence: ['Robustness metrics', 'ASR benchmarks', 'Trending analysis'],
            frameworks: ['NIST AI RMF', 'MLOps Best Practices'],
            regulations: ['ai-act'],
            mitigates: ['Model degradation', 'Attack effectiveness tracking']
          }
        ]
      },
      {
        id: 'ai-governance',
        name: 'Gobernanza de IA',
        description: 'Políticas, compliance y gestión de riesgos de IA',
        ssdlcPhases: ['requirements', 'design'],
        questions: [
          {
            id: 'ai-gov-1',
            question: '¿Existe una política de uso responsable de IA y LLMs?',
            description: 'Directrices de uso ético, límites, casos de uso prohibidos',
            level: 1,
            evidence: ['AI Policy documentada', 'Casos de uso aprobados', 'Training de usuarios'],
            frameworks: ['NIST AI RMF', 'EU AI Act', 'ISO 42001'],
            regulations: ['ai-act', 'gdpr'],
            mitigates: ['Misuse', 'Ethical violations', 'Regulatory penalties']
          },
          {
            id: 'ai-gov-2',
            question: '¿Se realiza evaluación de impacto de privacidad para sistemas con LLMs (DPIA)?',
            description: 'DPIA según GDPR Art. 35 para procesamiento con IA',
            level: 2,
            evidence: ['DPIA completado', 'Riesgos identificados', 'Mitigaciones implementadas'],
            frameworks: ['GDPR Art. 35', 'ISO 27701', 'NIST Privacy Framework'],
            regulations: ['gdpr', 'ai-act'],
            mitigates: ['Privacy violations', 'Unlawful processing', 'Data breaches']
          },
          {
            id: 'ai-gov-3',
            question: '¿Se documenta el inventario de modelos de IA y sus riesgos (AI Model Card)?',
            description: 'Model Cards con capabilities, limitations, biases, risks',
            level: 2,
            evidence: ['Model registry', 'Model cards', 'Risk assessments'],
            frameworks: ['Model Cards (Google)', 'NIST AI RMF', 'ISO 42001'],
            regulations: ['ai-act'],
            mitigates: ['Unknown AI assets', 'Undocumented risks', 'Accountability gaps']
          },
          {
            id: 'ai-gov-4',
            question: '¿Se cumple con requisitos de transparencia del EU AI Act (high-risk AI)?',
            description: 'Documentación técnica, logs, human oversight, conformity assessment',
            level: 4,
            evidence: ['Technical documentation', 'Audit logs', 'Human oversight mechanisms'],
            frameworks: ['EU AI Act Art. 13-15', 'ISO 42001'],
            regulations: ['ai-act'],
            mitigates: ['Non-compliance', 'Fines', 'Operational restrictions']
          }
        ]
      },
      {
        id: 'ai-monitoring',
        name: 'Monitorización de IA',
        description: 'Observability, detección de ataques y anomalías en sistemas de IA',
        ssdlcPhases: ['operations', 'monitoring'],
        questions: [
          {
            id: 'ai-mon-1',
            question: '¿Se monitorizan y alertan intentos de prompt injection en tiempo real?',
            description: 'Detección de patrones: "ignore instructions", encoding, jailbreak attempts',
            level: 2,
            evidence: ['Detection rules', 'Real-time alerts', 'SIEM integration'],
            frameworks: ['OWASP LLM01', 'MITRE ATLAS'],
            regulations: ['nis2', 'ai-act'],
            mitigates: ['OWASP LLM01', 'Real-time attack prevention']
          },
          {
            id: 'ai-mon-2',
            question: '¿Se registran y auditan todas las interacciones con LLMs?',
            description: 'Logs de prompts (sanitizados), responses, tokens, latency, errors',
            level: 2,
            evidence: ['Comprehensive logging', 'Audit trail', 'Retention policy'],
            frameworks: ['OWASP ASVS V7', 'ISO 27001 A.12.4', 'NIST AI RMF'],
            regulations: ['gdpr', 'ai-act', 'nis2'],
            mitigates: ['Forensics', 'Compliance', 'Incident investigation']
          },
          {
            id: 'ai-mon-3',
            question: '¿Se detectan model drift y degradación de performance?',
            description: 'Monitoring de accuracy, hallucination rate, response quality',
            level: 3,
            evidence: ['Model monitoring', 'Performance metrics', 'Drift alerts'],
            frameworks: ['MLOps', 'NIST AI RMF', 'ISO 42001'],
            regulations: ['ai-act'],
            mitigates: ['Model degradation', 'Quality issues', 'Silent failures']
          },
          {
            id: 'ai-mon-4',
            question: '¿Existe detección de data exfiltration vía outputs del LLM?',
            description: 'DLP para outputs, detección de PII, secrets scanning',
            level: 3,
            evidence: ['DLP rules', 'PII detection', 'Secrets scanning'],
            frameworks: ['OWASP LLM06', 'GDPR', 'Data Protection'],
            regulations: ['gdpr', 'hipaa', 'pci-dss'],
            mitigates: ['OWASP LLM06', 'Data breaches', 'PII exposure']
          }
        ]
      }
    ]
  }
];

// Helper para calcular nivel de madurez de un dominio
export const calculateDomainMaturity = (responses: Record<string, boolean>): number => {
  const answeredYes = Object.values(responses).filter(v => v).length;
  const total = Object.values(responses).length;
  return total > 0 ? Math.round((answeredYes / total) * 5) : 0;
};

// Mapeo de normativas prioritarias por sector
const sectorRegulations: Record<string, string[]> = {
  financiero: ['dora', 'nis2', 'pci-dss', 'gdpr', 'iso-27001'],
  salud: ['gdpr', 'hipaa', 'iec-81001', 'iso-27001', 'nis2'],
  industrial: ['iec-62443', 'iso-21434', 'nis2', 'cra', 'iso-27001'],
  tecnologia: ['gdpr', 'iso-27001', 'soc2', 'cra', 'ai-act'],
  general: ['iso-27001', 'gdpr', 'nist-800-53', 'nis2', 'soc2']
};

// Helper para generar recomendaciones sector-aware
export const generateRecommendations = (
  domain: AssessmentDomain,
  responses: Record<string, boolean>,
  sector: string = 'general'
): string[] => {
  const recommendations: { 
    text: string; 
    priority: number; 
    level: number;
    hasRegulation: boolean;
  }[] = [];
  
  const priorityRegulations = sectorRegulations[sector] || sectorRegulations.general;
  
  domain.practices.forEach(practice => {
    practice.questions.forEach(question => {
      if (!responses[question.id]) {
        // Verificar si la pregunta está vinculada a normativas prioritarias del sector
        const hasRelevantRegulation = question.regulations.some(reg => 
          priorityRegulations.includes(reg)
        );
        
        // Calcular prioridad:
        // - Nivel bajo (1-2) = alta prioridad (fundamentos)
        // - Normativa sectorial = +5 puntos
        // - MITRE ATT&CK = +3 puntos (amenazas reales)
        let priority = 10 - question.level; // Nivel 1 = 9, Nivel 5 = 5
        
        if (hasRelevantRegulation) priority += 5;
        if (question.mitigates.length > 0) priority += 3;
        
        recommendations.push({
          text: `${practice.name}: ${question.question}`,
          priority,
          level: question.level,
          hasRegulation: hasRelevantRegulation
        });
      }
    });
  });
  
  // Ordenar por prioridad descendente
  recommendations.sort((a, b) => b.priority - a.priority);
  
  // Retornar top 5 con indicadores
  return recommendations.slice(0, 5).map(rec => {
    const badges = [];
    if (rec.hasRegulation) badges.push(`[${sector.toUpperCase()}]`);
    if (rec.level <= 2) badges.push('[BÁSICO]');
    const prefix = badges.length > 0 ? `${badges.join(' ')} ` : '';
    return `${prefix}${rec.text}`;
  });
};
