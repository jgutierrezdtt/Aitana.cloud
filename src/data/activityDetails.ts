// Detalles completos de actividades SSDLC con normativas, herramientas y mejores prácticas

export interface ActivityDetail {
  activity: string;
  area: string;
  phase: string;
  description: string;
  regulations: string[];
  tools: string[];
  bestPractices: string[];
  metrics: string[];
}

export const activityDetailsMap: Record<string, ActivityDetail> = {
  // REQUIREMENTS - GOVERNANCE
  "requirements_governance_0": {
    activity: "Definir clasificación de datos del proyecto",
    area: "Gobierno del SSDLC",
    phase: "Requirements",
    description: "Establecer niveles de clasificación de datos (público, interno, confidencial, crítico) para determinar controles de seguridad aplicables",
    regulations: [
      "GDPR Art. 32 - Seguridad del tratamiento",
      "ISO 27001 A.8.2.1 - Clasificación de información",
      "PCI-DSS 3.2.1 Req. 9 - Proteger datos de titulares",
      "NIST SP 800-53 MP-1 - Media Protection Policy"
    ],
    tools: [
      "Microsoft Information Protection para etiquetado automático",
      "Varonis Data Classification Framework",
      "BigID para descubrimiento y clasificación de datos sensibles"
    ],
    bestPractices: [
      "Definir matriz de clasificación con criterios objetivos (PII, secretos comerciales, datos financieros)",
      "Involucrar a stakeholders legales y de negocio en la definición de niveles",
      "Automatizar etiquetado cuando sea posible mediante DLP y metadata",
      "Revisar clasificación anualmente o cuando cambie el contexto regulatorio"
    ],
    metrics: [
      "% de datasets clasificados vs total",
      "Tiempo promedio para clasificar nuevos datos",
      "# de incidentes relacionados con clasificación incorrecta"
    ]
  },
  
  "requirements_governance_1": {
    activity: "Identificar requisitos regulatorios aplicables",
    area: "Gobierno del SSDLC",
    phase: "Requirements",
    description: "Mapear regulaciones, estándares y frameworks de compliance que aplican según industria, geografía y tipo de datos",
    regulations: [
      "GDPR - Protección de datos en UE",
      "HIPAA - Datos de salud en USA",
      "PCI-DSS - Datos de pago",
      "SOX - Controles financieros",
      "ISO 27001 - Sistema de gestión de seguridad"
    ],
    tools: [
      "OneTrust para gestión de privacidad y compliance",
      "ServiceNow GRC para mapeo de controles",
      "Vanta para automatización de compliance continuo"
    ],
    bestPractices: [
      "Crear matriz de aplicabilidad regulatoria por producto/servicio",
      "Asignar DPO o compliance officer desde inicio del proyecto",
      "Documentar gaps de compliance en fase temprana",
      "Establecer requisitos de residencia de datos según GDPR/Cloud Act"
    ],
    metrics: [
      "# de regulaciones identificadas y mapeadas",
      "% de requisitos implementados vs identificados",
      "Tiempo de respuesta a consultas regulatorias"
    ]
  },

  // REQUIREMENTS - DESIGN
  "requirements_design_0": {
    activity: "Especificar requisitos de autenticación y autorización",
    area: "Seguridad por Diseño",
    phase: "Requirements",
    description: "Definir mecanismos de autenticación (MFA, SSO, passwordless) y modelo de autorización (RBAC, ABAC) según criticidad",
    regulations: [
      "NIST SP 800-63B - Digital Identity Guidelines",
      "PCI-DSS Req. 8 - Identificar y autenticar acceso",
      "ISO 27001 A.9.4 - Sistema de gestión de acceso",
      "GDPR Art. 32 - Medidas técnicas apropiadas"
    ],
    tools: [
      "Okta, Auth0, Azure AD para SSO enterprise",
      "FIDO2/WebAuthn para passwordless",
      "OAuth 2.0 + OpenID Connect para APIs"
    ],
    bestPractices: [
      "MFA obligatorio para funciones administrativas y datos sensibles",
      "Implementar principio de least privilege desde diseño",
      "Usar tokens con expiración corta y refresh tokens seguros",
      "Planificar federación de identidades para B2B"
    ],
    metrics: [
      "% de usuarios con MFA habilitado",
      "Tasa de adopción de passwordless",
      "# de intentos de autenticación fallidos"
    ]
  },

  // DESIGN - DESIGN
  "design_design_0": {
    activity: "Ejecutar threat modeling (STRIDE/PASTA)",
    area: "Seguridad por Diseño",
    phase: "Design",
    description: "Análisis sistemático de amenazas usando metodologías como STRIDE para identificar riesgos en arquitectura",
    regulations: [
      "ISO 27001 A.14.1.2 - Asegurar servicios de aplicación",
      "NIST SP 800-30 - Risk Assessment",
      "PCI-DSS 6.5 - Vulnerabilidades comunes en desarrollo",
      "OWASP SAMM - Threat Assessment"
    ],
    tools: [
      "Microsoft Threat Modeling Tool",
      "OWASP Threat Dragon",
      "IriusRisk para threat modeling automatizado",
      "ThreatModeler para enterprise"
    ],
    bestPractices: [
      "Ejecutar threat modeling en arquitectura review meetings",
      "Usar STRIDE para clasificar amenazas: Spoofing, Tampering, Repudiation, Info Disclosure, DoS, Elevation",
      "Documentar controles para cada amenaza identificada",
      "Revisar threat model cuando cambien componentes críticos"
    ],
    metrics: [
      "# de amenazas identificadas por componente",
      "% de amenazas mitigadas con controles",
      "Cobertura de threat modeling en proyectos críticos"
    ]
  },

  // DEVELOPMENT - DEVSECOPS
  "development_devsecops_0": {
    activity: "SAST en cada commit con SonarQube/Semgrep",
    area: "DevSecOps",
    phase: "Development",
    description: "Análisis estático de código en pipeline CI/CD para detectar vulnerabilidades antes de merge",
    regulations: [
      "PCI-DSS 6.3.2 - Revisión de código",
      "OWASP ASVS V14 - Configuration",
      "ISO 27001 A.14.2.1 - Política de desarrollo seguro"
    ],
    tools: [
      "SonarQube para análisis completo multi-lenguaje",
      "Semgrep para reglas custom y SAST rápido",
      "Checkmarx, Fortify para enterprise",
      "Snyk Code para análisis en IDE"
    ],
    bestPractices: [
      "Configurar quality gates que bloqueen merge si hay vulnerabilidades críticas",
      "Priorizar remediación según CVSS y explotabilidad",
      "Crear reglas custom para patrones específicos del negocio",
      "Integrar feedback en IDE para fix inmediato"
    ],
    metrics: [
      "# de vulnerabilidades detectadas pre-producción",
      "Tiempo medio de remediación por severidad",
      "Tasa de falsos positivos"
    ]
  },

  // TESTING - DEVSECOPS
  "testing_devsecops_0": {
    activity: "DAST con OWASP ZAP/Burp en staging",
    area: "DevSecOps",
    phase: "Testing",
    description: "Dynamic Application Security Testing en entorno de staging para detectar vulnerabilidades en runtime",
    regulations: [
      "OWASP Top 10 - Principales riesgos",
      "PCI-DSS 6.6 - Revisiones de aplicaciones públicas",
      "ISO 27001 A.14.2.8 - Testing de seguridad"
    ],
    tools: [
      "OWASP ZAP para escaneos automatizados",
      "Burp Suite Enterprise para testing avanzado",
      "Acunetix, Netsparker para enterprise",
      "StackHawk para DAST en CI/CD"
    ],
    bestPractices: [
      "Ejecutar DAST en staging con datos realistas pero no sensibles",
      "Combinar escaneos programados y on-demand",
      "Integrar con issue tracking (Jira) para remediación",
      "Validar findings con pentest manual en aplicaciones críticas"
    ],
    metrics: [
      "# de vulnerabilidades OWASP Top 10 detectadas",
      "Tiempo de escaneo completo",
      "% de cobertura de endpoints"
    ]
  },

  // DEPLOYMENT - CONTROLS
  "deployment_controls_0": {
    activity: "Activar monitoreo de seguridad en SIEM",
    area: "Controles de Seguridad",
    phase: "Deployment",
    description: "Configurar recolección de logs de seguridad y correlación de eventos en SIEM antes de go-live",
    regulations: [
      "PCI-DSS 10.1 - Implementar audit trails",
      "GDPR Art. 32 - Capacidad de detectar brechas",
      "ISO 27001 A.12.4 - Logging y monitoreo",
      "NIST SP 800-53 AU-2 - Audit Events"
    ],
    tools: [
      "Splunk Enterprise Security para SIEM",
      "ELK Stack (Elasticsearch, Logstash, Kibana)",
      "Azure Sentinel para cloud-native",
      "Datadog Security Monitoring"
    ],
    bestPractices: [
      "Definir casos de uso de detección (login failures, privilege escalation, data exfiltration)",
      "Configurar alertas con severidad y playbooks de respuesta",
      "Asegurar logs tamper-proof con firmas digitales",
      "Retención de logs según compliance (6-12 meses mínimo)"
    ],
    metrics: [
      "# de eventos de seguridad por día",
      "Tiempo medio de detección (MTTD)",
      "% de alertas investigadas en SLA"
    ]
  },

  // MONITORING - CONTROLS
  "monitoring_controls_0": {
    activity: "Threat hunting proactivo con MITRE ATT&CK",
    area: "Controles de Seguridad",
    phase: "Monitoring",
    description: "Búsqueda activa de amenazas usando framework MITRE ATT&CK para detectar TTPs de atacantes",
    regulations: [
      "NIST CSF - Detect (DE)",
      "ISO 27001 A.16.1 - Gestión de incidentes",
      "PCI-DSS 11.4 - Detección de intrusiones"
    ],
    tools: [
      "MITRE Caldera para emulación de adversarios",
      "Atomic Red Team para testing de detecciones",
      "Splunk Threat Hunting app",
      "Elastic Security con integration MITRE ATT&CK"
    ],
    bestPractices: [
      "Desarrollar hipótesis basadas en threat intelligence",
      "Mapear detecciones a técnicas MITRE ATT&CK",
      "Ejecutar purple team exercises (red + blue team)",
      "Documentar findings y mejorar playbooks"
    ],
    metrics: [
      "# de hipótesis de threat hunting ejecutadas",
      "% de técnicas MITRE ATT&CK con cobertura de detección",
      "Amenazas avanzadas detectadas pre-breach"
    ]
  }
};
