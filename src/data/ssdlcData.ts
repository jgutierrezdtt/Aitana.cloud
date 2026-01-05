// Datos detallados para modales de actividades SSDLC
export const activityDetails: Record<string, {
  description: string;
  regulations: string[];
  tools: string[];
  bestPractices: string[];
  metrics: string[];
}> = {
  // Governance - Requirements
  "governance-requirements-0": {
    description: "Clasificación de datos según niveles de sensibilidad (Público, Interno, Confidencial, Crítico) para establecer controles de seguridad apropiados.",
    regulations: ["ISO 27001 A.8.2.1", "GDPR Art. 5", "PCI-DSS Req. 3"],
    tools: ["Microsoft Information Protection", "Varonis", "BigID"],
    bestPractices: [
      "Crear matriz de clasificación clara y documentada",
      "Automatizar etiquetado cuando sea posible",
      "Revisar clasificación trimestralmente",
      "Integrar con DLP para enforcement automático"
    ],
    metrics: ["% datos clasificados", "Tiempo medio de clasificación", "Incidentes de mala clasificación"]
  },
  "governance-requirements-1": {
    description: "Identificación temprana de requisitos de GDPR, HIPAA, PCI-DSS, SOC 2 u otras regulaciones aplicables al proyecto.",
    regulations: ["GDPR Art. 25", "HIPAA §164.308", "PCI-DSS Req. 12.3"],
    tools: ["OneTrust", "TrustArc", "Compliance.ai"],
    bestPractices: [
      "Realizar Data Protection Impact Assessment (DPIA) si aplica GDPR",
      "Documentar decisiones de compliance en ADRs",
      "Involucrar Legal y Compliance desde el inicio",
      "Crear checklist de requisitos regulatorios"
    ],
    metrics: ["% proyectos con DPIA completado", "Días para aprobación regulatoria"]
  },
  
  // Design - Requirements
  "design-requirements-0": {
    description: "Especificación de mecanismos de autenticación (MFA, SSO, biométricos) y modelos de autorización (RBAC, ABAC).",
    regulations: ["NIST 800-63B", "ISO 27001 A.9.4", "PCI-DSS Req. 8"],
    tools: ["Auth0", "Okta", "Azure AD", "AWS Cognito"],
    bestPractices: [
      "MFA obligatorio para funciones privilegiadas",
      "Implementar principle of least privilege",
      "Sesiones con timeout adecuado por criticidad",
      "Soporte para passwordless cuando sea posible"
    ],
    metrics: ["% usuarios con MFA activado", "Intentos de autenticación fallidos", "Promedio de permisos por rol"]
  },

  // DevSecOps - Development
  "devsecops-development-0": {
    description: "Análisis estático de código (SAST) en cada commit para detectar vulnerabilidades antes de merge.",
    regulations: ["OWASP ASVS 14.1", "PCI-DSS Req. 6.3.2"],
    tools: ["SonarQube", "Semgrep", "Checkmarx", "Fortify", "Snyk Code"],
    bestPractices: [
      "Configurar quality gates con umbrales de seguridad",
      "Integrar en pre-commit hooks",
      "Tuning regular para reducir falsos positivos",
      "Training a desarrolladores sobre hallazgos comunes"
    ],
    metrics: ["Vulnerabilidades detectadas por severidad", "Tiempo medio de remediación", "% falsos positivos"]
  },

  // Controls - Testing
  "controls-testing-0": {
    description: "Pentesting manual por equipo especializado para validar controles de seguridad end-to-end.",
    regulations: ["PCI-DSS Req. 11.3", "ISO 27001 A.12.6", "NIST SP 800-115"],
    tools: ["Burp Suite Pro", "Metasploit", "Cobalt Strike", "BloodHound"],
    bestPractices: [
      "Ejecutar pentests antes de cada release mayor",
      "Scope claro: graybox vs blackbox",
      "Retest de vulnerabilidades críticas corregidas",
      "Documentar todas las excepciones aprobadas"
    ],
    metrics: ["Vulnerabilidades críticas encontradas", "% remediadas antes de producción", "Cobertura de superficie de ataque"]
  }
};
