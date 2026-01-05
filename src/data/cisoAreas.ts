// Definición de áreas CISO y sus pilares

export interface CISOPillar {
  title: string;
  items: string[];
}

export interface CISOAreaData {
  title: string;
  icon: string;
  gradient: string;
  description: string;
  pillars: CISOPillar[];
}

export type CISOArea = 'governance' | 'design' | 'devsecops' | 'controls';

export const cisoAreasData: Record<CISOArea, CISOAreaData> = {
  governance: {
    title: "Gobierno del SSDLC",
    icon: "⚖️",
    gradient: "from-blue-600 to-cyan-600",
    description: "Marco de políticas, estándares y procesos para garantizar la seguridad en todo el ciclo de vida del desarrollo",
    pillars: [
      {
        title: "Políticas y Estándares de Seguridad",
        items: [
          "Política corporativa de desarrollo seguro alineada con ISO 27001 y NIST",
          "Estándares de codificación segura (OWASP ASVS, CWE Top 25)",
          "Requisitos de seguridad mínimos por clasificación de datos",
          "Política de gestión de vulnerabilidades con SLAs por criticidad",
          "Estándares de arquitectura de referencia segura"
        ]
      },
      {
        title: "Gestión de Riesgos en SSDLC",
        items: [
          "Metodología de threat modeling (STRIDE, PASTA) en fase de diseño",
          "Análisis de riesgos de terceros y componentes open source",
          "Risk scoring basado en CVSS y contexto de negocio",
          "Matriz de aceptación de riesgos con umbrales por entorno"
        ]
      },
      {
        title: "Compliance y Frameworks Regulatorios",
        items: [
          "Mapeo de controles: PCI-DSS, GDPR, HIPAA, SOC 2, ISO 27001",
          "Trazabilidad de requisitos regulatorios a controles técnicos",
          "Evidencias automatizadas para auditorías (logs, escaneos, reportes)",
          "Gestión de Privacy by Design y Data Protection Impact Assessments"
        ]
      },
      {
        title: "Métricas y KPIs Ejecutivos",
        items: [
          "% de aplicaciones con cobertura de SAST/DAST/SCA",
          "Tiempo medio de remediación por severidad (MTTR)",
          "Densidad de vulnerabilidades por 1000 líneas de código",
          "Puntuación de madurez OWASP SAMM o BSIMM"
        ]
      }
    ]
  },
  design: {
    title: "Seguridad por Diseño",
    icon: "🏗️",
    gradient: "from-purple-600 to-pink-600",
    description: "Integración de principios de seguridad desde las fases tempranas de diseño y arquitectura",
    pillars: [
      {
        title: "Threat Modeling y Análisis de Amenazas",
        items: [
          "Metodología STRIDE para identificación sistemática de amenazas",
          "Data Flow Diagrams (DFDs) para mapear superficies de ataque",
          "Attack Trees para análisis de vectores de ataque complejos",
          "Herramientas: Microsoft Threat Modeling Tool, OWASP Threat Dragon"
        ]
      },
      {
        title: "Patrones de Arquitectura Segura",
        items: [
          "Zero Trust Architecture: never trust, always verify",
          "Defense in Depth: capas múltiples de seguridad",
          "Principle of Least Privilege en diseño de permisos",
          "API Gateway con rate limiting, autenticación y autorización"
        ]
      },
      {
        title: "Requisitos de Seguridad Funcionales",
        items: [
          "Autenticación multi-factor obligatoria para funciones críticas",
          "Control de acceso basado en roles (RBAC) y atributos (ABAC)",
          "Cifrado end-to-end para datos sensibles en tránsito",
          "API rate limiting y throttling por usuario/IP"
        ]
      }
    ]
  },
  devsecops: {
    title: "DevSecOps",
    icon: "🔄",
    gradient: "from-green-600 to-emerald-600",
    description: "Automatización de controles de seguridad en pipelines CI/CD con shift-left approach",
    pillars: [
      {
        title: "Pipeline de Seguridad Automatizado",
        items: [
          "Pre-commit hooks: secrets scanning (Talisman, git-secrets)",
          "SAST en IDE: SonarLint, Snyk Code en tiempo real",
          "Build-time: SAST (Checkmarx, Fortify, Semgrep), SCA (Snyk)",
          "Container scanning: Trivy, Clair, Anchore en registry"
        ]
      },
      {
        title: "Shift-Left Security Testing",
        items: [
          "Unit tests de seguridad: fuzzing de inputs, boundary testing",
          "Integration tests con casos de abuso y misuse cases",
          "Security smoke tests en cada PR: top 10 OWASP checks",
          "Chaos engineering para resiliencia"
        ]
      },
      {
        title: "Gestión de Vulnerabilidades y Dependencias",
        items: [
          "Software Composition Analysis (SCA) continuo",
          "Monitoreo de CVEs en tiempo real con GitHub Dependabot, Snyk",
          "Política de actualización: parches críticos < 48h",
          "SBOM (Software Bill of Materials) en formato SPDX/CycloneDX"
        ]
      }
    ]
  },
  controls: {
    title: "Controles de Seguridad",
    icon: "🛡️",
    gradient: "from-red-600 to-orange-600",
    description: "Controles técnicos, detective y preventivos para protección en runtime y respuesta a incidentes",
    pillars: [
      {
        title: "Controles Preventivos en Runtime",
        items: [
          "Web Application Firewall (WAF) con reglas OWASP ModSecurity",
          "API Gateway con OAuth 2.0, rate limiting, schema validation",
          "Runtime Application Self-Protection (RASP)",
          "DDoS protection con CDN (CloudFlare, Akamai, AWS Shield)"
        ]
      },
      {
        title: "Detección de Amenazas y Monitoreo",
        items: [
          "Intrusion Detection Systems (IDS): Snort, Suricata",
          "Security Information and Event Management (SIEM) con correlación",
          "User and Entity Behavior Analytics (UEBA) con ML",
          "Container runtime security: Falco, Sysdig"
        ]
      },
      {
        title: "Gestión de Identidades y Accesos (IAM)",
        items: [
          "Identity Provider centralizado: Okta, Azure AD, Auth0",
          "Single Sign-On (SSO) con SAML 2.0 / OAuth 2.0",
          "Multi-Factor Authentication (MFA) obligatorio",
          "Privileged Access Management (PAM) para cuentas admin"
        ]
      }
    ]
  }
};
