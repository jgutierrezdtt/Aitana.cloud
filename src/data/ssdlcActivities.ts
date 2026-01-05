// Actividades del SSDLC por fase y área

export type SSDLCPhase = 'requirements' | 'design' | 'development' | 'testing' | 'deployment' | 'operations' | 'monitoring';

export const ssdlcPhasesData: { id: SSDLCPhase; name: string; color: string }[] = [
  { id: 'requirements', name: 'Requirements', color: '#3b82f6' },
  { id: 'design', name: 'Design', color: '#8b5cf6' },
  { id: 'development', name: 'Development', color: '#ec4899' },
  { id: 'testing', name: 'Testing', color: '#f59e0b' },
  { id: 'deployment', name: 'Deployment', color: '#10b981' },
  { id: 'operations', name: 'Operations', color: '#06b6d4' },
  { id: 'monitoring', name: 'Monitoring', color: '#6366f1' }
];

export const ssdlcActivitiesData: Record<SSDLCPhase, {
  governance: string[];
  design: string[];
  devsecops: string[];
  controls: string[];
}> = {
  requirements: {
    governance: [
      "Definir clasificación de datos del proyecto",
      "Identificar requisitos regulatorios aplicables",
      "Establecer SLAs de seguridad según criticidad",
      "Asignar Security Champion al equipo"
    ],
    design: [
      "Especificar requisitos de autenticación y autorización",
      "Definir requisitos de cifrado para datos sensibles",
      "Documentar flujos de datos con niveles de confianza",
      "Establecer requisitos de logging y auditoría"
    ],
    devsecops: [
      "Configurar repositorio con protecciones de rama",
      "Habilitar pre-commit hooks para secrets",
      "Definir umbrales de calidad de código y seguridad",
      "Crear historias de usuario con abuse cases"
    ],
    controls: [
      "Identificar superficies de ataque expuestas",
      "Definir controles de red requeridos",
      "Planificar estrategia de monitoreo",
      "Establecer requisitos de backup y DR"
    ]
  },
  design: {
    governance: [
      "Revisión de arquitectura por comité de seguridad",
      "Aprobar excepciones de estándares si aplican",
      "Documentar decisiones de seguridad en ADRs",
      "Validar compliance con frameworks regulatorios"
    ],
    design: [
      "Ejecutar threat modeling (STRIDE/PASTA)",
      "Diseñar controles para cada amenaza identificada",
      "Definir arquitectura de confianza cero",
      "Crear diagramas de flujo de datos (DFD)"
    ],
    devsecops: [
      "Configurar IaC con templates seguros",
      "Definir pipeline CI/CD con gates de seguridad",
      "Seleccionar herramientas SAST/DAST/SCA",
      "Crear tests de seguridad automatizados"
    ],
    controls: [
      "Diseñar microsegmentación de red",
      "Planificar estrategia de WAF y API Gateway",
      "Definir políticas de cifrado (algoritmos, key mgmt)",
      "Establecer controles de identidad (IAM, MFA)"
    ]
  },
  development: {
    governance: [
      "Formación en secure coding para el equipo",
      "Revisión de código con security checklist",
      "Tracking de vulnerabilidades en backlog",
      "Reporte de métricas de seguridad a management"
    ],
    design: [
      "Implementar input validation centralizada",
      "Aplicar output encoding context-aware",
      "Usar librerías criptográficas aprobadas",
      "Implementar controles de autorización granular"
    ],
    devsecops: [
      "SAST en cada commit con SonarQube/Semgrep",
      "SCA para detectar CVEs en dependencias",
      "Peer review de código con foco en seguridad",
      "Unit tests con casos de ataque (fuzzing)"
    ],
    controls: [
      "Implementar logging de eventos de seguridad",
      "Configurar secrets manager para credenciales",
      "Aplicar security headers en respuestas HTTP",
      "Hardening de configuraciones por defecto"
    ]
  },
  testing: {
    governance: [
      "Validar cumplimiento de estándares de seguridad",
      "Aprobar remediaciones de vulnerabilidades",
      "Documentar vulnerabilidades aceptadas",
      "Generar evidencias para auditoría"
    ],
    design: [
      "Validar implementación de controles diseñados",
      "Verificar threat model vs implementación real",
      "Testing de casos de abuso documentados",
      "Validación de principios de least privilege"
    ],
    devsecops: [
      "DAST con OWASP ZAP/Burp en staging",
      "Pentesting automatizado de APIs",
      "Container scanning con Trivy/Clair",
      "Infrastructure scanning con Checkov/Terrascan"
    ],
    controls: [
      "Pruebas de penetración (graybox/blackbox)",
      "Red team exercises en sistemas críticos",
      "Validación de controles IAM y segregación",
      "Testing de DLP, WAF y otros controles runtime"
    ]
  },
  deployment: {
    governance: [
      "Sign-off de seguridad para producción",
      "Verificar documentación de seguridad completa",
      "Confirmar plan de respuesta a incidentes",
      "Comunicar cambios a equipo de SOC"
    ],
    design: [
      "Verificar configuración segura en producción",
      "Validar que secrets no están hardcoded",
      "Confirmar TLS/HTTPS en todos los endpoints",
      "Revisar políticas de CORS y CSP"
    ],
    devsecops: [
      "Deployment automatizado con blue/green o canary",
      "Scanning final de imágenes antes de producción",
      "Verificación de firmas digitales de artefactos",
      "Rollback plan probado y documentado"
    ],
    controls: [
      "Activar monitoreo de seguridad en SIEM",
      "Configurar alertas de anomalías",
      "Habilitar WAF en modo enforcement",
      "Backup inicial post-deployment"
    ]
  },
  operations: {
    governance: [
      "Revisiones de acceso trimestrales",
      "Auditorías de compliance periódicas",
      "Gestión de cambios con aprobación de seguridad",
      "Actualización de registro de riesgos"
    ],
    design: [
      "Revisión de arquitectura ante cambios mayores",
      "Actualizar threat model con nuevas features",
      "Validar que cambios no introducen regresiones",
      "Documentar lessons learned de incidentes"
    ],
    devsecops: [
      "Patcheo automatizado de vulnerabilidades",
      "Rotación automática de secretos y certificados",
      "Scanning continuo de infraestructura",
      "Testing de recuperación ante desastres"
    ],
    controls: [
      "Monitoreo 24/7 por SOC",
      "Gestión de parches con SLAs por severidad",
      "Respuesta a alertas de seguridad",
      "Hardening continuo basado en CIS benchmarks"
    ]
  },
  monitoring: {
    governance: [
      "Dashboard ejecutivo con KPIs de seguridad",
      "Informes de compliance mensual/trimestral",
      "Tracking de remediación de vulnerabilidades",
      "Análisis de tendencias y mejora continua"
    ],
    design: [
      "Análisis de patrones de ataque observados",
      "Feedback loop: ataques reales → threat model",
      "Evolución de controles basado en amenazas",
      "Benchmarking con estándares de industria"
    ],
    devsecops: [
      "Métricas de pipeline: tiempo de detección/remediación",
      "Análisis de falsos positivos y tuning",
      "Optimización de tests de seguridad",
      "Automatización incremental de controles"
    ],
    controls: [
      "Threat hunting proactivo con MITRE ATT&CK",
      "Análisis forense de incidentes",
      "Tuning de reglas de detección (SIEM, IDS)",
      "Ejercicios de red team/blue team"
    ]
  }
};
