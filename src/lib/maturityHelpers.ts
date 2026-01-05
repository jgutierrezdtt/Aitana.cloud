// Sector-specific actions mapping
export const sectorActions: Record<string, { short: string[]; medium: string[]; long: string[] }> = {
  general: {
    short: ['Documentar SSDLC', 'SAST y SCA en CI', 'Formación OWASP básica'],
    medium: ['DAST en QA', 'Threat modeling aplicaciones críticas', 'Generar SBOMs'],
    long: ['Programa de Security Champions', 'Auditoría externa', 'Bug Bounty/VDP']
  },
  financiero: {
    short: ['Inventario de aplicaciones críticas', 'Controles de acceso reforzados', 'SAST + SCA obligatorios'],
    medium: ['TLPT para sistemas críticos', 'Integración SIEM/SOAR', 'Seguridad en terceros'],
    long: ['Pruebas de estrés de seguridad', 'Auditoría DORA/CBEST', 'Programa de Red Team']
  },
  salud: {
    short: ['Clasificación de datos sensibles', 'SAST y manejo de datos en tests', 'Formación GDPR/Protección Datos'],
    medium: ['DAST y pruebas de integración', 'Control de acceso granular', 'SBOM para equipos médicos'],
    long: ['Auditoría de cumplimiento', 'Monitoreo en tiempo real', 'Plan de recuperación específico']
  },
  industrial: {
    short: ['Segmentación de redes OT/IT', 'Inventario de activos críticos', 'SAST/IaC para controladores'],
    medium: ['Pruebas IEC 62443, ISO 21434 mapping', 'Hardening de dispositivos', 'SBOM y cadena de suministro'],
    long: ['Red teaming físico-digital', 'Integración con procesos de seguridad industrial', 'Certificaciones sectoriales']
  },
  tecnologia: {
    short: ['Integración SCA + SAST', 'Pipeline con quality gates', 'Formación DevSecOps'],
    medium: ['Shift-left completo', 'Infraestructura como código segura', 'Firma de artefactos (Sigstore)'],
    long: ['Observability de seguridad', 'Optimización y automatización avanzada', 'Bug Bounty']
  }
};

// Simple maturity projection over 4 quarters
export const projectedMaturity = (base: number): number[] => {
  const q1 = Math.min(5, base + Math.round(0.3 * Math.max(0, 3 - base)));
  const q2 = Math.min(5, q1 + 1);
  const q3 = Math.min(5, q2 + 1);
  const q4 = Math.min(5, q3);
  return [base, q1, q2, q3, q4];
};
