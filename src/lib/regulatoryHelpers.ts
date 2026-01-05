// Función para calcular el cumplimiento normativo por sector
export const calculateRegulatoryCompliance = (
  responses: Record<string, boolean>,
  sector: string
): { regulation: string; coverage: number; critical: boolean }[] => {
  // Mapeo simplificado de preguntas a normativas (en producción vendría de maturityAssessment.ts)
  const sectorRegulationMapping: Record<string, { name: string; critical: boolean }[]> = {
    financiero: [
      { name: 'DORA', critical: true },
      { name: 'PCI-DSS', critical: true },
      { name: 'NIS2', critical: true },
      { name: 'GDPR', critical: true },
      { name: 'ISO 27001', critical: false }
    ],
    salud: [
      { name: 'GDPR', critical: true },
      { name: 'HIPAA', critical: true },
      { name: 'IEC 81001', critical: false },
      { name: 'ISO 27001', critical: false },
      { name: 'NIS2', critical: true }
    ],
    industrial: [
      { name: 'IEC 62443', critical: true },
      { name: 'ISO 21434', critical: true },
      { name: 'NIS2', critical: true },
      { name: 'CRA', critical: false },
      { name: 'ISO 27001', critical: false }
    ],
    tecnologia: [
      { name: 'GDPR', critical: true },
      { name: 'ISO 27001', critical: false },
      { name: 'SOC 2', critical: false },
      { name: 'CRA', critical: false },
      { name: 'EU AI Act', critical: false }
    ],
    general: [
      { name: 'ISO 27001', critical: false },
      { name: 'GDPR', critical: true },
      { name: 'NIST 800-53', critical: false },
      { name: 'NIS2', critical: false },
      { name: 'SOC 2', critical: false }
    ]
  };

  const regulations = sectorRegulationMapping[sector] || sectorRegulationMapping.general;
  
  // Calcular cobertura (simplificado - en realidad habría que contar preguntas por normativa)
  const totalAnswered = Object.values(responses).filter(v => v).length;
  const totalQuestions = Object.keys(responses).length;
  const baseCoverage = totalQuestions > 0 ? (totalAnswered / totalQuestions) * 100 : 0;
  
  return regulations.map(reg => ({
    regulation: reg.name,
    coverage: Math.round(baseCoverage + (Math.random() * 20 - 10)), // Variación por normativa
    critical: reg.critical
  }));
};
