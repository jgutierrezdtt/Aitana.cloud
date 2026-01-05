// Sectores industriales con normativas aplicables y requisitos específicos

export type IndustrySector = 
  | 'finance'
  | 'healthcare'
  | 'energy'
  | 'telecom'
  | 'public'
  | 'industrial'
  | 'retail'
  | 'tech'
  | 'automotive'
  | 'aerospace';

export interface SectorRequirements {
  id: IndustrySector;
  name: string;
  icon: string;
  description: string;
  mandatoryRegulations: string[]; // IDs de regulations.ts
  recommendedRegulations: string[];
  criticalDomains: string[]; // IDs de maturityAssessment domains
  targetMaturityLevel: number; // 1-5
  timelineMultiplier: number; // Factor de ajuste de timeline (1.0 = estándar)
  specificRequirements: {
    title: string;
    description: string;
    frameworks: string[];
    deadline?: string;
  }[];
  industryBenchmark: {
    governance: number;
    design: number;
    devsecops: number;
    controls: number;
    'ai-security'?: number; // Optional para sectores sin foco en IA
  };
  compliancePriorities: string[];
}

export const industrySectorsData: Record<IndustrySector, SectorRequirements> = {
  finance: {
    id: 'finance',
    name: 'Servicios Financieros',
    icon: '🏦',
    description: 'Banca, seguros, fintech y servicios de pago',
    mandatoryRegulations: ['dora', 'pci-dss', 'gdpr', 'nis2', 'iso-27001'],
    recommendedRegulations: ['soc2', 'tiber-eu', 'ens', 'ai-act'],
    criticalDomains: ['governance', 'controls', 'ai-security'],
    targetMaturityLevel: 4,
    timelineMultiplier: 0.8, // Más estricto
    specificRequirements: [
      {
        title: 'DORA - Digital Operational Resilience Act',
        description: 'Cumplimiento obligatorio para entidades financieras en UE desde enero 2025',
        frameworks: ['DORA', 'TIBER-EU', 'ISO 22301'],
        deadline: '17 enero 2025'
      },
      {
        title: 'PCI-DSS v4.0',
        description: 'Protección de datos de tarjetas de pago',
        frameworks: ['PCI-DSS 4.0', 'PA-DSS'],
        deadline: '31 marzo 2025'
      },
      {
        title: 'Threat-Led Penetration Testing (TLPT)',
        description: 'Pruebas avanzadas de penetración dirigidas por amenazas',
        frameworks: ['TIBER-EU', 'CBEST', 'DORA'],
      },
      {
        title: 'Gestión de Riesgo de Terceros (TPRM)',
        description: 'Due diligence exhaustiva de proveedores críticos',
        frameworks: ['DORA Art. 28-30', 'ISO 27036'],
      }
    ],
    industryBenchmark: {
      governance: 3.8,
      design: 3.5,
      devsecops: 3.7,
      controls: 4.2,
      'ai-security': 3.2 // Banca está adoptando IA para fraude, riesgo crediticio
    },
    compliancePriorities: [
      'Implementar controles DORA para resiliencia operativa digital',
      'Certificación PCI-DSS v4.0 para procesamiento de pagos',
      'Establecer programa TLPT según TIBER-EU',
      'Framework de gestión de riesgo de terceros (TPRM)',
      'Plan de continuidad de negocio (BCP) y disaster recovery (DR)'
    ]
  },

  healthcare: {
    id: 'healthcare',
    name: 'Salud y Farmacéutico',
    icon: '🏥',
    description: 'Hospitales, clínicas, dispositivos médicos, telemedicina',
    mandatoryRegulations: ['gdpr', 'hipaa', 'iec-81001', 'ai-act', 'nis2'],
    recommendedRegulations: ['iso-27001', 'soc2', 'iec-62443'],
    criticalDomains: ['governance', 'design', 'controls', 'ai-security'],
    targetMaturityLevel: 4,
    timelineMultiplier: 0.9,
    specificRequirements: [
      {
        title: 'IEC 81001 - Seguridad de Dispositivos Médicos',
        description: 'Requisitos de ciberseguridad para dispositivos médicos conectados',
        frameworks: ['IEC 81001-5-1', 'FDA Cybersecurity', 'MDR'],
      },
      {
        title: 'EU AI Act - Sistemas de IA Médicos',
        description: 'IA de alto riesgo en diagnóstico y tratamiento',
        frameworks: ['EU AI Act', 'ISO 42001', 'MITRE ATLAS'],
        deadline: '2 agosto 2026'
      },
      {
        title: 'HIPAA Security Rule',
        description: 'Protección de ePHI (Electronic Protected Health Information)',
        frameworks: ['HIPAA', 'HITECH Act'],
      },
      {
        title: 'NIS2 - Infraestructuras Críticas Sanitarias',
        description: 'Requisitos de ciberseguridad para proveedores de salud',
        frameworks: ['NIS2', 'ENS Alto'],
        deadline: '17 octubre 2024'
      }
    ],
    industryBenchmark: {
      governance: 3.5,
      design: 3.8,
      devsecops: 3.2,
      controls: 3.9,
      'ai-security': 3.6 // Salud usa IA para diagnóstico, telemedicina
    },
    compliancePriorities: [
      'Certificación IEC 81001 para dispositivos médicos conectados',
      'Cumplimiento GDPR/HIPAA para protección de datos sanitarios',
      'Evaluación de riesgo de IA médica según EU AI Act',
      'Segmentación de red para sistemas críticos (IEC 62443)',
      'Auditorías de privacidad y consentimiento informado'
    ]
  },

  energy: {
    id: 'energy',
    name: 'Energía y Utilities',
    icon: '⚡',
    description: 'Electricidad, gas, agua, renovables, redes inteligentes',
    mandatoryRegulations: ['nis2', 'iec-62443', 'ens', 'gdpr'],
    recommendedRegulations: ['iso-27001', 'nist-800-53', 'ccn-stic'],
    criticalDomains: ['controls', 'design'],
    targetMaturityLevel: 4,
    timelineMultiplier: 1.0,
    specificRequirements: [
      {
        title: 'NIS2 - Operadores de Servicios Esenciales',
        description: 'Ciberseguridad para infraestructuras críticas energéticas',
        frameworks: ['NIS2', 'CER Directive', 'ENISA Guidelines'],
        deadline: '17 octubre 2024'
      },
      {
        title: 'IEC 62443 - Seguridad Industrial (ICS/SCADA)',
        description: 'Estándar para sistemas de control industrial',
        frameworks: ['IEC 62443-3-3', 'NIST SP 800-82', 'ISA/IEC 62443'],
      },
      {
        title: 'Esquema Nacional de Seguridad (ENS Alto)',
        description: 'Requisitos para sistemas de información del sector público',
        frameworks: ['ENS', 'CCN-STIC', 'ISO 27001'],
      }
    ],
    industryBenchmark: {
      governance: 3.5,
      design: 3.9,
      devsecops: 3.2,
      controls: 4.1
    },
    compliancePriorities: [
      'Implementar IEC 62443 para protección de ICS/SCADA',
      'Cumplimiento NIS2 con medidas de seguridad de red',
      'Segmentación de red OT/IT según ISA/IEC 62443',
      'Plan de respuesta a incidentes para infraestructuras críticas',
      'Auditorías de seguridad física y ciberfísica'
    ]
  },

  telecom: {
    id: 'telecom',
    name: 'Telecomunicaciones',
    icon: '📡',
    description: '5G, ISPs, operadores móviles, proveedores de servicios digitales',
    mandatoryRegulations: ['nis2', 'gdpr', 'eidas', 'cra'],
    recommendedRegulations: ['iso-27001', 'soc2', 'iec-62443'],
    criticalDomains: ['governance', 'devsecops', 'controls'],
    targetMaturityLevel: 4,
    timelineMultiplier: 0.85,
    specificRequirements: [
      {
        title: 'NIS2 - Proveedores de Servicios Digitales',
        description: 'Requisitos de seguridad para redes y servicios de comunicaciones',
        frameworks: ['NIS2', 'ENISA 5G Security', 'GSMA NESAS'],
        deadline: '17 octubre 2024'
      },
      {
        title: 'Cyber Resilience Act (CRA)',
        description: 'Seguridad de productos digitales con elementos digitales',
        frameworks: ['CRA', 'EN 303 645', 'ETSI TS 103 701'],
        deadline: '2027 (estimado)'
      },
      {
        title: 'Seguridad 5G',
        description: 'Toolbox 5G de la UE y medidas de seguridad de red',
        frameworks: ['EU 5G Toolbox', 'GSMA NESAS', 'NIST SP 800-187'],
      }
    ],
    industryBenchmark: {
      governance: 3.7,
      design: 3.6,
      devsecops: 3.9,
      controls: 4.0
    },
    compliancePriorities: [
      'Cumplimiento NIS2 para servicios de comunicaciones electrónicas',
      'Implementar EU 5G Security Toolbox',
      'Preparación para Cyber Resilience Act (CRA)',
      'Gestión de vulnerabilidades de red (CVSS >= 7.0)',
      'Supply chain security para equipamiento de red'
    ]
  },

  public: {
    id: 'public',
    name: 'Sector Público',
    icon: '🏛️',
    description: 'Administración, defensa, servicios públicos digitales',
    mandatoryRegulations: ['ens', 'gdpr', 'nis2', 'ccn-stic'],
    recommendedRegulations: ['iso-27001', 'nist-800-53'],
    criticalDomains: ['governance', 'controls'],
    targetMaturityLevel: 3,
    timelineMultiplier: 1.2,
    specificRequirements: [
      {
        title: 'Esquema Nacional de Seguridad (ENS)',
        description: 'Obligatorio para AAPP en España',
        frameworks: ['ENS Alto/Medio/Bajo', 'CCN-STIC 800-series'],
      },
      {
        title: 'CCN-STIC - Guías Técnicas',
        description: 'Instrucciones técnicas del CCN-CERT',
        frameworks: ['CCN-STIC 800', 'CCN-STIC 400', 'Beam'],
      },
      {
        title: 'NIS2 - Entidades Críticas',
        description: 'AAPP como entidades esenciales o importantes',
        frameworks: ['NIS2', 'CER Directive'],
        deadline: '17 octubre 2024'
      }
    ],
    industryBenchmark: {
      governance: 3.4,
      design: 2.9,
      devsecops: 2.7,
      controls: 3.6
    },
    compliancePriorities: [
      'Certificación ENS (categoría según análisis de riesgo)',
      'Implementación de guías CCN-STIC aplicables',
      'Auditoría de cumplimiento ENS cada 2 años',
      'Notificación de incidentes a CCN-CERT',
      'Formación específica en ciberseguridad para empleados públicos'
    ]
  },

  industrial: {
    id: 'industrial',
    name: 'Industrial y Manufactura',
    icon: '🏭',
    description: 'Fabricación, logística, Industry 4.0, smart factories',
    mandatoryRegulations: ['iec-62443', 'iso-27001', 'gdpr'],
    recommendedRegulations: ['nis2', 'ens', 'nist-800-53'],
    criticalDomains: ['design', 'controls'],
    targetMaturityLevel: 3,
    timelineMultiplier: 1.1,
    specificRequirements: [
      {
        title: 'IEC 62443 - Seguridad Industrial',
        description: 'Protección de sistemas de automatización y control industrial',
        frameworks: ['IEC 62443-4-1', 'IEC 62443-4-2', 'ISA99'],
      },
      {
        title: 'Industry 4.0 Security',
        description: 'Seguridad en IoT industrial, edge computing, gemelos digitales',
        frameworks: ['IIC Security Framework', 'NIST Cybersecurity Framework', 'VDI/VDE 2182'],
      },
      {
        title: 'Supply Chain Security',
        description: 'Seguridad de cadena de suministro y proveedores',
        frameworks: ['NIST 800-161r1', 'ISO 28000', 'C-TPAT'],
      }
    ],
    industryBenchmark: {
      governance: 2.8,
      design: 3.4,
      devsecops: 2.9,
      controls: 3.7
    },
    compliancePriorities: [
      'Implementar IEC 62443 para sistemas OT (Operational Technology)',
      'Segmentación de redes IT/OT (Purdue Model)',
      'Gestión de vulnerabilidades de PLC, HMI, SCADA',
      'Backup y recuperación de configuraciones de dispositivos industriales',
      'Monitorización de anomalías en protocolos industriales (Modbus, PROFINET, etc.)'
    ]
  },

  retail: {
    id: 'retail',
    name: 'Retail y E-commerce',
    icon: '🛒',
    description: 'Comercio electrónico, punto de venta, omnicanal',
    mandatoryRegulations: ['pci-dss', 'gdpr'],
    recommendedRegulations: ['iso-27001', 'soc2', 'nis2'],
    criticalDomains: ['devsecops', 'controls'],
    targetMaturityLevel: 3,
    timelineMultiplier: 1.0,
    specificRequirements: [
      {
        title: 'PCI-DSS v4.0',
        description: 'Protección de datos de tarjetas de pago',
        frameworks: ['PCI-DSS 4.0', 'PA-DSS', '3DS 2.0'],
        deadline: '31 marzo 2025'
      },
      {
        title: 'GDPR - Consentimiento y Privacidad',
        description: 'Gestión de consentimiento, cookies, marketing',
        frameworks: ['GDPR', 'ePrivacy Directive', 'EDPB Guidelines'],
      },
      {
        title: 'Seguridad en Pagos Digitales',
        description: 'PSD2, autenticación fuerte (SCA), antifraude',
        frameworks: ['PSD2', 'SCA', 'EMV 3DS'],
      }
    ],
    industryBenchmark: {
      governance: 2.9,
      design: 3.1,
      devsecops: 3.5,
      controls: 3.4
    },
    compliancePriorities: [
      'Certificación PCI-DSS v4.0 (SAQ o RoC según volumen)',
      'Implementar SCA (Strong Customer Authentication) según PSD2',
      'Protección contra fraude (card testing, credential stuffing)',
      'Seguridad de APIs de pago y checkout',
      'Cumplimiento GDPR en marketing y consentimiento de cookies'
    ]
  },

  tech: {
    id: 'tech',
    name: 'Tecnología y SaaS',
    icon: '💻',
    description: 'Software as a Service, cloud providers, plataformas digitales',
    mandatoryRegulations: ['gdpr', 'soc2'],
    recommendedRegulations: ['iso-27001', 'iso-27034', 'cra', 'nis2', 'ai-act'],
    criticalDomains: ['devsecops', 'design', 'ai-security'],
    targetMaturityLevel: 4,
    timelineMultiplier: 0.9,
    specificRequirements: [
      {
        title: 'SOC 2 Type II',
        description: 'Auditoría de controles de seguridad para SaaS',
        frameworks: ['SOC 2', 'AICPA TSC', 'ISO 27001'],
      },
      {
        title: 'ISO 27034 - Application Security',
        description: 'Framework de seguridad de aplicaciones',
        frameworks: ['ISO 27034', 'OWASP SAMM', 'BSIMM'],
      },
      {
        title: 'Cyber Resilience Act (CRA)',
        description: 'Productos con elementos digitales en la UE',
        frameworks: ['CRA', 'SBOM (SPDX/CycloneDX)', 'SLSA'],
        deadline: '2027 (estimado)'
      },
      {
        title: 'Supply Chain Security',
        description: 'SBOM, firma de artefactos, gestión de dependencias',
        frameworks: ['SLSA', 'Sigstore', 'NIST SSDF', 'SBOM'],
      }
    ],
    industryBenchmark: {
      governance: 3.6,
      design: 4.1,
      devsecops: 4.3,
      controls: 3.8,
      'ai-security': 4.2 // Tech/SaaS liderando en IA (chatbots, copilots, analytics)
    },
    compliancePriorities: [
      'Certificación SOC 2 Type II anual',
      'Implementar SSDLC completo (OWASP SAMM Level 2+)',
      'Generar SBOMs automáticos (SPDX/CycloneDX)',
      'Pipeline DevSecOps con SAST, SCA, DAST, IaC scanning',
      'Bug Bounty o Vulnerability Disclosure Program (VDP)'
    ]
  },

  automotive: {
    id: 'automotive',
    name: 'Automoción',
    icon: '🚗',
    description: 'Vehículos conectados, conducción autónoma, V2X',
    mandatoryRegulations: ['iso-21434', 'gdpr', 'cra'],
    recommendedRegulations: ['iso-27001', 'iec-62443', 'ai-act'],
    criticalDomains: ['design', 'controls'],
    targetMaturityLevel: 4,
    timelineMultiplier: 1.0,
    specificRequirements: [
      {
        title: 'ISO 21434 - Automotive Cybersecurity',
        description: 'Requisitos de ciberseguridad para vehículos',
        frameworks: ['ISO 21434', 'SAE J3061', 'UNECE WP.29 R155'],
      },
      {
        title: 'EU AI Act - Sistemas de IA en Vehículos',
        description: 'IA de alto riesgo para conducción autónoma',
        frameworks: ['EU AI Act', 'ISO 42001', 'MITRE ATLAS'],
        deadline: '2 agosto 2026'
      },
      {
        title: 'UNECE R155 - Cybersecurity Management System',
        description: 'Obligatorio para homologación de vehículos',
        frameworks: ['UNECE R155', 'ISO 21434', 'SAE J3061'],
      },
      {
        title: 'Over-the-Air (OTA) Update Security',
        description: 'Actualizaciones seguras de software vehicular',
        frameworks: ['UNECE R156', 'Uptane', 'Secure Boot'],
      }
    ],
    industryBenchmark: {
      governance: 3.5,
      design: 4.2,
      devsecops: 3.6,
      controls: 4.0
    },
    compliancePriorities: [
      'Implementar ISO 21434 para ciclo de vida del vehículo',
      'Cumplimiento UNECE R155 para homologación',
      'Threat Analysis and Risk Assessment (TARA) según ISO 21434',
      'Seguridad de actualizaciones OTA (UNECE R156)',
      'Evaluación de riesgo de IA en sistemas ADAS/AD'
    ]
  },

  aerospace: {
    id: 'aerospace',
    name: 'Aeroespacial y Defensa',
    icon: '✈️',
    description: 'Aviación, sistemas de defensa, satélites, drones',
    mandatoryRegulations: ['nis2', 'ens', 'gdpr'],
    recommendedRegulations: ['iso-27001', 'nist-800-53', 'iec-62443', 'ccn-stic'],
    criticalDomains: ['governance', 'design', 'controls'],
    targetMaturityLevel: 5,
    timelineMultiplier: 0.7,
    specificRequirements: [
      {
        title: 'DO-326A / ED-202A - Airworthiness Security',
        description: 'Proceso de seguridad de aeronavegabilidad',
        frameworks: ['DO-326A', 'DO-356A', 'EUROCAE ED-202A'],
      },
      {
        title: 'NIS2 - Infraestructuras Críticas Aeroportuarias',
        description: 'Seguridad de sistemas de gestión de tráfico aéreo',
        frameworks: ['NIS2', 'EASA Cybersecurity', 'ICAO Annex 17'],
        deadline: '17 octubre 2024'
      },
      {
        title: 'Clasificación de Información (NACIONAL/UE/OTAN)',
        description: 'Gestión de información clasificada',
        frameworks: ['ENS Alto', 'CCN-STIC', 'OTAN INFOSEC', 'EUCI'],
      },
      {
        title: 'Supply Chain Security (Critical Components)',
        description: 'Seguridad de cadena de suministro para componentes críticos',
        frameworks: ['NIST 800-161r1', 'CMMC', 'ISO 28000'],
      }
    ],
    industryBenchmark: {
      governance: 4.3,
      design: 4.5,
      devsecops: 3.9,
      controls: 4.7
    },
    compliancePriorities: [
      'Certificación ENS Alto para sistemas críticos de defensa',
      'Cumplimiento NIS2 para infraestructuras aeroportuarias',
      'Implementar DO-326A para sistemas embarcados aeronáuticos',
      'Gestión de información clasificada según CCN-STIC 800',
      'Auditorías de seguridad de supply chain (CMMC para EEUU)'
    ]
  }
};

export const getSectorByRegulation = (regulationId: string): IndustrySector[] => {
  const sectors: IndustrySector[] = [];
  
  Object.entries(industrySectorsData).forEach(([key, sector]) => {
    if (sector.mandatoryRegulations.includes(regulationId) || 
        sector.recommendedRegulations.includes(regulationId)) {
      sectors.push(key as IndustrySector);
    }
  });
  
  return sectors;
};

export const getRegulationPriority = (sectorId: IndustrySector, regulationId: string): 'mandatory' | 'recommended' | 'none' => {
  const sector = industrySectorsData[sectorId];
  if (sector.mandatoryRegulations.includes(regulationId)) return 'mandatory';
  if (sector.recommendedRegulations.includes(regulationId)) return 'recommended';
  return 'none';
};

export const calculateSectorCompliance = (
  sectorId: IndustrySector,
  currentScores: { governance: number; design: number; devsecops: number; controls: number }
): {
  overall: number;
  gaps: { domain: string; gap: number }[];
  priority: 'critical' | 'high' | 'medium' | 'low';
} => {
  const sector = industrySectorsData[sectorId];
  const benchmark = sector.industryBenchmark;
  
  const gaps = [
    { domain: 'governance', gap: benchmark.governance - currentScores.governance },
    { domain: 'design', gap: benchmark.design - currentScores.design },
    { domain: 'devsecops', gap: benchmark.devsecops - currentScores.devsecops },
    { domain: 'controls', gap: benchmark.controls - currentScores.controls }
  ];
  
  const avgGap = gaps.reduce((sum, g) => sum + Math.max(0, g.gap), 0) / 4;
  const overall = Math.max(0, 100 - (avgGap * 20)); // Convertir a porcentaje
  
  const priority = avgGap > 1.5 ? 'critical' : avgGap > 1.0 ? 'high' : avgGap > 0.5 ? 'medium' : 'low';
  
  return { overall, gaps, priority };
};
